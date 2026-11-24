# ADR-118: Short-lived, audience-bound credentials minted by the proxy

Status: proposed · Date: 2026-11-23 · Builds on ADR-020 (egress proxy), ADR-027 (session
credential), ADR-043 (TLS termination), ADR-087 (short-lived values from a program) ·
Numbered 118: 116 and 117 are taken by changes open at the time of writing

## Context

A brokered secret (ADR-020) keeps a value out of the agent's process: the agent sends a
placeholder, and the proxy puts the value in the request to the secret's own host. Two gaps
remained.

1. **The value is as wide and as long-lived as what the person holds.** A personal access
   token, an AWS access key or a Google credential reaches everything the person can reach
   and lives until revoked. ADR-087 lets a program print a short-lived value, but leaves it
   to that program to narrow it, and pins only the program file.
2. **Tools that sign their own requests or keep TLS end to end get nothing.** git over
   HTTPS sends its credential inside a tunnel the proxy does not open unless the host says
   `tls: terminate`; the AWS tools sign each request with the secret key (SigV4), so there is
   no header the proxy could fill in at all.

Each of the three providers people asked for has an official call that turns a credential
the person holds into a narrower one that expires on its own:

| Provider | Call | Narrowed to | Lifetime |
|---|---|---|---|
| GitHub | `POST /app/installations/{id}/access_tokens`, signed with the App's JWT | named repositories and permissions | 1 hour, fixed by GitHub |
| AWS | STS `AssumeRole` with an inline session policy | the intersection of the role's permissions and the session policy | 15 minutes to 12 hours |
| Google Cloud | IAM Credentials `generateAccessToken` | named OAuth scopes of one service account | up to 1 hour |

GitHub has no call that narrows an OAuth or personal access token, such as the one
`gh auth token` prints: a token made from it would have every scope and repository the
person's login has. So a GitHub mint starts from a GitHub App only.

## Decision

1. **`source: { mint: { <provider>: … } }`** (`openmoat-core/src/secret/mint.rs`), one of
   `github-app`, `aws-sts`, `gcp`. Every narrowing field is required: `repositories` and
   `permissions` for GitHub (1 to 500 repositories, levels `read`, `write`, `admin`);
   `actions` and `resources` for AWS, never a whole service (`s3:*`) or `*`; `scopes` for
   Google, each a Google OAuth scope. A mint that would hand out everything the person's
   credential can do does not load. Lifetimes are checked against each provider's limits;
   the default is 15 minutes, renewed a fifth of the lifetime before it ends (10 minutes
   before for GitHub's hour).
2. **Only the proxy mints** (`openmoat-cli/src/secrets/mint.rs`), outside every sandbox,
   like a `command` source (`Source::proxy_only`): `openmoat guard`, audit delivery and
   Claude Code's broker refuse or skip it. Each mint reads the person's credential file
   (the App's key, the AWS credentials file's profile, Google's credential file) at that
   moment, signs the request in process (RS256 JWTs and SigV4 with `ring`, which rustls
   already builds with), and sends it straight to the provider's fixed endpoint over the
   system's trust roots, not through the agent's proxy. A Google credential file's own
   `token_uri` is not followed. A GitHub answer that grants a permission the policy did not
   ask for is refused. Errors name the provider's status and error code, never a body or a
   value.
3. **Renewal is ADR-087's**: one `Fetch` trait for programs and mints, the same refresher
   thread per secret, the same deadline. The value is used for the shorter of the asked
   lifetime and the provider's expiry; an answer that ends within 10 seconds is refused; a
   request that would get an expired value is refused (`proxy-secret-expired`). An AWS
   session's secret key and session token are masked in the audit log on their own, besides
   the whole value.
4. **`helper:` hands a value to a tool's own helper protocol**, without TLS termination:
   `helper: { git: { username: … } }` for git's credential helper, `helper: aws` for the AWS
   tools' `credential_process`. An `aws-sts` mint needs `helper: aws` and cannot have
   `tls`, `plain_http` or `allow`; `helper: aws` takes nothing but an `aws-sts` mint;
   `helper: git` needs a DNS name.
   - **Protocol `MOAT-HELPER/1`** on the proxy's own port (`openmoat-proxy/src/server/helper.rs`):
     one line `MOAT-HELPER/1 <tool> <secret-id> <host or -> <base64 of session:token>`, the
     session credential from the run's proxy variables (ADR-027), so only the session's
     processes are answered; the answer is `OK <user or -> <value>` or `NO <reason>`.
   - **The broker decides** (`Broker::hand_out`): the secret must name that tool's helper, a
     git helper must ask for the secret's own host exactly, an AWS helper names no host, and
     an expired value is never handed out. Each answer, given or refused, is an audit row
     with rule `proxy-helper` written before the value is sent; a row that cannot be written
     sends nothing.
   - **`openmoat credential git|aws <id>`** is the client, a hidden command that git or the
     AWS tools start. It reads only `HTTPS_PROXY`, refuses an address that is not loopback,
     and prints the value as the tool reads it.
   - **`openmoat run` sets it up** (`commands/run/helpers.rs`): for git, two
     `GIT_CONFIG_*` entries per secret (protected configuration, read after every file),
     `credential.https://<host>.helper` set empty, which drops the helpers the person's files
     name for that host, then set to the client; for AWS, a config file of the run's own
     (`AWS_CONFIG_FILE`) with a profile `openmoat-<id>` per secret, `AWS_PROFILE` when there
     is one, `AWS_SHARED_CREDENTIALS_FILE` pointing at an empty file, and the key variables
     removed, since both would come before `credential_process`. The files hold no value
     and are removed when the run ends; under `--isolate` their folder is bound in
     read-only.
5. **The lint warns** when no deny `fs.read` rule covers the file a mint starts from, as it
   does for a `file` source.

## Consequences

- An agent session gets a credential that can do what the policy names, for minutes, and
  the person's own credential never enters the sandbox.
- **A value handed to a helper is in the session.** git and the AWS tools are processes the
  agent starts, so any command of the session can run `openmoat credential` and read the
  value, as it could read a token in an environment variable. What bounds it is its
  narrowing, its lifetime, and the egress policy: the proxy refuses a placeholder or value
  sent to any other host where it can read the request (plain HTTP, a terminated tunnel),
  but not inside a tunnel it does not open to a host the policy allows. Use `helper:` for
  minted values only, and keep the hosts the agent may reach few.
- **The agent's own login stays readable to its child commands.** `openmoat run` lets the
  agent read its own credential so it can start (ADR-054); its commands run with the same
  rights, so they can read that login too. Minting narrows the credentials the agent is
  handed, not the one it signs in with.
- A GitHub OAuth or personal access token cannot be minted from, by GitHub's design; the
  docs say so and point to a GitHub App.
- No new crate: `ring` (already in the build through rustls) for RSA and HMAC, and the
  channels' HTTPS transport (`remote/https.rs`) widened to any method and headers.
- Tests use no network: each signed request is compared with a golden file and each answer
  read from a fixture shaped as the provider's documentation shows.
