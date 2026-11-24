# Team mode

A team can give every machine the same OpenMoat rules and settings, and see what each
machine has, without a server of any kind. Three pieces do it, all local:

- a **team bundle**: a folder with the team's rules and required settings, signed with
  the team's SSH key, kept in a repository or at a path your MDM tool manages;
- **`openmoat team join`**, which a person runs once to install the bundle as a managed
  layer over their own policy, and `openmoat team update` for newer bundles;
- **`openmoat inventory`**, one machine's state as JSON or OCSF, with `--check` to exit 1
  when the machine differs from what the bundle requires, and `--deliver` to send it to
  the collector you already deliver the audit log to.

Nothing leaves the machine unless you configure a sink for it. The design is
[ADR-119](adr/ADR-119-team-mode-without-a-service.md).

## The layer only narrows

The bundle's rules can deny and hold for review; they cannot allow. Your own policy can
make them stricter and never wider:

| The bundle says | Your policy says | What happens |
|---|---|---|
| deny `npm publish` | allow `npm publish` | denied: a deny wins over every allow |
| review `terraform apply` | allow `terraform apply`, or `openmoat allow` for it | held for review: the team's review rules are tried before your allow rules |
| `sandbox.strict: true` | nothing, or `strict: false` | strict: the stricter of the two |
| `hooks.foreign: hold` | `warn` | hold |
| `mcp.allow_sampling: false` | `true` | off |
| nothing about `curl` | allow `curl https://example.com` | your rule decides: the team said nothing |

A rule file with an allow rule, or a setting given its weaker value (`sandbox.strict:
false`), does not parse: it would read as a requirement and require nothing. A team that
wants to allow something ships a [policy pack](POLICY.md#11-signed-policy-packs), which
each person installs, or asks people to add it to their own policy.

Team rules show up in decisions and the audit log as `team:<team>:<file>:<id>`
(`team:acme:policy:no-publish`).

## A bundle in a repository

```text
acme-openmoat/                  # a repository the team owns, cloned on each machine
├── openmoat-team.yaml          # the manifest
├── openmoat-team.yaml.sig      # its signature
├── policy.yaml                 # the team's main rule file
└── packs/
    └── cloud.yaml              # more rule files of the same shape
```

The manifest names every file with its SHA-256, so the one signature covers them all:

```yaml
format: openmoat-team-bundle-v1
name: acme                     # lowercase letters, digits, - and _
serial: 3                      # raise it with every bundle you publish
policy:
  path: policy.yaml
  sha256: 9f2c…                # sha256sum policy.yaml
packs:
  - name: cloud
    path: packs/cloud.yaml
    sha256: 41ab…
settings:                      # each only its stricter value
  sandbox.strict: true
  sandbox.package_min_release_age_days: 7
  hooks.foreign: hold
  unattended: review
  mcp.trust_first_sight: false
  mcp.allow_sampling: false
require_hooks: [claude-code, codex]   # checked by `openmoat inventory --check`
```

A rule file has a repository policy's shape without `allow`
([POLICY.md](POLICY.md#10-repository-policy)): `version`, `deny`, `review`, `require`
(the least protection level an agent must have, §9.2) and `requests:` deny lists:

```yaml
version: 1
deny:
  - id: no-publish
    title: publishing a package
    shell: ["npm publish", "cargo publish", "twine upload"]
review:
  - id: infra-apply
    shell: ["terraform apply", "kubectl apply", "kubectl delete"]
require:
  protection: hook-only          # every agent: an agent without the hook is denied every call
```

Whoever maintains the bundle signs the manifest in the team namespace:

```bash
sha256sum policy.yaml packs/cloud.yaml        # put the digests in openmoat-team.yaml
ssh-keygen -Y sign -f ~/.ssh/acme_ed25519 -n openmoat-team-bundle openmoat-team.yaml
git add -A && git commit -m "openmoat bundle 3" && git push
```

and publishes the public key as an allowed-signers line, for example in the
repository's README:

```text
security@acme.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA…
```

## Join, update, leave

Each person, once, from their own terminal:

```bash
git clone https://git.acme.example/acme-openmoat ~/src/acme-openmoat
openmoat team join ~/src/acme-openmoat \
  --signer "security@acme.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA…"
```

`team join` trusts that key for team bundles only (namespace `openmoat-team-bundle`;
it signs no pack or repository policy here), verifies the signature and every file,
shows what the bundle changes, installs a copy of the exact bytes that verified under
`~/.moat/team/` and re-pins the lock. It refuses a URL: OpenMoat fetches nothing, so you
clone first.

When the team publishes a newer bundle:

```bash
git -C ~/src/acme-openmoat pull
openmoat team update            # reads the folder `team join` used; or give another
```

`team update` verifies the bundle against the key you joined with, refuses another
team's bundle and a serial that is not above the installed one (so an old bundle
cannot be put back to undo a newer rule), and shows what changes. A bundle that only
adds rules or raises settings installs at once; one that removes a rule or drops a
setting widens your policy, and waits for your `y`.

`openmoat team leave` shows what leaving widens, asks, and removes the layer.

All three must be run by you from a terminal, refuse while the lock shows drift, and
are denied to agents. The installed files are pinned by the lock, so a change to them
is drift: every call is denied until you look (`openmoat doctor`).

## With an MDM tool

An MDM tool can keep the bundle's folder up to date (a managed path such as
`/Library/Application Support/Acme/openmoat-team` or `C:\ProgramData\Acme\openmoat-team`)
and run the check on a schedule as the person:

```bash
openmoat inventory --check "/Library/Application Support/Acme/openmoat-team" --format json
echo $?      # 0: the machine has what the bundle requires; 1: it differs; 64: usage error
```

It cannot accept a bundle for the person: only `openmoat team update` from their
terminal installs it, so a newer bundle in the folder is reported as drift
("serial 4 is published, 3 is installed") until they do.

`--check` exits 1 for each of these, one line each (or `{"drift": [...]}` with
`--format`):

| Check | When |
|---|---|
| `team` | no team is joined, or the folder is another team's bundle |
| `bundle` | the folder holds a newer or another bundle than the installed one |
| `lock` | a pinned file changed: every call is denied |
| `policy` | the policy does not load: every call is denied |
| `setting` | a setting the bundle requires is not in force |
| `rule` | a rule of the bundle is not in force |
| `hook` | an agent of `require_hooks` has no current hook, or ran without it (liveness `missing` or `unchecked`) |
| `required-level` | an agent is below the level the policy requires |

A bundle whose signature does not verify against the joined team's key is a usage error
(64), not drift: it says nothing about what the machine should be.

## Inventory

```bash
openmoat inventory                     # JSON, format openmoat-inventory-v1
openmoat inventory --format ocsf       # OCSF 1.3.0 events
openmoat inventory --format ocsf > /var/tmp/openmoat-inventory.json   # a file for the MDM tool to collect
```

It reads files only and prints. What it holds:

| Key | What |
|---|---|
| `machine` | the `machine:` of your accepted delivery configuration (never the host name), OS and architecture |
| `agents[]` | id, name, whether its configuration directory is here, the version its program reports, hook installed, hook liveness (`reported`, `not-yet`, `missing`, `unchecked`), level, tier (`hook-and-os-sandbox`, `openmoat-run`, `hook-only`, `none`) and score (`openmoat run`'s for `openmoat-run`, 0 for the hook alone, none for an agent's own sandbox), whether it meets the required level |
| `run_tiers[]` | each tier `openmoat run` can start here and its protection score |
| `foreign_hooks` | `hooks.foreign` in force and the ledger's counts: recorded, waiting for `openmoat hooks accept`, holding calls |
| `mcp_servers[]` | host, name, file, pinned or not, the pin's digest prefix, the package release it records, protected or not |
| `mcp_proxied[]` | servers `openmoat mcp proxy` pinned the tools of: tool and held counts |
| `policy` | SHA-256 of `policy.yaml`, schema version, `source` (`team` or `local`), the team's name, serial, signer and manifest digest, packs, rule counts, why it does not load |
| `lock` | present, intact, pinned and drifted file counts |
| `audit` | event count, the checkpoint signing key's fingerprint, the latest checkpoint's size and whether the log still holds it |

It never holds a file's contents, a command line, an MCP server's arguments or a secret.
Paths are written with your home as `~`, and every text passes the audit log's
redaction.

### OCSF

`--format ocsf` prints an array of OCSF 1.3.0 events, all in the Discovery category
(5) with activity `Collect` (2), so `type_uid` is `class_uid × 100 + 2`:

| OCSF class | One per | Mapped | OpenMoat's own facts |
|---|---|---|---|
| [Software Inventory Info](https://schema.ocsf.io/1.3.0/classes/software_info) (5020) | agent whose directory is here | `package.name` the agent id, `package.version` its version (`unknown` when it cannot be read), `product.name` its name | `unmapped.openmoat`: the agent's entry above |
| [Device Config State](https://schema.ocsf.io/1.3.0/classes/config_state) (5002) | machine | `severity_id` 1, or 4 when the lock drifted or the policy does not load | `unmapped.openmoat`: policy, lock, audit, foreign hooks, MCP servers, run tiers |

Every event has `metadata` (`version` 1.3.0, `product` OpenMoat and its version,
`log_name` `openmoat-inventory`), `time` (ms) and a
[`device`](https://schema.ocsf.io/1.3.0/objects/device): `type_id` 0 (OpenMoat does not
tell a laptop from a server), `name` the delivery configuration's `machine:` or
`unnamed`, and `os` with its [type](https://schema.ocsf.io/1.3.0/objects/os) (100
Windows, 200 Linux, 300 macOS). The classes list `cloud` and `osint` as required only
under the Cloud and OSINT profiles, which these events do not declare. [Device Inventory
Info](https://schema.ocsf.io/1.3.0/classes/inventory_info) (5001) describes the device
itself, which OpenMoat does not inventory.

### Send it to your collector

Off by default. Add `inventory: true` to a sink of `~/.moat/delivery.yaml`
([DELIVERY.md](DELIVERY.md)), accept the file (`openmoat doctor --accept`), then run
the inventory on a schedule:

```yaml
version: 1
machine: dev-laptop-17
sinks:
  - id: collector
    otlp: https://otel.acme.example/v1/logs
    headers:
      - name: Authorization
        prefix: "Bearer "
        value: { file: "~/.moat/delivery/otel-token" }
    inventory: true
```

```bash
openmoat inventory --deliver        # e.g. daily from cron, launchd or a scheduled task
```

An OTLP sink gets one logs request (scope `openmoat.inventory`, one record per OCSF
event, its body the event's JSON); a webhook sink gets one signed body with `format:
openmoat-inventory-delivery-v1` and the events. They are masked as delivered audit
events are: your policy's brokered secrets and the sink's own key and header values.
A sink without `inventory: true` gets nothing. The command exits 64 when a sink does
not take it. The guard never sends an inventory.

## Limits

- Updates wait for a person. Neither an MDM tool nor a script can accept a bundle:
  `inventory --check` can only report that one waits.
- `--signer` is trusted as you give it: a wrong key trusts the wrong team. Take the line
  from a place the team controls, and read the signer and rules `team join` prints.
- One team per machine. A second team's rules go in a pack.
- A bundle cannot allow anything, and cannot set the settings it does not list.
- The inventory is what this machine reports about itself: a machine whose owner turns
  OpenMoat off reports nothing, and an absent report is the signal. An MDM tool that
  runs `inventory --check` sees exit 64 or no answer there.
- More in [LIMITS.md](LIMITS.md#team-mode).
