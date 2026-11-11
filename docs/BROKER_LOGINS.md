# Keep an agent's API key out of `openmoat run`

[README](../README.md) · [Docs index](README.md) · [openmoat.dev/docs](https://openmoat.dev/docs/)

> [!NOTE]
> **Read this when** you run an agent under `openmoat run` with a provider API key and
> want the commands it runs unable to read that key.

Under `openmoat run` the agent runs inside the sandbox, so the sandbox keeps its own
login readable, and every command the agent runs can read it too
([SANDBOX.md](SANDBOX.md), ADR-054). Other agents' logins stay denied. For an agent that
signs in with a provider **API key** taken from an environment variable, the key can stay
out of the sandbox altogether: OpenMoat's broker (ADR-020, ADR-043) gives the agent a
placeholder, and the run's proxy puts the real key into HTTPS requests to the provider's
host only.

This does not work for OAuth sign-ins (Claude Code or Codex with a subscription, GitHub
Copilot CLI, Gemini CLI with a Google account): those agents refresh their token and
write it back to their login file, which a placeholder cannot follow. For them the
running agent's login stays readable to its commands under `openmoat run`; the agent's
own sandbox (the Standard tier, `openmoat init`) denies it to every command instead.

## Steps

1. Put the key in a file only you read, outside every path the sandbox grants:

   ```bash
   install -m 600 /dev/null ~/.config/moat/anthropic   # then paste the key into it
   ```

2. Broker it for the provider's API host, with TLS termination: the API is HTTPS, and
   the proxy puts a value into HTTPS only for a secret that says so.

   ```bash
   openmoat secret add anthropic --host api.anthropic.com --header x-api-key \
     --file ~/.config/moat/anthropic --tls-terminate
   openmoat allow --site api.anthropic.com
   ```

   `openmoat secret add` shows the policy change and asks. It adds a deny rule for the
   file (`secret-anthropic`), so neither the agent nor any sandbox can read it, and
   offers to make the proxy's certificate authority (`openmoat proxy ca init`).

3. Start the agent with the placeholder where it reads its key:

   ```bash
   ANTHROPIC_API_KEY=moat-secret:anthropic:placeholder \
     openmoat run --write ~/.claude --write ~/.claude.json -- claude
   ```

   The agent sends `x-api-key: moat-secret:anthropic:placeholder`; the proxy replaces
   the placeholder with the key in requests to `api.anthropic.com` and refuses any
   request to another host that carries it (`proxy-secret`).

## Other providers

The same three steps, with the provider's host, header and the variable the agent
reads:

| Provider | `--host` | `--header` | Variable |
|---|---|---|---|
| Anthropic | `api.anthropic.com` | `x-api-key` | `ANTHROPIC_API_KEY` |
| OpenAI | `api.openai.com` | `Authorization` | `OPENAI_API_KEY` |
| Google Gemini API | `generativelanguage.googleapis.com` | `x-goog-api-key` | `GEMINI_API_KEY` |

With `Authorization`, the agent sends `Bearer moat-secret:<id>:placeholder` and the
proxy replaces only the placeholder, so the file holds the bare key.

## Tokens that expire (preview)

A cloud CLI that prints a short-lived token (an example: `gcloud auth print-access-token`)
can be the source itself: `openmoat proxy` runs it, uses the token for at most the
lifetime you set and runs it again before it ends, and refuses a request rather than send
an expired token. The policy entry, and the deny rule that keeps the agent from changing
the program, are in [POLICY.md §2.2](POLICY.md#22-short-lived-values-from-a-program-source-command-preview).
`openmoat secret add` does not write this form; add it with `openmoat edit`.

## Limits

- Check which variable or file your agent reads its key from, and that no login file
  overrides it: an agent that also has a stored login (`~/.codex/auth.json` from an
  earlier `codex login`) may use that instead.
- The agent's HTTP client must trust the run's CA through `SSL_CERT_FILE` or
  `NODE_EXTRA_CA_CERTS`, which `openmoat run` sets. A client that ignores them, or pins
  certificates, cannot reach the host; its request is refused (`proxy-tls`) and the key
  is never sent. Node.js agents read `NODE_EXTRA_CA_CERTS`.
- These recipes follow each provider's documented header; no agent session with an
  account was run through them when they were written.
- Only under `openmoat run`: the standalone `openmoat proxy` of the Standard tier never
  terminates TLS.
