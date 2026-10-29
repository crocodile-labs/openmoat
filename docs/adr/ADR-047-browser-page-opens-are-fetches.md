# ADR-047: A browser MCP call that only opens a page is a `fetch`

Status: accepted · Date: 2026-10-28 · Refines ADR-017 and ADR-035

## Context

The default policy denies network to unlisted hosts (`defaults: net: deny`). An MCP
call whose arguments name a URL becomes a `net` atom of its host (`wire/mcp.rs`), so a
browser server's `navigate https://docs.example.com` was denied for every host outside
`registries`. Agents drive browsers through MCP every day (Chrome DevTools MCP, Playwright
MCP, Puppeteer, Claude in Chrome, Browserbase) to read documentation, check a page they
are building and reproduce a bug. Denying that pushed people to allow whole hosts or to
switch the `net` default off, which protects less than a narrower rule.

A navigation that sends nothing but its URL is the same risk as `WebFetch` (ADR-017): a
GET of a URL the agent chose. The servers' own schemas (sources below) show the shapes:

| Server | Page open | Sends data |
|---|---|---|
| Chrome DevTools MCP 1.12 ([tools](https://github.com/ChromeDevTools/chrome-devtools-mcp/blob/chrome-devtools-mcp-v1.12.0/docs/tool-reference.md), [pages.ts](https://github.com/ChromeDevTools/chrome-devtools-mcp/blob/chrome-devtools-mcp-v1.12.0/src/tools/pages.ts)) | `navigate_page {pageId, type, url, timeout, ignoreCache, handleBeforeUnload}`, `new_page {url, background, isolatedContext, timeout}` | `navigate_page.initScript` (runs on every load), `click`, `fill`, `fill_form`, `type_text`, `upload_file`, `evaluate_script`, `emulate.extraHttpHeaders` |
| Playwright MCP 0.0.83 ([backend tools](https://github.com/microsoft/playwright/tree/main/packages/playwright-core/src/tools/backend), [README](https://github.com/microsoft/playwright-mcp/blob/main/README.md)) | `browser_navigate {url}`, `browser_tabs {action: new, url}` | `browser_click`, `browser_type`, `browser_fill_form`, `browser_file_upload`, `browser_evaluate`, `browser_run_code_unsafe`, `browser_route`, `browser_cookie_set` |
| Puppeteer ([index.ts](https://github.com/modelcontextprotocol/servers-archived/blob/main/src/puppeteer/index.ts)) | `puppeteer_navigate {url}` | `launchOptions`, `allowDangerous`, `puppeteer_fill`, `puppeteer_evaluate` |
| Claude in Chrome (no public schema; the tool schemas the extension registers) | `navigate {url, tabId}`, `url` also `back`/`forward` | `computer` (type, click), `form_input`, `javascript_tool`, `file_upload` |
| Browserbase 3.0 ([tools](https://github.com/browserbase/mcp-server-browserbase/tree/v3.0.0/src/tools)) | `navigate {url}` (earlier `browserbase_stagehand_navigate`) | `act` |

Three things make a browser more than `WebFetch`, and the decision has to answer each:
it follows redirects and links the page chooses; it parses URLs the way the URL Standard
says, not the way `curl` does; and it opens schemes that are no web page at all
(`file:`, `javascript:`, `data:`, `chrome:`).

## Decision

1. **The adapter reports what the call opens, not a verdict.** `wire/mcp/browser.rs`
   reports the URL in a new `Action::McpTool.opens` field, instead of `hosts`, only when
   the call provably sends nothing else. The check is an allowlist, as ADR-035's is for
   `curl`: the tool's name has a word that opens a page (`navigate`, `goto`, `visit`,
   `open`, `new_page`, `new_tab`, `go_to`, or the argument `action: new`) and none that
   sends data (`type`, `fill`, `click`, `submit`, `upload`, `evaluate`, `script`,
   `cookie`, `header`, `post`, `send`, `set`, `install`, `launch`, …); the arguments are
   one object with exactly one non-empty string under a URL key and otherwise only
   settings that send nothing (`pageId`, `tabId`, `timeout`, `ignoreCache`,
   `handleBeforeUnload`, `background`, `isolatedContext`, `waitUntil`, and `type` or
   `action` with a navigation value) as plain values. Any other key, a nested value or a
   second URL keeps the call as before. A generic HTTP server's `fetch` is left out:
   such servers send methods, headers and bodies under names of their own.
2. **The engine decides the page** (`engine/atoms/urls.rs`, `host/web.rs`):
   - a `fetch` atom of each host only for a plain web page: `http` or `https`, no user
     part, and a domain name for every host. An IP address in any spelling and a
     single-label name stay `net`, as for ADR-035, so `local-net` defers a localhost dev
     server and private, link-local and metadata addresses are denied as for `curl`;
   - every host a client may read the URL as reaching: `curl`'s reading and the URL
     Standard's (tabs and newlines dropped, control characters trimmed, `\` read as `/`,
     any slashes after `http:`, the host percent-decoded). Strictest wins across them.
     This applies to `WebFetch`, `net` and every MCP URL argument as well: until now
     `WebFetch https://evil.com\@github.com/` was decided as `github.com`, which
     `registries` allows, while a browser and Claude Code's fetcher go to `evil.com`;
   - the hosts of web URLs inside the URL (a redirect target such as `?next=https://…`,
     percent-decoded up to three times), `fetch` or `net` by the same rule;
   - a `file:` URL in any MCP URL argument is an `fs.read` of its path (and `net` to the
     host of `file://host/share`, which Windows reaches over SMB); until now it named no
     host and deferred. `about:blank` is nothing. A scheme that names no network address
     (`javascript:`, `data:`, `blob:`, `view-source:`, `chrome:`, other `about:` pages,
     extension pages) is `unparseable` and asks.
3. **Policy key.** `mcp: { browser_open: fetch | net }`, absent meaning `fetch`. `net`
   keeps every page open a `net` connection, as before this ADR; the `fetch` default and
   `fetch` rules are not touched, so a person can keep browsers strict and `WebFetch` as it
   is.
4. **Data in the URL.** `token-egress` and `placeholder-egress` read the whole URL of an
   open, user part, path, query and fragment included, and send it to every host above.
   After a secret read the open asks (`session-taint`), as every network and MCP call
   does. A URL that then also carries one encoded run of 80 or more characters (base64,
   base64url or hex: all hex digits, or upper and lower case letters and digits) is denied:
   the engine adds `@encoded-egress <host>`, which the new deny group `encoded-egress`
   names. The rule: once a secret is in the session, a person reading the ask can judge a
   short URL, but not a few hundred characters of encoded text, and that is what the
   secret looks like on its way out through a GET. 80 is above a SHA-256 in hex (64), a
   UUID and a commit id, and below 60 encoded bytes; `+`, `/`, `.`, `=` and `&` end a run,
   so a query of words never counts. It applies to every URL a fetch, network or MCP tool
   names, not only to browsers, and not to shell commands, whose clients that can send
   data are `net` already.
5. **Website content is untrusted.** Every MCP call has marked the session as having read
   untrusted content since ADR-020, so opening any site does, and so does the new `fetch`
   atom. That already makes the steps that outlive the session ask: a write to a protected
   (runs-later) path (`session-taint`), a push that changes one (`push-runs-later`), and
   file provenance carries it to the sessions that read or run what this one wrote
   (ADR-029). Reading files, editing source and running tests do not ask. This ADR adds no
   new taint consequence. Package installs and new hosts are not made to ask after
   untrusted content: every session reads documentation, so installs would ask in
   ordinary work; installs keep their own checks (ADR-030), and a new host is `net` (denied)
   or `fetch` (the agent's prompt) whatever the session read.

## Consequences

- `navigate https://docs.rs/serde` through any of the servers above defers to the
  agent's prompt; auto-approve modes run it, as they run `WebFetch`. `navigate
  http://localhost:5173/` defers through `local-net`. A navigation with `initScript`,
  launch options, headers or a form, and any URL under a policy with `browser_open: net`,
  is denied for an unlisted host as before.
- A `fetch` allow rule now covers browser page opens too, as ADR-035 made it cover `curl`.
  A policy that sets `defaults: fetch: allow` allows them.
- A screenshot, snapshot or trace tool writes the file its path names (`take_screenshot
  {filePath}`, `browser_take_screenshot {filename}`): `screenshot`, `snapshot` and `trace`
  join the write verbs, so `take_screenshot {filePath: "~/.zshrc"}` is denied by
  `shell-rc` instead of being read as a read.
- Residual risk, accepted because the agent's own prompt or a person approves each open,
  as for `WebFetch`:
  - The page's own scripts, links, forms and server-side redirects lead where the hook
    cannot see, metadata and private addresses included, and a name may resolve to an
    internal address. Only a proxy after DNS can refuse those: `openmoat proxy` refuses
    link-local and metadata addresses only for a browser whose traffic goes through it,
    and the user's own browser (Claude in Chrome) does not.
  - Data in a URL below the encoded threshold, cut into shorter runs or spread over several
    opens is not denied; after a secret read every open still asks.
  - What a page says can steer the agent (prompt injection). The session is marked as
    having read untrusted content, which covers writes that run later and pushes, not
    installs or later opens.
  - Later browser calls on the open page (click, type, evaluate) name no URL and are
    decided by their name and the paths they name, as before.
  - The allowlist trusts a server's tool name for what the tool does, as `safe-mcp` and
    the write verbs do; a malicious server is the MCP pinning's to catch (ADR-026, ADR-032).
- Follow-up: whether untrusted content should make package installs and first contact
  with a new host ask, measured against MoatBench's developer workflows first.
