# openmoat-sdk

OpenMoat's policy decisions for your own agent product: compile a policy once, then
decide each tool call (a shell command, a file read or write, a network host, an MCP
tool call) before your loop runs it. Part of
[OpenMoat](https://github.com/crocodile-labs/openmoat).

```rust
use openmoat_sdk::{Action, Context, DEFAULT_POLICY, Engine, Policy, Verdict};

let context = Context::new("/home/me", "/home/me/app").project("/home/me/app");
let engine = Engine::new(Policy::parse(DEFAULT_POLICY)?, &context)?;
let decision = engine.decide(&Action::shell("cat ~/.ssh/id_rsa"));
assert_eq!(decision.verdict, Verdict::Deny);
```

**The SDK decides; your code enforces.** A denied call must not run, and an `ask` must
not run until a person approves that exact call. It is not a sandbox. Pure: no I/O
(except `Policy::read` with the `fs` feature), no network, no telemetry.

It makes the same decisions as `openmoat guard` of the same version: every conformance
fixture is checked both ways. Guide: [docs/SDK.md](https://github.com/crocodile-labs/openmoat/blob/main/docs/SDK.md);
stability contract: [ADR-046](https://github.com/crocodile-labs/openmoat/blob/main/docs/adr/ADR-046-sdk-contract.md).
