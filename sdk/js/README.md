# @openmoat/sdk

OpenMoat's policy decisions for your own agent product, in JavaScript: the engine
compiled to WebAssembly behind a typed API. Decide each tool call before your loop runs
it. No dependencies, no network, no telemetry: the module imports nothing from its host.

```js
import { load, Session } from "@openmoat/sdk";

const openmoat = await load();
const engine = openmoat.compile({
  policy: openmoat.defaultPolicy,
  context: { home: "/home/me", cwd: "/home/me/app", project: "/home/me/app" },
});
const session = new Session();

const d = engine.decide({ type: "shell", command: "cat ~/.ssh/id_rsa" }, { session });
if (d.verdict === "allow") {
  run(d.action); // the frozen copy of exactly what was decided
  session.record(engine, d.action);
}
```

**The SDK decides; your code enforces.** A `deny` must not run; an `ask` (and a `defer`,
if your product has no permission flow of its own) runs only after a person approves
that exact call. It is not a sandbox.

It decides every OpenMoat conformance fixture exactly as `openmoat guard` of the same
version. Full guide, actions, facts and sessions:
[docs/SDK.md](https://github.com/crocodile-labs/openmoat/blob/main/docs/SDK.md).
A complete agent loop: `examples/agent-loop.js`.

Build from a checkout with `scripts/ci/sdk-js.sh`, which writes `dist/openmoat.wasm` and
its SHA-256 and runs the tests.
