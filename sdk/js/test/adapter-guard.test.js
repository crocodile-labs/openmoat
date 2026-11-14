// The guard every framework adapter shares (src/adapters/guard.js): verdicts,
// reviewers, defer, failures, the path search, timing.
import { test } from "node:test";
import assert from "node:assert/strict";

import { createGuard, describe, nodeContext, pathsIn } from "../src/adapters/guard.js";
import { scratchHome } from "./adapter-home.js";

const h = scratchHome();
test.after(() => h.done());

const shellTools = { run: describe.shell("cmd"), read: describe.read("file") };

test("an allowed call runs; a denied one does not, with the reason and rules", async () => {
  const events = [];
  const guard = createGuard({ ...h.options, tools: shellTools, onDecision: (e) => events.push(e) });
  const ok = await guard.check({ tool: "run", input: { cmd: "ls" } });
  assert.deepEqual([ok.run, ok.verdict, ok.message], [true, "allow", ""]);

  const key = await guard.check({ tool: "read", input: { file: h.key }, id: "call-2" });
  assert.equal(key.run, false);
  assert.equal(key.verdict, "deny");
  assert.deepEqual(key.rules, ["secrets-paths"]);
  assert.match(key.message, /^OpenMoat blocked this tool call \(secrets-paths\): secret material/);
  assert.match(key.message, /It did not run\.$/);

  // Latency is recorded per call and in total.
  assert.equal(events.length, 2);
  assert.equal(events[1].id, "call-2");
  for (const e of events) assert.ok(e.ms >= e.decideMs && e.decideMs >= 0);
  assert.deepEqual([guard.stats.calls, guard.stats.ran, guard.stats.blocked], [2, 1, 1]);
  assert.ok(guard.stats.totalMs >= guard.stats.maxMs && guard.stats.maxMs > 0);
});

test("a review needs a person: without a reviewer, or with a no, the call does not run", async () => {
  const action = { type: "unchecked", action: { type: "shell", command: "ls" }, reason: "test" };
  const none = createGuard(h.options);
  const held = await none.check({ tool: "x", input: {}, action });
  assert.deepEqual([held.run, held.verdict], [false, "review"]);
  assert.match(held.message, /No person can approve it here, so it did not run\.$/);

  const asked = [];
  const no = createGuard({ ...h.options, review: (call) => (asked.push(call), false) });
  const refused = await no.check({ tool: "x", input: {}, action });
  assert.deepEqual([refused.run, refused.approved], [false, false]);
  assert.equal(asked[0].decision.verdict, "review");

  // Only `true` approves: a truthy value is not an approval.
  const truthy = createGuard({ ...h.options, review: () => /** @type {any} */ ("yes") });
  assert.equal((await truthy.check({ tool: "x", input: {}, action })).run, false);

  const yes = createGuard({ ...h.options, review: async () => true });
  const approved = await yes.check({ tool: "x", input: {}, action });
  assert.deepEqual([approved.run, approved.approved], [true, true]);

  const broken = createGuard({ ...h.options, review: () => { throw new Error("pager down"); } });
  const failed = await broken.check({ tool: "x", input: {}, action });
  assert.deepEqual([failed.run, failed.verdict], [false, "deny"]);
  assert.match(failed.message, /could not decide this tool call \(pager down\)/);
});

test("defer goes to the framework by default, or to review when asked", async () => {
  const call = { tool: "run", input: { cmd: "git push" } };
  const quiet = await createGuard({ ...h.options, tools: shellTools }).check(call);
  assert.deepEqual([quiet.run, quiet.verdict], [true, "defer"]);
  const strict = await createGuard({ ...h.options, tools: shellTools, defer: "review" }).check(call);
  assert.deepEqual([strict.run, strict.verdict], [false, "defer"]);
  assert.match(strict.message, /No person can approve it here/);
});

test("every failure fails closed: a missing field, a broken module, a bad policy", async () => {
  const missing = await createGuard({ ...h.options, tools: shellTools }).check({ tool: "run", input: {} });
  assert.equal(missing.run, false);
  assert.match(missing.message, /no string "cmd"/);

  const noModule = createGuard({ ...h.options, openmoat: Promise.reject(new Error("no wasm")) });
  for (let i = 0; i < 2; i++) {
    const r = await noModule.check({ tool: "x", input: {} });
    assert.deepEqual([r.run, r.verdict], [false, "deny"]);
  }
  assert.equal(noModule.stats.errors, 2);
  await assert.rejects(noModule.ready());

  const badPolicy = await createGuard({ ...h.options, policy: "version: [" }).check({ tool: "x", input: {} });
  assert.equal(badPolicy.run, false);

  // An observer that throws changes nothing.
  const loud = createGuard({ ...h.options, onDecision: () => { throw new Error("log full"); } });
  assert.equal((await loud.check({ tool: "x", input: {} })).run, true);
});

test("an undescribed tool is an unknown tool whose path-like strings are reads", async () => {
  const guard = createGuard({ ...h.options, host: "my-agent" });
  const plain = await guard.check({ tool: "summarise", input: { text: "hello", n: 3 } });
  assert.equal(plain.run, true);
  assert.deepEqual(plain.action, { type: "unknown_tool", host: "my-agent", tool: "summarise" });

  const nested = await guard.check({ tool: "upload", input: { files: [{ from: "~/.ssh/id_ed25519" }] } });
  assert.deepEqual([nested.run, nested.verdict, nested.rules], [false, "deny", ["secrets-paths"]]);

  assert.deepEqual(pathsIn({ a: "/etc/hosts", b: ["C:\\x", "~", "relative/path", "https://x.test/"] }).paths.sort(), [
    "/etc/hosts",
    "C:\\x",
    "~",
  ]);
  let deep = {};
  for (let i = 0; i < 40; i++) deep = { deep };
  const tooDeep = await guard.check({ tool: "t", input: deep });
  assert.deepEqual([tooDeep.run, tooDeep.verdict], [false, "review"]);
  const many = await guard.check({ tool: "t", input: Array.from({ length: 1100 }, () => "x") });
  assert.equal(many.run, false);
});

test("the Node context makes the working directory the project, never the home", async () => {
  const inProject = await nodeContext(h.project);
  assert.equal(inProject.cwd, h.project);
  assert.equal(inProject.project, h.project);
  assert.equal((await nodeContext("/")).project, undefined);
  const home = (await nodeContext()).home;
  assert.equal((await nodeContext(home)).project, undefined);
});
