// The Node example (examples/agent-loop.js) against a throwaway home: what it
// runs, and what it never runs.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { load } from "../src/index.js";
import { createAgent } from "../examples/agent-loop.js";

const openmoat = await load();
const posix = process.platform !== "win32";

function home() {
  const dir = mkdtempSync(join(tmpdir(), "openmoat-loop-test-"));
  const home = join(dir, "home");
  const project = join(home, "app");
  mkdirSync(join(home, ".ssh"), { recursive: true });
  mkdirSync(project, { recursive: true });
  writeFileSync(join(home, ".ssh", "id_ed25519"), "SECRET-KEY");
  return { dir, home, project, done: () => rmSync(dir, { recursive: true, force: true }) };
}

test("allowed calls run; a denied one never reaches the approver or the tool", { skip: !posix }, async () => {
  const h = home();
  const asked = [];
  const agent = createAgent({ openmoat, ...h, approve: (call) => (asked.push(call), true) });

  const greet = await agent.step({ name: "shell", input: { command: "echo hello > g.txt && cat g.txt" } });
  assert.deepEqual([greet.ran, greet.output], [true, "hello\n"]);

  const key = await agent.step({ name: "shell", input: { command: "cat ~/.ssh/id_ed25519" } });
  assert.deepEqual([key.ran, key.verdict], [false, "deny"]);
  assert.match(key.reason, /secret material/);
  assert.deepEqual(asked, [], "a deny is never offered for approval");

  const notes = join(h.project, "NOTES.md");
  const wrote = await agent.step({ name: "write_file", input: { path: notes, contents: "hi" } });
  assert.equal(wrote.ran, true);
  assert.equal(readFileSync(notes, "utf8"), "hi");
  agent.engine.free();
  h.done();
});

test("a call that needs a person waits for one, and nothing runs without", { skip: !posix }, async () => {
  const h = home();
  let answer = false;
  const agent = createAgent({ openmoat, ...h, approve: () => answer });
  const todo = join(h.home, "todo.txt");
  const call = { name: "write_file", input: { path: todo, contents: "milk" } };
  const refused = await agent.step(call);
  assert.equal(refused.ran, false);
  assert.notEqual(refused.verdict, "deny");
  assert.equal(existsSync(todo), false);
  // A fetch the person refused never touches the network.
  assert.equal((await agent.step({ name: "fetch", input: { url: "https://example.invalid/" } })).ran, false);
  answer = true;
  assert.equal((await agent.step(call)).ran, true);
  assert.equal(readFileSync(todo, "utf8"), "milk");
  agent.engine.free();
  h.done();
});

test("a link in the project to ~/.ssh is followed, not trusted", { skip: !posix }, async () => {
  const h = home();
  symlinkSync(join(h.home, ".ssh"), join(h.project, "keys"));
  const agent = createAgent({ openmoat, ...h, approve: () => true });
  const read = await agent.step({ name: "read_file", input: { path: join(h.project, "keys", "id_ed25519") } });
  assert.deepEqual([read.ran, read.verdict], [false, "deny"]);
  const viaShell = await agent.step({ name: "shell", input: { command: "cat keys/id_ed25519" } });
  assert.equal(viaShell.ran, false);
  agent.engine.free();
  h.done();
});
