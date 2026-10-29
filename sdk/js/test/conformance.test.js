// Every conformance fixture (tests/conformance/*.yaml) through the WebAssembly
// module: the decision must equal the engine's, verdict, rules, reasons and
// context. The vectors, with the engine's decisions, are written by
// `OPENMOAT_SDK_VECTORS=<file> cargo test -p openmoat-sdk --test conformance`;
// scripts/ci/sdk-js.sh runs both.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

import { load, Session } from "../src/index.js";

const file = process.env.OPENMOAT_SDK_VECTORS;

test("every fixture decides as the engine does", { skip: !file && "OPENMOAT_SDK_VECTORS not set" }, async () => {
  const vectors = JSON.parse(await readFile(/** @type {string} */ (file), "utf8"));
  assert.ok(vectors.length > 1000, `only ${vectors.length} vectors`);
  const openmoat = await load();
  const engines = new Map();
  const differ = [];
  for (const v of vectors) {
    const key = JSON.stringify([v.context, v.repository]);
    let engine = engines.get(key);
    if (!engine) {
      engine = openmoat.compile({
        policy: openmoat.defaultPolicy,
        context: v.context,
        repository: v.repository ?? undefined,
      });
      engines.set(key, engine);
    }
    const session = new Session();
    for (const earlier of v.session) session.record(engine, earlier, v.facts);
    const d = engine.decide(v.action, { facts: v.facts, session });
    const got = { verdict: d.verdict, rules: d.rules, reasons: d.reasons, context: d.context };
    try {
      assert.deepEqual(got, v.expect);
    } catch {
      differ.push(`${v.id}: engine ${JSON.stringify(v.expect)}, js ${JSON.stringify(got)}`);
    }
  }
  for (const engine of engines.values()) engine.free();
  assert.equal(differ.length, 0, `${differ.length} of ${vectors.length} differ:\n${differ.join("\n")}`);
  console.log(`# ${vectors.length} fixtures: identical to the engine`);
});
