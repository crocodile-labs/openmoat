// A throwaway home for the adapter tests: never the real one, no network.
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { load } from "../src/index.js";

export const openmoat = await load();

const slash = (p) => p.replaceAll("\\", "/");

/** A home with a key in `~/.ssh` and a project, and guard options for it. */
export function scratchHome() {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "openmoat-adapter-")));
  const home = slash(join(dir, "home"));
  const project = slash(join(dir, "home", "app"));
  mkdirSync(join(home, ".ssh"), { recursive: true });
  mkdirSync(project, { recursive: true });
  writeFileSync(join(home, ".ssh", "id_ed25519"), "not a real key\n");
  return {
    home,
    project,
    key: `${home}/.ssh/id_ed25519`,
    options: {
      openmoat,
      context: { home, cwd: project, project },
      facts: false,
    },
    done: () => rmSync(dir, { recursive: true, force: true }),
  };
}
