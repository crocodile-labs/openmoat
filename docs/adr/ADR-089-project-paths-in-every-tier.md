# ADR-089: What the policy denies inside the project holds in every Linux tier

Status: accepted · Date: 2026-11-12 · Builds on ADR-018 (OS sandbox tiers), ADR-080
(the Isolated tier by default on Linux), ADR-082 (Landlock ABI ladder), ADR-085
(workspace snapshots)

## Context

The policy denies commands some paths inside the project: reading `.env` files
(`secrets-paths`), writing the project's `.moat` (`kernel-self`), writing `.git`
(`git-internals`, which the hook holds for review and no OS layer can ask about), and
writing what an agent loads as its own configuration in its next session
(`.claude/hooks/`, `.github/hooks/`, `.pi/extensions/`, …). On macOS, Seatbelt denies
them by path, so a file created during the session is covered as well as one that
existed at the start.

On Linux the three ways `openmoat run` starts did not agree:

1. **Lightweight, without a network namespace** (no bubblewrap, or unprivileged user
   namespaces restricted, as on a stock Ubuntu; also `--no-isolate` there). Landlock
   only grants: a rule allows access below a directory, created files included, and
   nothing inside a granted tree can be denied again. The project was granted whole,
   so every command could read and write `.env`, create `.envrc`, write `.moat` and
   add files under `.git/hooks`. `openmoat run` said so on every start, and
   `docs/EVIDENCE.md` marked the five hostile-script rows as gaps.
2. **Lightweight, with a network namespace** (bubblewrap works, `--no-isolate`). The
   namespace's mounts covered the agents' configuration and hook settings directly in
   the project, not `.env`, `.git` or `.moat`, which stayed as open as in case 1.
3. **Isolated** (bubblewrap, the default where it works). Every denied path that
   exists at the start is covered by a mount, and a missing `.env`, `.envrc` or
   `.moat` directly in the project gets a placeholder. A path created after the
   start where no placeholder stood was not covered: a mount needs something to cover.
   A command could create `.claude/hooks/` in an existing `.claude` and put a hook in
   it, which Claude Code would run in its next session outside any sandbox.

The plain `openmoat run` on a stock Linux is case 1, so the weakest case is also a
common one.

## Decision

1. **Without a network namespace, the project is granted entry by entry**
   (`sandbox/landlock/entries.rs`).
   - The project directory gets one rule that allows listing only (Landlock
     `ReadDir`, which holds for directories below too). Nothing can be created,
     renamed or removed directly in it, so a missing `.env`, `.envrc` or `.moat`
     cannot appear and no entry can be moved aside and back.
   - Each entry at its top gets a rule of its own: none when the policy denies
     reading it (`.env`; the template `.env.example` is readable), read-only when it
     denies writing it or anything below it (`.git`, `.moat`), read-write otherwise.
   - A folder that holds a path a rule names below it (`.claude` for
     `**/.claude/settings.json`, `.github` for `.github/hooks/`, `.moat` for
     `**/.moat/policy.lock`) is split the same way one level further down.
   - A granted tree that holds the project (a read root such as `/tmp`, where a test
     or a scratch project may live) is granted around it: each folder on the way down
     for listing only, every other entry as the tree was.
   - Symbolic links get no rule: a Landlock rule follows a link, so a rule on a link
     to `/etc` would grant `/etc`. What a link names is decided where it points, as
     before.
   - Files a build or an install writes (`runs-later`: `.husky/`, `.github/workflows/`,
     `.vscode/`) stay writable, as Seatbelt leaves them; an agent's configuration among
     them does not.
2. **With a network namespace, the project gets the Isolated tier's masks**
   (`bwrap::project_masks`, the same walk as under `--isolate`): `.env` files hidden,
   `.git`, `.moat` and every agent configuration read-only wherever they are at the
   start, and placeholders for the missing names. Files a build writes stay writable,
   as above. The project is still granted whole by Landlock, so nothing at its top is
   lost.
3. **Missing agent configuration folders become read-only folders for the session.**
   In both tiers that mount (the Isolated tier and the namespace), a folder of an
   agent's configuration (`.claude/hooks`, `.github/hooks`, `.pi/extensions`,
   `.openclaw/extensions`, `.opencode/plugins`, …) that is missing where its holder
   folder exists is created empty and bound read-only, so a file created in it later is
   refused (`EROFS`). A mount over a folder covers files made in it after the start;
   one over a file cannot. `.git` and an existing `.moat` are bound read-only as whole
   folders already. The folder is removed when the session ends if it is still empty.
   A holder folder is not created for this alone: a project that has no `.pi` gets no
   `.pi` from OpenMoat.
4. **Every start says what stays open, and `doctor` says it before.** Without a
   namespace `openmoat run` names, before the agent starts, each path the policy
   denies in the project that a rule still leaves open: it computes the Isolated
   tier's masks for the project and lists those a Landlock rule still covers
   (`sub/.env`, a `.git` below the top), up to eight and a count. With a namespace it
   says that a match created after the start stays open. `openmoat doctor` on Linux
   without a namespace prints the same list for the current directory.
5. **A test-only switch.** Debug builds start `openmoat run` without a namespace when
   `MOAT_TEST_NO_NETNS` is set, so CI, which installs bubblewrap, runs the hostile
   scripts against case 1 too (`landlock-port-only` in `tests/differential/
   scenarios.yaml`). Release builds do not read it.

## Trade-offs

- **Nothing new at the top of the project without bubblewrap.** Landlock has no
  "this directory only" right: any right to create in the project would reach into
  `.git/hooks` too. So in case 1 a command cannot create `notes.txt`, a `target/` or a
  `node_modules/` at the top, and an editor that saves through a new file and a
  rename fails there. The control row of the hostile scripts shows it (EACCES on
  `echo ok > out.txt`). Existing folders and everything below them work as before.
  The start notice says to create what is needed before the run, or to install
  bubblewrap, which needs none of this. A `--write` path inside the project is still
  granted as given.
- **Entries created later.** An entry created at the top of the project after the
  start by someone outside the sandbox has no rule, so commands cannot read it; a
  folder created at the top during the run is likewise invisible until the next start.
- **Deeper matches.** Only the top and the holder folders are split. A `.env` in a
  subfolder, or a nested `.git`, lies in a folder granted whole and stays open in
  case 1; the start notice and `doctor` name each one that exists. Splitting every
  folder that holds one would stop commands creating files in those folders too.
- **Number of rules.** One rule per entry at the top, per entry of each holder and per
  entry of each folder above the project in a tree that holds it. A project has tens;
  a `/tmp` read root may hold thousands. Each rule is one open and one
  `landlock_add_rule` call at start; past 100 000 the run is refused rather than
  started with something other than the policy. Landlock looks up the rules of each path
  component on access, so access cost does not grow with the number of rules on
  siblings.
- **The walk.** Naming what stays open walks the project, as the Isolated tier does
  already (up to a million entries; past that the notice says the paths could not be
  listed, and the run still starts with the rules above).
- **Races at start.** The rules are built from a listing just before the agent starts.
  An entry replaced by a link to elsewhere between the listing and the rule (only by a
  process outside the sandbox) would be followed; that process already has the
  person's rights.

## What this does not cover (the copy workspace, designed here, not built)

A match of a deny rule created after the start where nothing stood (`.env.local`
written during the session by the person or a tool outside the sandbox, a `.env` in a
new folder) stays open in the namespace and the Isolated tier: a mount needs a path,
and the project root must stay writable. The complete answer for unattended runs is a
**copy workspace**:

- `openmoat run --workspace=copy` would start the agent in a copy of the project made
  under the state directory, with every path the policy denies left out of the copy
  (as ADR-085's snapshot leaves out secrets, ignored and large files and OpenMoat's
  own), and the agent's network and grants as today. On Linux, an overlay mount
  (`overlayfs` in bubblewrap's user namespace, lower layer the project, upper layer a
  directory under the state directory) gives the same view without copying; the
  denied paths are whited out in the upper layer before the agent starts. Nothing the
  person creates in the project during the run reaches the agent, and nothing the
  agent writes reaches the project until it is brought back.
- Bringing the work back reuses ADR-085: the copy's changes are taken as a snapshot,
  shown file by file, and written to the project only by a person (`openmoat restore`
  semantics, the same link-safe write and undo snapshot), with every path the policy
  denies refused on the way back, so a hook or `.envrc` the agent wrote is never
  written into the project.
- Costs to settle before building: disk and time for a large project without overlay
  (macOS, or a kernel without unprivileged overlay mounts), tools that keep absolute
  paths to the project (the copy lives elsewhere unless it is mounted at the project's
  path, which the Isolated tier can do), and how an attended session sees its own
  changes (the copy is the agent's view; the person's editor still shows the project).

## Consequences

- Case 1's five hostile-script gaps close (`script-reads-project-env`,
  `script-writes-project-env`, `script-plants-envrc`, `script-writes-project-policy`,
  `script-plants-git-hook`), at the cost above, which the evidence table shows as a
  gap of the control row in that column.
- Case 2 now keeps `.git` and `.moat` read-only, as the Isolated tier and macOS do:
  `git commit` inside `openmoat run --no-isolate` fails there as it does under
  `--isolate` and on macOS; commit outside the run.
- The Isolated tier and the namespace refuse a hook written into a new
  `.claude/hooks/` (or another agent configuration folder) during the session.
- `docs/SANDBOX.md`, `docs/THREAT_MODEL.md` and `docs/LIMITS.md` describe each case
  as above.
