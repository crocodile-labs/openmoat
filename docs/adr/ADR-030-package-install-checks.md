# ADR-030: Package install checks: an offline near-miss list, and a release age inside `moat run`

Status: accepted · Date: 2026-10-18

## Context

An agent installs packages all day, and a package install runs the package's code on
the machine. Three ways a bad package arrives are common enough to plan for:

- **Typo-squats.** A name one letter away from a popular package (`reqeusts`,
  `lodahs`), or the popular name with a word around it (`python-requests`,
  `express-js`, `react_dom`).
- **Made-up names.** A model suggests a package that does not exist; someone registers
  that name later with malicious code. Such names usually look like a popular one.
- **Fresh malicious versions.** A popular package's maintainer account is taken over
  and a bad version is published. Registries usually remove it within days.

Under ADR-025 every install defers to the agent's own prompt, which shows the command
but not that the name is one letter off. OpenMoat must not start asking about every
install either: unknown packages are normal (internal packages, new libraries), and
an ask for each would be the noise ADR-025 removed. Nothing may leave the machine, so
OpenMoat cannot ask a registry whether a name exists, how old it is or who owns it.

## Decision

1. **The classifier reads installs** (`shell/installs.rs`): `npm install|i|add`,
   `pnpm add`, `yarn add`, `bun add`; `pip install` (also `pip3`, `python -m pip`),
   `uv pip install`, `uv add`, `uv tool install`, `poetry add`, `pipx install`;
   `cargo add`, `cargo install`; `gem install`; `go get`, `go install`. The package
   names on the line are read with versions, extras, markers and options removed.
   Paths, URLs, archives, git sources and requirement files name no registry package,
   and an install from the lockfile names none. An install whose names are not near
   misses (point 2) gives no atom of its own and decides exactly as its command does:
   an atom for every install would fall to the policy's catch-all and, since the
   strictest atom wins, ask again for an install a rule allows.
2. **A bundled list of popular names per registry** (`openmoat-core/data/top-packages/`,
   a few hundred to about a thousand names each, plain text with its source and date).
   A name not on its list that is one edit (Damerau, optimal string alignment) from a
   listed name of at least five characters, differs from one only in `-`, `_`, `.` or
   doubled letters, or adds or drops a squatter's prefix or suffix (`node-`, `-js`,
   `python-`, `py`, `-rs`, `ruby-`, …) gives the atom `@package-near-miss <ecosystem>
   <name> <popular name>`. Names are compared as each registry compares them (PEP 503 for
   PyPI, `-`/`_` alike for crates.io, no `/vN` for Go). The default policy asks for that
   atom (`package-near-miss`), and the reason names the popular package. An exact
   popular name, or a name far from every popular one, gets nothing new.
3. **A release age inside `moat run`** (`sandbox.package_min_release_age_days`, default
   7, `0` off). `moat run` sets `npm_config_before` (npm's documented `before` setting)
   and `UV_EXCLUDE_NEWER` (uv's documented `--exclude-newer`) in the agent's
   environment to the start of the UTC day that many days back. Only settings the
   tools document are used, and no configuration file is changed. A cut-off the person
   set (in the environment, the project's `.npmrc`, `pyproject.toml` or `uv.toml`) is
   kept, and a project with a `uv.lock` gets no `UV_EXCLUDE_NEWER`, because uv records
   the setting in its lockfile and a cut-off that moves daily would re-resolve it.
   `npm_config_ignore_scripts` is not set: too many packages need their install
   scripts.

The list is written by hand for the first release and refreshed by
`scripts/refresh-top-packages.py`, which a maintainer runs and reviews; OpenMoat
itself never downloads it.

## Consequences

- `pip install reqeusts` and `npm i lodahs` ask, naming `requests` and `lodash`;
  `pip install numpy pandas`, `npm i react react-dom`, `cargo add serde` and
  `npm i some-new-internal-pkg` defer as before. Conformance fixtures pin both.
- A real but less popular package close to a listed one asks; the fix is to add it to
  the list. Names of four letters or fewer are never compared, since one letter
  separates many real short names.
- The check is only as good as the list: it goes stale, it has no download counts for
  Go, and it cannot see a squat far from every listed name, a compromised popular
  package, dependencies a package pulls in, or lockfile installs (THREAT_MODEL.md §5).
- Other package managers' release-age settings (npm's newer `min-release-age`, pnpm's
  `minimumReleaseAge`, Yarn's `npmMinimalAgeGate`, Bun's `minimumReleaseAge`, pip's
  `--uploaded-prior-to`) are not set until their environment forms are confirmed in
  each tool's documentation; pip has no environment setting for it today.
- npm then fails an install of a package that has no version older than the cut-off;
  a person who needs one sets their own `npm_config_before` or the key to `0`.
- `openmoat-core` gains a data directory and no dependency (the list is
  `include_str!`, parsed once with `std::sync::LazyLock`).
