# ADR-132: Building each policy glob when a call first needs it

Status: accepted · Date: 2026-11-27 · Builds on ADR-080 (the
latency budget and its two 2026-11-26 amendments), ADR-111 (the never-widen proof),
ADR-130 (the phase times), ADR-131 (its option E, deferred)

## Context

Every hook call is a new `openmoat guard` process, and each one compiles the whole policy
for the call's context (`CompiledPolicy::compile`). On the user's Mac, `openmoat bench` on
release 0.29.0 put that phase first (ordinary work, p50 / p95 in µs):

| Phase | p50 | p95 |
|---|---|---|
| `compile` | 36,923 | 59,805 |
| `lock` | 14,422 | 22,317 |
| `taint` | 9,477 | 21,487 |
| `policy` | 8,982 | 14,809 |
| `decide` | 1,765 | 4,350 |
| the guard's own time, whole call | 77 ms | |

ADR-080's second amendment found that 69 % of a compile is globset's `GlobBuilder::build`
and that its cost grows with the length of the home directory, which every `~` pattern
spells out. It left two ideas alone: matching the home prefix outside globset (it would
change the regex text the never-widen proof reads) and building a glob only on first use
(globset has no constructor that cannot fail, so a deferred build "would add an error
branch inside the matcher with no safe answer for an allow list"). ADR-131 deferred its
cache and proposed the second idea as its option E, with a failure mark that makes the
guard deny. This ADR measures both ideas and the others, and decides.

### How a compile spends its time

What `CompiledPolicy::build` does, in order (`engine.rs`):

1. For each rule group of `deny`, `repo_review`, `allow`, `review` and `defer`: each shell
   pattern is lexed and each of its words that holds glob syntax gets a glob
   (`ShellPattern::compile_in`, `pattern/word.rs`); each path, host, environment and MCP
   pattern is spelled for the context (`EvalContext::spellings`: `~` as the home and its
   resolved form, `${project}` as the project and its resolved form, and once more under
   each moved directory) and each spelling gets a glob (`GlobPattern::compile_in`, two for
   `dir/**`, which also matches `dir`); `when` conditions do the same.
2. The taint lists (`taint::compile_protected`, `compile_private`), the places a read is
   not collection (`staging::compile_inside`), the folders of deny rules
   (`contents::ProtectedFolders`, spellings and string work, no globs) and the request
   rules.

Each glob is built once per compile by text and options (`pattern/built.rs`, #876). Its
build is globset's parse into tokens and its regex text (`Tokens::to_regex_with`), which
allocates a `String` for every literal character (`char_to_escaped_literal`). The regex
behind the matcher is compiled only when a candidate reaches it (`pattern/lazy.rs`), and
two checks read from the glob's own text refuse most candidates before that: its literal
start (`lazy.rs`) and its literal end (`tail.rs`, #874).

### Measured

All numbers below are from this development Mac (x86-64, macOS 12, a load average of 6 to
11 from other work during the runs), with scratch code that is not part of this change:
the core's tests built with the release profile, the default policy, one context per home,
40 to 60 rounds each, the homes taken in turn within each round and the variants run
again in a second pass. p50 / p95 in µs. Four contexts, all with the project at
`<home>/proj` and case-insensitive paths, as on macOS:

- **9**: home `/Users/me`;
- **30**: a 30-character home under `/Users/`, as a typical user's;
- **120**: a 120-character home under the temporary directory, as `openmoat bench`'s;
- **120 + resolved**: the same with its resolved spelling (`/private/var/…` for
  `/var/…`), which is what `openmoat bench` really gets on macOS: its home is under
  `std::env::temp_dir()`, and `/var` is a link to `/private/var`, so every `~` and
  `${project}` pattern is spelled twice.

**Where the time goes** (today's code, first pass of 60 rounds; the steps are timed apart,
so they overlap where noted and do not add to the total):

| Step | 9 | 30 | 120 | 120 + resolved |
|---|---|---|---|---|
| `Policy::parse` (for comparison) | 6,798 / 11,154 | 6,720 / 10,423 | 6,963 / 10,726 | 6,829 / 10,095 |
| **`CompiledPolicy::compile`** | **10,197 / 14,097** | **11,508 / 19,337** | **18,324 / 26,122** | **33,621 / 41,477** |
| spellings alone (`EvalContext::spellings` over every pattern) | 668 / 1,222 | 708 / 1,266 | 830 / 1,414 | 2,659 / 4,460 |
| shell patterns (`ShellPattern::compile_in`, all groups) | 2,955 / 4,810 | 2,892 / 4,832 | 2,839 / 4,795 | 2,877 / 4,261 |
| of which lexing the patterns | 871 / 1,551 | 883 / 1,579 | 868 / 1,436 | 868 / 1,509 |
| group globs with their spellings, and `when` | 5,626 / 8,742 | 6,969 / 12,123 | 12,809 / 19,905 | 25,846 / 33,553 |
| taint lists | 793 / 1,406 | 832 / 1,562 | 948 / 1,600 | 1,288 / 1,888 |
| `staging::compile_inside` | 302 / 549 | 386 / 921 | 709 / 1,342 | 1,510 / 2,378 |
| `ProtectedFolders::compile` | 523 / 913 | 544 / 994 | 648 / 1,123 | 1,720 / 2,034 |
| `GlobBuilder::build` of every text the compile builds | 5,550 / 7,978 | 6,845 / 10,662 | 12,421 / 17,521 | 22,623 / 31,380 |
| writing the same regex texts in one pass into one buffer (a lower bound for an own writer) | 124 / 190 | 152 / 263 | 261 / 420 | 482 / 648 |
| `GlobBuilder::build` of the distinct texts after each glob's literal folder (option A) | 3,365 / 5,652 | 3,205 / 5,887 | 3,237 / 5,893 | 3,185 / 4,559 |

**What a compile builds:**

| | 9 | 30 | 120 | 120 + resolved |
|---|---|---|---|---|
| globs built (distinct texts, paths and shell words) | 1,322 | 1,322 | 1,320 | 1,782 |
| characters in them | 30,073 | 39,817 | 81,550 | 151,300 |
| of them with `[`, `{`, `}` or `\` (the only texts globset's parser can refuse) | 165 | 165 | 165 | 175 |
| with a literal folder at the start (option A) | 605 | 605 | 603 | 1,065 |
| distinct texts after that folder | 978 | 978 | 978 | 977 |

**What a call uses.** For each call a fresh compile, then `decide_with` and
`exposure_and_collection`, as the guard's `decide` and `taint` phases run them; "consulted"
is the number of distinct globs asked about a candidate, "regex" the number whose literal
start and end let a candidate through to the regex:

| Call | consulted | reached the regex |
|---|---|---|
| `git status` | 67 | 4 |
| `Read` of a file in the project | 200 (311 with the resolved home) | 5 |
| `Write` of a file in the project | 442 (767) | 3 |
| an MCP tool call | 4 | 1 |

So a call needs at most 5 of the 1,322 to 1,782 globs it builds. The other 99.6 % are
built for nothing.

Inside globset's build, a sampling profile (`sample`, 8 s of compiles for the 120 home;
globset is optimised in every profile of this workspace) put 73 % in the regex text
(`Tokens::to_regex_with`, about half of that in `char_to_escaped_literal`, which allocates a `String` per character) and
the rest in the parse into tokens and the copies of the text, close to #876's 45 % of
compile for the regex text out of 69 % for the build.

Three facts follow:

1. **globset's build is 54 % to 67 % of a compile**, and grows with the characters in the
   globs: 5.6 ms with a 9-character home, 22.6 ms with the bench's home. Writing the same
   regex texts into one buffer takes 0.1 to 0.5 ms, so the cost is globset's allocations,
   not the work itself.
2. **The bench's compile is inflated by its own home.** Its home has two spellings, which
   adds 462 globs and 70,000 characters: 33.6 ms against 18.3 ms for the same home with
   one, and 11.5 ms for a 30-character home. The user's 36.9 ms p50 matches the two-spelling
   row; a guard in a home such as `/Users/<name>`, without a link in its path, compiles in
   about a third of that on this machine. This was not visible before because
   `openmoat bench` always works in a throwaway home under the temporary directory.
3. **A call needs almost none of it**: 1 to 5 globs reach the regex.

### A prototype of the deferred build

To measure option C rather than estimate it, a scratch change (not part of this commit)
kept each glob's text and options in `LazyGlob` and built the `Glob` behind a `OnceLock`
when the regex was first needed, in two modes:

- **safe**: only texts without `[`, `{`, `}` or `\` are deferred, the rest are built at
  compile as today;
- **all**: every text is deferred.

Each variant in turn, 40 rounds per pass (p50 / p95 in µs). Passes 1 and 2 ran today's
code and the safe mode in turn; pass 3 ran all three in turn:

| `compile` | 9 | 30 | 120 | 120 + resolved |
|---|---|---|---|---|
| today, pass 1 | 10,301 / 15,852 | 11,689 / 19,384 | 18,208 / 24,822 | 32,775 / 48,368 |
| today, pass 2 | 10,636 / 16,130 | 12,496 / 22,647 | 17,797 / 25,276 | 32,904 / 49,198 |
| today, pass 3 | 10,103 / 18,410 | 11,804 / 15,877 | 17,816 / 28,784 | 33,793 / 43,489 |
| safe, pass 1 | 6,054 / 9,602 | 6,268 / 9,435 | 6,842 / 9,601 | 11,815 / 17,998 |
| safe, pass 2 | 5,989 / 8,088 | 6,194 / 8,593 | 6,947 / 9,459 | 12,046 / 19,604 |
| safe, pass 3 | 5,870 / 8,508 | 6,205 / 7,915 | 6,890 / 11,225 | 11,896 / 14,510 |
| all, pass 3 | 4,391 / 6,147 | 4,721 / 7,597 | 5,095 / 7,556 | 9,472 / 13,899 |

| First decisions: the four calls above, `decide_with` and `exposure_and_collection`, summed | 9 | 120 + resolved |
|---|---|---|
| today, passes 1 to 3 | 1,487 / 2,472; 1,548 / 3,207; 1,556 / 2,200 | 2,230 / 3,587; 2,252 / 3,347; 2,301 / 2,936 |
| safe, passes 1 to 3 | 1,744 / 2,562; 1,536 / 2,081; 1,492 / 2,041 | 2,306 / 3,341; 2,272 / 3,304; 2,236 / 2,819 |
| all, pass 3 | 1,568 / 2,016 | 2,282 / 3,136 |

The first decisions cost what they did: the few globs they now build are within the run
to run spread. With the safe mode, what is left of a compile is the 165 to 175 texts still
built eagerly (1.2 to 1.8 ms), the shell patterns' lexing (0.9 ms), the spellings, the
`ProtectedFolders` scan and the bookkeeping of 1,300 to 1,800 globs.

**Decisions with the prototype.** With the safe mode, the core's whole test suite passed
unchanged: the 816 unit tests (among them the two default-policy corpus tests of
`pattern/tail/tests.rs` and `lazy.rs`'s test of both readings of `\`), the conformance
fixtures, the README and USAGE tables, the IR consistency test, the never-widen tests
(`ir_never_widens.rs`, `policy_widen.rs`), the obfuscation tests and their fuzz test, and the
policy schema tests. With every text deferred, five unit tests failed, every one of them a
test that a bad pattern fails the compile (`a_pattern_broken_by_expansion_fails_the_compile_up_front`,
a home `/h{x`; a bad `taint.protected_writes`; a bad `when`; bad shell words; and
`built.rs`'s error test): the error timing the safe mode keeps.

## Options

Each gain is from the tables above, on this machine; the user's machine, which ran the
bench at about the speed of the two-spelling row here, should see the same proportions.

### A. Match the literal prefix outside globset

Split each spelled glob at the end of its literal folder (`/Users/me/.ssh/**` into
`/Users/me/.ssh/` and `**`), compare the prefix as bytes and build a glob only for the
rest. The 1,322 to 1,782 texts become 978 distinct rests whatever the home, so the build
would cost about 3.2 ms in every context.

- **Gain today:** 2.2 ms (9), 3.6 ms (30), 9.2 ms (120), 19.4 ms (120 + resolved).
- **Gain after C:** almost none. With C the compile builds only the 165 to 175 texts that
  may fail, and a call builds at most 5 more; A would shorten those builds, a few hundred
  microseconds in all.
- **Cost to the safety argument:** the engine would no longer match with the regex the
  never-widen proof reads. The proof (`widen/proof.rs`, `widen/nfa.rs`) reads
  `Glob::regex()` so that what it proves is about the matcher the engine runs; with A it
  would have to read the prefix bytes and the rest's regex as one automaton (a
  concatenation `nfa.rs` does not build today), or a new test would have to show the
  split matcher equals the whole regex. The prefix compare would also have to repeat what
  globset does to a candidate: on Windows a path matcher turns `\` into `/` before
  matching, and `(?-u)(?i)` folds ASCII letters only, so `K` (KELVIN SIGN) does not match
  `k`. Today's literal-start check (`lazy.rs` `may_match`) and literal-end check
  (`tail.rs`) already do the cheap half of A, and safely, because they can only refuse:
  a candidate with a non-ASCII character or a `\` goes to the regex, and every "may match"
  is still decided by globset. A would make the prefix compare say yes on its own, which
  is the half that needs the new proof.
- **Side finding:** `paths::expand_pattern` writes the home into the glob as is (a
  project holding glob characters is treated as no project; the home has no such check). A home holding `[`,
  `{`, `}` or `\` makes the compile fail, which a test holds
  (`a_pattern_broken_by_expansion_fails_the_compile_up_front`) and the guard turns into a
  deny; that is the one way a spelled glob can fail after the raw pattern passed the lint,
  and C below keeps it. A home holding `*` or `?` builds, and is read as a wildcard:
  `~/.ssh/**` with a home `/home/a?` also matches `/home/ab/.ssh/key`, in deny and allow
  lists alike. No ordinary home holds these characters. It is recorded for its own issue,
  not changed here.
- **Rejected for now.** It saves little once C is in, and it is the only option that
  changes what the proof reads.

### B. A cheaper glob-to-regex step

Write the regex text ourselves, in one pass into one buffer, from the glob's own text. The
measured lower bound for that is 0.1 to 0.5 ms, against 5.6 to 22.6 ms for globset's build.

- **The catch:** the matcher can only come from globset's `Glob` (`Glob::compile_matcher`);
  globset has no way to build a matcher from regex text. An own writer could not replace
  the build unless the core also depended on `regex` directly to compile its text. `regex`
  is already in the build through globset, but a direct dependency changes invariant 7
  (`openmoat-core` depends only on `serde`, `serde-saphyr`, `globset`, `thiserror`) and
  needs its own ADR. A pooled buffer inside globset needs a change to globset itself: an
  upstream patch to `char_to_escaped_literal` would help everyone, but its timing is not
  ours.
- **How sameness would be proved, if built:** the own text equals `Glob::regex()` byte for
  byte, not only in what it matches: for every string up to five characters over an
  alphabet of the glob characters, `/`, `,`, `!`, `-`, a letter, `é`, `K` and `ſ`, in both
  case modes, both `literal_separator` settings and both readings of `\`; for every
  default-policy glob spelled for the four contexts above; for every shell word. Errors:
  the same `ErrorKind` for every string that does not parse. Equal text means the
  matcher and the proof read the same thing.
- **Gain after C:** at most the 1.2 to 1.8 ms of the texts still built at compile.
- **Not proposed.** It is the fallback if C is refused, and then it needs the dependency
  decision.

### C. Build each glob when a candidate first needs its regex

`LazyGlob` keeps the glob's text and options; the `Glob` and its matcher are built behind
`OnceLock`s the first time a candidate passes the literal start and end, and when the
never-widen proof asks for `regex()`. The prefix and tail checks already read only the
text, so nothing that runs before the regex changes.

**ADR-080's objection, answered.** The objection was that globset's build can fail, so a
deferred build has a failure with no safe answer. Two things make that failure
unreachable for the texts deferred, and a third makes it safe if it is reached anyway:

1. **Only texts that cannot fail are deferred** (the safe mode above). globset's parser
   (0.4.21, `Parser::parse`) returns an error only for a class (`[`: unclosed, or a bad
   range), an alternation (`{`, `}`: unopened or unclosed) or an escape (`\` at the end);
   its regex step (`Tokens::to_regex_with`) returns a `String` and has no error at all. A
   text with none of `[`, `{`, `}`, `\` therefore builds, and the lint already relies on
   that (`pattern/word.rs` `cannot_fail`, with its test that every such string up to five
   characters builds as a path glob and as a word glob). Every other text is built at
   compile time exactly as today, so every compile error, its text and the pattern it
   names, comes where and when it does now, and `CompiledPolicy::compile` fails exactly
   when it does today. Callers that rely on that (`ir::lower`, the SDK, the proxy, the
   remote MCP transport, `openmoat policy`) are unchanged.
2. **This does not depend on the lint.** Patterns the CLI adds after the lint (recorded
   binary paths, MCP names, the repository policy) and spellings with an unusual home go
   through the same test of their spelled text: a spelled text holding `[`, `{`, `}` or `\`
   is built eagerly, wherever the character came from.
3. **If a deferred build fails anyway** (a globset upgrade that parses differently, before
   the test above catches it), the glob answers "no match", the `OnceLock` keeps the
   error, and the compiled policy's failure mark is set. One glob can be shared by a deny
   list and an allow list (`pattern/built.rs`), so it cannot know which answer is strict
   for its list; instead the answer of the whole call is made strict. `decide` and
   `decide_with` read the mark after deciding and return the error deny
   (`kernel-error`) in its place, so every caller of the core gets it without code of its
   own; the guard also reads the mark after its `taint` phase, whose session checks match
   globs outside `decide`, and denies with the same rule (invariant 4). `regex()` for a
   glob that did not build gives the proof nothing to read, and the proof reports the kind
   as not proven, as it does for any regex it cannot read (`Unsupported`). So the outcome
   is a deny, as a compile error gives today, one step later.

- **Gain (measured, safe mode):** `compile` 10.3 → 6.0 ms (9), 11.7 → 6.2 ms (30),
  18.2 → 6.9 ms (120), 32.8 → 11.9 ms (120 + resolved), p50; the p95s fall in proportion.
  On the bench's home that is about 21 ms of the call. The first decisions do not move.
- **Gain (all texts deferred, pass 3):** `compile` 4.4 ms (9), 4.7 ms (30), 5.1 ms (120),
  9.5 ms (120 + resolved), so 1.5 to 2.4 ms more than the safe mode. That needs the 165
  texts that may fail to be shown to parse without building them, by an own check that mirrors globset's parser
  errors, tested against globset over every short string; where the check says "fails",
  the glob is built to get globset's own error. It is a second step, for the user to
  choose.
- **Cost to the safety argument:** none to what is matched. The `Glob` is built from the
  same text with the same options by the same globset call, so its regex text and its
  matcher are the ones built today; the never-widen proof reads the same `regex()`
  (built on demand there); the prefix and tail checks are unchanged. What is new is a
  failure path that the eager rule makes unreachable and the mark makes a deny.
- **Touches:** `pattern/lazy.rs`, `pattern.rs`, `pattern/word.rs`, `engine.rs` (the mark
  and its read in `decide`), the guard's read after `taint`. No new dependency, no file,
  no key, no state between calls.

### D. Fewer spellings

`EvalContext::spellings` expands every pattern once per home spelling and per project
spelling, then sorts and removes duplicates: with a resolved home and project that is four
expansions of every pattern, even of one that names neither `~` nor `${project}`, and
`ProtectedFolders::compile` asks for the same spellings again.

- **Change:** take the home spellings only for a pattern that starts with `~`, the project
  spellings only for one that names `${project}`, and hand `ProtectedFolders` the
  spellings the deny groups already made. The output set is the same, so nothing it feeds
  changes.
- **Gain:** about 0.3 ms with one spelling of each, about 2 to 3 ms with two
  (spellings 2.7 ms and `ProtectedFolders` 1.7 ms in the 120 + resolved row).
- **Proof:** for every pattern of the default policy and of the conformance fixtures, in
  every context of the four above, with and without moved directories, the new spellings
  equal the old ones as sets.
- **Rejected variant:** one glob for both home spellings, `{/var/…,/private/var/…}/.ssh/**`.
  It halves the globs but changes their regex text, their literal start (now empty) and
  their tail, so it touches what the proof reads and what the prefix check refuses.

### E. Combinations

- **C and D** together: C removes the builds, D the duplicated string work that remains;
  neither touches what is matched. On the bench's home they leave about 9 to 10 ms of
  `compile` (estimated from the safe row less D's share).
- **C and A, or C and B:** after C, A or B would only speed up the 165 eager builds and at
  most five builds per call, 1 to 2 ms, at the cost of the proof's reading (A) or a new
  core dependency (B). Not proposed.

### F. Do nothing

The user's 36.9 ms p50 is mostly the bench's two-spelling home; a real home on this
machine compiles in 10 to 12 ms. But the throwaway homes of CI runners, sandboxes and
`openmoat run` are of the bench's kind, and 1,300 globs built per call for at most five
used is waste that a one-file change in the core removes.

### Summary

| Option | `compile` saved, p50, 30-char home | on the bench's home | Proof or trust touched | Code |
|---|---|---|---|---|
| A. Prefix outside globset | 3.6 ms (0.3 after C) | 19.4 ms (0.5 after C) | yes: the proof would read a split matcher | core |
| B. Own regex writer | about 6.7 ms (1.3 after C) | about 22 ms (1.8 after C) | a direct `regex` dependency (invariant 7) | core |
| C. Build on first use, safe mode | 5.5 ms | 21 ms | none: same globset call, new failure path made a deny | core, guard |
| C, all texts | 7.1 ms | 24 ms | an own parse check, tested against globset | core |
| D. Fewer spellings | 0.3 ms | 2 to 3 ms | none: same output set | core |
| F. Nothing | 0 | 0 | none | none |

## Decision

The user answered the questions this ADR first ended with (2026-11-27):

1. **C, in its safe mode.** A glob is built on first use only when its spelled text holds
   none of `[`, `{`, `}` and `\`, the only characters globset's parser can refuse; every
   other glob is built at compile, as before, so a bad pattern fails the compile exactly as
   it did. A deferred build that fails anyway answers "no match" and sets the compiled
   policy's failure mark. This reverses ADR-080's second amendment ("deferring the build
   stays out") for those texts only.
2. **The mark is read inside the core.** Every public decision entry point of
   `CompiledPolicy` (`decide`, `decide_with`, `evaluate_atomic`, `with_arguments`,
   `with_injected`, `with_taint`, `with_staging`, `with_trifecta`) returns, once the mark
   is set, the deny a compile error gives in `openmoat guard`: rule `kernel-error`, reason
   "kernel could not evaluate this action: " and the compile error's words (`bad glob
   ``…``: …`, naming the spelled text). So every caller of the core (the guard, the SDK,
   the proxy, `openmoat policy`) gets that deny with no code of its own. The guard reads the
   mark again after its session checks, which match globs outside those entry points, and
   fails the call through its error path, as a compile error does.
3. **The safe mode only.** No own parse check for the texts still built at compile.
4. **D in the same change**, with a test that the set of spellings is the same.
5. **`openmoat bench`'s throwaway home** is created under the resolved temporary
   directory, so it has one spelling and the bench's `compile` line is what a guard in an
   ordinary home pays (question 5 below). A home given with `--scratch-dir` is used as
   written.
6. **The unescaped home** (question 6, the side finding under A) was fixed in its own
   change before this one (#881): a home, project or moved directory is spliced in as
   literal text, each glob character as a one-character class (`/Users/a*b` as
   `/Users/a[*]b`). Such a spelling holds `[`, so it is built at compile; a home no longer
   makes a compile fail, and the failure mark's tests reach it with a pattern added after
   the lint instead.

A and B are not built: A changes what the never-widen proof reads, B needs a new direct
dependency in the core, and after C neither has much left to save.

## What was built

- **`pattern/lazy.rs`.** `LazyGlob` keeps its text and globset options, the literal start
  and end it reads from that text, the `Glob` behind a `OnceLock<Option<Glob>>` and the
  matcher behind another. `LazyGlob::build` builds at once unless the compile defers and
  the text passes `cannot_fail` (`pattern/word.rs`, the lint's own test), which is read
  from the text globset is given: for a path glob its spelled text, wherever a character
  came from (the policy, the home, the project, a pattern the CLI adds after the lint); for
  a shell word the text after `\\` is swapped out. `regex()` builds on demand and is empty
  for a glob that did not build, which the never-widen proof reads as an unsupported regex
  and reports as not proven. The failure mark (`Unbuilt`) keeps the first failure's words.
- **`pattern/built.rs`.** A compile's glob store says whether its globs may wait:
  `Built::default()` (a pattern compiled alone, `GlobPattern::compile`) builds everything
  at once, `Built::deferring` is what `CompiledPolicy::compile` uses.
- **`engine/unbuilt.rs`.** The mark's reads (`CompiledPolicy::unbuilt`, and the check each
  entry point above applies last), and a hidden `GlobBuilds` mode (`AtCompile`,
  `OnFirstUse`, `EveryOnFirstUse`) with `CompiledPolicy::compile_owned_building`, not a
  stable API: tests compare the modes, and reach the mark with every glob deferred, which
  no text the safe mode defers can do.
- **`openmoat guard`** (`commands/guard/unbuilt.rs`): after the last check that uses the
  compile, a set mark fails the call, which the guard answers with the `kernel-error` deny,
  and the session cache and provenance the call computed are dropped. The fold of the
  session's earlier calls (`taint.rs`) also refuses to write a cache row while the mark is
  set, so a fold that may have missed what tainted the session is never kept, by the guard
  or by `catch_up` after a call ran.
- **D** (`engine/context.rs`, `engine/contents.rs`): `EvalContext::spellings` expands a
  pattern under every home spelling only when it starts with `~`, and under every project
  spelling only when it names `${project}` (or the home it is spelled with does); any other
  expansion gives the same text under each. `ProtectedFolders` reads the deny groups'
  compiled spellings (`GlobPattern::source`) instead of spelling the deny patterns again; a
  spelling keeps its pattern's `!`, so the negated patterns are the negated spellings.
  `paths::expand_pattern` is unchanged.
- **`openmoat bench`** (`commands/bench/hook.rs`): the scratch root is under
  `canonicalize(temp_dir())`, without Windows' verbatim prefix. Nothing else read the
  unresolved path: the hook, the OS sandbox proof and the run proof take the paths from
  the scratch directory itself.

## Proof plan

Every decision and every error must be what it is today. The tests:

1. **Same text, same glob.** For every glob of the default policy spelled for each of the
   four contexts above (and with a moved directory), in both case modes, and for every
   shell word: the deferred glob's `regex()` equals the eager glob's byte for byte, and
   `is_match` gives the same answer over each glob's own matches and near misses
   (`widen::samples`), their case-flipped forms, the non-ASCII foldings (`K` for `k`, `ſ`
   for `s`), `é`, and candidates with `\`. This extends `pattern/tail/tests.rs`'s two
   corpus tests, which already compare the prefix and tail checks with the regex.
2. **What is deferred cannot fail.** `cannot_fail`'s exhaustive test grows: every string up
   to five characters over `a`, `/`, `*`, `?`, `,`, `!`, `.`, `-`, `]`, `é`, `K`, `ſ`, `~`,
   `$` and a space builds in both case modes, with and without `literal_separator`, and with
   `\` as escape and as separator. A second test spells raw patterns with homes and project
   paths holding each glob character and checks that each spelled text with one of `[`,
   `{`, `}`, `\` is built at compile and every other is deferred.
3. **Errors unchanged.** For every pattern in `pattern/check.rs`'s and `built.rs`'s error
   tests, and for bad patterns added through each route that skips the lint (an MCP name, a
   binary path, a repository policy): `CompiledPolicy::compile`'s error, its text and its
   order are the same as today's; `ir::lower` fails on the same policies.
4. **The failure mark.** A test-only constructor makes a deferred glob whose build fails:
   the glob answers "no match", `decide` and `decide_with` return the `kernel-error` deny
   for any action that reached it, an action that did not reach it is decided as before,
   and an end-to-end guard test sees exit 2. The SDK's `decide` returns the same deny.
5. **Decisions unchanged.** The conformance fixtures (`tests/conformance`), the README and
   USAGE verdict tables (`doc_tables.rs`), the never-widen tests (`ir_never_widens.rs`,
   `policy_widen.rs`, `widen/tests.rs`, which read `regex()` and now build it on demand),
   the obfuscation tests, the IR consistency test and the end-to-end suite pass unchanged.
   One more test runs every conformance fixture through a compile with deferral and one
   without and compares verdicts and rule lists.
6. **Windows.** CI runs the tests on Windows, where a path glob reads `\` as a separator and
   a shell word reads it as an escape (`word.rs` swaps it out first). Texts holding `\` are
   built eagerly under both readings; `lazy.rs`'s test already checks both readings, and
   gains the deferred variant.
7. **Threads.** The SDK keeps one compiled policy for as long as it likes, possibly across
   threads: a test decides the same calls from several threads at once on a fresh compile
   and gets the same answers (`OnceLock` builds each glob once).
8. **D.** The set test in option D.

## Measured after the change

The method above (scratch code, not committed: the core's tests built with the release
profile, the default policy, the four contexts with the project at `<home>/proj` and
case-insensitive paths, 60 rounds, the homes taken in turn within each round), run on
`main` before this change (66419da1) and on this change in turn, three passes. "First
decisions" is `decide_with` and `exposure_and_collection` of `git status`, a read and a
write in the project, summed, on the fresh compile. The development Mac was far busier than
for the prototype (load average 28 to 77 from other work), so every figure is higher than
the prototype's, and the p95s are wide; the proportions are what to read. p50 / p95 in µs:

| `compile` | 9 | 30 | 120 | 120 + resolved (the bench's home before) |
|---|---|---|---|---|
| before, pass 1 | 23,890 / 73,295 | 27,569 / 76,602 | 41,557 / 97,114 | 86,334 / 170,989 |
| after, pass 1 | 10,016 / 26,776 | 10,439 / 35,936 | 11,528 / 26,492 | 15,081 / 32,952 |
| before, pass 2 | 17,629 / 36,715 | 20,255 / 33,224 | 31,694 / 54,063 | 64,252 / 99,171 |
| after, pass 2 | 9,517 / 28,187 | 10,077 / 42,530 | 10,809 / 34,101 | 15,671 / 40,731 |
| before, pass 3 | 19,736 / 70,600 | 21,201 / 48,368 | 32,785 / 78,120 | 66,113 / 112,472 |
| after, pass 3 | 9,675 / 17,146 | 9,542 / 15,065 | 10,727 / 18,445 | 13,221 / 28,058 |

| First decisions | 9 | 30 | 120 | 120 + resolved |
|---|---|---|---|---|
| before, passes 1 to 3 | 1,727; 1,619; 1,737 | 1,811; 1,802; 1,823 | 2,346; 2,298; 2,377 | 2,440; 2,342; 2,497 |
| after, passes 1 to 3 | 1,737; 1,699; 1,683 | 1,862; 1,873; 1,824 | 2,406; 2,386; 2,373 | 2,467; 2,474; 2,402 |

(First decisions are p50s; their p95s, 2.6 to 20 ms on both sides, are the load's.)

- `compile` fell to about half for the 9- and 30-character homes, to a third for the
  120-character home, and to a fifth for the two-spelling home; it now grows little with
  the home's length, since most texts are no longer built.
- The first decisions did not move beyond their spread: the few globs a call builds cost
  what the regex they then compile already cost.
- With `openmoat bench`'s home resolved, the bench now measures the "120" column, not the
  "120 + resolved" one.

## Measurement in CI

- `openmoat bench`'s phase line (ADR-130) in MoatBench's CI job and on the user's machine,
  before and after: `compile` should fall by about 60 % on the bench's home and `decide`
  should not rise beyond its run to run spread. The PR quotes both.
- The guard latency comparison (ADR-080: the commit before and this one timed in turn on
  the same runner, p95 of the guard's own time) on `ubuntu-latest` and `macos-15`.
- Since the bench's home has two spellings on macOS and a real home usually one, the bench
  should say which it measured. A run with `openmoat bench --scratch-dir` under a directory
  without a link in its path gives the one-spelling figure; whether the bench reports both
  is a question below.

## Consequences

- ADR-080's second amendment's conclusion, "deferring the build stays out", no longer holds
  for the texts C defers; that amendment stays as written and this ADR records why. ADR-131's
  option E is built in this form, with the mark read in `decide` itself rather than only in
  the guard and the SDK.
- A glob's build moves from compile time to its first use; a call pays for the few it needs
  (1 to 5 in the calls measured).
- `regex()` builds on demand, so the never-widen proof builds the globs it reads, as the
  engine did before at compile.
- Nothing is kept between calls; ADR-131's cache stays deferred.

## The questions the user answered (see the decision)

1. May C reverse ADR-080's second amendment for texts without `[`, `{`, `}` or `\`, with the
   failure mark turning into the `kernel-error` deny?
2. Should the mark be read inside `decide` and `decide_with` (every caller of the core gets
   the deny) or only by the guard and the SDK, as ADR-131 proposed?
3. Build only the safe mode, or also the second step (an own parse check so the remaining
   165 texts are deferred, 1.5 to 2.4 ms more on this machine)?
4. D in the same PR as C, or its own?
5. Should `openmoat bench` report the compile phase for a one-spelling home too, so that its
   line matches what a guard in the user's own home pays?
6. The home is written into globs unescaped (side finding under A): open an issue to escape
   it or refuse such a home?
