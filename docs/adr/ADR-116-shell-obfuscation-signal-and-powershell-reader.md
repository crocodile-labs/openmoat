# ADR-116: Obfuscation as a signal, and a PowerShell reader

Status: proposed · Date: 2026-11-23 · Builds on ADR-013 (the classifier is triage),
ADR-025 (`unparseable` defers), ADR-083 (Windows crossings, `@opaque-code`) · Numbered
116: 114 and 115 are taken by changes open at the time of writing

## Context

The shell classifier reads the words bash builds: `c''at`, `$'\x63at'` and `cat${IFS}f`
are `cat`. What it cannot follow is a value computed when the line runs. Such a line is
`unparseable`, and under the default policy `unparseable` defers to the agent's own
prompt (ADR-025), so a line written to hide what it runs got the same treatment as a
line the classifier merely did not model. Bashfuscator and hand-written evasions spell
commands with exactly those constructs: `${s:2:3}` cuts of a longer string, `${!r}`
indirection, `IFS` changes, `tr` rotations, `printf` escapes, letters joined from
variables.

MITRE ATT&CK's detection strategy DET0505 (obfuscated command lines, T1027.010) names
the signals defenders use: escape and quote density, character-by-character
concatenation, indirect expansion, strings built and decoded at run time, unusual length
and high-entropy words. None of them alone proves intent, and agents' everyday commands
contain some of them (colour escapes, `${GITHUB_SHA:0:7}`, `IFS= read`).

PowerShell had no reader at all. Every PowerShell command (Claude Code's `PowerShell`
tool, and the shell tools of Cline, Copilot CLI, Gemini CLI, OpenClaw, pi and Qwen Code
on Windows) was `unparseable` with no atoms, so `Remove-Item -Recurse -Force ~` and
`Get-Content $env:USERPROFILE\.ssh\id_rsa` were left to the agent like `dotnet build`.
A POSIX line that starts PowerShell (`pwsh -c '…'`, `powershell -enc …`) was decided on
its POSIX words alone.

## Decision

1. **An obfuscation score** (`openmoat-core/src/obfuscation.rs`, one file per dialect).
   A deterministic, pure function scores a command line on DET0505's signals, each with
   a weight and each counting only text agents' everyday commands do not contain: three
   or more escapes of printable ASCII (not colour escapes or UTF-8 bytes), quotes
   splitting a word around one or two letters, backslashes before letters, a command
   word built by an expansion (more for a cut or an indirection), brace expansion as a
   command, `eval`, `${!x}`, numeric `${x:…}` cuts, case and pattern changes, an `IFS`
   assignment that is not `IFS= read`, short assignments joined into one word, decoders,
   `rev`, rotated `tr` alphabets, base-`#` arithmetic and `printf` character codes,
   escape density, length over 4096 outside here-documents, and a 64-character word with
   more than 5 bits of entropy per character (which alone never reaches the threshold).
   PowerShell has its own: backticks inside bare words, `[char]` codes, joined string
   literals, `-join` and `-f` building, reversal, `-bxor`, `FromBase64String`,
   `-EncodedCommand`, `Invoke-Expression`, alternating case and characters indexed out
   of known strings.
2. **The `@obfuscated <signals>` atom.** A line whose score reaches 3 gets the atom,
   which the new default `review` rule `obfuscated` names. It only adds: the line is
   classified as before, so a deny still wins, and an everyday line gets no atom. The
   threshold is calibrated, not guessed: `openmoat-core/tests/obfuscation.rs` scores
   every allowed conformance fixture and every allowed or deferred MoatBench step and
   fails if one reaches it, and checks that every `obfuscated` attack fixture does.
3. **What the classifier can follow, it follows.** For a variable whose values are known
   on the line, `${s:offset:length}` is cut as bash cuts it (`locals/slice.rs`) and
   `${!r}` is the variable `r` names; a command substitution whose output is known text
   (`echo` or `printf %s` of plain words) is classified a second time as that text
   (`shell/fold.rs`), both sets of atoms counting. A differential fuzz test
   (`tests/obfuscation_fuzz.rs`) rewrites commands the default policy denies the way
   Bashfuscator does, word by word and line by line, from a fixed seed, and fails if a
   variant is neither denied nor held.
4. **A PowerShell reader** (`shell/powershell.rs` and `powershell/`). A minimal lexer
   reads quotes, escapes, comments, variables, `$env:` and statements; each simple
   statement becomes the POSIX command that does the same (`Remove-Item -Recurse -Force`
   is `rm -rf`, `Get-Content` is `cat`, `iwr URL | iex` is `curl URL | sh`, `\` is the
   path separator, `$env:USERPROFILE` is `$HOME`), which the POSIX classifier and the
   default rules decide. Parameters match as PowerShell matches them (case, unique
   prefixes, `-Name:value`). Code built at run time (`iex` of anything but piped input,
   `Invoke-Command`, `[scriptblock]`, `.Invoke(`, `Add-Type`, `FromBase64String`,
   `-EncodedCommand`, a computed program) gets `@opaque-code powershell`; the text an
   encoded command or a base64 literal decodes to, and a literal `iex` runs, is read as
   PowerShell too. A statement it does not read (pipelines into script blocks,
   parentheses, arrays) adds no atom but its literal paths and `$env:` reads.
   `Set-ExecutionPolicy` for the user or the machine is `@execution-policy <policy>
   <scope>`, which `persistence` holds; `-Scope Process` gives no atom.
5. **PowerShell is never allowed on the reader alone.** `Action::ForeignShell` with the
   shell `PowerShell` (`openmoat_core::POWERSHELL`, which the host adapters use) stays
   `unparseable`: the reader only adds atoms, so a rule can deny or hold what it reads,
   and anything else is the agent's prompt as before. A POSIX line that runs
   `powershell`/`pwsh` gets the reader's atoms for the line it runs; a part the reader
   does not read leaves the POSIX verdict as it was, and only an error that needs review
   (an open quote, a limit) is kept. Injected-input linking and untrusted output for a
   PowerShell line keep reading its text (`engine/injection/foreign.rs`).

## Consequences

- Lines that hide what they run are held for review instead of deferring, on both
  shells; nothing that was denied or held is decided more loosely, and no allowed
  fixture or MoatBench step changes verdict (both checked by tests).
- PowerShell commands that do what a default rule denies are denied: deleting the home,
  reading a key, piping a download into `iex`, handing work to WSL. Some fixtures that
  expected `review` or `defer` for PowerShell are now `deny`.
- The score is a heuristic. A line can be written to stay under it; it is a signal for
  review, not a boundary, and the OS sandbox remains what enforces (ADR-013, ADR-018).
- The reader is a preview: it reads simple statements only, its cmdlet table covers
  file, web, process and evaluation cmdlets, and PowerShell's own parsing has corners
  (here-strings, splatting, `-f` formats, script blocks) it leaves unread. A host that
  runs `cmd` or an unknown Windows shell is unchanged.
- Future work: an entropy signal for encoded tokens in data, a larger benign PowerShell
  corpus from real agent sessions, and `cmd` lines.
