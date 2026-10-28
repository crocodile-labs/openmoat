//! From tokens to simple commands to atomic actions.

mod fetch;
mod locals;
mod payload;
mod piped;
mod pipelines;
mod recover;
mod wrappers;

use super::tables::{
    ENV_BUILTINS, HOST_PROGRAMS, MAKES, PACKAGE_RUNNERS, RESERVED_CLOSERS, RESERVED_PREFIXES,
    SHELLS, SOURCE_BUILTINS, WRITE_ALL_PATHS, inline_flags,
};
use super::tokens::{
    assignment_name, flag_payload, for_variable, kill_substituted, program_name, strip_at,
    word_env_refs,
};
use super::{ClassifyError, MAX_DEPTH, ShellContext, Sink};
use super::{
    copy, cwd, database, decoders, embedded, extract, git, invocation, mailbox, make, operands,
    options, text,
};
use crate::action::AtomicAction;
use crate::host;
use crate::lexer::{self, Operator, Token, Word};
use crate::paths;
use piped::Piped;
use recover::lex_like_bash;

/// A simple command, or the opening or closing parenthesis of a subshell.
#[derive(Debug)]
enum Item {
    Command(SimpleCommand),
    Open,
    Close,
}

/// One simple command: words (assignments + argv), its redirection targets and
/// its stdin data.
#[derive(Debug, Default, Clone)]
struct SimpleCommand {
    words: Vec<Word>,
    reads: Vec<String>,
    writes: Vec<String>,
    /// `<<<` here-strings and unquoted here-document bodies: expanded by the shell.
    stdin: Vec<Word>,
    /// Here-document bodies with a quoted delimiter: taken literally.
    literal_stdin: Vec<String>,
    /// Data the previous command of a pipe passes on (`piped.rs`).
    piped: Vec<Piped>,
}

impl SimpleCommand {
    fn is_empty(&self) -> bool {
        self.words.is_empty()
            && self.reads.is_empty()
            && self.writes.is_empty()
            && self.stdin.is_empty()
            && self.literal_stdin.is_empty()
    }

    fn stdin_texts(&self) -> impl Iterator<Item = &str> {
        let expanded = self.stdin.iter().map(|w| w.text.as_str());
        expanded.chain(self.literal_stdin.iter().map(String::as_str))
    }
}

/// The names Codex applies a patch under when a shell command runs it.
const APPLY_PATCH: [&str; 2] = ["apply_patch", "applypatch"];

pub(super) fn classify_into(
    command: &str,
    ctx: &ShellContext<'_>,
    sink: &mut Sink,
    depth: u8,
) -> Result<(), ClassifyError> {
    if depth > MAX_DEPTH {
        return Err(ClassifyError::TooDeep);
    }
    let (tokens, too_many) = lexer::expand_braces(lex_like_bash(command)?);
    if let Some(e) = too_many {
        sink.skip(e.into());
    }
    sink.note_globs(&tokens);
    let mut dirs = ctx.cwd.to_vec();
    let mut saved = Vec::new();
    for item in group_commands(&tokens) {
        match item {
            Item::Open => saved.push(dirs.clone()),
            // The shell refuses a `)` it did not open; so does the classifier.
            Item::Close => match saved.pop() {
                Some(outer) => dirs = outer,
                None => sink.skip(ClassifyError::UnbalancedParens),
            },
            Item::Command(cmd) => {
                let here = ShellContext { cwd: &dirs, ..*ctx };
                if let Err(e) = classify_simple(&cmd, &here, sink, depth) {
                    sink.skip(e);
                }
                let moved = cwd::targets(&cmd.words, &here);
                cwd::merge(&mut dirs, moved)?;
            }
        }
    }
    if !saved.is_empty() {
        sink.skip(ClassifyError::UnbalancedParens);
    }
    pipelines::push(&tokens, sink)?;
    decoders::push(&tokens, sink)
}

/// Group tokens into simple commands. The commands inside subshell
/// parentheses are governed exactly like top-level ones; the parentheses are
/// kept only to scope `cd`.
fn group_commands(tokens: &[Token]) -> Vec<Item> {
    let mut commands = Vec::new();
    let mut current = SimpleCommand::default();
    let mut pending_redirect: Option<Operator> = None;

    for token in tokens {
        match token {
            Token::Operator(op) if op.is_separator() || op.is_grouping() => {
                pending_redirect = None;
                if !current.is_empty() {
                    let piped = piped::data(&current).filter(|_| *op == Operator::Pipe);
                    commands.push(Item::Command(std::mem::take(&mut current)));
                    current.piped.extend(piped);
                } else if *op == Operator::Pipe && matches!(commands.last(), Some(Item::Close)) {
                    // `( … ) | sh`: what the group prints is not on the command line.
                    current.piped.push(Piped::Output("( … )".to_owned()));
                }
                match op {
                    Operator::OpenParen => commands.push(Item::Open),
                    Operator::CloseParen => commands.push(Item::Close),
                    _ => {}
                }
            }
            Token::Operator(op) => pending_redirect = Some(*op),
            Token::HereDoc {
                body,
                literal: true,
            } => current.literal_stdin.push(body.text.clone()),
            Token::HereDoc { body, .. } => current.stdin.push(body.clone()),
            Token::Word(w) => match pending_redirect.take() {
                Some(Operator::RedirectIn) => current.reads.push(w.text.clone()),
                Some(Operator::HereString) => current.stdin.push(w.clone()),
                Some(Operator::RedirectOut | Operator::RedirectAppend) => {
                    current.writes.push(w.text.clone());
                }
                Some(Operator::RedirectReadWrite) => {
                    current.reads.push(w.text.clone());
                    current.writes.push(w.text.clone());
                }
                Some(Operator::DuplicateDescriptor) => {
                    // `>&2` / `<&-` duplicate or close a descriptor; anything else is a file.
                    if !w.text.chars().all(|c| c.is_ascii_digit() || c == '-') {
                        current.writes.push(w.text.clone());
                    }
                }
                None | Some(_) => current.words.push(w.clone()),
            },
        }
    }
    if !current.is_empty() {
        commands.push(Item::Command(current));
    }
    commands
}

fn classify_simple(
    cmd: &SimpleCommand,
    ctx: &ShellContext<'_>,
    sink: &mut Sink,
    depth: u8,
) -> Result<(), ClassifyError> {
    // `d=~/.ssh; cat $d/id_rsa`: a variable set earlier on the line is classified
    // with each value it may hold
    if locals::classify_with_values(cmd, ctx, sink, depth)? {
        return Ok(());
    }
    classify_as_written(cmd, ctx, sink, depth)
}

/// [`classify_simple`] without substituting variables: for a command whose
/// variables were substituted already. The shell expands a value once and
/// never again, so a value holding `${e}` (from single quotes) stays that
/// text; expanding it again would recurse without end (`e='${e}'; cat $e`).
fn classify_as_written(
    cmd: &SimpleCommand,
    ctx: &ShellContext<'_>,
    sink: &mut Sink,
    depth: u8,
) -> Result<(), ClassifyError> {
    for w in cmd.words.iter().chain(&cmd.stdin) {
        for inner in &w.substitutions {
            // A substitution that cannot be classified (`TooDeep`, a lexer
            // error) does not take this command's own reads, writes and
            // operands with it: they are still decided below.
            if let Err(e) = classify_into(inner, ctx, sink, depth + 1) {
                sink.skip(e);
            }
        }
    }
    sink.enter(depth);
    for w in &cmd.stdin {
        for name in word_env_refs(w) {
            sink.push(AtomicAction::EnvRead { name })?;
        }
    }
    for r in &cmd.reads {
        sink.redirect_read(ctx, r)?;
    }
    for w in &cmd.writes {
        sink.redirect_write(ctx, w)?;
    }

    // `do git log`, `if cat x; then`: the command after a reserved word is the
    // one that runs; `done`, `fi`, `}` alone run nothing.
    let mut idx = cmd
        .words
        .iter()
        .take_while(|w| !w.quoted && RESERVED_PREFIXES.contains(&w.text.as_str()))
        .count();
    if let [only] = &cmd.words[idx..]
        && !only.quoted
        && RESERVED_CLOSERS.contains(&only.text.as_str())
    {
        return Ok(());
    }
    if let Some(loop_var) = for_variable(&cmd.words[idx..]) {
        sink.push(AtomicAction::EnvSet {
            name: loop_var.to_owned(),
        })?;
        for word in &cmd.words[idx + 3..] {
            for name in word_env_refs(word) {
                sink.push(AtomicAction::EnvRead { name })?;
            }
        }
        sink.note_local(
            loop_var,
            locals::loop_values(&cmd.words[idx + 3..], ctx.home),
        );
        return Ok(());
    }
    let first_assignment = idx;
    while let Some(word) = cmd.words.get(idx) {
        let Some(name) = assignment_name(&word.text) else {
            break;
        };
        sink.push(AtomicAction::EnvSet {
            name: name.to_owned(),
        })?;
        for name in word_env_refs(word) {
            sink.push(AtomicAction::EnvRead { name })?;
        }
        idx += 1;
    }
    let words = &cmd.words[idx..];
    if words.is_empty() {
        // `x=1` on its own sets a shell variable for the rest of the line
        for word in &cmd.words[first_assignment..idx] {
            if let Some(name) = assignment_name(&word.text) {
                let value = locals::assignment_value(word, ctx.home);
                sink.note_local(name, value.map(|v| vec![v]));
            }
        }
        return Ok(());
    }
    let argv: Vec<String> = words.iter().map(|w| w.text.clone()).collect();
    let program = program_name(&argv[0]);
    sink.refuse_dot_dirs(program);
    super::push::note(&argv, program, ctx, sink);
    super::installs::note(&argv, program, sink)?;

    if program == "git" {
        git::push_shell(&argv, ctx, sink)?;
    } else {
        sink.push(AtomicAction::Shell { argv: argv.clone() })?;
    }
    push_kill_substituted(program, words, sink)?;

    if ENV_BUILTINS.contains(&program) {
        for name in argv[1..].iter().filter_map(|w| assignment_name(w)) {
            sink.push(AtomicAction::EnvSet {
                name: name.to_owned(),
            })?;
        }
        locals::note_builtin(&words[1..], program, ctx.home, sink);
    }
    locals::note_read_targets(&words[1..], program, sink);
    if program == "printenv" {
        for name in argv[1..].iter().filter(|a| !a.starts_with('-')) {
            sink.push(AtomicAction::EnvRead { name: name.clone() })?;
        }
    }
    if SOURCE_BUILTINS.contains(&program)
        && let Some(file) = argv.get(1)
    {
        sink.read(ctx, file)?;
    }
    // `apply_patch <<'EOF'`: Codex applies a patch a shell command hands it,
    // here-document, piped text or argument alike, so every file it names is
    // written
    if APPLY_PATCH.contains(&program) {
        let texts = cmd
            .stdin_texts()
            .chain(cmd.piped.iter().filter_map(Piped::text))
            .chain(argv[1..].iter().map(String::as_str));
        for path in texts.flat_map(crate::patch::writes) {
            sink.write(ctx, &path)?;
        }
    }
    let mut text_operands = text::classify(&argv, program, ctx, sink)?;
    let stdin = cmd
        .stdin_texts()
        .chain(cmd.piped.iter().filter_map(Piped::text));
    text_operands
        .data
        .extend(database::classify(&argv, program, stdin, ctx, sink)?);
    text_operands.data.extend(git::data_words(&argv, program));
    text_operands
        .data
        .extend(options::fd_pattern(&argv, program).or(options::grep_pattern(&argv, program)));
    super::path_options::classify(&argv, program, &mut text_operands, ctx, sink)?;
    classify_arguments(&argv, program, words, &text_operands, ctx, sink)?;
    for dir in extract::destinations(&argv, program) {
        sink.write(ctx, &dir)?;
    }
    for code in embedded::commands(&argv, program) {
        classify_into(&code, ctx, sink, depth + 1)?;
    }

    if MAKES.contains(&program) {
        return make::classify(&argv, ctx, sink, depth);
    }

    if program == "eval" && argv.len() > 1 {
        return classify_into(&argv[1..].join(" "), ctx, sink, depth + 1);
    }
    if SHELLS.contains(&program) {
        let run = invocation::parse(program, &argv)?;
        // `bash <<< 'cmd'`, `bash <<EOF` and `cat <<EOF | bash` run their stdin
        // as the program.
        let piped = cmd.piped.iter().filter_map(Piped::text);
        let stdin_code = cmd.stdin_texts().chain(piped).filter(|_| run.reads_stdin);
        for code in run.code.into_iter().chain(stdin_code) {
            classify_into(code, ctx, sink, depth + 1)?;
        }
        if let Some(script) = run.script {
            sink.read(ctx, script)?;
        }
        if !run.reads_stdin || !cmd.piped.iter().any(Piped::is_hidden) {
            return Ok(());
        }
        // The shell runs text the line does not show: `<shell> @stdin`, which no
        // allow rule names, so a rule can ask for it (`opaque-code`).
        sink.push(AtomicAction::Shell {
            argv: vec![program.to_owned(), "@stdin".to_owned()],
        })?;
        return match cmd.piped.iter().find_map(Piped::unknown) {
            Some(producer) => Err(ClassifyError::UnknownStdin(producer.into())),
            None => Ok(()),
        };
    }
    if PACKAGE_RUNNERS.contains(&program)
        && let Some(payload) = flag_payload(&argv, &["-c", "--call"])
    {
        return classify_into(payload, ctx, sink, depth + 1);
    }
    if let Some(done) = wrappers::classify(cmd, &argv, program, ctx, sink, depth) {
        return done;
    }
    let inline = inline_flags(program);
    if let Some(flags) = inline
        && let Some(payload) = flag_payload(&argv, flags)
    {
        payload::scan_payload(payload, ctx, sink)?;
    }
    if inline.is_some() {
        for text in cmd.stdin_texts() {
            payload::scan_payload(text, ctx, sink)?;
        }
    }
    options::classify(&argv, program, ctx, sink, depth)
}

/// The second atom of a `kill` of substituted pids ([`kill_substituted`]).
fn push_kill_substituted(
    program: &str,
    words: &[Word],
    sink: &mut Sink,
) -> Result<(), ClassifyError> {
    match kill_substituted(program, words) {
        Some(argv) => sink.push(AtomicAction::Shell { argv }),
        None => Ok(()),
    }
}

/// Classify a wrapper's inner argv (`sudo rm …` → `rm …`) as its own command.
pub(super) fn classify_wrapped(
    inner: &[String],
    ctx: &ShellContext<'_>,
    sink: &mut Sink,
    depth: u8,
) -> Result<(), ClassifyError> {
    if depth >= MAX_DEPTH {
        return Err(ClassifyError::TooDeep);
    }
    // The wrapping command already recorded the variables these words expand,
    // with their quoting; the inner words carry none, so they are not rescanned.
    let cmd = SimpleCommand {
        words: inner
            .iter()
            .map(|t| Word {
                text: t.clone(),
                literal: std::iter::once(0..t.len()).collect(),
                ..Word::default()
            })
            .collect(),
        ..SimpleCommand::default()
    };
    classify_simple(&cmd, ctx, sink, depth + 1)
}

fn classify_arguments(
    argv: &[String],
    program: &str,
    words: &[Word],
    text_operands: &text::Operands,
    ctx: &ShellContext<'_>,
    sink: &mut Sink,
) -> Result<(), ClassifyError> {
    // A copy or a move writes its destination, or the entries it creates in it
    // (`copy.rs`); a remote destination (`host:/dir`) is not a local write.
    let copy = copy::destination(argv, program).filter(|d| {
        paths::looks_like_path(d.word) || operands::file_operand(d.word, program, true).is_some()
    });
    let mut sources = Vec::new();
    let options_end = argv.iter().position(|a| a == "--");
    // git's global options come before the subcommand (`git -C dir push host:x`).
    let names_hosts =
        HOST_PROGRAMS.contains(&program) || (program == "git" && git::names_hosts(argv));
    // a curl or wget request that sends nothing is a fetch (ADR-035)
    let fetch_only = fetch::sends_nothing(argv, program, words, sink);

    for (i, (tok, word)) in argv.iter().zip(words).enumerate() {
        for name in word_env_refs(word) {
            sink.push(AtomicAction::EnvRead { name })?;
        }
        if program == "env"
            && i > 0
            && let Some(name) = assignment_name(tok)
        {
            sink.push(AtomicAction::EnvSet {
                name: name.to_owned(),
            })?;
        }
        let skip = copy.as_ref().is_some_and(|d| d.index == i) || mailbox::names_no_host(argv, i);
        if i == 0 || text_operands.data.contains(&i) || skip {
            continue;
        }
        let options_ended = options_end.is_some_and(|end| i > end);
        if options_ended || !tok.starts_with('-') {
            sources.push(tok.as_str());
        }
        // `curl file:///etc/passwd` reads the file, whatever the program
        if let Some(path) = host::file_url_path(tok) {
            sink.read(ctx, &path)?;
            continue;
        }
        let candidate = strip_at(tok);
        // `dd of=~/x`: bash expands the `~` after `=`, and the word is no path
        let file = if program == "dd"
            && let Some((key @ ("if" | "of"), value)) = tok.split_once('=')
        {
            if key == "if" {
                sink.read(ctx, value)?;
            } else {
                sink.write(ctx, value)?;
            }
            continue;
        } else if paths::looks_like_path(candidate) {
            Some(candidate)
        } else if (!word.quoted || names_hosts || tok.contains("://"))
            && let Some(host) = host::of_argument(program, tok)
        {
            // Quoted prose ("see example.com") is not a host unless it is a full URL
            // or an argument of a program that names hosts (`curl 'evil.com'`).
            // Without a scheme and outside such a program, the word only looks like
            // one (`check_runs.0.id`, ADR-025).
            sink.push(if fetch_only && fetch::fetchable_host(&host) {
                AtomicAction::Fetch { host }
            } else if tok.contains("://") || names_hosts {
                AtomicAction::Net { host }
            } else {
                AtomicAction::NetWord { host }
            })?;
            continue;
        } else {
            operands::file_operand(tok, program, options_ended)
        };
        if let Some(file) = file {
            if WRITE_ALL_PATHS.contains(&program) || text_operands.writes.contains(&i) {
                sink.write(ctx, file)?;
            } else {
                sink.read(ctx, file)?;
            }
        }
    }
    if let Some(dest) = &copy {
        for path in copy::writes(argv, program, dest, &sources) {
            sink.write(ctx, &path)?;
        }
    }
    Ok(())
}
