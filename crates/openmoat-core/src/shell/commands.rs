//! From tokens to simple commands to atomic actions.

mod piped;

use super::tables::{
    ENV_BUILTINS, INLINE_INTERPRETERS, MAKES, PACKAGE_RUNNERS, SHELLS, SOURCE_BUILTINS,
    WRAPPER_OPTIONS_WITH_VALUE, WRAPPER_SUBCOMMANDS, WRAPPERS, WRAPPERS_WITH_VALUE,
    WRITE_ALL_PATHS,
};
use super::tokens::{assignment_name, basename, env_refs, flag_payload, strip_at, word_env_refs};
use super::{ClassifyError, MAX_DEPTH, ShellContext, Sink};
use super::{copy, cwd, decoders, git, invocation, make, operands, options, text};
use crate::action::AtomicAction;
use crate::host;
use crate::lexer::{self, Operator, Token, Word};
use crate::paths;
use piped::Piped;

/// A simple command, or the opening or closing parenthesis of a subshell.
#[derive(Debug)]
enum Item {
    Command(SimpleCommand),
    Open,
    Close,
}

/// One simple command: words (assignments + argv), its redirection targets and
/// its stdin data.
#[derive(Debug, Default)]
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

pub(super) fn classify_into(
    command: &str,
    ctx: &ShellContext<'_>,
    sink: &mut Sink,
    depth: u8,
) -> Result<(), ClassifyError> {
    if depth > MAX_DEPTH {
        return Err(ClassifyError::TooDeep);
    }
    let (tokens, too_many) = lexer::expand_braces(lexer::lex(command)?);
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
    push_pipelines(&tokens, sink)?;
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
    for w in cmd.words.iter().chain(&cmd.stdin) {
        for inner in &w.substitutions {
            classify_into(inner, ctx, sink, depth + 1)?;
        }
    }
    for w in &cmd.stdin {
        for name in word_env_refs(w) {
            sink.push(AtomicAction::EnvRead { name })?;
        }
    }
    for r in &cmd.reads {
        sink.read(ctx, r)?;
    }
    for w in &cmd.writes {
        sink.write(ctx, w)?;
    }

    let mut idx = 0;
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
        return Ok(());
    }
    let argv: Vec<String> = words.iter().map(|w| w.text.clone()).collect();
    let program = basename(&argv[0]);

    if program == "git" {
        git::push_shell(&argv, ctx, sink)?;
    } else {
        sink.push(AtomicAction::Shell { argv: argv.clone() })?;
    }

    if ENV_BUILTINS.contains(&program) {
        for name in argv[1..].iter().filter_map(|w| assignment_name(w)) {
            sink.push(AtomicAction::EnvSet {
                name: name.to_owned(),
            })?;
        }
    }
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
    let text_operands = text::classify(&argv, program, ctx, sink)?;
    classify_arguments(&argv, program, words, &text_operands, ctx, sink)?;

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
        return match cmd.piped.iter().find_map(Piped::unknown) {
            Some(program) if run.reads_stdin => Err(ClassifyError::UnknownStdin(program.into())),
            _ => Ok(()),
        };
    }
    if PACKAGE_RUNNERS.contains(&program)
        && let Some(payload) = flag_payload(&argv, &["-c", "--call"])
    {
        return classify_into(payload, ctx, sink, depth + 1);
    }
    if let Some(inner) = wrapped_command(&argv, program) {
        return classify_wrapped(inner, ctx, sink, depth);
    }
    if let Some((_, flags)) = INLINE_INTERPRETERS
        .iter()
        .find(|(name, _)| *name == program)
        && let Some(payload) = flag_payload(&argv, flags)
    {
        scan_payload(payload, ctx, sink)?;
    }
    if INLINE_INTERPRETERS.iter().any(|(name, _)| *name == program) {
        for text in cmd.stdin_texts() {
            scan_payload(text, ctx, sink)?;
        }
    }
    options::classify(&argv, program, ctx, sink, depth)
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

/// For `sudo -u x cmd …`, `env A=1 cmd …`, `xargs -0 cmd …`, `timeout 5 cmd …`
/// return the wrapped argv.
fn wrapped_command<'a>(argv: &'a [String], program: &str) -> Option<&'a [String]> {
    if let Some((_, subcommands)) = WRAPPER_SUBCOMMANDS
        .iter()
        .find(|(name, _)| *name == program)
    {
        if !subcommands.contains(&argv.get(1)?.as_str()) {
            return None;
        }
        let mut i = 2;
        while let Some(arg) = argv.get(i) {
            if arg == "--" {
                i += 1;
                break;
            }
            if !arg.starts_with('-') {
                break;
            }
            i += 1;
        }
        return argv.get(i..).filter(|rest| !rest.is_empty());
    }
    if !WRAPPERS.contains(&program) {
        return None;
    }
    let options_with_value = WRAPPER_OPTIONS_WITH_VALUE
        .iter()
        .find(|(name, _)| *name == program)
        .map_or(&[][..], |(_, opts)| *opts);
    let mut i = 1;
    let mut value_pending = WRAPPERS_WITH_VALUE.contains(&program);
    while let Some(arg) = argv.get(i) {
        if arg == "--" {
            i += 1;
            break;
        }
        if options_with_value.contains(&arg.as_str()) {
            i += 2;
            continue;
        }
        let is_env_assignment = program == "env" && assignment_name(arg).is_some();
        if arg.starts_with('-') || is_env_assignment {
            i += 1;
            continue;
        }
        if value_pending {
            value_pending = false;
            i += 1;
            continue;
        }
        break;
    }
    argv.get(i..).filter(|rest| !rest.is_empty())
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
        let is_destination = copy.as_ref().is_some_and(|d| d.index == i);
        if i == 0 || text_operands.data.contains(&i) || is_destination {
            continue;
        }
        let options_ended = options_end.is_some_and(|end| i > end);
        if options_ended || !tok.starts_with('-') {
            sources.push(tok.as_str());
        }
        let candidate = strip_at(tok);
        let file = if paths::looks_like_path(candidate) {
            Some(candidate)
        } else if program == "dd"
            && let Some((key, value)) = tok.split_once('=')
        {
            match key {
                "if" => sink.read(ctx, value)?,
                "of" => sink.write(ctx, value)?,
                _ => {}
            }
            continue;
        } else if (!word.quoted || tok.contains("://"))
            && let Some(host) = host::of_word(tok)
        {
            // Quoted prose ("see example.com") is not a host unless it is a full URL.
            sink.push(AtomicAction::Net { host })?;
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
        for path in copy::written(dest, &sources) {
            sink.write(ctx, &path)?;
        }
    }
    Ok(())
}

/// Mine inline interpreter code for the resources it names. The payload is
/// not shell, so it is scanned rather than parsed.
fn scan_payload(
    payload: &str,
    ctx: &ShellContext<'_>,
    sink: &mut Sink,
) -> Result<(), ClassifyError> {
    let is_separator =
        |c: char| c.is_whitespace() || matches!(c, '(' | ')' | ',' | ';' | '\'' | '"' | '`');
    for raw in payload.split(is_separator).filter(|s| !s.is_empty()) {
        if paths::looks_like_path(raw) {
            sink.read(ctx, raw)?;
        } else if let Some(host) = host::of_word(raw) {
            sink.push(AtomicAction::Net { host })?;
        }
        for name in env_refs(raw) {
            sink.push(AtomicAction::EnvRead { name })?;
        }
    }
    Ok(())
}

/// Emit a `Pipeline` atom for every suffix of a pipeline/list with ≥ 2 commands
/// so prefix rules such as `curl * | sh` match at any boundary.
fn push_pipelines(tokens: &[Token], sink: &mut Sink) -> Result<(), ClassifyError> {
    let mut flat: Vec<String> = Vec::new();
    let mut starts: Vec<usize> = Vec::new();
    let mut at_command_start = true;
    // Separators pushed since the last word. Counted from the tokens, not by
    // comparing text: an escaped word `\&` has the same text as the operator.
    let mut trailing_separators = 0;
    for token in tokens {
        match token {
            Token::Word(w) => {
                if at_command_start {
                    starts.push(flat.len());
                    at_command_start = false;
                }
                flat.push(w.text.clone());
                trailing_separators = 0;
            }
            Token::Operator(op) if op.is_separator() => {
                if !at_command_start {
                    flat.push(op.symbol().to_owned());
                    trailing_separators += 1;
                }
                at_command_start = true;
            }
            Token::Operator(op) if op.is_redirect() => {
                flat.push(op.symbol().to_owned());
                trailing_separators = 0;
            }
            Token::Operator(_) | Token::HereDoc { .. } => {}
        }
    }
    flat.truncate(flat.len() - trailing_separators);
    if starts.len() < 2 {
        return Ok(());
    }
    for &start in &starts[..starts.len() - 1] {
        sink.push(AtomicAction::Pipeline {
            argv: flat[start..].to_vec(),
        })?;
    }
    Ok(())
}
