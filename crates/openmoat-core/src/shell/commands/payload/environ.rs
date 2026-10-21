//! What inline interpreter code reads of the environment: `os.environ['X']`,
//! `os.getenv('X')`, `process.env.X`, `ENV['X']`, `$ENV{X}`, `getenv('X')`,
//! `$env:X` read the variable they name; `print(os.environ)`,
//! `console.log(process.env)`, `ENV.to_h`, `%ENV`, `getenv()` or a name chosen
//! at run time (`os.environ[k]`) read all of them. Forms that name none of
//! these bases (`getattr(os, 'environ')`, `subprocess.run(['env'])`,
//! `Get-ChildItem Env:`) are in `indirect.rs`. The code is scanned, not
//! parsed, like the rest of a payload: an alias (`e = os.environ`, `g = getattr`)
//! is not followed.

mod indirect;

/// The ways code names the environment. `environ` also stands for `os.environ`.
const BASES: &[&str] = &[
    "environ",
    "process.env",
    "Deno.env",
    "Bun.env",
    "ENV",
    "$ENV",
    "%ENV",
    "$_ENV",
    "$_SERVER",
    "getenv",
    "$env:",
];

/// Methods that hand over every variable (`os.environ.items()`, `ENV.to_h`).
const WHOLE_METHODS: &[&str] = &[
    "items",
    "values",
    "to_h",
    "to_hash",
    "to_a",
    "each",
    "each_pair",
    "inspect",
    "to_s",
    "toObject",
    "entries",
];

/// Statements that print their argument without parentheses (`p ENV`, `puts ENV`).
const PRINTERS: &[&str] = &["p", "pp", "puts", "print", "say", "echo"];

/// What one use of the environment reads.
enum Access {
    Name(String),
    Whole,
    Other,
}

/// The variables `code` names, and whether it reads the environment whole
/// (the expression that does, for the `@env-dump` atom).
pub(super) fn reads(code: &str) -> (Vec<String>, Option<&'static str>) {
    let mut names: Vec<String> = Vec::new();
    let mut whole = None;
    for (at, base) in uses(code) {
        let after = &code[at + base.len()..];
        let all = match access(base, after) {
            Access::Name(name) => {
                if !names.contains(&name) {
                    names.push(name);
                }
                false
            }
            Access::Whole => true,
            Access::Other => printed(code, at, base, after),
        };
        if all {
            whole = whole.or(Some(base));
        }
    }
    let indirect = indirect::reads(code, &mut names);
    (names, whole.or(indirect))
}

fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Every position of a base in `code` that stands on its own (`ENV`, not
/// `ENVIRONMENT` or `$ENV`; `os.environ`, not `environment`).
fn uses(code: &str) -> Vec<(usize, &'static str)> {
    let mut out = Vec::new();
    for base in BASES {
        for (at, _) in code.match_indices(base) {
            let before = code[..at].chars().next_back();
            let after = code[at + base.len()..].chars().next();
            let open_before = match *base {
                // `os.environ`, `os.getenv(`, `Sys.getenv(`
                "environ" | "getenv" => before.is_none_or(|c| !is_ident(c)),
                "ENV" => before.is_none_or(|c| !is_ident(c) && !matches!(c, '$' | '%' | '@' | '.')),
                _ => before.is_none_or(|c| !is_ident(c) && c != '.'),
            };
            let open_after = base.ends_with(':') || after.is_none_or(|c| !is_ident(c));
            if open_before && open_after {
                out.push((at, *base));
            }
        }
    }
    out.sort_unstable();
    out
}

/// A quoted name at the start of `text` (`'X'`, `"X"`), and the text after it.
fn literal(text: &str) -> Option<(String, &str)> {
    let text = text.trim_start();
    let quote = text.chars().next().filter(|c| matches!(c, '\'' | '"'))?;
    let body = &text[1..];
    let end = body.find(quote)?;
    let name = &body[..end];
    (!name.is_empty() && name.chars().all(is_ident)).then(|| (name.to_owned(), &body[end + 1..]))
}

/// The argument of a getter call (`get('X')`, `getenv(k)`) at `args`, the text
/// after its `(`: a name, every variable for a name chosen at run time or no
/// argument at all when `empty_is_whole`, or nothing.
fn argument(args: &str, empty_is_whole: bool) -> Access {
    if let Some((name, _)) = literal(args) {
        return Access::Name(name);
    }
    if args.trim_start().starts_with(')') && !empty_is_whole {
        return Access::Other;
    }
    Access::Whole
}

fn access(base: &str, after: &str) -> Access {
    match base {
        "%ENV" => Access::Whole,
        "getenv" => match after.trim_start().strip_prefix('(') {
            Some(args) => argument(args, true),
            None => Access::Other,
        },
        "$env:" => {
            let name: String = after.chars().take_while(|c| is_ident(*c)).collect();
            if name.is_empty() {
                Access::Other
            } else {
                Access::Name(name)
            }
        }
        "$ENV" => match after.strip_prefix('{') {
            Some(body) => {
                let inner = body.split('}').next().unwrap_or_default();
                let key = inner.trim_matches(|c| matches!(c, '\'' | '"'));
                if !key.is_empty() && key.chars().all(is_ident) {
                    Access::Name(key.to_owned())
                } else {
                    Access::Whole
                }
            }
            None => Access::Other,
        },
        _ => member(base, after),
    }
}

/// `[...]` or `.name` after a base that is an object.
fn member(base: &str, after: &str) -> Access {
    if let Some(index) = after.strip_prefix('[') {
        if let Some((name, rest)) = literal(index)
            && rest.trim_start().starts_with(']')
        {
            return Access::Name(name);
        }
        // `os.environ[k] = v` sets a variable; `os.environ[k]` reads one chosen at run time
        let assigned = index.split_once(']').is_some_and(|(_, rest)| {
            let rest = rest.trim_start();
            rest.starts_with('=') && !rest.starts_with("==")
        });
        return if assigned {
            Access::Other
        } else {
            Access::Whole
        };
    }
    let Some(field) = after.strip_prefix('.') else {
        return Access::Other;
    };
    let method: String = field.chars().take_while(|c| is_ident(*c)).collect();
    let rest = &field[method.len()..];
    if WHOLE_METHODS.contains(&method.as_str()) {
        return Access::Whole;
    }
    if let Some(args) = rest.trim_start().strip_prefix('(') {
        return if matches!(method.as_str(), "get" | "fetch") {
            argument(args, false)
        } else {
            Access::Other
        };
    }
    // `process.env.NPM_TOKEN`: a JavaScript runtime's variables are its fields
    if !method.is_empty() && base.contains(".env") {
        return Access::Name(method);
    }
    Access::Other
}

/// Whether the environment object at `at` is printed or converted whole: the
/// only argument of a call (`print(os.environ)`, `dict(os.environ)`), unless
/// that call is handed on as a child's environment (`env=dict(os.environ)`);
/// the operand of a printing statement (`p ENV`); or the whole code (`node -p
/// process.env`).
fn printed(code: &str, at: usize, base: &str, after: &str) -> bool {
    if base == "getenv" {
        return false;
    }
    // `os.environ`: the expression starts at `os`
    let start = code[..at]
        .trim_end_matches(|c: char| is_ident(c) || c == '.')
        .len();
    let start = if base.starts_with(['$', '%']) {
        at
    } else {
        start
    };
    let before = code[..start].trim_end();
    let rest = after.trim_start();
    if before.is_empty() && rest.trim_end_matches([';', '\n', ' ']).is_empty() {
        return true;
    }
    if let Some(call) = before.strip_suffix('(')
        && rest.starts_with(')')
    {
        let name_start = call
            .trim_end_matches(|c: char| is_ident(c) || c == '.')
            .len();
        let outer = code[..name_start].trim_end();
        let handed_on = outer
            .strip_suffix(['=', ':'])
            .is_some_and(|o| o.trim_end().ends_with("env"));
        return !handed_on;
    }
    let word_start = before.trim_end_matches(is_ident).len();
    let word = &before[word_start..];
    let spaced = start > before.len();
    spaced && PRINTERS.contains(&word) && (rest.is_empty() || rest.starts_with([';', '\n', ')']))
}
