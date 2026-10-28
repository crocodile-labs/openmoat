//! Inline code whose files, hosts or variables the scan cannot read: code that
//! reaches files, the network, the environment or other programs, and builds
//! the name it hands them at run time. `open(os.path.expanduser("~/.s" +
//! "sh/id_rsa"))` names no path the scan sees, so no rule would match the file
//! it opens; the payload is opaque, and asks (`opaque-code`).
//!
//! Code that uses none of those APIs (`print(1+1)`), or hands them only
//! literal text (`open('pyproject.toml')`, which the scan reads as a path), is
//! not opaque. The code is scanned, not parsed, like the rest of a payload.

/// Names that reach files, the network, the environment or other programs.
/// One that starts with a letter matches only at the start of a word.
const APIS: &[&str] = &[
    // files
    "open(",
    "open ",
    "io.open",
    "pathlib",
    "Path(",
    "read_text",
    "read_bytes",
    "readFile",
    "createReadStream",
    "readdir",
    "require('fs')",
    "require(\"fs\")",
    "require('node:fs')",
    "require(\"node:fs\")",
    "fs.",
    "fs/promises",
    "File.",
    "IO.",
    "Dir.",
    "<F>",
    "<$",
    "file_get_contents",
    "fopen",
    "readfile(",
    "Deno.read",
    "Deno.open",
    "Bun.file",
    "Get-Content",
    "shutil",
    "os.listdir",
    "os.walk",
    "os.scandir",
    "glob.",
    // network
    "urllib",
    "urlopen",
    "requests",
    "httpx",
    "aiohttp",
    "http.client",
    "socket",
    "fetch(",
    "XMLHttpRequest",
    "http.",
    "https.",
    "net.",
    "Net::HTTP",
    "LWP",
    "IO::Socket",
    "HTTP::Tiny",
    "curl_",
    "fsockopen",
    "open-uri",
    "URI.open",
    "Invoke-WebRequest",
    "Invoke-RestMethod",
    "WebClient",
    // environment
    "environ",
    "getenv",
    "expandvars",
    "expanduser",
    "process.env",
    "Deno.env",
    "Bun.env",
    "$ENV",
    "%ENV",
    "ENV[",
    "ENV.",
    "$_ENV",
    "$_SERVER",
    "$env:",
    "Path.home",
    "homedir",
    "Dir.home",
    // other programs and code
    "subprocess",
    "os.system",
    "os.popen",
    "os.exec",
    "os.spawn",
    "pty.",
    "child_process",
    "execSync",
    "execFile",
    "spawn(",
    "spawnSync",
    "exec(",
    "eval(",
    "system(",
    "system ",
    "popen",
    "Process.",
    "__import__",
    "importlib",
    "getattr(",
    "compile(",
    "Function(",
    "Deno.Command",
    "Deno.run",
    "Bun.spawn",
    "Start-Process",
    "Invoke-Expression",
    "qx",
];

/// Calls that build or decode text at run time.
const BUILDERS: &[&str] = &[
    ".format(",
    "join(",
    "chr(",
    "fromCharCode",
    "atob(",
    "b64decode",
    "base64",
    "fromhex",
    "unhexlify",
    ".decode(",
    "[::-1]",
    "reverse",
    ".replace(",
    "rot13",
    "codecs.",
    "pack(",
    "sprintf",
    "String.raw",
    "Buffer.from",
    ".concat(",
    "%s",
];

/// Calls whose first argument is the file, address or command they use: one
/// that is not literal text names what the scan cannot read (`open(p)`).
const TAKE_A_NAME: &[&str] = &[
    "open(",
    "Path(",
    "urlopen(",
    "Request(",
    "readFile(",
    "readFileSync(",
    "createReadStream(",
    "readdirSync(",
    "fetch(",
    "requests.get(",
    "requests.post(",
    "httpx.get(",
    "httpx.post(",
    "http.get(",
    "https.get(",
    "http.request(",
    "https.request(",
    "create_connection(",
    "net.connect(",
    "net.createConnection(",
    "fopen(",
    "file_get_contents(",
    "File.read(",
    "File.open(",
    "File.readlines(",
    "IO.read(",
    "IO.readlines(",
    "os.system(",
    "os.popen(",
    "subprocess.run(",
    "subprocess.call(",
    "subprocess.Popen(",
    "subprocess.check_output(",
    "execSync(",
    "spawn(",
    "spawnSync(",
    "system(",
    "exec(",
    "eval(",
    "__import__(",
];

/// Whether `code` reaches files, the network, the environment or other
/// programs with text it builds at run time.
pub(super) fn opaque(code: &str) -> bool {
    APIS.iter().any(|api| has(code, api)) && builds_text(code)
}

/// Whether `code` builds text at run time: joins strings, interpolates into
/// them, decodes them, or hands a call that takes a name something other
/// than literal text.
fn builds_text(code: &str) -> bool {
    BUILDERS.iter().any(|b| has(code, b))
        || strings(code).iter().any(|s| s.interpolates || s.joined)
        || TAKE_A_NAME
            .iter()
            .any(|call| starts(code, call).any(|at| !literal_argument(&code[at + call.len()..])))
        || perl_open_takes_a_variable(code)
}

/// The byte offsets where `token` starts in `code`; at the start of a word
/// when it starts with a letter (`fs.` is not in `dfs.`).
fn starts<'a>(code: &'a str, token: &'a str) -> impl Iterator<Item = usize> + 'a {
    let word = token.starts_with(|c: char| c.is_ascii_alphanumeric());
    code.match_indices(token)
        .map(|(at, _)| at)
        .filter(move |&at| {
            !word
                || !code[..at]
                    .chars()
                    .next_back()
                    .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
        })
}

fn has(code: &str, token: &str) -> bool {
    starts(code, token).next().is_some()
}

/// Whether the arguments `rest` (after a call's `(`) start with literal
/// text: a string, possibly in a list or tuple, or nothing.
fn literal_argument(rest: &str) -> bool {
    let rest = rest.trim_start_matches(|c: char| c.is_whitespace() || c == '(' || c == '[');
    let rest = rest.trim_start_matches(['r', 'b', 'u', 'R', 'B', 'U']);
    rest.is_empty() || rest.starts_with(['\'', '"', ')', ']'])
}

/// Perl's `open F, $path` or `open(my $f, '<', $path)`: the last argument of
/// the statement is not literal text.
fn perl_open_takes_a_variable(code: &str) -> bool {
    starts(code, "open").any(|at| {
        let statement = code[at..].split(';').next().unwrap_or_default();
        statement
            .rsplit(',')
            .next()
            .filter(|_| statement.contains(','))
            .is_some_and(|last| !literal_argument(last.trim_end_matches([')', ' '])))
    })
}

/// A string literal of the code, as the scan sees it.
#[derive(Debug, Default)]
struct Literal {
    /// It interpolates code or variables into itself (`f"{x}"`, `` `${x}` ``,
    /// `"$ENV{HOME}"`, `"#{x}"`).
    interpolates: bool,
    /// It is joined to other text (`"a" + b`, `"a" . $b`, `"a" "b"`, `"a" .. b`).
    joined: bool,
}

/// The string literals of `code`, with backslash escapes and Python's triple
/// quotes read; an unterminated one ends the code.
fn strings(code: &str) -> Vec<Literal> {
    let bytes = code.as_bytes();
    let mut found: Vec<Literal> = Vec::new();
    let mut last_end: Option<usize> = None;
    let mut i = 0;
    while i < bytes.len() {
        let quote = bytes[i];
        if !matches!(quote, b'\'' | b'"' | b'`') {
            i += 1;
            continue;
        }
        let triple = bytes.get(i..i + 3) == Some(&[quote; 3][..]);
        let open = if triple { 3 } else { 1 };
        let start = i;
        let closes = |at: usize| {
            bytes.get(at) == Some(&quote)
                && (!triple || bytes.get(at..at + 3) == Some(&[quote; 3][..]))
        };
        let mut j = i + open;
        // (where the body ends, where the literal ends)
        let (body_end, end) = loop {
            match bytes.get(j) {
                None => break (bytes.len(), bytes.len()),
                Some(b'\\') => j += 2,
                Some(_) if closes(j) => break (j, j + open),
                Some(_) => j += 1,
            }
        };
        let body = code.get(start + open..body_end).unwrap_or_default();
        let end = end.min(code.len());
        let prefix = code[..start]
            .chars()
            .rev()
            .take_while(char::is_ascii_alphabetic)
            .collect::<String>();
        let before = code[..start].trim_end();
        let after = code[end.min(code.len())..].trim_start();
        let follows_string = last_end.is_some_and(|e| code[e..start].trim().is_empty());
        let literal = Literal {
            interpolates: interpolates(quote, &prefix, body),
            joined: follows_string
                || joins(before.chars().next_back(), true, before)
                || joins(after.chars().next(), false, after),
        };
        if follows_string && let Some(previous) = found.last_mut() {
            previous.joined = true;
        }
        found.push(literal);
        last_end = Some(end.min(code.len()));
        i = end.max(i + 1);
    }
    found
}

/// Whether a string opened with `quote`, after the letters `prefix`, with
/// `body`, interpolates.
fn interpolates(quote: u8, prefix: &str, body: &str) -> bool {
    let f_string = prefix.len() <= 2 && prefix.contains(['f', 'F']) && body.contains('{');
    let template = quote == b'`' && body.contains("${");
    let double = quote == b'"'
        && (body.contains("#{")
            || body.contains("${")
            || body.match_indices('$').any(|(at, _)| {
                body[at + 1..]
                    .starts_with(|c: char| c.is_ascii_alphabetic() || c == '_' || c == '{')
            }));
    f_string || template || double
}

/// Whether the character `next` beside a string (`before` it when `left`,
/// with `side` the text on that side) joins it to other text: `+`, `%`
/// formatting, or Perl's and PHP's `.` and Lua's `..` between strings.
fn joins(next: Option<char>, left: bool, side: &str) -> bool {
    match next {
        Some('+') => true,
        Some('%') => !left,
        Some('.') => {
            if left {
                // `$x . "a"`, `} . "a"`, `"a" . "b"`; not `obj."a"`, which no language writes
                true
            } else {
                let rest = side[1..].trim_start_matches('.').trim_start();
                rest.starts_with(['\'', '"', '$', '@'])
            }
        }
        _ => false,
    }
}
