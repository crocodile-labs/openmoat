//! The files inline code loads as code (`python3 -c 'import tool'`, `node -e
//! "require('./tool')"`, `ruby -e "require_relative 'tool'"`): a module of the
//! working directory it imports, and a program file it names. Without this, a
//! session that wrote `tool.py` could run it as `python3 -c 'import tool'`.
//! The code is scanned, not parsed, like the rest of a payload: an import built
//! at run time is the payload's own concern (`commands/payload/opaque.rs`).

use super::interpreters::file_like;

/// The words of `code`, which `program` runs, that name a file it may load as
/// code, relative to the working directory or absolute. `written`: the names
/// the code shows where it writes them (`commands/payload/writes.rs`), once
/// per place; a name shown only there is not one it runs, a name it also
/// shows elsewhere (`runpy.run_path("x.py")`) still is.
pub(super) fn loads(program: &str, code: &str, written: &[String]) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    // a program file the code names (`exec(open('tool.py').read())`, `require('./x.js')`)
    let words = code
        .split(|c: char| {
            c.is_whitespace() || matches!(c, '(' | ')' | ',' | ';' | '\'' | '"' | '`' | '[' | ']')
        })
        .collect::<Vec<_>>();
    for &word in &words {
        // a name the code shows only where it writes it is written, not run
        let shown = words.iter().filter(|&&w| w == word).count();
        let as_written = written.iter().filter(|&w| w == word).count();
        if shown > as_written
            && file_like(word)
            && word.rsplit_once('.').is_some_and(|(_, e)| !e.is_empty())
        {
            found.push(word.to_owned());
        }
    }
    let family = program.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    match family {
        "python" | "pypy" => python_modules(code, &mut found),
        "node" | "nodejs" | "deno" | "bun" => node_modules(code, &mut found),
        "ruby" => ruby_files(code, &mut found),
        _ => {}
    }
    found.sort();
    found.dedup();
    found
}

/// `import a.b, c as d`, `from a.b import x`, `__import__('a')`,
/// `importlib.import_module('a')`: `a/b.py`, `a/b/__init__.py` and so on.
fn python_modules(code: &str, found: &mut Vec<String>) {
    let mut modules: Vec<&str> = Vec::new();
    for statement in code.split([';', '\n']) {
        let statement = statement.trim();
        if let Some(names) = statement.strip_prefix("import ") {
            modules.extend(names.split(',').filter_map(|n| n.split_whitespace().next()));
        } else if let Some(rest) = statement.strip_prefix("from ") {
            modules.extend(rest.split_whitespace().next());
        }
    }
    for call in ["__import__(", "import_module("] {
        modules.extend(
            code.match_indices(call)
                .filter_map(|(at, _)| quoted(code[at + call.len()..].trim_start())),
        );
    }
    for module in modules {
        let module = module.trim_start_matches('.');
        if module.is_empty()
            || !module
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
        {
            continue;
        }
        let path = module.replace('.', "/");
        found.push(format!("{path}.py"));
        found.push(format!("{path}/__init__.py"));
    }
}

/// `require('./x')`, `import('./x')`, `from './x'`: a relative or absolute
/// module, as Node resolves it (`x`, `x.js`, `x.mjs`, `x.cjs`, `x/index.js`).
fn node_modules(code: &str, found: &mut Vec<String>) {
    for call in ["require(", "import(", "from "] {
        for (at, _) in code.match_indices(call) {
            let Some(module) = quoted(code[at + call.len()..].trim_start()) else {
                continue;
            };
            if !module.starts_with(['.', '/']) {
                continue;
            }
            found.push(module.to_owned());
            for ext in [".js", ".mjs", ".cjs", ".ts", "/index.js"] {
                found.push(format!("{module}{ext}"));
            }
        }
    }
}

/// `require_relative 'x'`, `require './x'`, `load 'x.rb'`: `x` and `x.rb`.
fn ruby_files(code: &str, found: &mut Vec<String>) {
    for call in ["require_relative", "require", "load"] {
        for (at, _) in code.match_indices(call) {
            let rest = code[at + call.len()..].trim_start_matches(['(', ' ']);
            let Some(file) = quoted(rest) else {
                continue;
            };
            if call == "require" && !file.starts_with(['.', '/']) {
                continue;
            }
            found.push(file.to_owned());
            found.push(format!("{file}.rb"));
        }
    }
}

/// The text of the string literal `text` starts with, if it starts with one.
fn quoted(text: &str) -> Option<&str> {
    let quote = text
        .chars()
        .next()
        .filter(|c| matches!(c, '\'' | '"' | '`'))?;
    let body = &text[1..];
    body.find(quote).map(|end| &body[..end])
}
