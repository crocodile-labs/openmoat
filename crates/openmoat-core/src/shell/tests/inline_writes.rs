//! Inline code that writes files writes every file name it shows
//! (`commands/payload/writes.rs`); code that only reads keeps its reads.

use super::{has_read, has_write, parsed};

#[test]
fn code_that_writes_writes_the_files_it_names() {
    for (cmd, path) in [
        (
            r#"python3 -c 'open("/Users/me/.zshrc","a").write("x")'"#,
            "/Users/me/.zshrc",
        ),
        (
            r#"python3 -c 'open("x.py","w").write("print(1)")'"#,
            "/p/x.py",
        ),
        (
            r#"python3 -c 'open("x.py", mode="wb").write(b"")'"#,
            "/p/x.py",
        ),
        (r#"python3 -c 'open("x.py","r+").write("")'"#, "/p/x.py"),
        (
            r#"python3 -c 'import pathlib; pathlib.Path("x.py").write_text("1")'"#,
            "/p/x.py",
        ),
        (
            r#"python3 -c 'import shutil; shutil.copy("a.py", "/Users/me/.bashrc")'"#,
            "/Users/me/.bashrc",
        ),
        (
            r#"python3 -c 'import os; os.replace("a", "x.sh")'"#,
            "/p/x.sh",
        ),
        (
            r#"python3 -c 'from pathlib import Path; Path("x.sh").touch()'"#,
            "/p/x.sh",
        ),
        (
            r#"node -e "require('fs').writeFileSync('/Users/me/.zshrc','x')""#,
            "/Users/me/.zshrc",
        ),
        (
            r#"node -e "require('fs').appendFileSync('x.js','x')""#,
            "/p/x.js",
        ),
        (
            r#"node -e "require('fs').createWriteStream('x.js')""#,
            "/p/x.js",
        ),
        (
            r#"node -e "require('fs').promises.writeFile('x.js','x')""#,
            "/p/x.js",
        ),
        (
            r#"ruby -e 'File.write("/Users/me/.zshrc", "x")'"#,
            "/Users/me/.zshrc",
        ),
        (
            r#"ruby -e 'File.open("x.rb", "a") { |f| f.puts 1 }'"#,
            "/p/x.rb",
        ),
        (
            r#"perl -e 'open F, ">>/Users/me/.zshrc"; print F "x"'"#,
            "/Users/me/.zshrc",
        ),
        (
            r#"perl -e 'open(my $f, ">", "x.pl"); print $f 1'"#,
            "/p/x.pl",
        ),
        (
            r#"php -r 'file_put_contents("/Users/me/.zshrc", "x");'"#,
            "/Users/me/.zshrc",
        ),
        (r#"php -r '$f = fopen("x.php", "w");'"#, "/p/x.php"),
        (
            r#"deno eval 'await Deno.writeTextFile("x.ts", "1")'"#,
            "/p/x.ts",
        ),
        (r#"lua -e 'io.open("x.lua", "w"):write("1")'"#, "/p/x.lua"),
        (
            "python3 - <<'EOF'\nopen('x.py', 'w').write('1')\nEOF",
            "/p/x.py",
        ),
        // the file name in a variable, the mode the only literal of the call
        (
            r#"python3 -c 'p="/Users/me/.zshrc"; open(p,"a").write("x")'"#,
            "/Users/me/.zshrc",
        ),
        (
            r#"python3 -c 'from pathlib import Path; Path("/Users/me/.zshrc").open("a").write("x")'"#,
            "/Users/me/.zshrc",
        ),
        (
            r#"python3 -c 'import os; os.open("/Users/me/.zshrc", os.O_WRONLY|os.O_APPEND)'"#,
            "/Users/me/.zshrc",
        ),
        (
            r#"node -e "require('fs').openSync('/Users/me/.zshrc','a')""#,
            "/Users/me/.zshrc",
        ),
        (
            r#"ruby -e 'File.new("/Users/me/.zshrc", "w").puts 1'"#,
            "/Users/me/.zshrc",
        ),
        (
            r#"ruby -e 'File.binwrite("/Users/me/.zshrc", "x")'"#,
            "/Users/me/.zshrc",
        ),
    ] {
        let atoms = parsed(cmd);
        assert!(has_write(&atoms, path), "{cmd}: {atoms:?}");
    }
}

#[test]
fn code_that_writes_also_writes_what_it_reads_by_name() {
    // which name the write goes to is not known: both count
    let atoms = parsed(r#"python3 -c 'd=open("/p/a.txt").read(); open("/p/b.txt","w").write(d)'"#);
    assert!(
        has_write(&atoms, "/p/a.txt") && has_write(&atoms, "/p/b.txt"),
        "{atoms:?}"
    );
    assert!(has_read(&atoms, "/p/a.txt"), "{atoms:?}");
}

#[test]
fn code_that_only_reads_writes_nothing() {
    for cmd in [
        r#"python3 -c 'print(open("README.md").read())'"#,
        r#"python3 -c 'import json;json.load(open("package.json"))'"#,
        r#"python3 -c 'print(open("/p/a.txt", "r").read())'"#,
        r#"python3 -c 'import sys; sys.stdout.write("x.py")'"#,
        r#"node -e "console.log(require('fs').readFileSync('./a.txt','utf8'))""#,
        r#"ruby -e 'puts File.read("Gemfile")'"#,
        r#"perl -e 'open F, "<", "x.pl"; print <F>'"#,
        r#"python3 -c 'print("x" + "y")'"#,
        r#"python3 -c 'import os; os.read(os.open("README.md", os.O_RDONLY), 9)'"#,
        r#"python3 -c 'from pathlib import Path; print(Path("README.md").open().read())'"#,
        r#"node -e "require('fs').openSync('README.md','r')""#,
    ] {
        let atoms = parsed(cmd);
        assert!(
            !atoms
                .iter()
                .any(|a| matches!(a, crate::action::AtomicAction::FsWrite { .. })),
            "{cmd}: {atoms:?}"
        );
    }
}

#[test]
fn code_that_writes_a_script_and_runs_it_asks() {
    // `exec` of what it reads back is code the scan cannot read
    let atoms = parsed(r#"python3 -c 'open("x.py","w").write("1"); exec(open("x.py").read())'"#);
    assert!(
        atoms.iter().any(|a| matches!(
            a,
            crate::action::AtomicAction::Shell { argv } if argv.first().is_some_and(|w| w == "@opaque-code")
        )),
        "{atoms:?}"
    );
}
