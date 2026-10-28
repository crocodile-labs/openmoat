use super::executed;
use crate::shell::ShellContext;

fn files(command: &str) -> Vec<String> {
    let cwd = [Some("/p".to_owned())];
    let ctx = ShellContext {
        home: "/h",
        cwd: &cwd,
    };
    executed(command, &ctx)
        .into_iter()
        .map(|(path, _)| path)
        .collect()
}

fn runs(command: &str, path: &str) -> bool {
    files(command).iter().any(|f| f == path)
}

#[test]
fn every_interpreter_form_names_its_script() {
    for (cmd, path) in [
        ("python x.py", "/p/x.py"),
        ("python3 x.py", "/p/x.py"),
        ("python3 -u x.py", "/p/x.py"),
        ("python3 -uB x.py arg", "/p/x.py"),
        ("python3 -W ignore x.py", "/p/x.py"),
        ("python3 -Werror x.py", "/p/x.py"),
        ("python3 -X dev x.py", "/p/x.py"),
        ("python3.12 x.py", "/p/x.py"),
        ("python3 -- x.py", "/p/x.py"),
        ("node x.js", "/p/x.js"),
        ("node x.mjs", "/p/x.mjs"),
        ("node --env-file .env x.js", "/p/x.js"),
        ("node --enable-source-maps x.js", "/p/x.js"),
        ("node -r ./setup.js x.js", "/p/setup.js"),
        ("node -r ./setup.js x.js", "/p/x.js"),
        ("node --import=./hook.mjs x.js", "/p/hook.mjs"),
        ("node x", "/p/x.js"),
        ("deno run x.ts", "/p/x.ts"),
        ("deno run --allow-net -c deno.json x.ts", "/p/x.ts"),
        ("deno x.ts", "/p/x.ts"),
        ("bun x.ts", "/p/x.ts"),
        ("bun run x.ts", "/p/x.ts"),
        ("bun run --cwd sub ./x.js", "/p/x.js"),
        ("ruby x.rb", "/p/x.rb"),
        ("ruby -I lib x.rb", "/p/x.rb"),
        ("ruby -r ./pre.rb x.rb", "/p/pre.rb"),
        ("perl x.pl", "/p/x.pl"),
        ("perl -Ilib -w x.pl", "/p/x.pl"),
        ("perl -I lib x.pl", "/p/x.pl"),
        ("php x.php", "/p/x.php"),
        ("php -d display_errors=1 x.php", "/p/x.php"),
        ("php -f x.php", "/p/x.php"),
        ("bash x.sh", "/p/x.sh"),
        ("sh x.sh", "/p/x.sh"),
        ("zsh x.sh", "/p/x.sh"),
        ("dash x.sh", "/p/x.sh"),
        ("fish x.fish", "/p/x.fish"),
        ("bash -e x.sh", "/p/x.sh"),
        ("source x.sh", "/p/x.sh"),
        (". ./x.sh", "/p/x.sh"),
        ("sh < x.sh", "/p/x.sh"),
        ("python3 < x.py", "/p/x.py"),
        ("go run x.go", "/p/x.go"),
        ("go run -tags dev x.go y.go", "/p/y.go"),
        ("pwsh -File x.ps1", "/p/x.ps1"),
        ("pwsh -NoProfile -file x.ps1", "/p/x.ps1"),
        ("pwsh x.ps1", "/p/x.ps1"),
        ("npx tsx x.ts", "/p/x.ts"),
        ("npx tsx watch x.ts", "/p/x.ts"),
        ("npx ts-node x.ts", "/p/x.ts"),
        ("lua x.lua", "/p/x.lua"),
        ("Rscript x.R", "/p/x.R"),
        ("uv run x.py", "/p/x.py"),
        ("python -m tool", "/p/tool.py"),
        ("python -m pkg.tool", "/p/pkg/tool/__main__.py"),
    ] {
        assert!(runs(cmd, path), "{cmd}: {:?}", files(cmd));
    }
}

#[test]
fn a_program_named_by_a_path_is_run() {
    for (cmd, path) in [
        ("./x", "/p/x"),
        ("bin/x --flag", "/p/bin/x"),
        ("/p/bin/x", "/p/bin/x"),
        ("~/bin/x", "/h/bin/x"),
        ("sub/../x", "/p/x"),
    ] {
        assert!(runs(cmd, path), "{cmd}: {:?}", files(cmd));
    }
}

#[test]
fn wrappers_and_nested_shells_are_unwrapped() {
    for cmd in [
        "env python3 x.py",
        "env A=1 python3 x.py",
        "time python3 x.py",
        "nice -n 5 python3 x.py",
        "timeout 10 python3 x.py",
        "sudo python3 x.py",
        "bash -c 'python3 x.py'",
        "sh -c \"python3 x.py\"",
        "echo $(python3 x.py)",
        "true && python3 x.py",
        "f=x.py; python3 $f",
    ] {
        assert!(runs(cmd, "/p/x.py"), "{cmd}: {:?}", files(cmd));
    }
}

#[test]
fn a_cd_moves_where_the_file_is() {
    assert!(runs("cd sub && python3 x.py", "/p/sub/x.py"));
    assert!(runs("(cd /tmp; ./x)", "/tmp/x"));
}

#[test]
fn modes_that_run_no_file_name_none() {
    for cmd in [
        "python -m pytest",
        "python3 -c 'print(1)'",
        "python3 -V",
        "python3",
        "node --version",
        "node -e 'console.log(1)'",
        "node -p 1",
        "node --check x.js",
        "bash -c 'echo hi'",
        "ruby -e 'puts 1' x.rb",
        "perl -e 'print 1' x.pl",
        "perl -pi -e 's/a/b/' x.txt",
        "php -r 'echo 1;' x.php",
        "php -l x.php",
        "pwsh -Command Get-Date",
        "go run .",
        "go run ./cmd/tool",
        "go build ./...",
        "bun run build",
        "bun install",
        "deno fmt x.ts",
        "deno test x_test.ts",
        "pytest tests/test_x.py",
        "npm test",
        "cargo test",
        "make",
        "cat x.py",
        "grep -n main x.py",
        "python3 $UNKNOWN",
    ] {
        let found: Vec<String> = files(cmd)
            .into_iter()
            .filter(|f| !f.ends_with("/pytest.py") && !f.ends_with("/pytest/__main__.py"))
            .collect();
        assert!(found.is_empty(), "{cmd}: {found:?}");
    }
}

#[test]
fn python_m_names_only_a_module_of_the_working_directory() {
    assert_eq!(
        files("python -m pytest -q"),
        ["/p/pytest.py", "/p/pytest/__main__.py"]
    );
}

#[test]
fn a_glob_operand_is_marked_for_expansion() {
    let cwd = [Some("/p".to_owned())];
    let ctx = ShellContext {
        home: "/h",
        cwd: &cwd,
    };
    assert_eq!(executed("bash *.sh", &ctx), [("/p/*.sh".to_owned(), true)]);
    assert_eq!(
        executed("bash '*.sh'", &ctx),
        [("/p/*.sh".to_owned(), false)]
    );
}

#[test]
fn inline_code_that_loads_a_file_of_the_working_directory_runs_it() {
    for (cmd, path) in [
        ("python3 -c 'import tool'", "/p/tool.py"),
        ("python3 -c 'import os, tool as t; t.main()'", "/p/tool.py"),
        (
            "python3 -c 'from pkg.tool import main; main()'",
            "/p/pkg/tool.py",
        ),
        ("python3 -c '__import__(\"tool\")'", "/p/tool.py"),
        ("python3 -c 'exec(open(\"tool.py\").read())'", "/p/tool.py"),
        ("python3 - <<'EOF'\nimport tool\nEOF", "/p/tool.py"),
        ("node -e \"require('./tool')\"", "/p/tool.js"),
        ("node -e \"import('./tool.mjs')\"", "/p/tool.mjs"),
        ("ruby -e \"require_relative 'tool'\"", "/p/tool.rb"),
        ("perl -e 'do \"./tool.pl\"'", "/p/tool.pl"),
    ] {
        assert!(runs(cmd, path), "{cmd}: {:?}", files(cmd));
    }
    // a package import or a module of the standard library names only the
    // working directory's file of that name
    assert_eq!(files("node -e \"require('lodash')\""), Vec::<String>::new());
}

#[test]
fn a_file_inline_code_only_writes_is_not_one_it_runs() {
    for cmd in [
        r#"python3 -c 'open("x.py","w").write("print(1)")'"#,
        r#"python3 -c 'from pathlib import Path; Path("x.py").write_text("1")'"#,
        r#"python3 -c 'from pathlib import Path; Path("x.py").open("w").write("1")'"#,
        r#"node -e "require('fs').writeFileSync('x.py','1')""#,
        r#"deno eval 'await Deno.writeFile("x.py", d)'"#,
        r#"perl -e 'open(my $f, ">", "x.py"); print $f 1'"#,
    ] {
        assert!(!runs(cmd, "/p/x.py"), "{cmd}: {:?}", files(cmd));
    }
}

#[test]
fn code_that_writes_still_runs_the_files_it_loads() {
    // writing one file does not hide another the code runs, nor the same
    // file shown again where it is run
    for (cmd, path) in [
        (
            r#"python3 -c 'open("log.txt","w").write("x"); import runpy; runpy.run_path("tool.py")'"#,
            "/p/tool.py",
        ),
        (
            r#"python3 -c 'open("x.py","w").write("1"); import runpy; runpy.run_path("x.py")'"#,
            "/p/x.py",
        ),
        (
            r#"python3 -c 'open("log.txt","w").write("x"); import tool'"#,
            "/p/tool.py",
        ),
        (
            r#"node -e "require('fs').writeFileSync('log.txt','x'); require('./tool.js')""#,
            "/p/tool.js",
        ),
        (
            r#"ruby -e 'File.write("log.txt", "x"); load "tool.rb"'"#,
            "/p/tool.rb",
        ),
    ] {
        assert!(runs(cmd, path), "{cmd}: {:?}", files(cmd));
    }
}
