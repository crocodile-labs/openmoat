//! An unquoted variable's value is split into words; inline code's reads of
//! the environment are named.

use super::*;

fn reads_env(atoms: &[AtomicAction], name: &str) -> bool {
    atoms.contains(&AtomicAction::EnvRead {
        name: name.to_owned(),
    })
}

#[test]
fn unquoted_value_is_split_into_words() {
    let atoms = parsed("x='.env leftover'; cat $x");
    assert!(has_shell(&atoms, "cat .env leftover"));
    assert!(has_read(&atoms, "/p/.env"));
    assert!(has_read(&atoms, "/p/leftover"));
    assert!(!has_read(&atoms, "/p/.env leftover"));
    let atoms = parsed("s=' '; cat${s}/etc/hosts");
    assert!(has_shell(&atoms, "cat /etc/hosts"));
}

#[test]
fn quoted_value_stays_one_word() {
    let atoms = parsed("x='a b'; cat \"$x\"");
    assert!(has_read(&atoms, "/p/a b"));
    assert!(!has_read(&atoms, "/p/a"));
}

#[test]
fn empty_unquoted_value_is_no_word() {
    assert!(has_shell(&parsed("x=; $x env"), "env"));
}

#[test]
fn assigned_ifs_splits_as_well() {
    let atoms = parsed("IFS=/; x=cat/.env; $x");
    assert!(has_read(&atoms, "/p/.env"));
}

#[test]
fn ifs_of_unknown_value_is_unparseable() {
    assert!(matches!(
        classify("read IFS; x='a b'; cat $x", &ctx()),
        ParseOutcome::Unparseable { .. }
    ));
}

#[test]
fn inline_code_names_the_variables_it_reads() {
    let atoms = parsed("python3 -c \"import os;print(os.environ['OPENAI_API_KEY'])\"");
    assert!(reads_env(&atoms, "OPENAI_API_KEY"));
    assert!(reads_env(
        &parsed("node -e 'f(process.env.NPM_TOKEN)'"),
        "NPM_TOKEN"
    ));
    assert!(reads_env(
        &parsed("php -r \"echo getenv('DB_PASS');\""),
        "DB_PASS"
    ));
    assert!(reads_env(
        &parsed("perl -e 'print $ENV{API_KEY}'"),
        "API_KEY"
    ));
    assert!(reads_env(&parsed("pwsh -c 'echo $env:API_KEY'"), "API_KEY"));
}

#[test]
fn indirect_reads_name_the_variable() {
    for (code, name) in [
        (
            "python3 -c \"import os;print(getattr(os,'environ')['API_KEY'])\"",
            "API_KEY",
        ),
        (
            "python3 -c \"import subprocess;subprocess.run(['printenv','GH_TOKEN'])\"",
            "GH_TOKEN",
        ),
        (
            "python3 -c \"import os;os.popen('printenv GH_TOKEN')\"",
            "GH_TOKEN",
        ),
        ("pwsh -c 'echo $Env:API_KEY'", "API_KEY"),
        ("pwsh -c 'echo ${env:API_KEY}'", "API_KEY"),
        (
            "pwsh -c \"[Environment]::GetEnvironmentVariable('API_KEY')\"",
            "API_KEY",
        ),
        (
            "pwsh -c \"[System.Environment]::GetEnvironmentVariable('API_KEY', 'User')\"",
            "API_KEY",
        ),
        ("pwsh -c 'Get-ChildItem Env:API_KEY'", "API_KEY"),
        ("pwsh -c 'gc env:\\API_KEY'", "API_KEY"),
        ("pwsh -c \"Get-Item -Path 'Env:API_KEY'\"", "API_KEY"),
    ] {
        let atoms = parsed(code);
        assert!(reads_env(&atoms, name), "{code}: {atoms:?}");
        assert!(
            !atoms
                .iter()
                .any(|a| matches!(a, AtomicAction::Shell { argv } if argv[0] == "@env-dump")),
            "{code}"
        );
    }
}

#[test]
fn inline_code_reading_every_variable_is_an_env_dump() {
    for (code, expression) in [
        ("python3 -c \"import os;print(os.environ)\"", "environ"),
        ("python3 -c 'import os;print(os.environ[k])'", "environ"),
        ("node -e 'console.log(process.env)'", "process.env"),
        ("node -p process.env", "process.env"),
        ("ruby -e 'p ENV'", "ENV"),
        ("perl -e 'print for %ENV'", "%ENV"),
        (
            "python3 -c \"import os;print(getattr(os,'environ'))\"",
            "getattr(os,'environ')",
        ),
        ("python3 -c 'import os;print(vars(os))'", "vars(os)"),
        ("python3 -c 'import os;print(os.__dict__)'", "os.__dict__"),
        (
            "python3 -c \"import os;print(os.popen('env').read())\"",
            "env",
        ),
        (
            "python3 -c \"import subprocess;subprocess.run(['env'])\"",
            "env",
        ),
        (
            "python3 -c \"import subprocess;subprocess.run('env | sort', shell=True)\"",
            "env",
        ),
        (
            "python3 -c \"import os;os.system('/usr/bin/printenv')\"",
            "printenv",
        ),
        (
            "pwsh -c '[System.Environment]::GetEnvironmentVariables()'",
            "[Environment]::GetEnvironmentVariables()",
        ),
        ("pwsh -c 'Get-ChildItem Env:'", "Env:"),
        ("pwsh -c 'gci env:'", "Env:"),
        ("pwsh -c 'ls env:'", "Env:"),
        ("pwsh -c 'dir Env:\\'", "Env:"),
        ("pwsh -c 'Get-ChildItem -Path Env:*'", "Env:"),
    ] {
        let atoms = parsed(code);
        assert!(
            has_shell(&atoms, &format!("@env-dump {expression}")),
            "{code}"
        );
    }
}

#[test]
fn inline_code_that_hands_the_environment_on_is_no_dump() {
    for code in [
        "python3 -c \"import os,subprocess;subprocess.run(['ls'],env=dict(os.environ))\"",
        "python3 -c \"import os;os.environ['A']='1'\"",
        "python3 -c \"import os;print(os.getcwd())\"",
        "node -e 'console.log(process.argv)'",
        "python3 -c 'print(environment)'",
        "python3 -c \"import os;print(getattr(os,'name'))\"",
        "python3 -c \"import subprocess;subprocess.run(['env','A=1','make'])\"",
        "python3 -c \"import os;os.system('envsubst < a > b')\"",
        "python3 -c \"import asyncio;asyncio.run(main())\"",
        "pwsh -c 'Get-ChildItem .'",
        "pwsh -c 'Set-Location env:'",
        "pwsh -c 'echo \"env: dev\"'",
    ] {
        let atoms = parsed(code);
        assert!(
            !atoms
                .iter()
                .any(|a| matches!(a, AtomicAction::Shell { argv } if argv[0] == "@env-dump")),
            "{code}"
        );
    }
}
