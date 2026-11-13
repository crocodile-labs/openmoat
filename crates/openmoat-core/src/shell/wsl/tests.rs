use super::*;

fn line(program: &str, args: &[&str]) -> runner::Found {
    let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
    runner::scan(program, &args)
}

#[test]
fn wsl_launchers_in_the_spellings_windows_opens() {
    for word in [
        "wsl",
        "wsl.exe",
        "WSL.EXE",
        "Wsl",
        r"C:\Windows\System32\wsl.exe",
        r"c:\windows\SYSTEM32\WSL.exe",
        "/c/Windows/System32/wsl.exe",
        "C:/Windows/Sysnative/wsl.exe",
        r"%SystemRoot%\System32\wsl.exe",
        "$WINDIR/System32/wsl.exe",
        r"\\?\C:\Windows\System32\wsl.exe",
        // Win32 drops trailing dots and spaces, and reads a stream's data
        "wsl.exe.",
        "wsl.exe. .",
        "wsl.",
        "wsl.exe::$DATA",
        r"C:\Windows\System32\wsl.exe:$DATA",
        "wslg.exe",
        "wslconfig",
        "WSLCON~1.EXE",
        r"C:\Windows\System32\bash.exe",
        "/c/WINDOWS/system32/BASH.EXE",
        "C:/Windows/Sysnative/bash",
        r"C:\Windows\System32\.\bash.exe",
        r"C:\Windows\System32\\bash.exe",
        "C:/Windows/System32/x/../bash.exe.",
        r"C:\Windows\WinSxS\amd64_microsoft-windows-lxss-bash_31bf3856ad364e35_10.0.19041.1_none_x\bash.exe",
        "ubuntu",
        "ubuntu2204.exe",
        "UBUNTU~1.EXE",
        r"C:\Users\me\AppData\Local\Microsoft\WindowsApps\ubuntu2404.exe",
        "debian.exe",
        "kali",
        "opensuse-leap-15.6.exe",
        "oraclelinux_9_1.exe",
    ] {
        assert!(launcher(word).is_some(), "{word}");
    }
}

#[test]
fn other_programs_are_not_wsl_launchers() {
    for word in [
        "bash",
        "bash.exe",
        "/usr/bin/bash",
        r"C:\Program Files\Git\bin\bash.exe",
        "/c/Program Files/Git/usr/bin/bash.exe",
        "C:/Windows/System32/x/bash.exe",
        "ubuntu-drivers",
        "ubuntu-advantage",
        "wslpath",
        "wsl2",
        "wslconfig-helper",
        "wslcon~",
        "debianize",
        "opensuse-",
        "cat",
        "",
    ] {
        assert_eq!(launcher(word), None, "{word}");
    }
}

#[test]
fn the_wsl_share_in_the_spellings_windows_opens() {
    for word in [
        r"\\wsl$\Ubuntu\home\me\.ssh\id_rsa",
        r"\\WSL$\Ubuntu",
        r"\\wsl$",
        r"\\wsl$.\Ubuntu",
        "//wsl$/Ubuntu/etc/passwd",
        r"\\wsl.localhost\Ubuntu\home\me",
        "//WSL.LOCALHOST/Ubuntu",
        r"\\?\UNC\wsl$\Ubuntu\home",
        r"\\.\UNC\wsl.localhost\Ubuntu",
        "//?/unc/WSL$/Ubuntu",
        r"\\?\GLOBALROOT\Device\Mup\wsl$\Ubuntu\home",
        r"\\server\wsl$",
        "file://wsl$/Ubuntu/home/me/.ssh/id_rsa",
        "FILE:////wsl.localhost/Ubuntu/x",
        r"--target-directory=\\wsl$\Ubuntu\tmp",
    ] {
        assert!(names_share(word), "{word}");
    }
}

#[test]
fn other_servers_and_words_are_not_the_share() {
    for word in [
        r"\\wsl$x\share",
        r"\\wslserver\share",
        "//wsl.localhostile/x",
        "wsl$",
        "/home/me/wsl.localhost",
        "/wsl$/x",
        "C:/wsl/x",
        "file:wsl$",
    ] {
        assert!(!names_share(word), "{word}");
    }
}

#[test]
fn a_runner_line_runs_the_program_of_each_segment() {
    let found = line("cmd", &["/c", "wsl cat x & bash -c id"]);
    assert_eq!(found.launchers, ["wsl", "bash"]);
    let found = line(
        "powershell.exe",
        &["-NoProfile", "-c", r"& 'C:\Windows\System32\wsl.exe' cat x"],
    );
    assert_eq!(found.launchers, ["wsl"]);
    let found = line("pwsh", &["-c", "Get-Date; . wsl id"]);
    assert_eq!(found.launchers, ["wsl"]);
    let found = line("cmd", &["/c", "call", "bash", "-c", "id"]);
    assert_eq!(found.launchers, ["bash"]);
    // a shell inside a shell's line
    let found = line("cmd", &["/c", "powershell -c wsl id"]);
    assert_eq!(found.launchers, ["wsl"]);
}

#[test]
fn only_the_program_word_of_a_shell_segment_counts() {
    for (program, args) in [
        ("cmd", &["/c", "docker", "run", "ubuntu"][..]),
        ("pwsh", &["-c", "docker pull debian"]),
        ("powershell", &["-c", "Write-Output kali; git log HEAD^"]),
        ("cmd", &["/c", "docker run -e X=1 ubuntu"]),
    ] {
        assert_eq!(
            line(program, args),
            runner::Found::default(),
            "{program} {args:?}"
        );
    }
}

#[test]
fn launching_programs_read_every_word() {
    for (program, args) in [
        ("start", &["", "wsl", "cat", "x"][..]),
        ("Start-Process", &["-FilePath", "WSL.EXE"]),
        ("cmd", &["/c", "start", "/b", "bash"]),
        ("pwsh", &["-c", "Start-Process wsl -ArgumentList id"]),
        ("pwsh", &["-c", "saps ubuntu2204"]),
        ("runas", &["/user:me", "wsl id"]),
        ("conhost", &["wsl.exe"]),
    ] {
        assert!(
            !line(program, args).launchers.is_empty(),
            "{program} {args:?}"
        );
    }
    assert!(line("explorer.exe", &[r"\\wsl$\Ubuntu"]).share);
    assert!(line("cmd", &["/c", r"type \\wsl.localhost\Ubuntu\etc\shadow"]).share);
}

#[test]
fn lines_built_at_run_time_are_opaque() {
    for (program, args) in [
        ("cmd", &["/c", "w^sl", "id"][..]),
        ("cmd", &["/c", "%w%", "id"]),
        ("cmd", &["/v:on", "/c", "set w=wsl&& !w! id"]),
        ("powershell", &["-c", "& ('ws'+'l') id"]),
        ("pwsh", &["-c", "& $w id"]),
        ("pwsh", &["-c", "iex $code"]),
        ("pwsh", &["-c", "Invoke-Expression 'wsl id'"]),
        ("powershell", &["-EncodedCommand", "dwBzAGwA"]),
        ("powershell", &["-enc", "dwBzAGwA"]),
        ("pwsh", &["-e", "dwBzAGwA"]),
        ("pwsh", &["-ec", "dwBzAGwA"]),
        ("wt", &["-p", "Ubuntu"]),
        ("cmd", &["/c", "wt"]),
    ] {
        assert!(line(program, args).opaque, "{program} {args:?}");
    }
    // `-e` after the program is that program's option
    assert!(!line("cmd", &["/c", "docker run -e X=1 img"]).opaque);
    assert!(!line("pwsh", &["-c", "git log -e"]).opaque);
    // beyond simple PowerShell: held, whatever it computes
    assert!(
        line(
            "pwsh",
            &["-c", "[Environment]::GetEnvironmentVariable('PATH')"]
        )
        .opaque
    );
    assert!(line("pwsh", &["-c", "$PSVersionTable"]).opaque);
    assert!(line("pwsh", &["-c", ". $w id"]).opaque);
}

#[test]
fn other_programs_have_no_runner_line() {
    assert_eq!(
        line("git", &["commit", "-m", "wsl"]),
        runner::Found::default()
    );
    assert_eq!(line("echo", &["cmd /c wsl"]), runner::Found::default());
}

#[test]
fn a_launcher_word_anywhere_in_a_runner_line_is_held() {
    for (program, args) in [
        ("cmd", &["/c", "echo", "wsl"][..]),
        (
            "cmd",
            &["/c", r"C:\Program Files\Git\bin\bash.exe", "-c", "ls"],
        ),
        ("Start-Process", &["code", "-ArgumentList", "bash"]),
        ("pwsh", &["-c", "Write-Output 'WSL.EXE.'"]),
        ("powershell", &["-c", "$p = 'wsl'; echo $p"]),
    ] {
        let found = line(program, args);
        assert!(found.opaque, "{program} {args:?}");
        assert!(found.launchers.is_empty(), "{program} {args:?}: {found:?}");
    }
    // no launcher word, nothing held
    assert!(!line("cmd", &["/c", "docker run ubuntu"]).opaque);
    assert!(!line("pwsh", &["-c", "Get-Content wslconfig.md.bak.txt"]).opaque);
}

#[test]
fn shell_options_and_their_values_are_not_the_program() {
    for (program, args) in [
        (
            "powershell",
            &["-ExecutionPolicy", "Bypass", "-Command", "wsl ls"][..],
        ),
        ("powershell", &["-w", "hidden", "wsl", "ls"]),
        (
            "pwsh",
            &["-NoProfile", "-WorkingDirectory", "C:/x", "-c", "wsl ls"],
        ),
        ("cmd", &["//c", "wsl", "ls"]),
        ("cmd", &["/cwsl", "ls"]),
        ("cmd", &["/Kwsl.exe", "ls"]),
        ("cmd", &["/q", "/rwsl", "ls"]),
    ] {
        assert_eq!(line(program, args).launchers, ["wsl"], "{program} {args:?}");
    }
    assert!(line("powershell", &["-Bogus", "x", "wsl"]).opaque);
}

#[test]
fn quotes_are_read_as_each_shell_reads_them() {
    // `cmd` does not quote with `'`
    let found = line("cmd", &["/c", "echo 'a & wsl ls & echo '"]);
    assert_eq!(found.launchers, ["wsl"]);
    let found = line("cmd", &["/c", "for /f %i in ('wsl ls') do @echo %i"]);
    assert_eq!(found.launchers, ["wsl"]);
    // a subexpression in a PowerShell double-quoted string runs
    assert!(line("powershell", &["-c", r#"echo "$(gci)""#]).opaque);
    assert!(!line("powershell", &["-c", "echo '$(gci)'"]).opaque);
}

#[test]
fn a_computed_program_after_a_call_operator_is_opaque() {
    for script in [
        "& (gcm wsl) ls",
        "& (-join ('w','sl'))",
        "& ('wXl' -replace 'X','s')",
        r#"& "ws$('l')""#,
        "& $env:x",
        "[scriptblock]::Create('x').Invoke()",
        "icm -ScriptBlock { x }",
    ] {
        assert!(line("pwsh", &["-c", script]).opaque, "{script}");
    }
    let found = line("pwsh", &["-c", r"ii C:\Windows\System32\wsl.exe"]);
    assert_eq!(found.launchers, ["wsl"]);
}

#[test]
fn links_to_a_launcher_are_launchers() {
    let found = line(
        "cmd",
        &["/c", r"mklink /H w.exe C:\Windows\System32\wsl.exe"],
    );
    assert_eq!(found.launchers, ["wsl"]);
    let found = line(
        "pwsh",
        &[
            "-c",
            r"New-Item -ItemType HardLink -Path w.exe -Target 'C:\Program Files\WSL\wslg.exe'",
        ],
    );
    assert_eq!(found.launchers, ["wslg"]);
    assert_eq!(
        line("cmd", &["/c", "mklink /H b.txt a.txt"]).launchers,
        Vec::<String>::new()
    );
}

#[test]
fn only_a_bare_or_system_bash_is_denied() {
    assert_eq!(
        line(
            "cmd",
            &["/c", r#""C:\Program Files\Git\bin\bash.exe" -c ls"#]
        )
        .launchers,
        Vec::<String>::new()
    );
    assert_eq!(
        line("Start-Process", &["code", "-ArgumentList", "bash"]).launchers,
        Vec::<String>::new()
    );
    assert_eq!(line("cmd", &["/c", "bash -c id"]).launchers, ["bash"]);
    assert_eq!(
        line("cmd", &["/c", r"C:\Windows\System32\bash.exe -c id"]).launchers,
        ["bash"]
    );
}

#[test]
fn shares_in_option_values_and_built_shares() {
    assert!(names_share(r"-Path:\\wsl$\Ubuntu"));
    assert!(names_share(r"/root:\\wsl.localhost\Ubuntu"));
    assert!(!names_share("-Path:C:/x"));
    assert!(line("cmd", &["/c", r"dir \\ws%x%l$\Ubuntu"]).opaque);
    assert!(line("pwsh", &["-c", r"Get-ChildItem -Path:\\wsl$\Ubuntu"]).share);
}

#[test]
fn launchers_scripts_and_wildcards_that_hide_the_program_are_opaque() {
    for (program, args) in [
        ("cmd", &["/c", "echo w^sl -e id> a.bat & a.bat"][..]),
        (
            "forfiles",
            &[
                "/p",
                "C:/Windows/System32",
                "/m",
                "ws?.exe",
                "/c",
                "@path -e id",
            ],
        ),
        ("pwsh", &["-c", "saps $a"]),
        ("pwsh", &["-c", "Start-Process -FilePath $a"]),
        (
            "pwsh",
            &[
                "-c",
                "saps ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('d3Ns')))",
            ],
        ),
        ("pwsh", &["-c", "[Diagnostics.Process]::Start('cmd')"]),
        (
            "powershell",
            &["-c", r"& C:\Windows\System32\ws?.exe -e id"],
        ),
        ("pwsh", &["-c", r"Invoke-Item C:\Windows\System32\ws?.exe"]),
        (
            "cmd",
            &["/c", r"copy C:\Windows\System32\ws?.exe x.exe & x -e id"],
        ),
    ] {
        assert!(line(program, args).opaque, "{program} {args:?}");
    }
    for (program, args) in [
        ("cmd", &["/c", "echo done> out.txt"][..]),
        ("forfiles", &["/p", "C:/logs", "/d", "-30"]),
        ("cmd", &["/c", r".\run.ps1"]),
        ("cmd", &["/c", "gradlew.bat", "build"]),
        ("cmd", &["/c", r"C:\tools\build.bat"]),
        ("powershell", &["-c", r".\build.ps1"]),
        ("powershell", &["-c", "Get-ChildItem *.log"]),
    ] {
        assert!(!line(program, args).opaque, "{program} {args:?}");
    }
}
