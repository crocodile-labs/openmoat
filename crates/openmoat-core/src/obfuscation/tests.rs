use super::{Dialect, assess};

fn posix(line: &str) -> (u32, Vec<&'static str>) {
    let a = assess(line, Dialect::Posix);
    (a.score, a.signals)
}

fn flagged(line: &str, dialect: Dialect) -> bool {
    assess(line, dialect).obfuscated()
}

#[test]
fn obfuscated_posix_lines_reach_the_threshold() {
    for line in [
        "c''a''t ~/.ssh/id_rsa",
        "'c'\"a\"'t' ~/'.s'\"s\"h/id_rsa",
        "\\c\\a\\t ~/.ssh/id_rsa",
        "$'\\x63\\x61\\x74\\x20\\x7e' f",
        "$'\\143\\141\\164\\040\\176' f",
        "v=x; r=v; ${!r} f",
        "a=c;b=a;d=t;$a$b$d f",
        "IFS=,;c=cat,f;$c",
        "{cat,~/.ssh/id_rsa}",
        "echo 'png' | tr a-z n-za-m | sh",
        "s=QZcatZQ; ${s:2:3} f",
        "$(printf \\\\$(printf %o 99))at f",
        "eval \"$x\"; ${y:1:2}; ${z:0:1}",
    ] {
        assert!(flagged(line, Dialect::Posix), "{line}: {:?}", posix(line));
    }
}

#[test]
fn everyday_posix_lines_stay_below_it() {
    for line in [
        "printf '%s\\n' \"$x\"",
        "sed 's/\\\\//g' f",
        "curl -d '{\"name\":\"a\",\"tags\":[\"x\",\"y\"]}' https://api.example.com",
        "echo -e \"\\033[31mred\\033[0m \\033[32mgreen\\033[0m\"",
        "while IFS= read -r line; do echo \"$line\"; done < f",
        "IFS=: read -ra parts <<< \"$PATH\"",
        "git commit -m \"fix: don't split\"",
        "echo 'it'\"'\"'s'",
        "eval \"$(ssh-agent -s)\"",
        "echo \"${GITHUB_SHA:0:7}\"",
        "find . -name \\*.rs -exec grep -l x {} \\;",
        "cp f{,.bak}",
        "mkdir -p src/{a,b}",
        "cd C:\\Users\\me",
        "for f in *.txt; do mv \"$f\" \"${f%.txt}.md\"; done",
        "x=\"${NAME:-default}\"",
        "docker run --rm -e A=1 -e B=2 img",
        "sha256sum f | cut -c1-64",
    ] {
        assert!(!flagged(line, Dialect::Posix), "{line}: {:?}", posix(line));
    }
}

#[test]
fn obfuscated_powershell_lines_reach_the_threshold() {
    for line in [
        "I`nv`oke-Ex`pression $x",
        "& ([char]105+[char]101+[char]120) $x",
        "&('Inv'+'oke-Exp'+'ression') $x",
        "powershell -enc ZQBjAGgAbwAgAGgAaQA=",
        "pwsh -EncodedCommand ZQBjAGgAbwAgAGgAaQA=",
        "iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b)))",
        "InVoKe-ExPrEsSiOn $x",
        "& ($env:comspec[4,15,25]-join'') $x",
    ] {
        let a = assess(line, Dialect::PowerShell);
        assert!(a.obfuscated(), "{line}: {a:?}");
    }
}

#[test]
fn everyday_powershell_lines_stay_below_it() {
    for line in [
        "Get-ChildItem -Recurse -Filter *.cs",
        "dotnet build",
        "npm test",
        "git status",
        "Write-Host \"done`n\"",
        "Get-Content package.json | ConvertFrom-Json",
        "$items = @(1, 2, 3); $items[0]",
        "\"{0} files\" -f $n",
        "Set-Location C:\\src\\app; dotnet test",
    ] {
        let a = assess(line, Dialect::PowerShell);
        assert!(!a.obfuscated(), "{line}: {a:?}");
    }
}

#[test]
fn a_long_encoded_word_adds_to_other_signals_only() {
    let blob: String = (0..96u8)
        .map(|i| {
            char::from(
                b"AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/aBcDeFgHiJkLmNoPqRsTuVwXyZ"
                    [usize::from(i) % 64],
            )
        })
        .collect();
    let alone = assess(&format!("echo {blob}"), Dialect::Posix);
    assert_eq!(alone.signals, vec!["entropy"]);
    assert!(!alone.obfuscated());
    let hex = "a".repeat(32) + &"0123456789abcdef".repeat(2);
    assert_eq!(
        assess(&format!("echo {hex}"), Dialect::Posix).signals,
        Vec::<&str>::new()
    );
}
