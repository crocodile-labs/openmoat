//! Arguments that are a command line the program runs through a shell:
//! `watch 'cmd'`, `git rebase --exec 'cmd'`, `git submodule foreach 'cmd'`,
//! `git bisect run cmd`, `git difftool --extcmd`, `git filter-branch --tree-filter`,
//! `git clone`/`fetch`/`pull`/`ls-remote --upload-pack`, `git push --receive-pack`,
//! `git archive --exec`,
//! `ssh -o ProxyCommand='cmd'` (and `LocalCommand`, `KnownHostsCommand`) and
//! `rsync -e 'cmd'`. Each one is classified as a command line of its own.

use super::git;

/// `watch` options that take a value.
const WATCH_VALUES: &[&str] = &["-n", "--interval", "-q", "--equexit"];
/// `git rebase` and `git difftool` options whose value is a command, and the
/// shortest abbreviation git accepts for the long one (`--exe=cmd`).
/// The program a fetch, clone or push runs for the other side of a local
/// remote (`--upload-pack`, `--receive-pack`, `git archive --exec`) is one too:
/// git hands it to a shell.
const GIT_COMMAND_OPTIONS: &[(&str, &str, &str, &str)] = &[
    ("rebase", "-x", "--exec", "--ex"),
    ("difftool", "-x", "--extcmd", "--ex"),
    ("clone", "-u", "--upload-pack", "--u"),
    ("ls-remote", "-u", "--upload-pack", "--u"),
    ("fetch", "", "--upload-pack", "--upl"),
    ("pull", "", "--upload-pack", "--upl"),
    ("push", "", "--receive-pack", "--rece"),
    ("push", "", "--exec", "--e"),
    ("archive", "", "--exec", "--e"),
];
/// `git filter-branch` options whose value is shell code.
const FILTER_BRANCH: &[&str] = &[
    "--env-filter",
    "--tree-filter",
    "--index-filter",
    "--parent-filter",
    "--msg-filter",
    "--commit-filter",
    "--tag-name-filter",
];
/// ssh options (`-o Key=value`) whose value is a local command.
const SSH_COMMAND_KEYS: &[&str] = &["proxycommand", "localcommand", "knownhostscommand"];
const SSH_PROGRAMS: &[&str] = &["ssh", "scp", "sftp", "autossh"];

/// Every command line `argv` hands to a shell, as written.
pub(super) fn commands(argv: &[String], program: &str) -> Vec<String> {
    match program {
        "watch" => watch(argv).into_iter().collect(),
        "git" => git_commands(&git::parse(argv).subcommand),
        "rsync" => option_values(argv, "-e", "--rsh", "--rsh"),
        p if SSH_PROGRAMS.contains(&p) => ssh(argv),
        _ => Vec::new(),
    }
}

/// `watch -n 1 'cmd'`: the words after the options, joined as `watch` does.
fn watch(argv: &[String]) -> Option<String> {
    let mut i = 1;
    while let Some(arg) = argv.get(i) {
        if arg == "--" {
            i += 1;
            break;
        }
        if !arg.starts_with('-') {
            break;
        }
        i += if WATCH_VALUES.contains(&arg.as_str()) {
            2
        } else {
            1
        };
    }
    let rest = argv.get(i..)?;
    (!rest.is_empty()).then(|| rest.join(" "))
}

fn git_commands(sub: &[String]) -> Vec<String> {
    let Some(name) = sub.get(1).map(String::as_str) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for (subcommand, short, long, shortest) in GIT_COMMAND_OPTIONS {
        if name == *subcommand {
            found.extend(option_values(sub, short, long, shortest));
        }
    }
    if name == "filter-branch" {
        for option in FILTER_BRANCH {
            found.extend(option_values(sub, "", option, option));
        }
    }
    // `git submodule [--quiet] foreach [--recursive] cmd…`, `git bisect run cmd…`
    let rest_after = |word: &str| {
        let at = sub.iter().position(|a| a == word)?;
        let rest: Vec<&String> = sub[at + 1..]
            .iter()
            .skip_while(|a| a.starts_with('-'))
            .collect();
        (!rest.is_empty()).then(|| {
            rest.iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        })
    };
    if name == "submodule" {
        found.extend(rest_after("foreach"));
    }
    if name == "bisect" && sub.get(2).is_some_and(|a| a == "run") {
        found.extend(rest_after("run"));
    }
    found
}

/// Values of `short VALUE`, `shortVALUE`, `long VALUE` and `long=VALUE`, where
/// `long` may be cut short down to `shortest`. An empty `short` or `long` matches
/// nothing. A short flag bundled before it (`-avze 'cmd'`) counts.
fn option_values(argv: &[String], short: &str, long: &str, shortest: &str) -> Vec<String> {
    let is_long =
        |name: &str| !long.is_empty() && name.starts_with(shortest) && long.starts_with(name);
    let mut values = Vec::new();
    let mut i = 1;
    while let Some(arg) = argv.get(i) {
        i += 1;
        if arg == "--" {
            break;
        }
        if let Some((name, value)) = arg.split_once('=')
            && is_long(name)
        {
            values.push(value.to_owned());
            continue;
        }
        if is_long(arg) {
            if let Some(value) = argv.get(i) {
                values.push(value.clone());
                i += 1;
            }
            continue;
        }
        // `-x cmd`, `-xcmd`, and in a cluster of flags `-qx cmd`, `-qxcmd`: the
        // rest of the word, or else the next word, is the value
        let Some(letter) = short.strip_prefix('-').filter(|l| l.len() == 1) else {
            continue;
        };
        let Some(cluster) = arg.strip_prefix('-').filter(|c| !c.starts_with('-')) else {
            continue;
        };
        let Some(at) = cluster.find(letter) else {
            continue;
        };
        if !cluster[..at].bytes().all(|b| b.is_ascii_alphabetic()) {
            continue;
        }
        let rest = &cluster[at + 1..];
        if !rest.is_empty() {
            values.push(rest.to_owned());
        } else if let Some(value) = argv.get(i) {
            values.push(value.clone());
            i += 1;
        }
    }
    values
}

/// `ssh -o ProxyCommand='cmd' host`, `-oProxyCommand=cmd`, `-o 'LocalCommand cmd'`.
fn ssh(argv: &[String]) -> Vec<String> {
    option_values(argv, "-o", "", "")
        .into_iter()
        .filter_map(|option| {
            let (key, value) = option
                .split_once(['=', ' ', '\t'])
                .map(|(k, v)| (k.trim(), v.trim_start_matches(['=', ' ', '\t']).trim()))?;
            let key = key.to_ascii_lowercase();
            (SSH_COMMAND_KEYS.contains(&key.as_str()) && !value.eq_ignore_ascii_case("none"))
                .then(|| value.to_owned())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::commands;

    fn run(line: &str) -> Vec<String> {
        let argv: Vec<String> = line.split(' ').map(str::to_owned).collect();
        commands(&argv, &argv[0])
    }

    #[test]
    fn finds_the_command_each_program_runs() {
        assert_eq!(run("watch -n 1 cat x"), ["cat x"]);
        assert_eq!(run("watch -d ls"), ["ls"]);
        assert_eq!(run("git rebase --exec=make main"), ["make"]);
        assert_eq!(run("git rebase main --exe=make"), ["make"]);
        assert_eq!(run("git rebase --ex make"), ["make"]);
        assert_eq!(run("git rebase --e=make"), Vec::<String>::new());
        assert_eq!(run("git rebase -x make main"), ["make"]);
        assert_eq!(run("git -C d rebase -xmake main"), ["make"]);
        assert_eq!(run("git rebase -qxid main"), ["id"]);
        assert_eq!(run("git rebase -ix make main"), ["make"]);
        assert_eq!(
            run("git submodule --quiet foreach --recursive git pull"),
            ["git pull"]
        );
        assert_eq!(run("git bisect run make test"), ["make test"]);
        assert_eq!(run("git difftool --extcmd=vimdiff"), ["vimdiff"]);
        assert_eq!(run("git filter-branch --tree-filter rm"), ["rm"]);
        assert_eq!(run("ssh -o ProxyCommand=nc x"), ["nc"]);
        assert_eq!(run("ssh -oLocalCommand=id x"), ["id"]);
        assert_eq!(run("ssh -o ProxyCommand=none x"), Vec::<String>::new());
        assert_eq!(run("ssh -o Port=22 x"), Vec::<String>::new());
        assert_eq!(run("rsync -avze sh a b"), ["sh"]);
        assert_eq!(run("rsync --rsh=sh a b"), ["sh"]);
        assert_eq!(run("rsync -av a b"), Vec::<String>::new());
        assert_eq!(run("git rebase main"), Vec::<String>::new());
        assert_eq!(run("git bisect start"), Vec::<String>::new());
    }

    #[test]
    fn finds_the_program_git_runs_for_the_other_side() {
        for (line, found) in [
            ("git clone -u up ./r x", &["up"][..]),
            ("git clone --upload-pack=up ./r", &["up"]),
            ("git ls-remote --u up .", &["up"]),
            ("git fetch --upl=up ../r", &["up"]),
            ("git fetch -u ../r", &[]),
            ("git pull --upload-pack up ../r", &["up"]),
            ("git push --receive-pack=rp ../r", &["rp"]),
            ("git push --exec rp ../r", &["rp"]),
            ("git archive --exec=ua --remote=../r HEAD", &["ua"]),
        ] {
            assert_eq!(run(line), found, "{line}");
        }
    }
}
