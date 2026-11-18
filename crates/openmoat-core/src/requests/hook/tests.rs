//! The hook's reading of commands, decided end to end by the engine.

use crate::{Action, CompiledPolicy, EvalContext, Policy, Verdict};

const POLICY: &str = "version: 1\ndefaults: { '*': defer, net: deny, fetch: defer }\n\
    allow:\n  - id: gh\n    net: [api.github.com, github.com]\n\
    requests:\n  - id: gists\n    host: api.github.com\n    hook_only: true\n    \
    deny: ['POST /gists', 'PATCH /gists/**', 'POST /gists/*/comments']\n";

fn ctx() -> EvalContext {
    EvalContext {
        home: "/h".into(),
        project: Some("/p".into()),
        real_home: None,
        real_project: None,
        moved_dirs: Vec::new(),
        cwd: "/p".into(),
        case_insensitive_paths: false,
    }
}

fn decide_in(policy: &str, action: &Action) -> (Verdict, Vec<String>) {
    let policy = Policy::parse(policy).unwrap();
    let d = CompiledPolicy::compile(&policy, &ctx())
        .unwrap()
        .decide(action);
    (d.verdict, d.rules)
}

fn shell(command: &str) -> (Verdict, Vec<String>) {
    decide_in(
        POLICY,
        &Action::Shell {
            command: command.into(),
        },
    )
}

fn ruled(command: &str) -> Verdict {
    let (verdict, rules) = shell(command);
    assert!(
        rules.iter().any(|r| r == "request-rule"),
        "{command}: {rules:?}"
    );
    verdict
}

#[test]
fn every_spelling_of_posting_a_gist_is_denied() {
    for command in [
        "curl -X POST https://api.github.com/gists -d @notes.txt",
        "curl --request=post https://api.github.com/gists -d @notes.txt",
        "curl --request POST https://api.github.com/gists --data-binary @f",
        "curl -XPOST https://api.github.com/gists",
        "curl -sSLXPOST https://api.github.com/gists",
        "curl -d @notes.txt https://api.github.com/gists",
        "curl -sd @notes.txt https://api.github.com/gists",
        "curl --json @f https://api.github.com/gists",
        "curl -F 'files=@f' https://api.github.com/gists",
        "curl --data-raw '{}' api.github.com/gists",
        "curl -d x https://API.GitHub.com/Gists",
        "curl -d x https://api.github.com/GISTS/",
        "curl -d x https://api.github.com/%67ists",
        "curl -d x https://user@api.github.com:443/gists",
        "curl -d x --url https://api.github.com/gists",
        "curl -d x -- https://api.github.com/gists",
        "curl -X PATCH -d x https://api.github.com/gists/abc",
        "curl -d x https://api.github.com/gists/abc/comments",
        "sudo curl -d x https://api.github.com/gists",
        "sh -c 'curl -d @f https://api.github.com/gists'",
        "/usr/bin/curl -d x https://api.github.com/gists",
        "wget --post-file=f https://api.github.com/gists",
        "wget --method=POST --body-data=x https://api.github.com/gists",
        "http POST api.github.com/gists files:=@f.json",
        "http api.github.com/gists description=x",
        "https post api.github.com/gists description=x",
        "xh post https://api.github.com/gists description=x",
        "gh gist create notes.txt",
        "gh gist create --public notes.txt",
        "gh gist edit abc notes.txt",
        "gh api gists -f description=x",
        "gh api /gists -F 'files[a][content]=@f'",
        "gh api -X POST gists --input f.json",
        "gh api --method=POST /gists",
        "gh api -XPATCH gists/abc",
        "gh api https://api.github.com/gists -f x=y",
    ] {
        assert_eq!(ruled(command), Verdict::Deny, "{command}");
    }
}

#[test]
fn a_path_the_server_could_read_as_another_or_a_method_override_is_denied() {
    for command in [
        "curl -d x https://api.github.com/a/..%2fgists",
        "curl -d x https://api.github.com/a%2fb",
        "curl https://api.github.com/x -H 'X-HTTP-Method-Override: POST'",
        "curl 'https://api.github.com/x?_method=POST'",
    ] {
        assert_eq!(ruled(command), Verdict::Deny, "{command}");
    }
}

#[test]
fn what_is_made_at_run_time_is_held_for_review() {
    for command in [
        "curl -X POST -d @f \"$URL\"",
        "curl -d @f \"https://api.github.com/$WHERE\"",
        "curl -X \"$M\" https://api.github.com/gists",
        "curl -K opts.txt https://api.github.com/gists",
        "curl -d x 'https://api.github.com/{gists,user}'",
        "curl -d x https://api.github.com/gists --next https://github.com",
        "wget -i urls.txt",
        "http api.github.com/gists",
        "gh api -X \"$M\" gists",
        "gh gist frobnicate",
    ] {
        assert_eq!(ruled(command), Verdict::Review, "{command}");
    }
}

#[test]
fn reads_and_other_requests_are_left_as_they_were() {
    let before = |command: &str| {
        let without = POLICY.split("requests:").next().unwrap();
        decide_in(
            without,
            &Action::Shell {
                command: command.into(),
            },
        )
    };
    for command in [
        "curl https://api.github.com/gists",
        "curl -s https://api.github.com/repos/o/r",
        "curl -I https://api.github.com/gists",
        "curl -G -d per_page=1 https://api.github.com/gists",
        "curl -d x https://api.github.com/repos/o/r/issues",
        "curl -s \"$URL\"",
        "wget https://api.github.com/gists",
        "http GET api.github.com/gists",
        "http --ignore-stdin api.github.com/gists",
        "gh api gists",
        "gh api repos/{owner}/{repo}/issues -f title=x",
        "gh api graphql -f query=x",
        "gh gist list",
        "gh gist view abc",
        "gh pr create --fill",
        "gh issue list",
        "git push origin main",
        "curl -d x https://github.com/gists",
    ] {
        let (verdict, rules) = shell(command);
        assert!(
            !rules.iter().any(|r| r == "request-rule"),
            "{command}: {rules:?}"
        );
        assert_eq!((verdict, rules), before(command), "{command}");
    }
}

#[test]
fn a_fetch_tool_sends_a_get() {
    let fetch = |url: &str| decide_in(POLICY, &Action::Fetch { url: url.into() });
    assert!(
        !fetch("https://api.github.com/gists")
            .1
            .contains(&"request-rule".to_owned())
    );
    let only_reads = "version: 1\nallow:\n  - id: gh\n    fetch: [api.github.com]\n\
        requests:\n  - id: api\n    host: api.github.com\n    allow: ['GET /repos/**']\n";
    let get = |url: &str| decide_in(only_reads, &Action::Fetch { url: url.into() });
    assert_eq!(get("https://api.github.com/user").0, Verdict::Deny);
    assert_ne!(get("https://api.github.com/repos/o/r").0, Verdict::Deny);
}

#[test]
fn the_rules_never_allow() {
    // A request the rules let pass keeps the verdict the policy gave it.
    let open = "version: 1\ndefaults: deny\nrequests:\n  - id: api\n    host: api.github.com\n    \
        allow: ['GET /**']\n";
    let (verdict, _) = decide_in(
        open,
        &Action::Shell {
            command: "curl https://api.github.com/user".into(),
        },
    );
    assert_eq!(verdict, Verdict::Deny);
}
