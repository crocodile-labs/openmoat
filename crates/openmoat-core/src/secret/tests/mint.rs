//! `source: { mint: … }` and `helper:` (ADR-118).

use super::{parse, problem};
use crate::lint::exposed_source;
use crate::secret::{Helper, MintSource, Source};

const GITHUB: &str = "  - id: gh-git\n    host: github.com\n    header: Authorization\n    \
                      helper: { git: { username: x-access-token } }\n    source:\n      mint:\n        \
                      github-app:\n";

fn github(fields: &str) -> String {
    format!("{GITHUB}{fields}")
}

const GITHUB_OK: &str = "          app: Iv23liExample\n          installation: 42\n          \
                         key: ~/.config/moat/app.pem\n          repositories: [openmoat]\n          \
                         permissions: { contents: read }\n";

const AWS: &str = "  - id: s3\n    host: s3.us-east-1.amazonaws.com\n    \
                   header: X-Amz-Security-Token\n    helper: aws\n    source:\n      mint:\n        \
                   aws-sts:\n          role: arn:aws:iam::123456789012:role/agent\n          \
                   region: us-east-1\n";

const GCP: &str = "  - id: gcs\n    host: storage.googleapis.com\n    header: Authorization\n    \
                   tls: terminate\n    source:\n      mint:\n        gcp:\n          \
                   service_account: agent@demo.iam.gserviceaccount.com\n";

#[test]
fn parses_each_provider_and_its_helper() {
    let p = parse(&format!(
        "{}{AWS}          actions: [s3:GetObject]\n          resources: ['arn:aws:s3:::bucket/*']\n          \
         lifetime: 20m\n{GCP}          scopes: [https://www.googleapis.com/auth/devstorage.read_only]\n",
        github(GITHUB_OK)
    ))
    .unwrap();
    let Source::Mint(MintSource::GithubApp(g)) = &p.secrets[0].source else {
        panic!("not a github-app mint: {:?}", p.secrets[0].source);
    };
    assert_eq!(g.installation, 42);
    assert_eq!(
        g.permissions.get("contents").map(String::as_str),
        Some("read")
    );
    assert_eq!(
        p.secrets[0].helper,
        Some(Helper::Git {
            username: "x-access-token".into()
        })
    );
    assert_eq!(p.secrets[1].helper, Some(Helper::Aws));
    let Source::Mint(aws) = &p.secrets[1].source else {
        panic!("not a mint");
    };
    assert_eq!(aws.lifetime_secs(), 20 * 60);
    assert_eq!(aws.refresh_before_secs(), 4 * 60);
    assert_eq!(aws.files(), ["~/.aws/credentials"]);
    let Source::Mint(gcp) = &p.secrets[2].source else {
        panic!("not a mint");
    };
    assert_eq!(gcp.lifetime_secs(), 15 * 60);
    assert!(p.secrets.iter().all(|s| s.source.proxy_only()));
    assert_eq!(p.secrets[2].source.describe(), "mint gcp");
    // `Debug` names the provider, never the key file or the role.
    let shown = format!("{:?}", p.secrets[1].source);
    assert!(
        shown.contains("aws-sts") && !shown.contains("123456789012"),
        "{shown}"
    );
}

#[test]
fn a_mint_that_would_not_narrow_is_refused() {
    let no_repos = GITHUB_OK.replace("repositories: [openmoat]", "repositories: []");
    assert!(problem(&github(&no_repos)).contains("every repository"));
    let no_perms = GITHUB_OK.replace("permissions: { contents: read }", "permissions: {}");
    assert!(problem(&github(&no_perms)).contains("every permission"));
    let bad_level = GITHUB_OK.replace("contents: read", "contents: all");
    assert!(problem(&github(&bad_level)).contains("`read`, `write` or `admin`"));
    let owner = GITHUB_OK.replace("[openmoat]", "[crocodile-labs/openmoat]");
    assert!(problem(&github(&owner)).contains("without its owner"));
    let relative = GITHUB_OK.replace("~/.config/moat/app.pem", "app.pem");
    assert!(problem(&github(&relative)).contains("absolute"));

    let aws = |rest: &str| problem(&format!("{AWS}{rest}"));
    assert!(
        aws("          actions: [s3:GetObject]\n          resources: []\n")
            .contains("session policy")
    );
    assert!(
        aws("          actions: ['s3:*']\n          resources: ['arn:aws:s3:::b']\n")
            .contains("not every action")
    );
    assert!(
        aws("          actions: ['*']\n          resources: ['arn:aws:s3:::b']\n")
            .contains("service:Action")
    );
    assert!(
        aws("          actions: [s3:GetObject]\n          resources: ['*']\n").contains("not `*`")
    );
    assert!(
        aws("          actions: [s3:GetObject]\n          resources: ['arn:aws:s3:::b']\n          lifetime: 5m\n")
            .contains("from 900s")
    );

    let gcp = |rest: &str| problem(&format!("{GCP}{rest}"));
    assert!(gcp("          scopes: []\n").contains("OAuth scopes"));
    assert!(gcp("          scopes: [https://example.com/auth/x]\n").contains("Google OAuth scope"));
    assert!(
        gcp("          scopes: [https://www.googleapis.com/auth/cloud-platform]\n          lifetime: 2h\n")
            .contains("from 60s")
    );
}

#[test]
fn an_aws_mint_goes_through_its_helper_only() {
    let rest = "          actions: [s3:GetObject]\n          resources: ['arn:aws:s3:::b/*']\n";
    let without = format!("{AWS}{rest}").replace("    helper: aws\n", "");
    assert!(problem(&without).contains("needs `helper: aws`"));
    let terminated = format!("{AWS}{rest}")
        .replace("    helper: aws\n", "    helper: aws\n    tls: terminate\n");
    assert!(problem(&terminated).contains("through `helper: aws` only"));
    // `helper: aws` hands out nothing but an aws-sts mint's credentials.
    let env = "  - id: k\n    host: example.com\n    header: X-Key\n    helper: aws\n    source: { env: K }\n";
    assert!(problem(env).contains("nothing else"));
    let git_ip = "  - id: k\n    host: 10.0.0.1\n    header: X-Key\n    \
                  helper: { git: { username: me } }\n    source: { env: K }\n";
    assert!(problem(git_ip).contains("needs a DNS name"));
    let git_user = "  - id: k\n    host: example.com\n    header: X-Key\n    \
                    helper: { git: { username: 'a b' } }\n    source: { env: K }\n";
    assert!(problem(git_user).contains("user name"));
}

#[test]
fn the_lint_warns_when_the_agent_can_read_the_credential_a_mint_starts_from() {
    let bare = parse(&github(GITHUB_OK)).unwrap();
    let warned = exposed_source(&bare, &bare.secrets[0]).unwrap();
    assert!(warned.contains("~/.config/moat/app.pem"), "{warned}");
    let covered = parse(&format!(
        "{}deny:\n  - id: app-key\n    fs.read: ['~/.config/moat/**']\n",
        github(GITHUB_OK)
    ))
    .unwrap();
    assert_eq!(exposed_source(&covered, &covered.secrets[0]), None);
}
