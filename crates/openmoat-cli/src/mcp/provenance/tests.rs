use std::fs;

use serde_json::json;

use super::*;

fn argv(line: &str) -> Vec<String> {
    line.split_whitespace().map(str::to_owned).collect()
}

fn no_roots() -> Roots {
    Roots {
        npm_cache: None,
        uv_tools: None,
    }
}

/// An npm cache with npx's install of `name` at `version`.
fn npx_cache(dir: &Path, hash: &str, name: &str, version: &str) {
    let install = dir.join("_npx").join(hash);
    fs::create_dir_all(&install).unwrap();
    let lock = json!({"packages": {format!("node_modules/{name}"): {
        "version": version, "integrity": format!("sha512-{version}-made-up")}}});
    fs::write(install.join("package-lock.json"), lock.to_string()).unwrap();
}

#[test]
fn the_command_line_names_the_package_and_an_exact_version() {
    let p = of_command(&argv("npx -y postmark-mcp@1.0.15"), &no_roots()).unwrap();
    assert_eq!(
        (p.ecosystem.as_str(), p.package.as_str()),
        ("npm", "postmark-mcp")
    );
    assert_eq!(p.version.as_deref(), Some("1.0.15"));
    let scoped = of_command(&argv("npx -y @scope/server@^2"), &no_roots()).unwrap();
    assert_eq!(scoped.package, "@scope/server");
    assert_eq!(scoped.version, None, "a range is no release");
    let latest = of_command(&argv("npx --yes postmark-mcp@latest"), &no_roots()).unwrap();
    assert_eq!(latest.version, None);
    let uvx = of_command(&argv("uvx mcp-server-git==2025.1.14"), &no_roots()).unwrap();
    assert_eq!(
        (uvx.ecosystem.as_str(), uvx.version.as_deref()),
        ("pypi", Some("2025.1.14"))
    );
    let from = of_command(
        &argv("uvx --from mcp-server-fetch@1.2 mcp-fetch"),
        &no_roots(),
    );
    assert_eq!(from.unwrap().package, "mcp-server-fetch");
    assert!(of_command(&argv("node server.js"), &no_roots()).is_none());
    assert!(of_command(&argv("npx ./local/server"), &no_roots()).is_none());
}

#[test]
fn an_image_digest_is_its_integrity() {
    let digest = format!("sha256:{}", "a".repeat(64));
    let line = format!("docker run -i --rm -e TOKEN ghcr.io/org/server:1.4@{digest}");
    let p = of_command(&argv(&line), &no_roots()).unwrap();
    assert_eq!(p.package, "ghcr.io/org/server");
    assert_eq!(p.version.as_deref(), Some("1.4"));
    assert_eq!(p.integrity.as_deref(), Some(digest.as_str()));
    let tag = of_command(&argv("docker run -i localhost:5000/server"), &no_roots()).unwrap();
    assert_eq!(tag.package, "localhost:5000/server");
    assert_eq!(
        (tag.version.as_deref(), tag.integrity),
        (Some("latest"), None)
    );
}

#[test]
fn npxs_install_gives_the_version_and_integrity_and_a_new_release_differs() {
    let dir = tempfile::tempdir().unwrap();
    let roots = Roots {
        npm_cache: Some(dir.path().to_owned()),
        uv_tools: None,
    };
    npx_cache(dir.path(), "a1", "postmark-mcp", "1.0.15");
    let before = of_command(&argv("npx -y postmark-mcp"), &roots).unwrap();
    assert_eq!(before.version.as_deref(), Some("1.0.15"));
    assert!(before.integrity.as_deref().unwrap().starts_with("sha512-"));
    // npx installs the next release in place: the pin no longer matches.
    npx_cache(dir.path(), "a1", "postmark-mcp", "1.0.16");
    let after = of_command(&argv("npx -y postmark-mcp"), &roots).unwrap();
    assert_ne!(before, after);
    assert!(after.shown().contains("1.0.16"), "{}", after.shown());
}

#[test]
fn a_uv_tool_install_gives_the_version_and_a_record_hash() {
    let dir = tempfile::tempdir().unwrap();
    let site = dir
        .path()
        .join("mcp-server-git")
        .join(if cfg!(windows) { "Lib" } else { "lib" })
        .join("python3.12")
        .join("site-packages")
        .join("mcp_server_git-2025.1.14.dist-info");
    fs::create_dir_all(&site).unwrap();
    fs::write(
        site.join("RECORD"),
        "mcp_server_git/__init__.py,sha256=x,10\n",
    )
    .unwrap();
    let roots = Roots {
        npm_cache: None,
        uv_tools: Some(dir.path().to_owned()),
    };
    let p = of_command(&argv("uvx mcp-server-git"), &roots).unwrap();
    assert_eq!(p.version.as_deref(), Some("2025.1.14"));
    assert!(p.integrity.unwrap().starts_with("sha256-record:"));
}
