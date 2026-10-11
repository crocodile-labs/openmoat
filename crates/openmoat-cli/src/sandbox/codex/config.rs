//! Merging the generated profile into Codex's `config.toml`, keeping every
//! other key, comment and table as the user wrote it.

use std::path::Path;

use anyhow::{Result, bail};
use toml_edit::{DocumentMut, Item, Table, Value, value};

use super::{Generated, PROFILE};

/// Set `default_permissions`, replace `[permissions.moat]` and turn on the
/// network proxy that enforces its domain rules. Returns whether anything
/// changed.
pub fn apply(doc: &mut DocumentMut, generated: &Generated) -> Result<bool> {
    let before = doc.to_string();
    doc.insert("default_permissions", value(PROFILE));
    let permissions = table_at(doc.as_table_mut(), "permissions")?;
    permissions.insert(PROFILE, Item::Table(generated.profile.clone()));
    let features = table_at(doc.as_table_mut(), "features")?;
    match features.get_mut("network_proxy") {
        // `[features.network_proxy]` with its own settings: keep them, enable it.
        Some(Item::Table(proxy)) => {
            proxy.insert("enabled", value(true));
        }
        _ => {
            features.insert("network_proxy", value(true));
        }
    }
    Ok(doc.to_string() != before)
}

/// The inverse of [`apply`]: remove `default_permissions` when it names the moat
/// profile, `[permissions.moat]` and a plain `features.network_proxy = true`, then
/// the tables that leaves empty. A `[features.network_proxy]` table has the
/// user's own settings and stays. Returns whether anything was removed.
pub fn remove(doc: &mut DocumentMut) -> bool {
    let before = doc.to_string();
    if doc.get("default_permissions").and_then(Item::as_str) == Some(PROFILE) {
        doc.remove("default_permissions");
    }
    for (table, key) in [("permissions", PROFILE), ("features", "network_proxy")] {
        let emptied = match doc.get_mut(table).and_then(Item::as_table_like_mut) {
            Some(parent)
                if key == PROFILE || parent.get(key).and_then(Item::as_bool) == Some(true) =>
            {
                parent.remove(key).is_some() && parent.is_empty()
            }
            _ => false,
        };
        if emptied {
            doc.remove(table);
        }
    }
    doc.to_string() != before
}

/// Deny commands the Codex home (`$CODEX_HOME`: this config, `auth.json`,
/// sessions) wherever it is; the policy names only `~/.codex`.
pub fn protect(generated: &mut Generated, codex_home: &Path) {
    let filesystem = generated
        .profile
        .get_mut("filesystem")
        .and_then(Item::as_table_mut);
    if let Some(filesystem) = filesystem {
        filesystem.insert(&crate::context::path_string(codex_home), value("deny"));
    }
}

/// Keep commands from writing each of `paths` (the `moat` binary, its target
/// and their directory): read-only where `readable` says the policy lets
/// commands read it, denied otherwise, so nothing is opened that was closed.
///
/// A path the nearest listed directory above it already covers (the same
/// mode, or `deny`) is left out, also when the generator listed it. On Linux Codex hides a denied directory under
/// a read-only tmpfs, and bubblewrap then fails every command trying to mount
/// over a file in it (`Can't create file at …: Read-only file system`).
pub fn read_only(generated: &mut Generated, paths: &[String], readable: impl Fn(&str) -> bool) {
    let filesystem = generated
        .profile
        .get_mut("filesystem")
        .and_then(Item::as_table_mut);
    let Some(filesystem) = filesystem else {
        return;
    };
    let mut paths: Vec<&String> = paths.iter().collect();
    paths.sort_by_key(|path| Path::new(path).components().count());
    for path in paths {
        let mode = if readable(path) { "read" } else { "deny" };
        let covered = nearest_listed_parent(filesystem, path)
            .is_some_and(|parent| parent == "deny" || parent == mode);
        if covered {
            // The generator lists `kernel-self`'s paths too.
            filesystem.remove(path.as_str());
        } else {
            filesystem.insert(path, value(mode));
        }
    }
}

/// The mode of the deepest literal path in `filesystem` strictly above `path`.
fn nearest_listed_parent<'a>(filesystem: &'a Table, path: &str) -> Option<&'a str> {
    let path = Path::new(path);
    filesystem
        .iter()
        .filter(|(key, _)| !key.starts_with(':') && !key.contains(['*', '?', '[', '{']))
        .filter(|(key, _)| Path::new(key) != path && path.starts_with(key))
        .max_by_key(|(key, _)| Path::new(key).components().count())
        .and_then(|(_, mode)| mode.as_str())
}

/// The part of a Codex config OpenMoat owns, in a canonical form that ignores
/// formatting, comments, key order and every other key. Codex writes the file
/// itself (trusted projects, notices, the model), so the lock pins this part
/// rather than the whole file.
pub fn owned_part(doc: &DocumentMut) -> String {
    let permissions = doc.get("permissions").and_then(|p| p.get(PROFILE));
    let proxy = doc.get("features").and_then(|f| f.get("network_proxy"));
    format!(
        "default_permissions={}\npermissions.{PROFILE}={}\nfeatures.network_proxy={}\n",
        canon(doc.get("default_permissions")),
        canon(permissions),
        canon(proxy)
    )
}

/// Whether the part OpenMoat owns already has its generated value.
pub fn in_sync(doc: &DocumentMut, generated: &Generated) -> bool {
    let mut expected = doc.clone();
    apply(&mut expected, generated).is_ok() && owned_part(&expected) == owned_part(doc)
}

/// Settings in `doc` that keep the moat profile from applying, worded for `moat
/// doctor`; `via_moat_proxy` when the policy sets `sandbox.proxy_port`.
pub fn weaknesses(doc: &DocumentMut, via_moat_proxy: bool) -> Vec<String> {
    let mut out = Vec::new();
    if doc.get("default_permissions").and_then(Item::as_str) != Some(PROFILE) {
        out.push(format!(
            "default_permissions is not \"{PROFILE}\": commands run under another profile"
        ));
    }
    if let Some(mode) = doc.get("sandbox_mode") {
        out.push(format!(
            "sandbox_mode is set ({}): remove it so the moat profile is the only one",
            mode.to_string().trim()
        ));
    }
    if doc
        .get("permissions")
        .and_then(|p| p.get(PROFILE))
        .is_none()
    {
        out.push(format!("[permissions.{PROFILE}] is missing"));
    }
    let proxy = doc.get("features").and_then(|f| f.get("network_proxy"));
    let enabled = proxy.and_then(Item::as_bool).unwrap_or(false)
        || proxy
            .and_then(|p| p.get("enabled"))
            .and_then(Item::as_bool)
            .unwrap_or(false);
    if !enabled {
        out.push("features.network_proxy is off: the domain rules are not enforced".to_owned());
    }
    let network = doc
        .get("permissions")
        .and_then(|p| p.get(PROFILE))
        .and_then(|p| p.get("network"));
    let set = |key: &str| network.and_then(|n| n.get(key)).and_then(Item::as_bool);
    if via_moat_proxy && set("allow_upstream_proxy") == Some(false) {
        out.push(
            "allow_upstream_proxy is false: Codex's proxy never hands traffic to `moat proxy`"
                .to_owned(),
        );
    }
    if set("allow_local_binding") == Some(true) {
        out.push(
            "allow_local_binding is true: commands connect to local services directly".to_owned(),
        );
    }
    out
}

/// One canonical line for an item: tables and inline tables sorted by key,
/// values without their formatting.
fn canon(item: Option<&Item>) -> String {
    match item {
        None | Some(Item::None) => "none".to_owned(),
        Some(Item::Value(v)) => canon_value(v),
        Some(Item::Table(t)) => canon_entries(t.iter().map(|(k, v)| (k, canon(Some(v))))),
        Some(Item::ArrayOfTables(a)) => {
            let tables: Vec<String> = a
                .iter()
                .map(|t| canon_entries(t.iter().map(|(k, v)| (k, canon(Some(v))))))
                .collect();
            format!("[{}]", tables.join(","))
        }
    }
}

fn canon_value(v: &Value) -> String {
    match v {
        Value::String(s) => format!("{:?}", s.value()),
        Value::Array(a) => {
            let items: Vec<String> = a.iter().map(canon_value).collect();
            format!("[{}]", items.join(","))
        }
        Value::InlineTable(t) => canon_entries(t.iter().map(|(k, v)| (k, canon_value(v)))),
        other => other.clone().decorated("", "").to_string(),
    }
}

fn canon_entries<'a>(entries: impl Iterator<Item = (&'a str, String)>) -> String {
    let mut pairs: Vec<String> = entries.map(|(k, v)| format!("{k:?}={v}")).collect();
    pairs.sort();
    format!("{{{}}}", pairs.join(","))
}

/// The table at `key`, created implicit (no header of its own) when missing.
fn table_at<'a>(parent: &'a mut Table, key: &str) -> Result<&'a mut Table> {
    let item = parent.entry(key).or_insert_with(|| {
        let mut table = Table::new();
        table.set_implicit(true);
        Item::Table(table)
    });
    match item {
        Item::Table(table) => Ok(table),
        _ => bail!("`{key}` in the Codex config is not a table"),
    }
}
