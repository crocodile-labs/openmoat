//! The person's Kerberos ticket caches, kept from `moat run`'s commands.
//!
//! The default policy's `kerberos-tickets` names the caches MIT Kerberos and
//! Heimdal keep in the temp folder by default (`/tmp/krb5cc_<uid>`). It is
//! `hook_only` (ADR-034): the host sandboxes cannot deny a glob inside the temp
//! folder they grant. `moat run`'s own sandbox can (Seatbelt by regex, the
//! Linux network namespace by hiding the caches that exist when it starts), so
//! for the run the rule is applied there too, with the cache `KRB5CCNAME`
//! names added wherever it is. Caches that are no file (`KEYRING:`, `KCM:`,
//! `API:`, `MEMORY:`) are not paths: the kernel keyring is closed to commands
//! on Linux by the seccomp filter (`keyctl`), the others are in LIMITS.

use openmoat_core::{Policy, RuleGroup};

use super::patterns::has_glob;

/// The default policy's rule for the caches.
pub const RULE: &str = "kerberos-tickets";

/// Where the caches are by default, as the default policy names them; the
/// rule gets them when the policy has none.
const DEFAULT_CACHES: [&str; 2] = ["/tmp/krb5cc_*", "/tmp/krb5cc_*/**"];

/// The patterns the cache `KRB5CCNAME` names: `FILE:<path>` or a bare path is
/// the file, `DIR:<path>` the directory and everything in it, `DIR::<path>`
/// one file of such a directory. Nothing for a cache type that is no path, a
/// relative path or one with glob syntax, which as a pattern would name other
/// files.
pub fn cache_patterns(ccname: Option<&str>) -> Vec<String> {
    let Some(name) = ccname.map(str::trim).filter(|n| !n.is_empty()) else {
        return Vec::new();
    };
    let (dir, path) = if let Some(path) = name.strip_prefix("FILE:") {
        (false, path)
    } else if let Some(one) = name.strip_prefix("DIR::") {
        (false, one)
    } else if let Some(path) = name.strip_prefix("DIR:") {
        (true, path)
    } else {
        (false, name)
    };
    if !path.starts_with('/') || has_glob(path) {
        return Vec::new();
    }
    let path = path.trim_end_matches('/');
    let mut patterns = vec![path.to_owned()];
    if dir {
        patterns.push(format!("{path}/**"));
    }
    patterns
}

/// `policy` for `moat run`'s sandbox: [`RULE`] applied by the sandbox too
/// (not `hook_only`), with `ccname`'s cache added to its reads and writes.
/// A policy without the rule gets it with the default caches.
pub fn for_run(policy: &mut Policy, ccname: Option<&str>) {
    let index = if let Some(index) = policy.deny.iter().position(|g| g.id == RULE) {
        index
    } else {
        let defaults: Vec<String> = DEFAULT_CACHES.iter().map(|p| (*p).to_owned()).collect();
        policy.deny.push(RuleGroup {
            id: RULE.to_owned(),
            reason: Some("a Kerberos ticket cache".to_owned()),
            fs_read: defaults.clone(),
            fs_write: defaults,
            ..RuleGroup::default()
        });
        policy.deny.len() - 1
    };
    let rule = &mut policy.deny[index];
    rule.hook_only = false;
    let added = cache_patterns(ccname);
    for list in [&mut rule.fs_read, &mut rule.fs_write] {
        for pattern in &added {
            if !list.contains(pattern) {
                list.push(pattern.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_cache_type_that_is_a_path_is_named() {
        assert_eq!(
            cache_patterns(Some("FILE:/tmp/krb5cc_1000_x")),
            ["/tmp/krb5cc_1000_x"]
        );
        assert_eq!(
            cache_patterns(Some("/home/me/.krb5/cache")),
            ["/home/me/.krb5/cache"]
        );
        assert_eq!(
            cache_patterns(Some("DIR:/run/user/1000/krb5cc/")),
            ["/run/user/1000/krb5cc", "/run/user/1000/krb5cc/**"]
        );
        assert_eq!(
            cache_patterns(Some("DIR::/run/user/1000/krb5cc/tkt")),
            ["/run/user/1000/krb5cc/tkt"]
        );
        for none in [
            None,
            Some(""),
            Some("KEYRING:persistent:1000"),
            Some("KCM:"),
            Some("API:"),
            Some("MEMORY:x"),
            Some("FILE:relative"),
            Some("FILE:/tmp/krb5cc_*"),
        ] {
            assert!(cache_patterns(none).is_empty(), "{none:?}");
        }
    }

    /// The default policy keeps the rule to the hook; the run applies it in
    /// its sandbox, with the session's own cache.
    #[test]
    fn the_run_applies_the_rule_with_the_sessions_cache() {
        let mut policy = Policy::parse(openmoat_core::DEFAULT_POLICY).unwrap();
        let rule = |p: &Policy| p.deny.iter().find(|g| g.id == RULE).cloned().unwrap();
        assert!(rule(&policy).hook_only, "the host sandboxes leave it out");
        assert_eq!(rule(&policy).fs_read, DEFAULT_CACHES);
        for_run(&mut policy, Some("FILE:/srv/krb/cc"));
        for_run(&mut policy, Some("FILE:/srv/krb/cc"));
        let applied = rule(&policy);
        assert!(!applied.hook_only);
        for list in [&applied.fs_read, &applied.fs_write] {
            assert_eq!(list.iter().filter(|p| *p == "/srv/krb/cc").count(), 1);
            assert!(list.iter().any(|p| p == "/tmp/krb5cc_*"), "{list:?}");
        }
        let mut bare = Policy::parse("version: 1\n").unwrap();
        for_run(&mut bare, None);
        assert_eq!(bare.deny.len(), 1);
        assert_eq!(bare.deny[0].fs_read, DEFAULT_CACHES);
        assert!(!bare.deny[0].hook_only);
    }
}
