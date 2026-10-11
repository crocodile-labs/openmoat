//! git's `safe.bareRepository=explicit`, exported through the environment.
//!
//! git treats any directory holding `HEAD`, `objects/` and `refs/` as a bare
//! repository and reads its `config` (`core.fsmonitor`, aliases, hooks), so a
//! command that plants one and a later `git status` inside it runs code with no
//! `.git` name involved. With `safe.bareRepository=explicit` git uses a bare
//! repository only when `--git-dir` or `GIT_DIR` names it. git reads that key
//! only from protected configuration, which includes `GIT_CONFIG_COUNT`,
//! `GIT_CONFIG_KEY_<n>` and `GIT_CONFIG_VALUE_<n>` (git 2.31 and later; the key
//! itself needs git 2.38). The entry is appended after any the environment
//! already has, so for a single-valued key it is the one git uses.

use anyhow::{Result, bail};

/// The git configuration key OpenMoat sets.
pub const KEY: &str = "safe.bareRepository";
/// Its value: bare repositories only where named explicitly.
pub const VALUE: &str = "explicit";
const COUNT: &str = "GIT_CONFIG_COUNT";

/// A change to an environment: set a variable, or remove it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// Set the variable to the value.
    Set(String, String),
    /// Remove the variable.
    Unset(String),
}

/// What reads one variable of an environment.
pub type Lookup<'a> = &'a dyn Fn(&str) -> Option<String>;

fn key_var(index: usize) -> String {
    format!("GIT_CONFIG_KEY_{index}")
}

fn value_var(index: usize) -> String {
    format!("GIT_CONFIG_VALUE_{index}")
}

/// `GIT_CONFIG_COUNT` as git reads it: missing or empty is none.
fn count(get: Lookup) -> Result<usize> {
    match get(COUNT) {
        None => Ok(0),
        Some(raw) if raw.is_empty() => Ok(0),
        Some(raw) if raw.bytes().all(|b| b.is_ascii_digit()) => match raw.parse() {
            Ok(n) => Ok(n),
            Err(_) => bail!("{COUNT}={raw} is too large"),
        },
        Some(raw) => bail!("{COUNT}={raw} is not a number, so git refuses every command"),
    }
}

fn is_key(name: Option<String>) -> bool {
    name.is_some_and(|k| k.eq_ignore_ascii_case(KEY))
}

/// Whether the last `safe.bareRepository` entry in `get` is `explicit`.
pub fn present(get: Lookup) -> bool {
    let Ok(n) = count(get) else {
        return false;
    };
    (0..n)
        .rev()
        .find(|&i| is_key(get(&key_var(i))))
        .is_some_and(|i| get(&value_var(i)).as_deref() == Some(VALUE))
}

/// The variables to set so that `safe.bareRepository=explicit` applies, after
/// the entries `get` already holds; nothing when it already does. Fails when
/// `GIT_CONFIG_COUNT` is not a number.
pub fn add(get: Lookup) -> Result<Vec<(String, String)>> {
    let n = count(get)?;
    if present(get) {
        return Ok(Vec::new());
    }
    Ok(vec![
        (COUNT.to_owned(), (n + 1).to_string()),
        (key_var(n), KEY.to_owned()),
        (value_var(n), VALUE.to_owned()),
    ])
}

/// The inverse of [`add`]: drop every `safe.bareRepository=explicit` entry and
/// renumber the others. Nothing when there is none or the count is not a number.
pub fn remove(get: Lookup) -> Vec<Change> {
    let Ok(n) = count(get) else {
        return Vec::new();
    };
    let entries: Vec<(Option<String>, Option<String>)> = (0..n)
        .map(|i| (get(&key_var(i)), get(&value_var(i))))
        .collect();
    let ours = |(k, v): &(Option<String>, Option<String>)| {
        is_key(k.clone()) && v.as_deref() == Some(VALUE)
    };
    if !entries.iter().any(ours) {
        return Vec::new();
    }
    let kept: Vec<_> = entries.iter().filter(|e| !ours(e)).collect();
    let mut changes = Vec::new();
    let mut put = |var: String, value: &Option<String>| {
        changes.push(match value {
            Some(v) => Change::Set(var, v.clone()),
            None => Change::Unset(var),
        });
    };
    for (i, (k, v)) in kept.iter().enumerate() {
        put(key_var(i), k);
        put(value_var(i), v);
    }
    for i in kept.len()..n {
        put(key_var(i), &None);
        put(value_var(i), &None);
    }
    let left = (!kept.is_empty()).then(|| kept.len().to_string());
    put(COUNT.to_owned(), &left);
    changes
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn added(map: &mut BTreeMap<String, String>) {
        let lookup = map.clone();
        for (k, v) in add(&|k| lookup.get(k).cloned()).unwrap() {
            map.insert(k, v);
        }
    }

    fn removed(map: &mut BTreeMap<String, String>) {
        let lookup = map.clone();
        for change in remove(&|k| lookup.get(k).cloned()) {
            match change {
                Change::Set(k, v) => map.insert(k, v),
                Change::Unset(k) => map.remove(&k),
            };
        }
    }

    #[test]
    fn an_empty_environment_gets_entry_zero() {
        let mut map = env(&[]);
        added(&mut map);
        let expected = env(&[
            ("GIT_CONFIG_COUNT", "1"),
            ("GIT_CONFIG_KEY_0", "safe.bareRepository"),
            ("GIT_CONFIG_VALUE_0", "explicit"),
        ]);
        assert_eq!(map, expected);
        added(&mut map);
        assert_eq!(map, expected, "adding twice changes nothing");
        removed(&mut map);
        assert!(map.is_empty(), "{map:?}");
    }

    #[test]
    fn existing_entries_are_kept_and_ours_comes_last() {
        let user = env(&[
            ("GIT_CONFIG_COUNT", "2"),
            ("GIT_CONFIG_KEY_0", "user.name"),
            ("GIT_CONFIG_VALUE_0", "me"),
            ("GIT_CONFIG_KEY_1", "SAFE.bareRepository"),
            ("GIT_CONFIG_VALUE_1", "all"),
        ]);
        let mut map = user.clone();
        added(&mut map);
        assert!(!present(&|k| user.get(k).cloned()), "a later `all` wins");
        assert_eq!(map["GIT_CONFIG_COUNT"], "3");
        assert_eq!(map["GIT_CONFIG_KEY_2"], "safe.bareRepository");
        assert_eq!(map["GIT_CONFIG_VALUE_2"], "explicit");
        assert!(present(&|k| map.get(k).cloned()));
        removed(&mut map);
        assert_eq!(map, user);
    }

    #[test]
    fn removing_renumbers_the_entries_after_ours() {
        let mut map = env(&[
            ("GIT_CONFIG_COUNT", "2"),
            ("GIT_CONFIG_KEY_0", "safe.bareRepository"),
            ("GIT_CONFIG_VALUE_0", "explicit"),
            ("GIT_CONFIG_KEY_1", "user.name"),
            ("GIT_CONFIG_VALUE_1", "me"),
        ]);
        removed(&mut map);
        let expected = env(&[
            ("GIT_CONFIG_COUNT", "1"),
            ("GIT_CONFIG_KEY_0", "user.name"),
            ("GIT_CONFIG_VALUE_0", "me"),
        ]);
        assert_eq!(map, expected);
        assert!(remove(&|k| map.get(k).cloned()).is_empty());
    }

    #[test]
    fn a_count_git_would_refuse_is_an_error() {
        for bad in ["x", "-1", "1 ", "99999999999999999999999"] {
            let map = env(&[("GIT_CONFIG_COUNT", bad)]);
            let get = |k: &str| map.get(k).cloned();
            assert!(add(&get).is_err(), "{bad}");
            assert!(!present(&get) && remove(&get).is_empty(), "{bad}");
        }
        let empty = env(&[("GIT_CONFIG_COUNT", "")]);
        assert_eq!(add(&|k| empty.get(k).cloned()).unwrap().len(), 3);
    }
}
