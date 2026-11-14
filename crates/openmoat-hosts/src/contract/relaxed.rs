//! The keys of a host's hook file that may drift while the guard keeps
//! deciding ([`InstallSpec::relaxed_keys`](super::InstallSpec::relaxed_keys)),
//! and how the lock compares them
//! ([`InstallSpec::relaxed_check`](super::InstallSpec::relaxed_check)).

/// A key of a host's hook file that may drift while the guard keeps deciding
/// ([`InstallSpec::relaxed_keys`](super::InstallSpec::relaxed_keys)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelaxedKey {
    /// The key's path from the top of the file, its names joined by `.`
    /// (`model.name` is `{"model": {"name": …}}`).
    pub path: &'static str,
    /// The only kind of value it may change to.
    pub shape: KeyShape,
}

impl RelaxedKey {
    /// A key whose value is a string.
    #[must_use]
    pub const fn string(path: &'static str) -> Self {
        Self {
            path,
            shape: KeyShape::String,
        }
    }

    /// A key whose value is `true` or `false`.
    #[must_use]
    pub const fn flag(path: &'static str) -> Self {
        Self {
            path,
            shape: KeyShape::Bool,
        }
    }

    /// A key whose value is a string, a number or a boolean.
    #[must_use]
    pub const fn scalar(path: &'static str) -> Self {
        Self {
            path,
            shape: KeyShape::Scalar,
        }
    }

    /// A key whose value may be anything: one the host reads only for how it
    /// looks or words its replies, or for whether it asks the person itself.
    #[must_use]
    pub const fn any(path: &'static str) -> Self {
        Self {
            path,
            shape: KeyShape::Any,
        }
    }

    /// A key whose value is one of `values`.
    #[must_use]
    pub const fn one_of(path: &'static str, values: &'static [&'static str]) -> Self {
        Self {
            path,
            shape: KeyShape::OneOf(values),
        }
    }

    /// A list that may change while it still holds every rule OpenMoat wrote
    /// into it.
    #[must_use]
    pub const fn keeping_written_rules(path: &'static str) -> Self {
        Self {
            path,
            shape: KeyShape::KeepsWrittenRules,
        }
    }
}

/// The kind of value a [`RelaxedKey`] may hold. A value of any other kind, an
/// object or a list among them, is drift like any other key's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyShape {
    /// A JSON string.
    String,
    /// A JSON boolean.
    Bool,
    /// A JSON string, number or boolean: a value with nothing inside it.
    Scalar,
    /// Any JSON value.
    Any,
    /// A JSON string among these.
    OneOf(&'static [&'static str]),
    /// A JSON list holding every rule OpenMoat wrote into it, and at least
    /// one: with no record of them a changed list cannot be told from a
    /// removed rule. Only [`RelaxedCheck::ByKey`] compares it.
    KeepsWrittenRules,
}

impl KeyShape {
    /// Whether a key of this kind may be removed: any but
    /// [`Self::KeepsWrittenRules`], whose removal takes OpenMoat's rules too.
    #[must_use]
    pub fn may_be_removed(self) -> bool {
        self != Self::KeepsWrittenRules
    }

    /// Whether `value` is of this kind, `written` being the rules OpenMoat
    /// wrote into the file ([`Self::KeepsWrittenRules`]).
    #[must_use]
    pub fn holds(self, value: &serde_json::Value, written: &[String]) -> bool {
        match self {
            Self::String => value.is_string(),
            Self::Bool => value.is_boolean(),
            Self::Scalar => value.is_string() || value.is_number() || value.is_boolean(),
            Self::Any => true,
            Self::OneOf(values) => value.as_str().is_some_and(|v| values.contains(&v)),
            Self::KeepsWrittenRules => value.as_array().is_some_and(|list| {
                !written.is_empty()
                    && written
                        .iter()
                        .all(|rule| list.iter().any(|v| v.as_str() == Some(rule.as_str())))
            }),
        }
    }
}

/// How the lock tells drift in a host's [`RelaxedKey`]s from any other change
/// ([`InstallSpec::relaxed_check`](super::InstallSpec::relaxed_check)).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum RelaxedCheck {
    /// The lock pins the digest of the file with each relaxed key that holds
    /// a value of its shape taken out; a drifted file whose rest has that
    /// digest changed only relaxed keys (Gemini CLI). Keys may be nested to
    /// any depth.
    #[default]
    Rest,
    /// The lock pins the digest of each top-level key's value, and of each
    /// key's of the one object the dotted relaxed keys are in; a drifted file
    /// is relaxed when every key whose digest changed is a relaxed key whose
    /// value now holds its shape, or is removed (Claude Code, whose
    /// `permissions.deny` may change while it keeps OpenMoat's rules). Keys
    /// are at most one level deep, all under one object.
    ByKey,
}

impl RelaxedCheck {
    /// The object the dotted keys of `keys` are in, for [`Self::ByKey`]:
    /// `permissions` for `permissions.allow`; `None` when every key is at the
    /// top.
    #[must_use]
    pub fn parent(keys: &[RelaxedKey]) -> Option<&'static str> {
        keys.iter()
            .find_map(|key| key.path.split_once('.').map(|(parent, _)| parent))
    }
}
