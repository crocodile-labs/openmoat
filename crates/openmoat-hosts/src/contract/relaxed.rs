//! The keys of a host's hook file that may drift while the guard keeps
//! deciding ([`InstallSpec::relaxed_keys`](super::InstallSpec::relaxed_keys)).

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
}

impl KeyShape {
    /// Whether `value` is of this kind.
    #[must_use]
    pub fn holds(self, value: &serde_json::Value) -> bool {
        match self {
            Self::String => value.is_string(),
            Self::Bool => value.is_boolean(),
        }
    }
}
