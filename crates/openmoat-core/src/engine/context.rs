//! What an [`EvalContext`] checks and expands: `moved_dirs` validation and the
//! spellings of one rule pattern (moved state and host directories, real paths).

use super::EvalContext;
use crate::paths;
use crate::policy::PolicyError;

impl EvalContext {
    /// Reject [`Self::moved_dirs`] entries whose `default` could alias every
    /// pattern body (empty-after-trim or a bare `/`) or does not look like a
    /// directory (must start with `/` or `~/`). The engine fails closed on such
    /// a context: without validation an empty `default` makes [`Self::spellings`]
    /// emit a spelling under `moved` for every pattern (#399), so a `moved_dirs`
    /// mistake in the caller would silently widen every rule. The CLI legitimately
    /// lists the same `default` twice when the moved directory has a resolved
    /// spelling or comes from both the environment and the recorded host dir,
    /// so a duplicate `default` is kept (its spellings deduped in [`Self::spellings`]).
    pub(crate) fn validate_moved_dirs(&self) -> Result<(), PolicyError> {
        for (default, _) in &self.moved_dirs {
            let trimmed = default.trim();
            let valid = !trimmed.is_empty()
                && trimmed != "/"
                && (trimmed == "~" || trimmed.starts_with("~/") || paths::is_absolute(trimmed));
            if !valid {
                return Err(PolicyError::Rule {
                    rule: "context.moved_dirs".to_owned(),
                    problem: format!(
                        "default directory `{default}` must be absolute (`/…`) or home-rooted (`~/…`), \
                         not empty, whitespace or a bare `/`"
                    ),
                });
            }
        }
        Ok(())
    }

    /// `raw` expanded once per spelling of the home directory and project root
    /// it names ([`paths::expand_pattern`]), and once more per directory in
    /// [`Self::moved_dirs`] it falls under; empty when it names no location.
    /// The policy compiler (`ir`) lowers patterns through the same expansion.
    pub(crate) fn spellings(&self, raw: &str) -> Vec<String> {
        let (negated, body) = crate::pattern::split_negation(raw);
        let bang = if negated { "!" } else { "" };
        let moved = self.moved_dirs.iter().filter_map(|(default, dir)| {
            let rest = body.strip_prefix(default.as_str())?;
            (rest.is_empty() || rest.starts_with('/')).then(|| format!("{bang}{dir}{rest}"))
        });
        let raws: Vec<String> = std::iter::once(raw.to_owned()).chain(moved).collect();
        let projects: Vec<Option<&str>> = match &self.project {
            Some(p) => [Some(p), self.real_project.as_ref()]
                .into_iter()
                .flatten()
                .map(|p| Some(p.as_str()))
                .collect(),
            None => vec![None],
        };
        let mut out = Vec::new();
        for home in [Some(&self.home), self.real_home.as_ref()]
            .into_iter()
            .flatten()
        {
            for project in &projects {
                out.extend(
                    raws.iter()
                        .filter_map(|raw| paths::expand_pattern(raw, home, *project)),
                );
            }
        }
        out.sort();
        out.dedup();
        out
    }
}
