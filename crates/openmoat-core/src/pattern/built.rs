//! The globs one policy compile built, kept by what each was built from.
//!
//! Building a glob (globset's parse and its regex text, a few allocations per
//! character) was most of `CompiledPolicy::compile`, and the default policy
//! names many texts more than once: an anchor's list under two kinds, a
//! `dir/**` beside its `dir`, a pattern in a deny rule and in the taint list,
//! one shell program (`{gh,*/gh}`) in many rules. A text built once is shared
//! by every pattern that names it, and so is its regex once a candidate needs
//! it. A glob is the same for the same text and options, so sharing changes
//! no answer; a text that does not build is not kept, so each pattern that
//! names it reports its own error, where it always did.

use std::collections::HashMap;
use std::sync::Arc;

use super::LazyGlob;

/// The globs of one compile, by text: path globs per case mode, and shell
/// words, which are built with their own options.
#[derive(Debug, Default)]
pub(crate) struct Built {
    /// Path globs, case-sensitive (`[0]`) and case-insensitive (`[1]`).
    paths: [HashMap<String, Arc<LazyGlob>>; 2],
    /// Shell words, by the word as the pattern spells it.
    words: HashMap<String, Arc<LazyGlob>>,
}

impl Built {
    /// The path glob for `glob` in this case mode: the one already built, or
    /// `build`'s, kept when it succeeds.
    pub(super) fn path<E>(
        &mut self,
        glob: &str,
        case_insensitive: bool,
        build: impl FnOnce() -> Result<LazyGlob, E>,
    ) -> Result<Arc<LazyGlob>, E> {
        get_or_build(&mut self.paths[usize::from(case_insensitive)], glob, build)
    }

    /// The glob for the shell word `word`, as [`Self::path`].
    pub(super) fn word<E>(
        &mut self,
        word: &str,
        build: impl FnOnce() -> Result<LazyGlob, E>,
    ) -> Result<Arc<LazyGlob>, E> {
        get_or_build(&mut self.words, word, build)
    }
}

fn get_or_build<E>(
    map: &mut HashMap<String, Arc<LazyGlob>>,
    key: &str,
    build: impl FnOnce() -> Result<LazyGlob, E>,
) -> Result<Arc<LazyGlob>, E> {
    if let Some(found) = map.get(key) {
        return Ok(Arc::clone(found));
    }
    let glob = Arc::new(build()?);
    map.insert(key.to_owned(), Arc::clone(&glob));
    Ok(glob)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::Built;
    use crate::pattern::word::WordGlob;
    use crate::pattern::{GlobPattern, ShellPattern, Token};

    /// The same text in the same case mode is built once and shared; another
    /// case mode, or a text that does not build, is not.
    #[test]
    fn a_text_is_built_once_per_case_mode() {
        let mut built = Built::default();
        let mut path = |raw: &str, ci: bool| GlobPattern::compile_in(raw, ci, &mut built);
        let tree = path("/h/.ssh/**", true).unwrap();
        let excluded = path("!/h/.ssh/**", true).unwrap();
        let folder = path("/h/.ssh", true).unwrap();
        let exact_case = path("/h/.ssh/**", false).unwrap();
        assert!(Arc::ptr_eq(&tree.matcher, &excluded.matcher));
        assert!(Arc::ptr_eq(tree.dir.as_ref().unwrap(), &folder.matcher));
        assert!(!Arc::ptr_eq(&tree.matcher, &exact_case.matcher));
        assert!(excluded.negated && !tree.negated);
        assert!(tree.is_match("/H/.SSH") && !exact_case.is_match("/H/.SSH"));
        for raw in ["/h/{a", "/h/{a/**"] {
            let alone = GlobPattern::compile(raw, true).unwrap_err().to_string();
            let first = GlobPattern::compile_in(raw, true, &mut built).unwrap_err();
            let again = GlobPattern::compile_in(raw, true, &mut built).unwrap_err();
            assert_eq!(first.to_string(), alone);
            assert_eq!(again.to_string(), alone);
        }
        let pr = ShellPattern::compile_in("{gh,*/gh} pr", &mut built).unwrap();
        let api = ShellPattern::compile_in("{gh,*/gh} api *", &mut built).unwrap();
        let word = |p: &ShellPattern| match &p.tokens[0] {
            Token::One(WordGlob::Glob(glob), _) => Arc::clone(glob),
            other => panic!("{other:?}"),
        };
        assert!(Arc::ptr_eq(&word(&pr), &word(&api)));
        assert!(pr.is_match(&["/usr/bin/gh".into(), "pr".into()]));
        assert!(api.is_match(&["gh".into(), "api".into(), "x".into()]));
        let err = ShellPattern::compile_in("a{b", &mut built)
            .unwrap_err()
            .to_string();
        assert_eq!(err, ShellPattern::compile("a{b").unwrap_err().to_string());
    }
}
