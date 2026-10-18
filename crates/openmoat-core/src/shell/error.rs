//! Why a command line could not be classified safely.

use super::{MAX_ATOMS, MAX_DEPTH, MAX_DIRS};
use crate::lexer::LexError;

/// Why a command line could not be classified safely; the engine turns it into `ask`.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ClassifyError {
    #[error(transparent)]
    Lex(#[from] LexError),
    #[error("command nesting deeper than {MAX_DEPTH}")]
    TooDeep,
    #[error("command expands to more than {MAX_ATOMS} actions")]
    TooManyActions,
    #[error("cannot interpret `{option}` for `{program}`")]
    ShellOption { program: String, option: String },
    #[error("`{program} {option}` runs code from a file or module the command line names")]
    LoadsCode { program: String, option: String },
    #[error("`{0}` names a path relative to a directory that is not known")]
    UnknownDirectory(String),
    #[error("`cd` may lead to more than {MAX_DIRS} directories")]
    TooManyDirectories,
    #[error("unbalanced parentheses")]
    UnbalancedParens,
    #[error("the shell runs text from `{0}` that the command line does not show")]
    UnknownStdin(String),
    #[error("`{0}` depends on a variable whose value is not known")]
    UnknownValue(String),
    #[error("a variable set on the line may hold more than {MAX_DIRS} combinations of values")]
    TooManyValues,
}

impl ClassifyError {
    /// The line could not be read in full, or a limit of the classifier was
    /// reached: what follows may be missing from the atoms, and any line can
    /// be padded to get here, so the call asks instead of taking the policy's
    /// catch-all. The other errors are one part the classifier cannot model;
    /// the rest of the line is classified around it.
    pub(crate) fn asks(&self) -> bool {
        matches!(
            self,
            Self::Lex(_)
                | Self::TooDeep
                | Self::TooManyActions
                | Self::TooManyDirectories
                | Self::TooManyValues
        )
    }
}
