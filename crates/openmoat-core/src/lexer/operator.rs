//! Control and redirect operators: `|`, `&&`, `;`, `>>`, `<<`, ….

use super::{Lexer, Operator};

/// A character that starts an operator. The run loop hands one of these to
/// [`Lexer::operator`], so the operator match covers every case it can get.
#[derive(Debug, Clone, Copy)]
pub(super) enum First {
    Bar,
    Amp,
    Semi,
    Open,
    Close,
    Less,
    Greater,
}

impl First {
    /// The operator that `c` starts, if any.
    pub(super) fn of(c: char) -> Option<Self> {
        Some(match c {
            '|' => Self::Bar,
            '&' => Self::Amp,
            ';' => Self::Semi,
            '(' => Self::Open,
            ')' => Self::Close,
            '<' => Self::Less,
            '>' => Self::Greater,
            _ => return None,
        })
    }
}

impl Lexer {
    /// Lex the operator at the current position, which starts with `first`.
    pub(super) fn operator(&mut self, first: First) {
        // Optional leading descriptor digits belong to a redirect: `2>&1`, `3<file`.
        if let Some(w) = &self.current {
            let is_fd = !w.text.is_empty() && w.text.chars().all(|c| c.is_ascii_digit());
            let is_redirect = matches!(first, First::Less | First::Greater);
            if is_fd && is_redirect && !w.quoted {
                self.current = None;
                self.boundaries.clear();
            }
        }
        self.bump();
        let next = self.peek();
        let op = match (first, next) {
            (First::Bar, Some('|')) => {
                self.bump();
                Operator::Or
            }
            // `|&` pipes stderr too; for what reaches the next command it is a pipe.
            (First::Bar, Some('&')) => {
                self.bump();
                Operator::Pipe
            }
            (First::Bar, _) => Operator::Pipe,
            (First::Amp, Some('&')) => {
                self.bump();
                Operator::And
            }
            (First::Amp, Some('>')) => {
                self.bump();
                if self.peek() == Some('>') {
                    self.bump();
                    Operator::RedirectAppend
                } else {
                    Operator::RedirectOut
                }
            }
            (First::Amp, _) => Operator::Background,
            (First::Semi, _) => {
                while self.peek() == Some(';') {
                    self.bump();
                }
                Operator::Sequence
            }
            (First::Open, _) => Operator::OpenParen,
            (First::Close, _) => Operator::CloseParen,
            (First::Less, Some('<')) if self.peek_at(1) == Some('<') => {
                self.pos += 2;
                Operator::HereString
            }
            (First::Less, Some('<')) => {
                self.bump();
                let strip_tabs = if self.peek() == Some('-') {
                    self.bump();
                    true
                } else {
                    false
                };
                self.flush_word();
                self.start_heredoc(strip_tabs);
                return;
            }
            (First::Less | First::Greater, Some('&')) => {
                self.bump();
                Operator::DuplicateDescriptor
            }
            (First::Less, Some('>')) => {
                self.bump();
                Operator::RedirectReadWrite
            }
            (First::Less, _) => Operator::RedirectIn,
            (First::Greater, Some('>')) => {
                self.bump();
                Operator::RedirectAppend
            }
            (First::Greater, Some('|')) => {
                self.bump();
                Operator::RedirectOut
            }
            (First::Greater, _) => Operator::RedirectOut,
        };
        self.push_operator(op);
    }
}
