use super::Trim;

fn trim(expansion: &str, value: &str) -> Option<String> {
    let (trim, used) = Trim::parse(expansion)?;
    assert_eq!(used, expansion.len(), "{expansion}");
    trim.apply(value)
}

#[test]
fn trims_as_the_shell_does() {
    for (expansion, value, expected) in [
        ("#*:}", "a:b:c", "b:c"),
        ("##*:}", "a:b:c", "c"),
        ("%:*}", "a:b:c", "a:b"),
        ("%%:*}", "a:b:c", "a"),
        ("%.md}", "docs/a.md", "docs/a"),
        ("##*/}", "src/a/b.rs", "b.rs"),
        ("#?}", "abc", "bc"),
        ("#x}", "abc", "abc"),
        ("#}", "abc", "abc"),
        ("%%*}", "abc", ""),
        ("#*}", "abc", "abc"),
        ("#*:}", "no-colon", "no-colon"),
        ("#é}", "éa", "a"),
    ] {
        assert_eq!(
            trim(expansion, value).as_deref(),
            Some(expected),
            "${{x{expansion} of {value}"
        );
    }
}

#[test]
fn patterns_it_does_not_read_stay_unknown() {
    for expansion in [
        "#[0-9]}", "#\"*\"}", "#'*'}", "#\\*}", "#$y}", "#`y`}", "#${y}}", ":-x}", "/a/b}", "^}",
        "#*",
    ] {
        assert!(Trim::parse(expansion).is_none(), "{expansion}");
    }
}

#[test]
fn a_long_value_is_not_trimmed() {
    let long = "a".repeat(5000);
    assert_eq!(trim("#*a}", &long), None);
}
