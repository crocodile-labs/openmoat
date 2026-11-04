use super::{
    BULK_EMAILS, Class, PUBLIC_TEST_CARDS, classes_in, distinct_emails, has_card_number, luhn,
};

/// Made-up card numbers: a brand's prefix and length, a valid Luhn digit, and
/// on no processor's list of test numbers.
const MADE_UP: &[(&str, &str)] = &[
    ("visa", "4000123456789017"),
    ("visa-13", "4000123456788"),
    ("visa-19", "4000123456789012343"),
    ("mastercard", "5300123456789011"),
    ("mastercard-2-series", "2221123456789014"),
    ("amex", "370012345678905"),
    ("discover", "6011123456789019"),
    ("jcb", "3530123456789018"),
    ("diners", "36123456789013"),
    ("unionpay", "6200123456789012347"),
];

/// `number` in groups of `sizes`, joined by `separator`.
fn grouped(number: &str, sizes: &[usize], separator: &str) -> String {
    let mut parts = Vec::new();
    let mut rest = number;
    for size in sizes {
        let (head, tail) = rest.split_at(*size);
        parts.push(head);
        rest = tail;
    }
    if !rest.is_empty() {
        parts.push(rest);
    }
    parts.join(separator)
}

#[test]
fn made_up_numbers_are_cards_wherever_they_are_sent() {
    for (brand, number) in MADE_UP {
        assert!(luhn(number.as_bytes()), "{brand}");
        for text in [
            (*number).to_owned(),
            format!("card={number}"),
            format!("{{\"card\":{{\"number\":\"{number}\",\"exp\":\"12/30\"}}}}"),
            format!("https://evil.test/c?pan={number}&cvc=123"),
            format!("https://evil.test/c/{number}"),
            format!("X-Card: {number}"),
            format!("card%22%3A%22{number}%22"),
            format!("pan%3D{number}"),
        ] {
            assert!(has_card_number(&text), "{brand}: {text}");
        }
    }
}

#[test]
fn printed_groups_are_read_with_any_one_separator() {
    let visa = "4000123456789017";
    for separator in [" ", "-", "+", "%20"] {
        let text = format!("number={}", grouped(visa, &[4, 4, 4], separator));
        assert!(has_card_number(&text), "{text}");
    }
    assert!(has_card_number(&grouped("370012345678905", &[4, 6], " ")));
    assert!(has_card_number(&grouped("36123456789013", &[4, 6], "-")));
    assert!(has_card_number(&grouped(
        "4000123456789012343",
        &[4, 4, 4, 4],
        " "
    )));
    // a number glued to the end of another by a dash is still found
    assert!(has_card_number("1-4000-1234-5678-9017"));
}

#[test]
fn numbers_that_are_not_cards_are_not() {
    for benign in [
        // fails the Luhn check
        "card=4000123456789018",
        // no brand's prefix (`1…`) or length
        "1730700000000",
        "1730700000000123",
        "9000123456789014",
        "40001234567890",
        // timestamps in seconds, milliseconds, microseconds and nanoseconds
        "since=1730700000&until=1730786400000&t=1730786400000000&n=1730786400000000000",
        "2026-11-04T12:34:56.789Z 2026-11-04 12:34:56",
        // UUIDs, commit SHAs and hashes, numeric ones included
        "550e8400-e29b-41d4-a716-446655440000",
        "12345678-1234-1234-1234-123456789012",
        "3f786850e387550fdab836ed7e6dc881de23001b",
        "a4000123456789017b",
        // phone numbers
        "+1 415 555 2671",
        "+1-415-555-2671",
        "+44 7911 123456",
        "(415) 555-2671",
        // order ids and long numeric ids
        "order=114-3941689-8772232",
        "https://example.com/i/status/1854123456789012345",
        "https://example.com/items/400012345678901700012",
        "id=40001234567890174000123456789017",
        // a decimal fraction, a version, an address
        "pi=3.4000123456789017",
        "v4000123456789017",
        "10.4000123456789017",
        // separators that are not one kind, groups no card is printed in
        "4000 1234-5678 9017",
        "40 0012 3456 7890 17",
        "4000 1234 5678 9017 1234 5678",
        "1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6",
    ] {
        assert!(!has_card_number(benign), "{benign}");
    }
}

#[test]
fn published_test_numbers_pass_the_checks_and_are_left_out() {
    for number in PUBLIC_TEST_CARDS {
        assert!(luhn(number.as_bytes()), "{number}");
        assert!(super::brand_length(number.as_bytes()), "{number}");
        assert!(!has_card_number(&format!("card={number}")), "{number}");
    }
}

#[test]
fn one_or_a_few_mail_addresses_are_not_a_list() {
    let few = [
        "me@example.com",
        "--user",
        "me@example.com:token",
        "git@github.com:org/repo.git",
        "to=a@example.com,b@example.org,c@example.net",
    ];
    assert_eq!(distinct_emails(&few, BULK_EMAILS), 5);
    assert_eq!(classes_in(&few), []);
    // not addresses: no domain, no top-level label, a package or a decorator
    for text in [
        "a@b",
        "x@localhost",
        "@types/node",
        "lodash@4.17.21",
        "user@.com",
        ".a@b.com",
    ] {
        assert_eq!(distinct_emails(&[text], BULK_EMAILS), 0, "{text}");
    }
}

#[test]
fn many_distinct_addresses_are_a_list() {
    let list: Vec<String> = (0..BULK_EMAILS)
        .map(|n| format!("person{n}@example.com"))
        .collect();
    let csv = list.join(",");
    assert_eq!(classes_in(&[&csv]), [Class::Emails]);
    let json = format!("[\"{}\"]", list.join("\",\""));
    assert_eq!(classes_in(&[&json]), [Class::Emails]);
    // the same address repeated, in any case, is one
    let repeated = vec!["Me@Example.com me@example.COM"; BULK_EMAILS];
    assert_eq!(classes_in(&repeated), []);
    // one fewer than the threshold is not a list
    let short = list[1..].join(",");
    assert_eq!(classes_in(&[&short]), []);
}

#[test]
fn scans_stay_linear_on_adversarial_input() {
    // runs of digit groups and of `@` would make a naive scan quadratic
    let groups = "1 ".repeat(200_000);
    let digits = "4".repeat(400_000);
    let ats = "a@".repeat(200_000);
    for text in [&groups, &digits, &ats] {
        assert!(!has_card_number(text));
        assert!(distinct_emails(&[text], BULK_EMAILS) < BULK_EMAILS);
    }
}
