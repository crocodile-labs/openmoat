//! Personal data in text on its way out of the machine (ADR-052): payment card
//! numbers and lists of mail addresses.
//!
//! [`super::engine`]'s egress check hands this module the same text it scans
//! for tokens (a URL, a web search query, the arguments of a command that
//! connects to a host) and turns each [`Class`] found into a
//! `@pii-egress <class> <host>` atom. Both scans are one pass over the bytes,
//! with no allocation for text that holds no candidate, so they stay inside the
//! guard's per-call budget.
//!
//! A card number is 13 to 19 digits, written contiguous or in the groups cards
//! are printed in (`4-4-4-4`, `4-6-5`, …) with one kind of separator (a space,
//! `-`, or a space as a query spells it, `+` or `%20`), between word
//! boundaries, with the issuer prefix and length of a card brand, and passing
//! the Luhn check. A run of digits longer than 19 is never one, nor digits
//! glued to letters (a commit SHA, a UUID), nor a decimal fraction. Card
//! numbers that payment processors publish for testing identify nobody and are
//! left out ([`PUBLIC_TEST_CARDS`]).
//!
//! A mail address is `local@domain.tld`; one is ordinary (a commit author, a
//! sign-up in a test, `--user me@example.com`), so only [`BULK_EMAILS`] or more
//! distinct addresses in one send count.

/// Personal data found in what a call sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Class {
    /// A payment card number.
    Card,
    /// [`BULK_EMAILS`] or more distinct mail addresses.
    Emails,
}

impl Class {
    /// The class's word in a `@pii-egress <class> <host>` atom.
    pub(crate) fn id(self) -> &'static str {
        match self {
            Self::Card => "card",
            Self::Emails => "emails",
        }
    }
}

/// Fewest distinct mail addresses in one send that count as a list of people.
pub(crate) const BULK_EMAILS: usize = 10;

/// Longest card number (ISO/IEC 7812).
const MAX_DIGITS: usize = 19;
/// Shortest card number a brand of [`brand_length`] issues.
const MIN_DIGITS: usize = 13;
/// Most groups a printed card number has (`4-4-4-4-3`).
const MAX_GROUPS: usize = 5;

/// Card numbers payment processors (Stripe, Adyen, Braintree and others) publish
/// for their test modes: sending one shares nothing about anyone.
const PUBLIC_TEST_CARDS: &[&str] = &[
    "4242424242424242",
    "4111111111111111",
    "4012888888881881",
    "4222222222222",
    "4000056655665556",
    "4000000000000002",
    "4000000000000069",
    "4000000000000077",
    "4000000000000119",
    "4000000000000127",
    "4000000000000341",
    "4000000000003220",
    "4000000000009995",
    "4000002500003155",
    "4000002760003184",
    "5555555555554444",
    "5105105105105100",
    "5454545454545454",
    "2223003122003222",
    "5200828282828210",
    "378282246310005",
    "371449635398431",
    "378734493671000",
    "6011111111111117",
    "6011000990139424",
    "3056930009020004",
    "30569309025904",
    "38520000023237",
    "36227206271667",
    "3566002020360505",
    "3530111333300000",
    "6200000000000005",
];

/// Every class of personal data in `texts`, the words or URL of one send.
pub(crate) fn classes_in(texts: &[&str]) -> Vec<Class> {
    let mut found = Vec::new();
    if texts.iter().any(|t| has_card_number(t)) {
        found.push(Class::Card);
    }
    if distinct_emails(texts, BULK_EMAILS) >= BULK_EMAILS {
        found.push(Class::Emails);
    }
    found
}

/// Whether `text` holds a card number (see the module documentation).
pub(crate) fn has_card_number(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if is_escape(bytes, i) {
            // The hex digits of `%20` or `%3D` are not the start of a number.
            i += 3;
        } else if bytes[i].is_ascii_digit() && starts_number(bytes, i) {
            match card_at(bytes, i) {
                Scan::Card => return true,
                // Another number may start at the next group (`1-4000…`);
                // each start reads at most `MAX_GROUPS` groups, so the scan
                // stays linear.
                Scan::Next(next) => i = next,
            }
        } else {
            i += 1;
        }
    }
    false
}

/// What reading a candidate number found.
enum Scan {
    Card,
    /// No card here; carry on at this offset.
    Next(usize),
}

/// Whether a number may start at `at`: the byte before it is no letter, digit
/// or `_` (part of a word, a hex id) and no `.` (a decimal fraction or an
/// address). A `%XX` escape before it is punctuation in a query.
fn starts_number(bytes: &[u8], at: usize) -> bool {
    let Some(&before) = at.checked_sub(1).and_then(|i| bytes.get(i)) else {
        return true;
    };
    let escaped = at >= 3 && is_escape(bytes, at - 3);
    escaped || !(before.is_ascii_alphanumeric() || before == b'_' || before == b'.')
}

/// Whether a percent escape (`%` and two hex digits) starts at `at`.
fn is_escape(bytes: &[u8], at: usize) -> bool {
    bytes.get(at) == Some(&b'%')
        && bytes
            .get(at + 1..at + 3)
            .is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit))
}

/// The separator that starts at `at`, and its length: a space, `-`, `+` (a
/// space in a query) or `%20`.
fn separator_at(bytes: &[u8], at: usize) -> Option<(&[u8], usize)> {
    match bytes.get(at)? {
        b' ' | b'-' | b'+' => Some((&bytes[at..=at], 1)),
        b'%' if bytes.get(at + 1..at + 3) == Some(b"20") => Some((&bytes[at..at + 3], 3)),
        _ => None,
    }
}

/// Read the groups of digits from `start` and judge them.
fn card_at(bytes: &[u8], start: usize) -> Scan {
    let mut digits = [0u8; MAX_DIGITS];
    let mut count = 0;
    let mut groups = [0usize; MAX_GROUPS];
    let mut group_count = 0;
    let mut separator: Option<&[u8]> = None;
    let mut second_group = None;
    let mut i = start;
    loop {
        let run = bytes[i..].iter().take_while(|b| b.is_ascii_digit()).count();
        if count + run > MAX_DIGITS || group_count == MAX_GROUPS {
            // Too long for a card: a long numeric id. Skip its digits.
            return Scan::Next(second_group.unwrap_or(i + run));
        }
        digits[count..count + run].copy_from_slice(&bytes[i..i + run]);
        count += run;
        groups[group_count] = run;
        group_count += 1;
        i += run;
        let next = separator_at(bytes, i).filter(|(sep, len)| {
            separator.is_none_or(|s| s == *sep)
                && bytes.get(i + len).is_some_and(u8::is_ascii_digit)
        });
        let Some((sep, len)) = next else { break };
        separator = Some(sep);
        i += len;
        second_group.get_or_insert(i);
    }
    let ends = bytes
        .get(i)
        .is_none_or(|b| !(b.is_ascii_alphanumeric() || *b == b'_'));
    let number = &digits[..count];
    if ends && printed_layout(&groups[..group_count]) && is_card(number) {
        Scan::Card
    } else {
        Scan::Next(second_group.unwrap_or(i))
    }
}

/// Whether `groups` (digits per group) is how a card is written: one run, or
/// `4-4-4-…` with a short last group, or the `4-6-4`/`4-6-5` of Amex and Diners.
fn printed_layout(groups: &[usize]) -> bool {
    match groups {
        [_] | [4, 6, 4 | 5] => true,
        [4, 4, 4, last] => (1..=4).contains(last),
        [4, 4, 4, 4, last] => (1..=3).contains(last),
        _ => false,
    }
}

/// Whether `number` (ASCII digits) has a brand's prefix and length, passes the
/// Luhn check, and is no published test number.
fn is_card(number: &[u8]) -> bool {
    (MIN_DIGITS..=MAX_DIGITS).contains(&number.len())
        && brand_length(number)
        && luhn(number)
        && !PUBLIC_TEST_CARDS.iter().any(|t| t.as_bytes() == number)
}

/// Whether the issuer prefix of `number` belongs to a card brand that issues
/// numbers of its length (`number` holds at least [`MIN_DIGITS`] digits).
fn brand_length(number: &[u8]) -> bool {
    let prefix = |len: usize| {
        number[..len]
            .iter()
            .fold(0u32, |acc, d| acc * 10 + u32::from(d - b'0'))
    };
    let len = number.len();
    let long = (16..=19).contains(&len);
    match number[0] {
        // Visa
        b'4' => matches!(len, 13 | 16 | 19),
        // Mastercard, and its 2-series
        b'5' => (51..=55).contains(&prefix(2)) && len == 16,
        b'2' => (2221..=2720).contains(&prefix(4)) && len == 16,
        // Amex; JCB; Diners Club
        b'3' => {
            (matches!(prefix(2), 34 | 37) && len == 15)
                || ((3528..=3589).contains(&prefix(4)) && long)
                || (((300..=305).contains(&prefix(3)) || matches!(prefix(2), 36 | 38 | 39))
                    && (14..=19).contains(&len))
        }
        // Discover; UnionPay
        b'6' => {
            (prefix(4) == 6011 || (644..=649).contains(&prefix(3)) || matches!(prefix(2), 62 | 65))
                && long
        }
        _ => false,
    }
}

/// The Luhn (mod 10) check of ISO/IEC 7812-1 over ASCII digits.
fn luhn(number: &[u8]) -> bool {
    let sum: u32 = number
        .iter()
        .rev()
        .enumerate()
        .map(|(i, d)| {
            let d = u32::from(d - b'0');
            match (i % 2 == 1, d * 2) {
                (false, _) => d,
                (true, doubled) if doubled > 9 => doubled - 9,
                (true, doubled) => doubled,
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

/// How many distinct mail addresses `texts` hold, counting no further than
/// `enough`. Letter case does not make two addresses distinct.
pub(crate) fn distinct_emails(texts: &[&str], enough: usize) -> usize {
    let mut seen: Vec<String> = Vec::new();
    for text in texts {
        for address in emails(text) {
            let address = address.to_ascii_lowercase();
            if !seen.contains(&address) {
                seen.push(address);
                if seen.len() >= enough {
                    return seen.len();
                }
            }
        }
    }
    seen.len()
}

/// Every mail address in `text`: a local part of letters, digits and
/// `. _ % + -`, an `@`, and a dotted domain whose last label is two or more
/// letters. Each `@` is looked at once and the parts around it stop at the
/// next `@`, so this is linear in `text`.
fn emails(text: &str) -> impl Iterator<Item = &str> {
    let bytes = text.as_bytes();
    bytes
        .iter()
        .enumerate()
        .filter(|(_, b)| **b == b'@')
        .filter_map(move |(at, _)| {
            let local = bytes[..at]
                .iter()
                .rev()
                .take_while(|b| b.is_ascii_alphanumeric() || b"._%+-".contains(b))
                .count();
            let domain = bytes[at + 1..]
                .iter()
                .take_while(|b| b.is_ascii_alphanumeric() || b"-.".contains(b))
                .count();
            let local_part = &text[at - local..at];
            let domain_part = text[at + 1..at + 1 + domain].trim_end_matches('.');
            (valid_local(local_part) && valid_domain(domain_part))
                .then(|| &text[at - local..at + 1 + domain_part.len()])
        })
}

fn valid_local(local: &str) -> bool {
    !local.is_empty() && !local.starts_with('.') && !local.ends_with('.')
}

fn valid_domain(domain: &str) -> bool {
    let tld = domain.rsplit('.').next().unwrap_or_default();
    domain.contains('.')
        && domain
            .split('.')
            .all(|l| !l.is_empty() && !l.starts_with('-') && !l.ends_with('-'))
        && tld.len() >= 2
        && tld.bytes().all(|b| b.is_ascii_alphabetic())
}

#[cfg(test)]
mod tests;
