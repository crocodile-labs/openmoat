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
//! left out ([`PUBLIC_TEST_CARDS`]). About one in ten numbers with a brand's
//! prefix passes the Luhn check, so a contiguous run counts only in a card's
//! context: as the value of a card's field (`card=`, `"cardNumber":`, `pan=`,
//! `card[number]=`) or sent with a security code or an expiry date. A bare
//! run in a path, a query or a search is an id (ADR-052, amended in 0.14.1);
//! printed groups (`4000 1234 5678 9017`) are a card wherever they are.
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
    let card_fields = texts.iter().any(|t| names_card_fields(t));
    if texts.iter().any(|t| card_number_in(t, card_fields)) {
        found.push(Class::Card);
    }
    if distinct_emails(texts, BULK_EMAILS) >= BULK_EMAILS {
        found.push(Class::Emails);
    }
    found
}

/// Whether `text` holds a card number (see the module documentation), with
/// only `text` itself as the send.
#[cfg(test)]
pub(crate) fn has_card_number(text: &str) -> bool {
    card_number_in(text, names_card_fields(text))
}

/// Whether `text` holds a card number in a card's context: written in the
/// groups a card is printed in, given as the value of a card's field
/// ([`card_key_before`]), or sent with the other fields of a card
/// (`card_fields`: a security code or an expiry date, [`names_card_fields`]).
/// A bare run of digits is otherwise an id (`/repositories/4000123456789017`,
/// `?id=…`, a search for a job number), which is what such a run in a URL or
/// a query usually is (ADR-052, amended in 0.14.1).
fn card_number_in(text: &str, card_fields: bool) -> bool {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if is_escape(bytes, i) {
            // The hex digits of `%20` or `%3D` are not the start of a number.
            i += 3;
        } else if bytes[i].is_ascii_digit() && starts_number(bytes, i) {
            match card_at(bytes, i) {
                Scan::Card { grouped, end } => {
                    if grouped || card_fields || card_key_before(bytes, i) {
                        return true;
                    }
                    i = end;
                }
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
    /// A card number's digits, `grouped` when written in two or more groups,
    /// ending at `end`.
    Card { grouped: bool, end: usize },
    /// No card here; carry on at this offset.
    Next(usize),
}

/// Most bytes of punctuation between a field's name and its value
/// (`"card":{"number":"`, `card%22%3A%22`).
const MAX_KEY_GAP: usize = 12;
/// Longest field name read before a value.
const MAX_KEY: usize = 32;

/// Whether the number at `start` is the value of a card's field: the name just
/// before it (past `=`, `:`, quotes, brackets, `/` or spaces, and percent
/// escapes of them) holds `card` (`card`, `cardNumber`, `credit_card`,
/// `X-Card`, `/cards/`), or is `cc`, `ccnum`, `ccn`, `ccno` or `pan`, or is
/// `number`/`num`/`no` right after such a name (`card[number]=`,
/// `{"card":{"number":`, `card number 4000…`). Reads a bounded window, so the
/// scan stays linear.
fn card_key_before(bytes: &[u8], start: usize) -> bool {
    let Some((key, key_start)) = key_before(bytes, start) else {
        return false;
    };
    if card_key(&key) {
        return true;
    }
    matches!(key.as_str(), "number" | "num" | "no" | "nr")
        && key_before(bytes, key_start).is_some_and(|(outer, _)| card_key(&outer))
}

/// The name of a card's field, lowercase without `_` and `-`.
fn card_key(key: &str) -> bool {
    key.contains("card") || matches!(key, "cc" | "ccnum" | "ccnumber" | "ccn" | "ccno" | "pan")
}

/// The field name that ends before `at` past at most [`MAX_KEY_GAP`] bytes of
/// punctuation, lowercase without `_` and `-`, and where it starts.
fn key_before(bytes: &[u8], at: usize) -> Option<(String, usize)> {
    let mut end = at;
    let gap_floor = at.saturating_sub(MAX_KEY_GAP);
    loop {
        if end >= 3 && end - 3 >= gap_floor && is_escape(bytes, end - 3) {
            end -= 3;
        } else if end > gap_floor
            && matches!(
                bytes[end - 1],
                b'=' | b':' | b'"' | b'\'' | b'[' | b']' | b'{' | b'/' | b' '
            )
        {
            end -= 1;
        } else {
            break;
        }
    }
    let mut begin = end;
    while begin > 0
        && end - begin < MAX_KEY
        && (bytes[begin - 1].is_ascii_alphanumeric() || matches!(bytes[begin - 1], b'_' | b'-'))
    {
        begin -= 1;
    }
    // `%22card`: the hex digits of an escape are not part of the name
    if begin >= 1 && bytes[begin - 1] == b'%' && end - begin > 2 {
        begin += 2;
    }
    let key: String = bytes[begin..end]
        .iter()
        .filter(|b| !matches!(b, b'_' | b'-'))
        .map(|b| char::from(b.to_ascii_lowercase()))
        .collect();
    (!key.is_empty()).then_some((key, begin))
}

/// Whether `text` names the other fields of a card: a security code (`cvv`,
/// `cvc`, `cvv2`, `cvc2`, `cvn`, `csc`) or an expiry date (`exp`, `expiry`,
/// `expiration`, `expmonth`, `expyear`), as a whole word in any case.
fn names_card_fields(text: &str) -> bool {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .any(|word| CARD_FIELDS.iter().any(|f| word.eq_ignore_ascii_case(f)))
}

/// The words of [`names_card_fields`].
const CARD_FIELDS: &[&str] = &[
    "cvv",
    "cvc",
    "cvv2",
    "cvc2",
    "cvn",
    "csc",
    "exp",
    "expiry",
    "expiration",
    "expmonth",
    "expyear",
];

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
        Scan::Card {
            grouped: group_count > 1,
            end: i,
        }
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
