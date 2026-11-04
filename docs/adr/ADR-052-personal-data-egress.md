# ADR-052: Payment card numbers leaving the machine are denied; mail address lists are an atom no default rule names

Status: accepted · Date: 2026-11-04 · Builds on ADR-025 and ADR-047

## Context

`token-egress` and `placeholder-egress` (POLICY.md §6) read what a call sends (a URL a
fetch, network or MCP tool opens or names, a web search query, the arguments of a command
that connects to a host with every command piped into it) and deny a known token going to
a host that is not its service's. Nothing looked at personal data in the same text. An
agent asked to "test the checkout against staging", to "post the failing rows to the issue"
or steered by a prompt injection can put a customer's card number or a list of users'
mail addresses into a `curl -d`, a `WebFetch` query or a web search. Those are leaks a
person would never approve, and the guard already has the text in hand.

The product direction (ADR-025) is to deny what must never happen and otherwise stay quiet
and leave the call to the agent's own prompt. A detector that prompts on a single mail
address (a commit author, `--user me@example.com`, a sign-up in a test) or on any long
number (a timestamp, a snowflake id, an order id) would break that and teach people to
approve without reading.

The guard has a 15 ms p95 budget per call; core has no regex engine and no I/O, and builds
for `wasm32`.

## Decision

1. **Same path, new atom.** `engine/egress.rs` scans the texts of each send it already
   builds for tokens with a second, pure detector (`personal.rs`). Each class found becomes
   `@pii-egress <class> <host>` for every host of that send except this machine
   (`localhost`, `*.localhost`, `127.0.0.0/8`, `::1`; other spellings of a loopback
   address are not recognised and count as leaving). A host with no readable name is
   `(unknown-host)`, as for tokens. Allowed hosts are not exempt: a `net` allow says a host
   may be reached, not that it may hold card numbers. The value never goes into an atom,
   so it never reaches a reason or the audit log.
2. **Card numbers (`card`).** 13 to 19 digits, contiguous or in the groups cards are
   printed in (`4-4-4-4`, `4-4-4-4-3`, `4-4-4-1…4`, `4-6-4`, `4-6-5`) with one kind of
   separator (space, `-`, a query's `+` or `%20`); not preceded by a letter, digit, `_` or
   `.` (a percent escape counts as punctuation) and not followed by a letter, digit or `_`;
   the issuer prefix and length of Visa, Mastercard (51–55, 2221–2720), Amex, Discover,
   JCB, Diners Club or UnionPay; and the Luhn check. Numbers payment processors publish
   for their test modes are left out: they identify nobody, and they are by far the most
   common card numbers in development traffic. The default policy denies the class
   (`card-egress`): a real card number has no business leaving a developer's machine
   through an agent, and the checks make a false positive rare (below).
3. **Mail address lists (`emails`).** Ten or more distinct addresses (case-insensitive)
   in one send. One to a few addresses are everyday work; ten distinct people in one
   request is a list of people. That still is not near-certain exfiltration (a CODEOWNERS
   sync, a mailing-list tool, test fixtures), so **the default policy names no rule for
   it** and it changes no decision unless a person adds one (`ask` or `deny`).
4. **An atom counts only where a rule names it.** The engine drops a `@pii-egress` atom
   that no rule of the policy matches, instead of giving it the catch-all verdict like
   other atoms. So the classes are configured with ordinary shell rules (on: a rule in any
   list; off: no rule; the verdict: the list it is in) and need no new schema; a policy
   written before this ADR, which names no such atom, decides every call exactly as
   before, and `emails` without a rule stays silent under any catch-all. `openmoat policy
   upgrade` offers `card-egress` to an existing policy.
5. **National id formats are not detected.** Most have no checksum, and those that do
   (a few European ids) are short digit runs whose patterns would match ordinary numbers
   far more often than ids. Names, postal addresses and phone numbers likewise.
6. **Cost.** Both scans are one forward pass over the bytes. A card candidate reads at
   most five groups and 19 digits before it gives up and the scan moves to the next
   group, so a run of digit groups is linear; each `@` of an address is examined once and
   the parts around it stop at the neighbouring `@`. No allocation happens for text
   without a candidate; the address set is capped at ten entries. A unit test runs both on
   400 000-byte adversarial inputs.

## Consequences

- A card number an agent sends as it is, by mistake or by a naive instruction, is denied
  wherever it goes but this machine: in a body, a header, JSON, a query, grouped with
  spaces or dashes, URL-escaped punctuation around it, through a pipe into `curl`, in a
  web search, to an allowed host.
- About one in ten random numbers with a card brand's prefix and length passes the Luhn
  check, so a 13 to 19 digit id starting `2`–`6` sent to a remote host is denied about
  that often. Ids that start with `1` (epoch timestamps in any unit, most snowflake ids),
  have more than 19 digits, are glued to letters (UUIDs, hashes) or are grouped otherwise
  (phone numbers, dates, Amazon order ids) never match. A person whose workflow sends such
  ids can narrow the rule (`@pii-egress card evil.example`) or remove it.
- Not seen: file contents (`curl -d @file`, `-T`, `-F f=@file`), here-documents,
  variables, MCP arguments other than URLs, and encoded, compressed, encrypted or split
  numbers. This is a safety net for the common case, not a boundary against a determined
  exfiltration, which `net` denying unlisted hosts and the operating-system layers
  address. POLICY.md §4.4 and THREAT_MODEL.md §5 say so.
- The test-number list is a widening of what the detector would otherwise flag; it holds
  only numbers processors publish, each checked in a unit test to pass the brand and Luhn
  checks, so it cannot be used to carry a real number.
