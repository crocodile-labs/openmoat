# ADR-123: Secrets hidden by an encoding, and data in host names

Status: accepted · Date: 2026-11-24 · Builds on ADR-112 (default rules from outside
benchmarks, its future work), ADR-047 (`encoded-egress`), ADR-052 (atoms that count
only where a rule names them)

## Context

ADR-112 left two classes of agent-egress-bench's attacks to future work
(docs/BENCHMARKS.md, "What is not stopped"):

- **Encoded secrets in URLs.** A known token or credential hidden by base64, hex (with
  or without a `-` between bytes), URL encoding once, twice or three times, URL encoding
  over base64, or zero-width characters between its letters. `token-egress` and
  `credential-egress` read the text as written; `encoded-egress` (ADR-047) applies only
  after the session read a secret, and judges length, not content.
- **Data in host names.** `https://<hex or base32>.exfil.example/`: the lookup alone hands
  the labels to the domain's name server, and a `GET` to an unlisted host is a read the
  default leaves to the agent (`fetch: defer`).

ADR-112 asked for a benign corpus before any rule: signed URLs, OAuth values, page
cursors, data URLs, CDN and preview hosts, since agents open those while testing a
deploy.

## Decision

1. **Decode, then read with the same shapes.** `token::decode` undoes, in layers up to
   four deep, URL encoding, base64 and base64url (a path's `/` may also split base64url
   values, so each piece is tried), hex bare or with one `-` or `:` between every byte,
   and zero-width characters (U+200B–U+200D, U+2060, U+FEFF, the soft hyphen). It decodes
   runs of 16 characters or more and keeps only results that are UTF-8 text with no
   control character but white space, so a hash, an id, an image or a signature decodes
   to nothing. At most 64 texts per value; a value over 16 KiB is not decoded. The
   decoded texts are read by the same `token` shapes and `token::credentials` as plain
   text, in the same places (`egress::sends`: URLs, web search queries, the arguments of
   a command that connects).
2. **`@encoded-secret <kind> <host>`, held for review.** A kind found only in the
   decoded text, going to a host that is not its service's (a credential, nor this
   machine), becomes the atom; `encoded-secret-egress` in the default policy holds it for
   review. Not a deny: a decoded text is a reading of what is sent, two layers of
   guessing removed from what the host receives, and a person can see the URL. A kind
   the plain text already shows is left to `token-egress` and `credential-egress`.
3. **`@host-data <host>`, held for review, for unlisted hosts.** A host whose labels below
   its last two hold hex or base32 of 16 characters or more, 24 or more letters and digits
   with at least four of each and no hyphen, or two or more hex or base32 labels of 8
   characters or more holding 24 together (an `xn--` prefix read past) becomes the atom;
   `hostname-data` holds it for review. The engine keeps it only when no allow rule lists
   the host (by name or pattern): a team that allows `*.its-cdn.example` is never asked.
   IP addresses and loopback are none.
4. **Both atoms count only where a rule names them** (ADR-052's `counts_where_named`): a
   policy without `encoded-secret-egress` or `hostname-data` decides as before, and no
   atom falls to a review catch-all.
5. **Fixtures.** Every encoding and host shape of the benchmark's cases is an attack
   fixture, with fake values (`AKIA0000FAKE0000TEST` encoded); the benign fixtures hold a
   page cursor in base64, a data URL image, a SHA-256 and a UUID in a path, an AWS
   presigned URL (the key id goes to AWS, its owner), a GitHub token in a Basic header to
   GitHub, and CDN, CloudFront, project-ref, deploy-preview and Codespaces hosts.

## Consequences

- agent-egress-bench: the before and after numbers are in docs/BENCHMARKS.md; no benign
  case of the corpus gained a review or a deny.
- What is still not stopped: a secret in an encoding this does not undo (gzip, a
  custom alphabet, ROT13, encryption), a shape `token` does not know (crypto keys, seed
  phrases, ADR-112 §5), data cut into labels shorter than 8 characters or of plain
  letters (`ghp-xxxx.yyyyzzzz…`), and a DNS-over-HTTPS query carrying a name (a message
  body in base64url is binary, not text).
- Hosts that are long letter-and-digit ids are held when no allow rule lists them: AWS
  Lambda function URLs, IPFS gateway hosts named by a CID. A team that uses them adds an
  allow rule for the domain, which also stops the hold. CDN hosts with short ids, hyphenated
  preview hosts and lowercase-letter project refs are not held (the benign fixtures).
- The decoding runs on every send the egress checks read; its limits (16 KiB, 64 texts,
  four layers) bound the cost per call.
