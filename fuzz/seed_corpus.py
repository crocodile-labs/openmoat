#!/usr/bin/env python3
"""Seed the fuzz corpora from the repository's own test data.

decide_shell and literal_pattern start from every shell command in the
conformance fixtures; host_payload from the golden host payloads; policy_parse
from the default policy; proxy_parse from a few request heads and a
ClientHello. Run from the repository root:

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
for path in glob.glob(os.path.join(ROOT, "tests", "fixtures", "hosts", "*", "*.json")):
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
for path in glob.glob(os.path.join(ROOT, "tests", "fixtures", "hosts", "openclaw", "*.json")):
    with open(path, "rb") as f:
        write("openclaw_json5", f.read())
print(f"seeded {len(commands)} commands")
