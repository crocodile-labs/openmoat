"""Generate docs/assets/how-it-works-{light,dark}.svg for the OpenMoat README.

Usage: python3 scripts/how-it-works-svg.py docs/assets

The example commands and verdicts come from the README's "Example verdicts" table;
keep them in step when the default policy changes.
"""
import sys
from xml.sax.saxutils import escape

SANS = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif"
MONO = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"

THEMES = {
    "light": dict(bg="#fafaf9", dot="#dcdcd7", card="#ffffff", line="#dad8d3", text="#171717",
                  muted="#525252", chip="#f1f0ec", arrow="#a3a3a3",
                  allow="#1f7a3c", defer="#2457c5", ask="#9a6400", deny="#b42318",
                  accent="#2A4525"),
    "dark": dict(bg="#111111", dot="#1c1c1c", card="#171717", line="#262626", text="#ededed",
                 muted="#a3a3a3", chip="#222222", arrow="#5c5c5c",
                 allow="#7fd88f", defer="#8ab4f8", ask="#f2c14e", deny="#ff8a7a",
                 accent="#95B670"),
}

W, H = 800, 790


def text(x, y, s, size=13, fill="text", font=SANS, weight=None, anchor="middle"):
    w = f' font-weight="{weight}"' if weight else ""
    return (f'<text x="{x}" y="{y}" text-anchor="{anchor}" font-family="{font}" '
            f'font-size="{size}"{w} fill="{{{fill}}}">{escape(s)}</text>')


def box(x, y, w, h, stroke="line", fill="card", r=12, sw=1):
    return (f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{r}" '
            f'fill="{{{fill}}}" stroke="{{{stroke}}}" stroke-width="{sw}"/>')


def arrow(x1, y1, x2, y2):
    return (f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{{arrow}}" '
            f'stroke-width="1.5" marker-end="url(#head)"/>')


def chip(cx, y, label):
    w = len(label) * 7.0 + 24
    return (f'<rect x="{cx - w / 2:.1f}" y="{y}" width="{w:.1f}" height="26" rx="13" '
            f'fill="{{chip}}" stroke="{{line}}"/>'
            + text(cx, y + 17.5, label, size=12, fill="muted"))


def build():
    p = []
    cx = W / 2

    # 1. The agent.
    p.append(box(40, 24, 720, 96))
    p.append(text(cx, 54, "AI coding agent", size=18, weight="700"))
    p.append(text(cx, 78, "Claude Code · Codex · Cursor · OpenClaw · Copilot CLI · pi · Gemini CLI",
                  size=13, fill="muted"))
    p.append(text(cx, 102, "wants to run a command, read or write a file, open a URL or call an MCP tool",
                  size=13))

    # 2. The hook.
    p.append(arrow(cx, 120, cx, 168))
    p.append(text(cx + 12, 149, "the agent's own hook, before the call runs", size=12,
                  fill="muted", anchor="start"))

    # 3. OpenMoat.
    p.append(box(40, 172, 720, 150, stroke="accent", sw=2))
    p.append(text(cx, 204, "OpenMoat", size=20, weight="700"))
    p.append(text(cx, 228, "checks what the call would actually do against one local policy",
                  size=13, fill="muted"))
    row1 = ["Secrets and keys", "Unknown hosts", "Destructive commands"]
    row2 = ["Git hooks and startup files", "MCP servers", "Changes to OpenMoat"]
    for row, y in ((row1, 246), (row2, 282)):
        widths = [len(s) * 7.0 + 24 for s in row]
        total = sum(widths) + 12 * (len(row) - 1)
        x = cx - total / 2
        for s, w in zip(row, widths):
            p.append(chip(x + w / 2, y, s))
            x += w + 12

    # 4. Four verdicts.
    cols = [
        ("allow", ["npm test", "git status"], ["runs as normal"]),
        ("defer", ["npm install left-pad", "git push origin main"],
         ["no rule: your agent's", "own prompt decides"]),
        ("ask", ["> .git/hooks/pre-commit", "core.hooksPath"],
         ["outlives the session:", "you decide, reason shown"]),
        ("deny", ["cat ~/.ssh/id_rsa", "git reset --hard"],
         ["never runs; the agent is", "told the rule and why"]),
    ]
    bw, gap = 165, 20
    top = 376
    p.append(arrow(cx, 322, cx, 346))
    xs = [40 + i * (bw + gap) for i in range(4)]
    p.append(f'<line x1="{xs[0] + bw / 2}" y1="346" x2="{xs[3] + bw / 2}" y2="346" '
             f'stroke="{{arrow}}" stroke-width="1.5"/>')
    for x, (verdict, examples, outcome) in zip(xs, cols):
        mx = x + bw / 2
        p.append(arrow(mx, 346, mx, top - 4))
        p.append(box(x, top, bw, 150, stroke=verdict, sw=1.5))
        p.append(text(mx, top + 28, verdict, size=17, fill=verdict, font=MONO, weight="700"))
        for i, e in enumerate(examples):
            p.append(text(mx, top + 56 + i * 20, e, size=11, font=MONO))
        for i, o in enumerate(outcome):
            p.append(text(mx, top + 112 + i * 18, o, size=12, fill="muted"))

    # 5. What allowed code still runs inside.
    y5 = 580
    allow_x = xs[0] + bw / 2
    p.append(f'<path d="M{allow_x} {top + 150} V{y5 - 22} H{cx} V{y5 - 4}" fill="none" '
             f'stroke="{{arrow}}" stroke-width="1.5" marker-end="url(#head)"/>')
    p.append(text(allow_x + 10, top + 176, "allowed code still runs inside", size=12,
                  fill="muted", anchor="start"))
    half = 354
    p.append(box(40, y5, half, 96))
    p.append(text(40 + half / 2, y5 + 28, "OS sandbox", size=15, weight="700"))
    p.append(text(40 + half / 2, y5 + 52, "Claude Code, Codex and Cursor's own, or", size=12, fill="muted"))
    p.append(text(40 + half / 2, y5 + 70, "openmoat run: no secret reads, no writes", size=12, fill="muted"))
    p.append(text(40 + half / 2, y5 + 88, "outside the project", size=12, fill="muted"))
    x2 = 40 + half + 12
    p.append(box(x2, y5, half, 96))
    p.append(text(x2 + half / 2, y5 + 28, "Egress proxy", size=15, weight="700"))
    p.append(text(x2 + half / 2, y5 + 52, "inside openmoat run: only the hosts the", size=12, fill="muted"))
    p.append(text(x2 + half / 2, y5 + 70, "policy lists; metadata and private", size=12, fill="muted"))
    p.append(text(x2 + half / 2, y5 + 88, "addresses refused; every connection kept", size=12, fill="muted"))

    # 6. Audit log.
    y6 = 700
    p.append(box(40, y6, 720, 64, fill="chip"))
    p.append(text(cx, y6 + 27, "Audit log", size=15, weight="700"))
    p.append(text(cx, y6 + 49, "every decision, kept locally and hash-chained: openmoat show, replay, report",
                  size=12, fill="muted"))

    return "\n".join(p)


def render(theme):
    c = THEMES[theme]
    body = build().format(**c)
    label = ("An AI coding agent wants to run a tool call. Through the agent's own hook, OpenMoat "
             "checks it against one local policy before it runs: npm test is allowed, a call with "
             "no rule is left to the agent's own prompt, a git hook write asks you, and reading "
             "~/.ssh/id_rsa is denied. Allowed code still runs inside the OS sandbox and the "
             "egress proxy, and every decision goes into a local hash-chained audit log.")
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" role="img" aria-label="{escape(label)}">
<defs>
<pattern id="dots" width="16" height="16" patternUnits="userSpaceOnUse"><circle cx="2" cy="2" r="1.2" fill="{c["dot"]}"/></pattern>
<marker id="head" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 z" fill="{c["arrow"]}"/></marker>
</defs>
<rect width="{W}" height="{H}" fill="{c["bg"]}"/>
<rect width="{W}" height="{H}" fill="url(#dots)"/>
{body}
</svg>
'''


out = sys.argv[1]
for t in THEMES:
    with open(f"{out}/how-it-works-{t}.svg", "w") as f:
        f.write(render(t))
print("ok")
