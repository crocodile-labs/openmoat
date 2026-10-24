# From installation to a blocked attack, with the real Claude Code (docs/DEMO.md).
# Record from the repository root, with the key already in your shell's
# environment, which VHS's shell inherits:
#
#   export ANTHROPIC_API_KEY=…    # or CLAUDE_CODE_OAUTH_TOKEN from `claude setup-token`
#   vhs scripts/demo/install-demo-live.tape
#
# Never add an `Env` line for the key: it would be written into this file. Without
# a key the script says so and runs the scripted demo instead. The run makes real,
# billed model calls; the model's choices differ between runs, so the video shows
# whatever this session did.

Output docs/assets/install-demo-live.mp4
Output docs/assets/install-demo-live.gif

Require bash
Require cargo
Require claude

Set Shell bash
Set FontSize 18
Set Width 1400
Set Height 860
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms

# Setup, not recorded: a short prompt and the release build the script installs.
Hide
Type "export PS1='$ ' DEMO_PACE=2.5"
Enter
Type "cargo build --release -p openmoat --quiet && clear && echo build-ready"
Enter
Wait+Screen@15m /build-ready/
Type "clear"
Enter
Sleep 500ms
Show

Type "scripts/demo/install-demo.sh --live"
Sleep 600ms
Enter
Wait+Screen@10m /Done\..The.throwaway.home.is.deleted/
Sleep 5s
