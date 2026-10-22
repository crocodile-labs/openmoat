# From installation to a blocked attack (docs/DEMO.md). Record from the
# repository root:
#
#   vhs scripts/demo/install-demo.tape
#
# The timing comes from the script (DEMO_PACE between steps): the tape types the
# command once and waits for the script's last line, so nothing here is staged.

Output docs/assets/install-demo.mp4
Output docs/assets/install-demo.gif

Require bash
Require cargo

Set Shell bash
Set FontSize 24
Set Width 1600
Set Height 1000
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

Type "scripts/demo/install-demo.sh"
Sleep 600ms
Enter
Wait+Screen@5m /Done\..The.throwaway.home.is.deleted/
Sleep 5s
