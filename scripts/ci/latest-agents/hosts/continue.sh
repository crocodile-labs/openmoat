# shellcheck shell=bash
# shellcheck disable=SC2034,SC2154 # latest-agents.sh sources this file: its variables
# The Continue CLI's own steps in the weekly latest-agent check
# (scripts/ci/latest-agents.sh sources this file; the record is in agents.json,
# written from the host's spec): a canary, not an install.

canary() {
    local package latest tarball calls
    begin install
    package=$(check get "$agent" package)
    latest=$(npm view "$package@latest" version)
    mkdir -p "$agent_dir"
    npm pack "$package@$latest" --pack-destination "$agent_dir" >/dev/null
    tarball=$(find "$agent_dir" -name '*.tgz' | head -1)
    tar -xzf "$tarball" -C "$agent_dir"
    version=$latest
    relation=$(check version "$agent" "$latest" | cut -f2)
    begin "cn runs no hooks yet"
    # `cn` 1.5.47 ships a hook runner (src/hooks/) that nothing outside it
    # calls: its tool executor sends `PreToolUse` only to its git-ai checkpoint.
    # The day a file outside src/hooks/ and the tests calls `firePreToolUse`,
    # OpenMoat can set `cn` up, and this fails to say so.
    [ -d "$agent_dir/package/src" ] || {
        echo "FAIL  the cn package no longer ships src/; read its dist/ by hand"
        return 1
    }
    calls=$(grep -rl 'firePreToolUse(' "$agent_dir/package/src" |
        grep -v -e '/src/hooks/' -e '\.test\.' -e '/test/' -e '/__tests__/' || true)
    if [ -n "$calls" ]; then
        echo "FAIL  cn $latest calls its PreToolUse hook (in $calls): give continue_cli.rs an InstallSpec"
        return 1
    fi
    echo "ok    cn $latest still runs no hooks; OpenMoat sets nothing up for it"
}
