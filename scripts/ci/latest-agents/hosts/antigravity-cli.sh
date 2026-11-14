# shellcheck shell=bash
# shellcheck disable=SC2034,SC2154 # latest-agents.sh sources this file: its variables
# Antigravity CLI's own steps in the weekly latest-agent check
# (scripts/ci/latest-agents.sh sources this file; the record is in agents.json,
# written from the host's spec).

install_agent() {
    # The installer URL is from third-party guides. Its only install option is
    # `-d <dir>`; `HOME` is a throwaway, so a profile it edits goes with it. The
    # script is printed by its sha256 before it runs. It installs the version
    # its manifest names (`<its DOWNLOAD_BASE_URL>/manifests/<platform>.json`)
    # and has no channel to choose: on 2026-11-10 that was 1.5.5, newer than
    # the 1.5.3 the changelog's CLI section lists last (its 2.x entries are the
    # Antigravity app's, not the CLI's).
    local script="$root/agy-install.sh"
    curl -fsSL --retry 3 -o "$script" https://antigravity.google/cli/install.sh
    if command -v sha256sum >/dev/null; then sha256sum "$script"; else shasum -a 256 "$script"; fi
    bash "$script" -d "$HOME/.local/bin"
    bin="$HOME/.local/bin/agy"
}

prepare_agent() {
    # The Gemini API at the fake server (`GOOGLE_GEMINI_BASE_URL` below), with
    # `modelProvider: gemini` so no sign-in is asked, and the project trusted;
    # unverified: taken from the documentation, the first run proves it.
    # The run reaching the fake API shows this file is read from `$HOME`: the
    # documentation says `GEMINI_API_KEY` does nothing without it. The
    # provider is the record's (`values.model_provider`).
    local provider
    provider=$(check get "$agent" values.model_provider)
    printf '{"modelProvider": "%s", "trustedWorkspaces": ["%s"]}\n' "$provider" "$project" \
        >"$HOME/.gemini/antigravity-cli/settings.json"
    # A probe entry beside OpenMoat's, with events that need no matcher and the
    # documented example matchers: it tells why no hook ran (agy_probe.py).
    python3 -I "$lib/agy_probe.py" install "$HOME/.gemini/config/hooks.json" "$out/agy-probe.log"
    # agy 1.5.5 refuses a `run_command` call without `toolSummary` and
    # `WaitMsBeforeAsync` in its own tool validation, before any hook runs
    # (run 43151268400: "missing properties 'toolSummary', 'WaitMsBeforeAsync'").
    start_fake "$out/fake-api.log" python3 -I "$lib/fake_gemini.py" \
        --call run_command="{\"CommandLine\": \"$denied\", \"toolSummary\": \"probe\", \"WaitMsBeforeAsync\": 0}" \
        --then run_command="{\"CommandLine\": \"$harmless\", \"toolSummary\": \"after-call capture\", \"WaitMsBeforeAsync\": 0}"
}

# agy_run <output> <log file> [flag...]: one headless `agy -p` turn against the
# fake Gemini API, agy's own log at <log file> (`--log-file`, in the CLI
# reference, used only if `--help` lists it), and the files it opens recorded
# by strace where the runner has it (<output>.strace). The time limit must end
# agy, not only strace: `bounded` signals the process it starts, so in front of
# strace it ends strace alone unless strace takes agy with it (`--kill-on-exit`,
# strace 6.6 and later, listed by `strace --help`; Ubuntu 24.04 ships 6.8). A
# strace without it starts agy under the limit itself, inside the trace (the
# same perl as `bounded`: strace cannot start a shell function), with a longer
# one on strace for a child agy leaves behind.
agy_run() {
    local output=$1 log=$2 run=(bounded 180) logging=() files
    shift 2
    if command -v strace >/dev/null; then
        files=(-f -qq -e trace=%file -o "$output.strace")
        if strace --help 2>&1 | grep -q -- '--kill-on-exit'; then
            run=(bounded 180 strace --kill-on-exit "${files[@]}")
        else
            run=(bounded 200 strace "${files[@]}"
                perl -e 'alarm shift; exec @ARGV or die "exec: $!\n"' 180)
        fi
    fi
    if grep -q -- '--log-file' "$out/agy-help.txt" 2>/dev/null; then
        logging=(--log-file "$log")
    fi
    (cd "$project" && GEMINI_API_KEY=fake-key GOOGLE_GEMINI_BASE_URL="http://127.0.0.1:$fake_port" \
        "${run[@]}" "$bin" -p "run it" ${logging[@]+"${logging[@]}"} "$@") \
        </dev/null >"$output" 2>&1 || true
}

# agy_diagnose: what the run shows of why a hook did or did not start, in the
# job log and in the artefact's agy-* files. Never fails the job.
agy_diagnose() {
    local trace
    echo "-- agy diagnostics (the artefact's agy-* files)"
    cp "$HOME/.gemini/config/hooks.json" "$out/agy-hooks.json" 2>/dev/null || true
    cp "$HOME/.gemini/antigravity-cli/settings.json" "$out/agy-settings.json" 2>/dev/null || true
    if grep -q "$marker" "$out/fake-api.log" 2>/dev/null; then
        echo "--    the denied command RAN: the fake key's text reached the model"
    else
        echo "--    the fake key's text never reached the model"
    fi
    echo "--    what the tool results said:"
    grep '^  result ' "$out/fake-api.log" 2>/dev/null | sed "s/$marker/<the fake key>/g" | cut -c1-300 || true
    # Every file the run wrote in the throwaway home, by name.
    find "$HOME" -path "$project/.git" -prune -o -type f -newer "$out/audit-before.json" -print \
        2>/dev/null | sort >"$out/agy-files.txt" || true
    echo "--    files written in the throwaway home:"
    cat "$out/agy-files.txt"
    if [ -s "$out/agy-cli.log" ]; then
        echo "--    lines of agy's log that name hooks or plugins:"
        # Into a file first: `head` closing the pipe early would end grep
        # with SIGPIPE, which `pipefail` turns into exit 141.
        grep -i -n -E 'hook|plugin' "$out/agy-cli.log" | cut -c1-300 >"$out/agy-log-hooks.txt" || true
        if [ -s "$out/agy-log-hooks.txt" ]; then
            head -60 "$out/agy-log-hooks.txt"
        else
            echo "      (none)"
        fi
    else
        echo "--    agy wrote no log at $out/agy-cli.log"
    fi
    trace="$out/agent.txt.strace"
    if [ -f "$trace" ]; then
        # Which hook and configuration files it looked for, and what it found.
        grep -E 'hooks\.json|/\.gemini/|/\.agents/' "$trace" | sed -E 's/^[0-9]+ +//' |
            cut -c1-240 | sort -u >"$out/agy-opened.txt" || true
        echo "--    configuration files agy looked for (strace):"
        head -80 "$out/agy-opened.txt"
    else
        echo "--    strace is not on this runner: which hook file agy read is not recorded"
    fi
    # `/hooks` lists the loaded hooks; print mode answers read-only slash
    # commands (changelog 1.1.11), which may or may not include this one.
    (cd "$project" && GEMINI_API_KEY=fake-key GOOGLE_GEMINI_BASE_URL="http://127.0.0.1:$fake_port" \
        bounded 60 "$bin" -p "/hooks") </dev/null >"$out/agy-hooks.txt" 2>&1 || true
    echo "--    agy -p /hooks:"
    head -60 "$out/agy-hooks.txt"
    python3 -I "$lib/agy_probe.py" report "$out/agy-probe.log" "$out/captured"
    if [ ! -s "$out/agy-probe.log" ]; then
        # Diagnostic only: the audit log was read before it, so it cannot pass the job.
        echo "--    no hook ran: once more without --dangerously-skip-permissions"
        agy_run "$out/agent-2.txt" "$out/agy-cli-2.log"
        # `|| true`: `head` may close the pipe before sed is done (exit 141).
        sed "s/$marker/<the fake key>/g" "$out/agent-2.txt" | head -40 || true
        echo "--    without the flag:"
        python3 -I "$lib/agy_probe.py" report "$out/agy-probe.log" "$out/captured"
    fi
}

load_hook() {
    # One headless turn (`-p`) against the fake Gemini API; `--dangerously-skip-permissions`
    # so no prompt waits for a person. Whether hooks run in this mode is not
    # documented: agy 1.5.5 ran none here in the first run, so the run is
    # traced and its log kept, and agy_diagnose says what it shows.
    bounded 60 "$bin" --help </dev/null >"$out/agy-help.txt" 2>&1 || true
    agy_run "$out/agent.txt" "$out/agy-cli.log" --dangerously-skip-permissions
    cat "$out/agent.txt"
    # Only this run counts: the audit log is read before the diagnostic run.
    audit "$out/audit-after.json"
    agy_diagnose
    check denied "$host" "$out/audit-before.json" "$out/audit-after.json" "$out/agent.txt=$marker"
}

# probe_agent <log prefix> <seconds>: the agent, with the hook as it is now,
# asked once to run the probe; as load_hook starts it, without its checks.
probe_agent() {
    local log=$1 limit=$2
    start_fake "$log-api.log" python3 -I "$lib/fake_gemini.py" \
        --call run_command="{\"CommandLine\": \"$probe_cmd\", \"toolSummary\": \"probe\", \"WaitMsBeforeAsync\": 0}"
    (cd "$project" && GEMINI_API_KEY=fake-key GOOGLE_GEMINI_BASE_URL="http://127.0.0.1:$fake_port" \
        bounded "$limit" "$bin" -p "run it" --dangerously-skip-permissions) </dev/null >"$log-agent.txt" 2>&1 || true
}
