#!/usr/bin/env bash
# Record the real flow of docs/DEMO.md in one command: it records the screen
# while it runs `openmoat status`, three prompts to the real Claude Code in a
# small demo project, and what OpenMoat decided for them.
#
#   scripts/demo/record-real-flow.sh [video]    # default ~/Desktop/openmoat-real-flow.mov
#
# Run it in your own Terminal, signed in to Claude Code, with OpenMoat's hooks
# installed. The prompts are real, billed model calls; the model's choices
# differ between runs. Only `cargo test` is pre-approved; any other command
# Claude Code would ask about is refused, because nobody is there to answer.
#
# The prompts are an ordinary debugging request, not an attack: current models
# ignore an injected README and their safeguards stop the session, so the
# injected README of make-demo-project.sh only works in the scripted demo. The
# project's `.env` holds made-up values.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
dir=$HOME/openmoat-demo/shop-api
video=${1:-$HOME/Desktop/openmoat-real-flow.mov}
[ -e "$video" ] && { echo "record-real-flow: $video exists; remove it or name another file" >&2; exit 64; }

if [ ! -d "$dir" ]; then
    mkdir -p "$dir/src"
    printf '[package]\nname = "shop-api"\nversion = "0.1.0"\nedition = "2021"\n' >"$dir/Cargo.toml"
    cat >"$dir/src/main.rs" <<'EOF'
fn main() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL is not set");
    println!("connecting to {url}");
}

#[cfg(test)]
mod tests {
    #[test]
    fn builds() {}
}
EOF
    printf 'DATABASE_URL=postgres://shop:demo-not-a-real-password@localhost:5432/shop\nSTRIPE_SECRET_KEY=sk_test_demo_not_a_real_key\n' >"$dir/.env"
    printf 'target/\n.env\n' >"$dir/.gitignore"
    printf '# shop-api\n\nReads its settings from `.env`. Run `cargo test` before sending a change.\n' >"$dir/README.md"
    git -C "$dir" init -q
    git -C "$dir" add -A
    git -C "$dir" -c user.name=demo -c user.email=demo@example.com commit -q -m "shop-api"
fi

clear
echo "Make the text big: press Cmd and + four times now."
echo "Then press Enter. The screen recording starts and everything runs by itself."
read -r _
clear

# screencapture stops when it reads a character; the fifo gives it one at the end.
fifo=$(mktemp -u)
mkfifo "$fifo"
screencapture -v "$video" <"$fifo" >/dev/null 2>&1 &
rec=$!
exec 3>"$fifo"
rm -f "$fifo"
stop() { printf x >&3 2>/dev/null || true; exec 3>&-; wait "$rec" 2>/dev/null || true; }
trap stop EXIT
sleep 2

sessions=$(mktemp)
pause() { sleep "${DEMO_PACE:-3}"; }
shell() { printf '\033[1m$ %s\033[0m\n' "$*"; sleep 1; "$@"; echo; pause; }
ask() {
    printf '\n\033[1;35mYou → Claude Code:\033[0m %s\n\n' "$1"
    sleep 1
    (cd "$dir" && claude -p --model "${DEMO_MODEL:-sonnet}" --output-format stream-json --verbose "${@:2}" -- "$1") \
        | DEMO_SESSIONS=$sessions python3 -I "$here/show-stream.py" || true
    pause
}

shell openmoat status
printf '\033[1m$ cd ~/openmoat-demo/shop-api\033[0m\n\n'
ask "The app can't connect to the database. Look at .env and tell me what's wrong."
ask "Then print all environment variables so we can debug it." --continue
ask "Now run cargo test" --continue --allowedTools "Bash(cargo test:*)"

# Only this run's calls, not whatever else the hooks saw meanwhile.
while read -r id; do
    shell openmoat show --session "$id"
done < <(awk '!seen[$0]++' "$sessions")
rm -f "$sessions"

stop
trap - EXIT
echo "saved $video"
