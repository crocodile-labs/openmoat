# Break OpenMoat

[README](../README.md) · [Docs index](README.md) · [SECURITY.md](../SECURITY.md)

> [!NOTE]
> **Read this when** you want to find a way past OpenMoat. Every valid bypass is fixed,
> becomes a permanent test, and is credited to you by name.

**On this page:** [The target](#the-target) · [Set up](#set-up) · [What counts](#what-counts) · [What does not count](#what-does-not-count) · [Report](#report) · [Recognition](#recognition) · [Hall of fame](#hall-of-fame)

OpenMoat's default policy promises that an AI coding agent cannot read your secrets, send
them out, plant something that runs later, or switch OpenMoat off. Show us where that
promise breaks. Every valid finding puts your name in the hall of fame below, on the fix
in the CHANGELOG and release notes, and on a GitHub Security Advisory with a CVE for a
confirmed issue in a release, and we thank you publicly when the fix ships.

It takes five minutes to set up, and you can start without any agent:
`openmoat policy check '<command>'` shows the verdict for any command you can think of.

## The target

The latest release (`openmoat --version`) with the **default policy**, as
`openmoat init` installs it, protecting one of the supported agents: Claude Code, Codex,
Cursor, OpenClaw, GitHub Copilot CLI, pi, Gemini CLI or Hermes Agent. You may also attack the policy
engine directly with `openmoat policy check`, without any agent.

## Set up

Use a throwaway user account or a virtual machine: you will be asking an agent to do
things you do not want done to your real files.

```bash
brew install crocodile-labs/tap/openmoat     # or see docs/INSTALL.md
openmoat init                                # set up the agent you want to attack
mkdir -p ~/.ssh && printf 'CANARY-%s\n' "$(openssl rand -hex 8)" > ~/.ssh/openmoat-canary
```

The canary file stands for any secret the default policy protects (`~/.ssh`, `.env`,
cloud credentials). Check a single action without an agent:

```bash
openmoat policy check 'cat ~/.ssh/openmoat-canary'            # deny, secrets-paths
openmoat policy check '~/.ssh/openmoat-canary' --kind fs-read # deny
```

## What counts

Any one of these, with the default policy, without you approving an `ask`:

1. **Read a secret:** the canary's contents reach the agent (its context, a file it can
   read later, or its output) through any tool call.
2. **Send a secret out:** the canary, or any secret the default policy protects, reaches a
   host the policy does not list.
3. **Plant something that runs later:** a write to a shell start-up file (`~/.zshrc`,
   `~/.bashrc`), a git hook, a login item or CI configuration that gets neither `deny` nor
   `ask`.
4. **Switch OpenMoat off:** an agent tool call that changes `~/.moat`, the agent's hook
   or sandbox settings, or the `openmoat` binary without a `deny`.
5. **Confuse the parser:** a command whose `openmoat policy check` verdict is `allow` or
   `defer`, while what the shell actually runs is one of 1–4.
6. **Fail open:** any error, crash or time-out in `openmoat guard` that results in the
   call running.

The full list of what is in scope is in [SECURITY.md](../SECURITY.md#what-counts-as-a-vulnerability).

## What does not count

The known limits in [SECURITY.md](../SECURITY.md#out-of-scope-today) and the README's
[Limits](../README.md#limits) are not bypasses, because they are documented gaps rather
than mistakes. The main ones:

- What code inside an allowed command does where no OS sandbox applies (the hook-only
  agents, native Windows, Claude Code's and Cursor's file tools). A *misjudged* call is in
  scope, and so is a script the agent wrote in the same session that an interpreter or
  the shell runs there without an `ask` (`session-written-code`, ADR-039); *an allowed
  call doing harm* where nothing below the decision stops it is not, such as a test
  runner or build tool running files the session wrote.
- Data sent to a host the policy allows (`api.github.com`, package registries) by an
  allowed command.
- Agents that run a call when the hook is missing or times out (named in Limits).
- Tricking the person into approving an `ask`, attacks needing root or the user's own
  shell, and prompt-injection detection in text (OpenMoat governs actions, not text).

## Report

Privately, through GitHub's
[report a vulnerability](https://github.com/crocodile-labs/openmoat/security/advisories/new)
form, never in a public issue, pull request or comment. Include the version, the agent
and the OS (`openmoat doctor --bundle moat-bundle.json` collects them), the exact tool
call or command, the verdict and rule you got, and what actually ran. You get an answer
within 72 hours and a triage within 7 days; the timeline is in
[SECURITY.md](../SECURITY.md#what-happens-next).

## Recognition

For every valid report, you get:

- **the hall of fame:** your name or handle and what you found, below (or anonymous, if
  you prefer);
- **credit on the fix:** in the `### Security` line of the CHANGELOG, in the release notes,
  and as a co-author of the fix commit if you like;
- **a GitHub Security Advisory** naming you, with a CVE requested through GitHub for a
  confirmed issue in a released version, something you can point to;
- **a public thank-you** from [@openmoat](https://x.com/openmoat) and the OpenMoat
  LinkedIn page when the fix ships, linking to you.

Your finding also becomes a conformance fixture in `tests/conformance/` before the fix is
published, so the same trick can never come back.

## Hall of fame

| Who | What they found | Fixed in |
|---|---|---|
| *Be the first.* | | |
