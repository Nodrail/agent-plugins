# Nodrail plugins for Claude Code and Codex

Every action the agent attempts is checked against your team's rules before it
runs. Anything no rule covers is blocked and a person is asked. An allow never
widens what the agent itself permits.

[![Check plugins](https://github.com/Nodrail/agent-plugins/actions/workflows/ci.yml/badge.svg)](https://github.com/Nodrail/agent-plugins/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Nodrail/agent-plugins/badge)](https://scorecard.dev/viewer/?uri=github.com/Nodrail/agent-plugins)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

Start in Nodrail: **Agents → Connect an agent**, and copy the credential. It is
shown once.

## Claude Code

Needs Claude Code 2.1.295 or later.

```
/plugin marketplace add Nodrail/agent-plugins
/plugin install nodrail@nodrail
```

Claude Code asks for the credential and keeps it in your system's secure store.
That's all. To change it later: `/plugin configure nodrail@nodrail`.

Self-hosting? Set the address in the same prompt.

## Codex

Needs Codex 0.155 or later.

```sh
codex plugin marketplace add Nodrail/agent-plugins
codex plugin add nodrail@nodrail

# Save the credential once, for every session on this machine:
mkdir -p ~/.nodrail && (umask 077; printf '%s' '<the credential>' > ~/.nodrail/credential)
```

Start Codex and approve the Nodrail hooks in `/hooks`. Codex doesn't run new
hooks until you do, so **nothing is checked before that step**.

To use a different credential for one project, set `NODRAIL_CREDENTIAL` there.
Self-hosting? Also set `NODRAIL_URL`.

## What is checked

|                  | Claude Code                      | Codex                                 |
| ---------------- | -------------------------------- | ------------------------------------- |
| Shell            | Yes                              | Yes                                   |
| File changes     | Yes                              | Yes, through `apply_patch`            |
| MCP tools        | Yes                              | Yes                                   |
| Web              | Yes                              | No: hosted search runs on OpenAI's side |
| New tools        | Yes, by default                  | No: governed tools are listed by name |
| Read-only tools  | No                               | No                                    |

A patch that touches several files, or renames one, is its own operation
(`files.file.patch`), so a rule for one folder can't let a second file through.

## When something goes wrong

If Nodrail can't be reached, the credential is refused, or a person doesn't
answer in time, the action is blocked. Each session also starts with a notice if
the credential is missing or refused.

- **Claude Code** blocks even if the hook itself crashes, through `onFailure`.
- **Codex** has no such setting: if the hook can't start at all, for example
  because Node.js is missing, Codex runs the tool. The hook answers before Codex's
  time limit, and a failure inside it blocks.

Someone who can edit the agent's settings, or a process outside the agent, can go
around the hook. This is a control for agents, not a sandbox.

## What leaves your machine

File contents never do, only a fingerprint and the path. Commands, URLs and MCP
inputs are sent so a person can review them, with anything that looks like a
secret removed. That filter is best effort.

## How it's built

Both plugins run the same file, `hooks/nodrail-hook.mjs`: the hook from
[`@nodrail/client`](https://github.com/Nodrail/nodrail-js/tree/main/packages/client),
bundled into one file with no dependencies so nothing else needs installing. Its
source, tests and changelog live there. `node scripts/check.mjs` checks that the
manifests agree and that the hook blocks when it isn't configured.

Versions are tagged here as `v<version>`, with a GitHub release for each.

## Contributing and security

Changes to the hook itself go to
[Nodrail/nodrail-js](https://github.com/Nodrail/nodrail-js). For the plugin
manifests and this README, see [CONTRIBUTING.md](CONTRIBUTING.md). Please report
vulnerabilities privately, as [SECURITY.md](SECURITY.md) describes.

## License

[Apache-2.0](LICENSE)
