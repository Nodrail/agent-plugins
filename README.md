# Nodrail plugins for Claude Code and Codex

The [marketplace](https://github.com/Nodrail/agent-plugins) is generated from
[Nodrail/nodrail](https://github.com/Nodrail/nodrail). Open issues and pull
requests in [the Nodrail monorepo](https://github.com/Nodrail/nodrail/issues).

Check supported tool calls against the policy in your Nodrail control plane, self-hosted or Nodrail Cloud, before they run. Each call is allowed or denied at once, with the reason; nothing waits for a person. Your team keeps the agent runtime and provider credentials.

These plugins use a Nodrail workspace credential and send each call to the control plane through its host API. To set up hosts from a repository instead, with the policy decided on the machine, declare them in `nodrail.yaml` and run `nodrail plan` and `nodrail apply` ([`@nodrail/cli`](https://www.npmjs.com/package/@nodrail/cli)). The project workflow supports Claude Code, Codex and GitHub Copilot CLI. For an existing plugin setup, follow the [upgrade to a repository connection](https://nodrail.com/docs/cli#upgrade-to-connect).

[![Check plugins](https://github.com/Nodrail/agent-plugins/actions/workflows/ci.yml/badge.svg)](https://github.com/Nodrail/agent-plugins/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Nodrail/agent-plugins/badge)](https://scorecard.dev/viewer/?uri=github.com/Nodrail/agent-plugins)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/16693/badge)](https://www.bestpractices.dev/projects/16693)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/Nodrail/agent-plugins/blob/main/LICENSE)

Start in Nodrail under **Agents → Connect a project**. The console shows the
CLI commands and the connection settings for your environment. For a standalone
Claude Code or SDK installation, open **Standalone plugin, manual hook or SDK**
and create a credential. The console shows it once, along with the server
address and host-specific steps.

Both plugins run their hook with Node.js 22 or later, which must be on your
`PATH`. On Windows the hook passes its tests, but hasn't been tried in the real
agents yet.

## Claude Code

Needs Claude Code 2.1.295 or later.

```
/plugin marketplace add Nodrail/agent-plugins
/plugin install nodrail@nodrail
```

Claude Code asks for the credential and its issuing origin. For Nodrail Cloud, enter `https://app.nodrail.com`. To change the pair, run `/plugin configure nodrail@nodrail`.

When `nodrail apply` installs a Claude Code project hook and verifies it against the user's private apply record, the standalone plugin steps aside. Start a new session after apply so it loads the project hook. Set `NODRAIL_REQUIRE_STANDALONE=1` in the host environment to keep the standalone plugin active.

## Codex

For project setup, use Codex 0.169.0 or later. In **Agents → Connect a project**, choose **Codex**.
With Nodrail CLI 0.7.0 or later and a matching control plane, sign in with
`nodrail login`, point `nodrail.yaml` at your environment, and run
`nodrail apply --runtime codex`. Apply enrolls the machine for that project
and environment, with a credential bound to the control plane's origin.

Open Codex in the project, trust the folder, then trust the Nodrail hook in
`/hooks`. Use the console's check-in command and Activity link to verify
that the hook reported a decision.

## What is checked

| Calls                    | Claude Code                                                                  | Codex                                   |
| ------------------------ | ---------------------------------------------------------------------------- | --------------------------------------- |
| Shell                    | Yes                                                                          | Yes                                     |
| File changes             | Yes                                                                          | Yes, through `apply_patch`              |
| MCP tools                | Yes                                                                          | Yes                                     |
| Web                      | Yes                                                                          | No: hosted search runs on OpenAI's side |
| New tools                | Yes, by default                                                              | No: governed tools are listed by name   |
| Reads (Read, Grep, Glob) | Checked on your machine for places credentials live, not sent to Nodrail     | Through the shell, like any command     |
| Starting a subagent      | Yes (tool `claude-code`, operation `agent`, the subagent's type as resource) | No                                      |

**Run-history walkthrough preview.** Recording subagent steps and reading receipts requires plugin 0.2.0 or later. The integration coverage table above describes the tool calls each plugin checks.

Claude Code also sends each subagent's start and stop to Nodrail as a step of
the run, with the receipt block it ended with, so gates in your rules can wait
for steps such as QA. The run is `NODRAIL_RUN`, else `<repo>/<branch>` where the
session started (such as `github.com/acme/app/feature/login`), kept for the
whole session even if you switch branch, or the session itself on the default
branch. Add a rule that allows `claude-code` `agent` for the subagents you use,
or each start is denied. `Task`, Claude Code's earlier name for
`Agent`, is checked the same way.

**Upgrading:** earlier versions of the Claude Code plugin didn't check starting
a subagent. Now they do, with the subagent's type as a resource of type `agent`
(`vercel:deployment-expert` becomes `vercel-deployment-expert`). Until a rule
allows it, each start is denied.

For a subagent to report a verdict, end its definition (for example
`.claude/agents/qa.md`) with an instruction to finish its final message with a
`nodrail-receipt` block, such as `verdict: pass`, and nothing after it. See
[Runs, gates and budgets (preview)](https://github.com/Nodrail/nodrail/blob/main/packages/policy-engine/docs/runs.md#receipts).

A patch that touches several files, or renames one, is its own operation (tool
`files`, operation `file.patch`), so a rule for one folder can't let a second
file through.

### Repository merge checks (GitHub pilot)

The plugins above check supported tools when an agent tries to use them. For [PR #11](https://github.com/Nodrail/agent-plugins/pull/11), we separately ran a local adapter and configured GitHub to require its status on the target branch. Installing a Claude Code or Codex plugin does not configure branch protection. [Read the GitHub merge check pilot](https://nodrail.com/guides/github-merge-check-ai-agent-qa).

## When something goes wrong

If Nodrail can't be reached, the credential is refused, or Nodrail doesn't
answer within 25 seconds, the action is blocked. Each session also starts with a notice if
the credential is missing or refused.

- **Claude Code** blocks even if the hook itself crashes, through `onFailure`.
- **Codex** has no such setting: if the hook can't start at all, for example
  because Node.js is missing, Codex runs the tool. The hook answers before Codex's
  time limit, and a failure inside it blocks.

Someone who can edit the agent's settings, or a process outside the agent, can go
around the hook. This is a control for agents, not a sandbox.

## What leaves your machine

File contents never do, only a fingerprint and the path. Commands, URLs and MCP
inputs are sent so rules can decide them and Activity can show them, with
anything that looks like a secret removed. That filter is best effort.

## Denied calls

A call no rule covers is denied, and so is one an unmet gate or a used-up
budget holds back. The agent is told why, so it can meet what is missing (run
the review step a gate waits for, say) and try again. Nothing waits for a
person.

## Turning it off

- **Claude Code:** `/plugin disable nodrail@nodrail`, or `/plugin uninstall nodrail@nodrail`.
- **Codex project setup:** run `nodrail destroy --runtime codex` from the project.
- **Existing standalone Codex plugin:** run `codex plugin remove nodrail@nodrail`.

## How it's built

Both plugins run the same file, `hooks/nodrail-hook.mjs`: the hook from
[`@nodrail/client`](https://github.com/Nodrail/nodrail/tree/main/packages/client),
bundled into one file with no dependencies so nothing else needs installing. Its
source, tests and changelog live there. `node scripts/check.mjs` checks that the
manifests agree and that the hook blocks when it isn't configured.

Plugin versions follow the client. See the
[Nodrail releases](https://github.com/Nodrail/nodrail/releases).

Two checks run in CI. One proves the hook is byte for byte the one in
`@nodrail/client` of the same version on npm. The other, run on demand once
API keys are configured, runs real Claude Code and Codex sessions with the
plugins installed, on Linux, macOS and Windows, against a mock Nodrail
(`scripts/real-agents.mjs`), and checks that an allowed command runs, a denied
one doesn't, and `.env` stays hidden.

## Contributing and security

See the [contributing guide](https://github.com/Nodrail/nodrail/blob/main/CONTRIBUTING.md).
Report vulnerabilities privately via the [security policy](https://github.com/Nodrail/nodrail/blob/main/SECURITY.md).

## License

[Apache-2.0](https://github.com/Nodrail/agent-plugins/blob/main/LICENSE)
