# Security policy

These plugins decide whether Claude Code or Codex may run an action. A way to
make a governed action run without Nodrail allowing it is a security problem.

## Reporting a vulnerability

Report it privately, never in a public issue:

- [Open a private advisory](https://github.com/Nodrail/agent-plugins/security/advisories/new) on GitHub (preferred), or
- write to hello@nodrail.com.

Include the agent and its version, the plugin version, and the tool call. We aim
to acknowledge reports within three working days and credit you in the advisory
unless you'd rather we didn't.

## What counts

- A governed tool runs without an exact allow from Nodrail.
- The hook lets a call through when Nodrail can't be reached, refuses the
  credential, or times out.
- The credential, or file contents, end up somewhere the README says they don't.

The README's **What is checked** and **When something goes wrong** sections list
known limits, such as Codex running a tool when the hook can't start at all.
Those aren't vulnerabilities, but we'd still like to hear about ways to close
them.

## Supported versions

Fixes go to the latest version. Update with `/plugin update` in Claude Code, or
`codex plugin add nodrail@nodrail` again in Codex.
