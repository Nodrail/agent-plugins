# Contributing

This marketplace is generated from [Nodrail/nodrail](https://github.com/Nodrail/nodrail).
Open issues and pull requests in the monorepo. Its
[contributing guide](https://github.com/Nodrail/nodrail/blob/main/CONTRIBUTING.md)
covers the checks and conventions.

Edit manifests, marketplace definitions and the README in
`packages/agent-plugins`. The generated `plugins/*/hooks/nodrail-hook.mjs`
files come from `packages/client`. Run `pnpm --filter @nodrail/agent-plugins test`
from the monorepo to build and check both plugins.

To try your own build, add `packages/agent-plugins` as a local marketplace in
Claude Code or Codex. The published installation commands use
`Nodrail/agent-plugins`.
