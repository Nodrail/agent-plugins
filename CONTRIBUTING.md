# Contributing

Thanks for helping.

## Where changes go

- **The hook** (what is checked, how a call is described, what is sent):
  [Nodrail/nodrail-js](https://github.com/Nodrail/nodrail-js), in
  `packages/client`. The file in `plugins/*/hooks/nodrail-hook.mjs` is built from
  there, so don't edit it here.
- **The plugin manifests, marketplaces and README:** here.

## Checking a change

Needs Node 22 or later.

```sh
node scripts/check.mjs
npx @anthropic-ai/claude-code@2.1.322 plugin validate --strict .
npx @anthropic-ai/claude-code@2.1.322 plugin validate --strict plugins/claude-code
```

To try your copy, add this folder as a marketplace instead of
`Nodrail/agent-plugins`:

```sh
claude plugin marketplace add ./
codex plugin marketplace add ./
```

## Pull requests

- Keep both plugins on the same version, and raise it when users would notice the
  change. Merging a new version tags it and writes its release.
- Describe how you tried it, with which agent and version.

Contributions are made under the [Apache-2.0](LICENSE) licence, as its section 5
describes. Everyone taking part follows the [code of conduct](CODE_OF_CONDUCT.md).
