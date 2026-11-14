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
npm test                   # manifests, the unconfigured hook, and the hook on npm
npm ci --prefix tools      # the exact versions CI uses, pinned by checksum
tools/node_modules/.bin/claude plugin validate --strict .
tools/node_modules/.bin/claude plugin validate --strict plugins/claude-code
node tools/fuzz-hook.js    # random events against the unconfigured hook
```

To try your copy, add this folder as a marketplace instead of
`Nodrail/agent-plugins`:

```sh
claude plugin marketplace add ./
codex plugin marketplace add ./
```

## Pull requests

Titles follow `type(scope): summary`, for example
`fix(engine): match secret names case-insensitively`, and a check enforces it.
See [names and descriptions](https://github.com/Nodrail/.github/blob/main/CONTRIBUTING.md#names-and-descriptions).

- Keep both plugins on the same version, and raise it when users would notice the
  change. Merging a new version tags it and writes its release.
- Describe how you tried it, with which agent and version.
- Add or update a check in `scripts/check.mjs` for any change to the manifests
  or marketplaces. A change to what the hook checks needs a test in
  `packages/client/tests` in nodrail-js.

Contributions are made under the [Apache-2.0](LICENSE) licence, as its section 5
describes. Everyone taking part follows the [code of conduct](CODE_OF_CONDUCT.md).

## How your change ships

This repository is generated from Nodrail's monorepo, so an accepted pull
request is applied there with you as co-author and comes back here in the next
sync, credited to you. Your pull request is then closed with a link to it. See
[GOVERNANCE.md](GOVERNANCE.md).
