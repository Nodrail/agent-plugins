// Checks the plugins as they are installed: manifests agree, every file they
// point at exists, and the hook blocks when it isn't configured. Needs nothing
// but Node, so it runs the same here and in the public repository.
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const json = (path) => JSON.parse(readFileSync(resolve(root, path), "utf8"));
const problems = [];
const expect = (ok, message) => ok || problems.push(message);

const claude = json("plugins/claude-code/.claude-plugin/plugin.json");
const codex = json("plugins/codex/.codex-plugin/plugin.json");
const claudeMarket = json(".claude-plugin/marketplace.json");
const codexMarket = json(".agents/plugins/marketplace.json");

expect(
  claude.version === codex.version,
  "the two plugins have different versions",
);
// The hook comes from @nodrail/client, and the plugins carry its version.
const hookVersion = /HOOK_VERSION = "([^"]+)"/.exec(
  readFileSync(
    resolve(root, "plugins/claude-code/hooks/nodrail-hook.mjs"),
    "utf8",
  ),
)?.[1];
expect(
  hookVersion === claude.version,
  `the plugins say ${claude.version}, but their hook is ${hookVersion ?? "unversioned"}`,
);
expect(
  claudeMarket.plugins.some(
    (entry) =>
      entry.name === claude.name && entry.source === "./plugins/claude-code",
  ),
  "the Claude Code marketplace doesn't list the plugin",
);
expect(
  codexMarket.plugins.some(
    (entry) =>
      entry.name === codex.name && entry.source?.path === "./plugins/codex",
  ),
  "the Codex marketplace doesn't list the plugin",
);
expect(
  claude.userConfig?.credential?.sensitive === true,
  "the Claude Code credential isn't kept in the secure store",
);
expect(
  codex.hooks === "./hooks/hooks.json",
  "the Codex plugin doesn't point at its hooks",
);

const hooks = {
  "claude-code": readFileSync(
    resolve(root, "plugins/claude-code/hooks/nodrail-hook.mjs"),
  ),
  codex: readFileSync(resolve(root, "plugins/codex/hooks/nodrail-hook.mjs")),
};
expect(
  hooks["claude-code"].equals(hooks.codex),
  "the two plugins ship different hooks",
);

for (const name of Object.keys(hooks)) {
  const declared = JSON.stringify(json(`plugins/${name}/hooks/hooks.json`));
  expect(
    declared.includes("/hooks/nodrail-hook.mjs"),
    `${name}: hooks.json doesn't run the bundled hook`,
  );
  for (const event of ["SessionStart", "PreToolUse", "PostToolUse"])
    expect(declared.includes(`"${event}"`), `${name}: no ${event} hook`);
}
expect(
  JSON.stringify(json("plugins/claude-code/hooks/hooks.json")).includes(
    '"onFailure":"block"',
  ),
  "Claude Code doesn't block when the hook itself fails",
);

// With no credential, every governed call must be blocked, for either agent.
const hook = resolve(root, "plugins/claude-code/hooks/nodrail-hook.mjs");
for (const agent of [[], ["codex"]]) {
  const result = spawnSync(process.execPath, [hook, ...agent], {
    input: JSON.stringify({
      hook_event_name: "PreToolUse",
      tool_name: "Bash",
      tool_input: { command: "rm -rf build" },
      tool_use_id: "check",
      cwd: root,
    }),
    encoding: "utf8",
    env: { PATH: process.env.PATH, NODRAIL_HOME: resolve(root, "nonexistent") },
    timeout: 20_000,
  });
  expect(
    result.status === 0 &&
      result.stdout.includes('"permissionDecision":"deny"'),
    `the ${agent[0] ?? "claude-code"} hook didn't block without a credential: ${result.stdout}${result.stderr}`,
  );
}

if (!existsSync(resolve(root, "README.md"))) problems.push("README.md missing");

if (problems.length) {
  console.error(
    `Plugin check failed:\n${problems.map((p) => `- ${p}`).join("\n")}`,
  );
  process.exit(1);
}
console.log("Plugin check passed.");
