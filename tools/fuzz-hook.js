// Feeds the hook random events while it has no credential, and checks it never
// lets a call through: whatever arrives, a tool call is denied or the hook
// exits 2, which both agents treat as blocked. Needs the packages in this
// folder: npm ci, then node fuzz-hook.js.
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import fc from "fast-check";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const hook = resolve(root, "plugins/claude-code/hooks/nodrail-hook.mjs");

function run(input, agent) {
  const result = spawnSync(process.execPath, [hook, ...agent], {
    input,
    encoding: "utf8",
    env: { PATH: process.env.PATH, NODRAIL_HOME: resolve(root, "nonexistent") },
    timeout: 20_000,
  });
  return { status: result.status, out: result.stdout };
}

const agents = fc.constantFrom([], ["codex"]);
const tools = fc.oneof(
  fc.constantFrom("Bash", "Read", "Write", "Edit", "Agent", "WebFetch"),
  fc.constantFrom("mcp__github__create_issue", "apply_patch", "shell"),
  fc.string(),
);
const toolCall = fc.record(
  {
    hook_event_name: fc.constant("PreToolUse"),
    tool_name: tools,
    tool_input: fc.oneof(
      fc.jsonValue(),
      fc.dictionary(fc.string(), fc.jsonValue()),
    ),
    tool_use_id: fc.string(),
    cwd: fc.constant(root),
  },
  { requiredKeys: ["hook_event_name"] },
);
const blocked = ({ status, out }) =>
  status === 2 || (status === 0 && out.includes('"permissionDecision":"deny"'));

// A tool call, however odd, is blocked.
fc.assert(
  fc.property(toolCall, agents, (event, agent) =>
    blocked(run(JSON.stringify(event), agent)),
  ),
  { numRuns: 150 },
);

// Anything else, even what isn't JSON, never allows and never crashes.
fc.assert(
  fc.property(
    fc.oneof(
      fc.string(),
      fc.jsonValue().map((value) => JSON.stringify(value)),
    ),
    agents,
    (input, agent) => {
      const { status, out } = run(input, agent);
      return (status === 0 || status === 2) && !out.includes('"allow"');
    },
  ),
  { numRuns: 150 },
);

console.log("Fuzzed the unconfigured hook: no call got through.");
