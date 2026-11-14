// Proves the hook these plugins ship is exactly the one in @nodrail/client of
// the same version on npm, and that npm's signatures for that package check
// out. A stale or altered hook can't pass. Needs the network and npm.
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const { version } = JSON.parse(
  readFileSync(
    join(root, "plugins/claude-code/.claude-plugin/plugin.json"),
    "utf8",
  ),
);
const spec = `@nodrail/client@${version}`;
// CI runs the agents against the client tools/package-lock.json pins.
const pinned = JSON.parse(
  readFileSync(join(root, "tools/package-lock.json"), "utf8"),
).packages["node_modules/@nodrail/client"]?.version;
if (pinned !== version)
  throw new Error(
    `tools/package-lock.json pins @nodrail/client ${pinned}, not ${version}. Run npm install @nodrail/client@${version} --save-exact in tools.`,
  );
const folder = mkdtempSync(join(tmpdir(), "nodrail-hook-"));
const npm = (args) =>
  execFileSync("npm", args, { cwd: folder, encoding: "utf8", stdio: "pipe" });

try {
  writeFileSync(
    join(folder, "package.json"),
    JSON.stringify({ name: "verify", private: true }),
  );
  try {
    npm(["install", "--no-audit", "--no-fund", "--ignore-scripts", spec]);
  } catch {
    throw new Error(
      `${spec} isn't on npm yet. Release and approve it before these plugins.`,
    );
  }
  // Registry signatures, and provenance where the version has it.
  console.log(npm(["audit", "signatures"]).trim());

  const published = readFileSync(
    join(folder, "node_modules/@nodrail/client/dist/nodrail-hook.mjs"),
  );
  for (const plugin of ["claude-code", "codex"]) {
    const shipped = readFileSync(
      join(root, "plugins", plugin, "hooks/nodrail-hook.mjs"),
    );
    if (!shipped.equals(published))
      throw new Error(
        `plugins/${plugin}/hooks/nodrail-hook.mjs is not the hook in ${spec}.`,
      );
  }
  console.log(`Both plugins ship the hook from ${spec}, byte for byte.`);
} finally {
  rmSync(folder, { recursive: true, force: true });
}
