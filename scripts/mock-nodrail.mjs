// A stand-in for Nodrail's runtime API, for running real agents in CI. It
// answers like the service, with digests from the published @nodrail/client,
// so the hook checks every answer exactly as it would in production.
//
// Allows a shell command starting with "mkdir allowed"; denies everything else.
// Writes each call it sees to $MOCK_LOG, one JSON line each.
import { appendFileSync } from "node:fs";
import { createServer } from "node:http";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const { actionDigest, descriptorDigest } = await import(
  pathToFileURL(join(process.env.NODRAIL_CLIENT_DIR ?? "", "dist/protocol.js"))
    .href
);

export const CREDENTIAL = "ci-credential";
const INSTALLATION = "11111111-1111-4111-8111-111111111111";
const port = Number(process.env.MOCK_PORT ?? 4319);
const log = process.env.MOCK_LOG ?? "mock-nodrail.log";
const actions = new Map();
let count = 0;

const decide = (descriptor) =>
  descriptor.tool === "shell" &&
  String(descriptor.resource?.id ?? "").startsWith("mkdir allowed")
    ? "READY"
    : "DENIED";

function status(action) {
  const digest = descriptorDigest(INSTALLATION, action.descriptor);
  return {
    code: action.code,
    action_id: action.id,
    installation_id: INSTALLATION,
    permit_id: null,
    descriptor_digest: digest,
    action_digest: actionDigest(action.id, digest),
    reference: "APR-CI000001",
    reason: null,
    expires_at: new Date(Date.now() + 60_000).toISOString(),
  };
}

function answer(path, body) {
  if (path === "/heartbeat") return { ok: true };
  if (path === "/actions") {
    count += 1;
    const { tool, operation, resource, params } = body;
    const descriptor = { tool, operation, resource, params };
    const action = {
      id: `22222222-2222-4222-8222-${String(count).padStart(12, "0")}`,
      descriptor,
      code: decide(descriptor),
    };
    actions.set(action.id, action);
    appendFileSync(
      log,
      `${JSON.stringify({ ...descriptor, code: action.code })}\n`,
    );
    return status(action);
  }
  const [, id, verb] = path.split("/").slice(1);
  const action = actions.get(id ?? "");
  if (!action) return null;
  if (verb === "permit") {
    const issued = new Date();
    return {
      code: "ALLOW",
      permit_id: `permit-${action.id}`,
      action_id: action.id,
      action_digest: status(action).action_digest,
      installation_id: INSTALLATION,
      claim_nonce: body.nonce,
      issued_at: issued.toISOString(),
      expires_at: new Date(issued.getTime() + 30_000).toISOString(),
    };
  }
  if (verb === "reports") return { ok: true };
  return status(action);
}

createServer((request, response) => {
  let raw = "";
  request.on("data", (chunk) => (raw += chunk));
  request.on("end", () => {
    const send = (code, value) => {
      response.writeHead(code, { "content-type": "application/json" });
      response.end(JSON.stringify(value));
    };
    if (request.headers.authorization !== `Bearer ${CREDENTIAL}`)
      return send(401, { error: { code: "UNAUTHENTICATED" } });
    const path = (request.url ?? "").split("/api/v1/runtime")[1] ?? "";
    const result = answer(path, raw ? JSON.parse(raw) : {});
    return result ? send(200, result) : send(404, {});
  });
}).listen(port, "127.0.0.1", () => console.log(`Mock Nodrail on ${port}`));
