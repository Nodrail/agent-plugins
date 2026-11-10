#!/usr/bin/env node

// ../policy-engine/src/actions.ts
import { realpathSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";

// ../policy-engine/src/commands.ts
var shellSyntax = /[;&|`$<>(){}\n\r\\]/;
var unusualWhitespace = /[^\S \t]/;
var assignment = /^[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?\+?=/;
var computedProgram = /^=|[*?[\]]/;
var wrappers = new Set(
  `sudo doas su env xargs eval exec command builtin source . time nohup nice
   ionice timeout watch setsid stdbuf chroot flock parallel script taskset
   unshare nsenter caffeinate arch open at batch strace ltrace gdb lldb expect
   tmux screen busybox sh bash zsh dash fish ksh pwsh powershell cmd awk gawk
   mawk nawk sed node deno bun tsx ts-node npx pnpx bunx perl ruby php lua
   tclsh rscript osascript pypy pypy3 vi vim nvim emacs ssh scp sftp docker
   podman kubectl`.split(/\s+/)
);
var python = /^python[0-9.]*$/;
var riskyArgument = /^(?:-c|-e|-exec|-execdir|-ok|-okdir|-delete|-fprint.*|-fls|--eval|--expression(?:=.*)?|--(?:exec|output|rsh|to-command|checkpoint-action|use-compress-program|upload-pack|receive-pack|open-files-in-pager|pre|config-env)(?:=.*)?)$/;
var riskyByProgram = {
  git: /^(?:-x|-O.*)$/,
  tar: /^(?:-I.*|-[a-zA-Z]*I)$/,
  rsync: /^-e.*$/,
  curl: /^(?:-[oOKTdF].*|--(?:output|remote-name|config|upload-file|data.*|form.*|json)(?:=.*)?)$/,
  wget: /^(?:-[oO].*|--(?:output-document|output-file|post-file)(?:=.*)?)$/,
  dd: /^of=/,
  make: /^(?:-[fC].*|--(?:file|makefile|directory|eval)(?:=.*)?)$/
};
var riskySubcommands = {
  git: /^(?:bisect|submodule|filter-branch|difftool|mergetool|config|alias|credential|hook)$/,
  npm: /^(?:exec|x)$/,
  pnpm: /^(?:exec|dlx)$/,
  yarn: /^(?:exec|dlx)$/
};
function runsAnotherCommand(words) {
  const first = words[0] ?? "";
  if (computedProgram.test(first)) return true;
  const program = (first.split("/").pop() ?? "").toLowerCase();
  if (wrappers.has(program) || python.test(program)) return true;
  const args = words.slice(1);
  if (program === "git" && args[0]?.startsWith("-")) return true;
  if (riskySubcommands[program]?.test(args[0] ?? "")) return true;
  const specific = riskyByProgram[program];
  return args.some(
    (word) => riskyArgument.test(word) || specific?.test(word) === true
  );
}
function splitWords(line) {
  const words = [];
  let word = "";
  let started = false;
  let quote = null;
  for (const char of line) {
    if (quote) {
      if (char === quote) quote = null;
      else word += char;
    } else if (char === '"' || char === "'") {
      quote = char;
      started = true;
    } else if (char === " " || char === "	") {
      if (started) words.push(word);
      word = "";
      started = false;
    } else {
      word += char;
      started = true;
    }
  }
  if (quote) return null;
  if (started) words.push(word);
  return words;
}
var render = (words) => words.map((word) => /^[^\s"']+$/.test(word) ? word : JSON.stringify(word)).join(" ");
var MAX_CHAIN_PARTS = 20;
function splitChain(text) {
  const parts = [];
  let part = "";
  let quote = null;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index] ?? "";
    if (quote) {
      if (char === quote) quote = null;
    } else if (char === '"' || char === "'") quote = char;
    if (quote || !";&|\n".includes(char)) {
      part += char;
      continue;
    }
    const doubled = text[index + 1] === char;
    if (char === "&" && !doubled) return null;
    if (doubled && (char === ";" || char === "\n")) return null;
    if (doubled) index += 1;
    parts.push(part);
    part = "";
  }
  if (quote) return null;
  parts.push(part);
  if (parts.at(-1)?.trim() === "") parts.pop();
  return parts;
}
function judgeSimple(text) {
  const compound = { operation: "command.compound", text };
  if (shellSyntax.test(text) || unusualWhitespace.test(text)) return compound;
  const words = splitWords(text);
  if (!words?.length) return compound;
  if (assignment.test(words[0] ?? "") || runsAnotherCommand(words))
    return compound;
  return { operation: "command.run", text: render(words) };
}
function chainParts(text) {
  const split = splitChain(text);
  if (!split || split.length < 2 || split.length > MAX_CHAIN_PARTS) return null;
  const shapes = split.map(
    (part) => judgeSimple(part.replace(/^[ \t]+|[ \t]+$/g, ""))
  );
  return shapes.every((shape) => shape.operation === "command.run") ? shapes.map((shape) => shape.text) : null;
}
var isShellSpace = (char) => char === " " || char === "	" || char === "\r" || char === "\n";
function trimShellSpace(line) {
  let start = 0;
  let end = line.length;
  while (start < end && isShellSpace(line[start])) start += 1;
  while (end > start && isShellSpace(line[end - 1])) end -= 1;
  return line.slice(start, end);
}
function classifyCommand(line) {
  const text = trimShellSpace(line);
  const parts = chainParts(text);
  return parts ? { operation: "command.compound", text, parts } : judgeSimple(text);
}

// ../policy-engine/src/protocol.ts
import { createHash } from "node:crypto";

// ../../node_modules/.pnpm/canonicalize@5.1.0/node_modules/canonicalize/lib/canonicalize.js
function serializeString(value) {
  if (!value.isWellFormed()) {
    throw new Error("Lone surrogate is not allowed");
  }
  return JSON.stringify(value);
}
function serializePrimitive(value) {
  switch (typeof value) {
    case "number":
      if (isNaN(value)) {
        throw new Error("NaN is not allowed");
      }
      if (!isFinite(value)) {
        throw new Error("Infinity is not allowed");
      }
      return JSON.stringify(value);
    case "string":
      return serializeString(value);
    case "boolean":
      return value ? "true" : "false";
    default:
      return JSON.stringify(value);
  }
}
function enterValue(value, seen) {
  let wrappers2 = null;
  while (value !== null && typeof value === "object" && typeof value.toJSON === "function") {
    if (seen.has(value)) {
      throw new Error("Circular reference detected");
    }
    seen.add(value);
    (wrappers2 ??= []).push(value);
    value = value.toJSON();
  }
  if (value instanceof Number || value instanceof String || value instanceof Boolean) {
    value = value.valueOf();
  }
  if (value === null || typeof value !== "object") {
    if (wrappers2 !== null) {
      for (const wrapper of wrappers2) seen.delete(wrapper);
    }
    return serializePrimitive(value);
  }
  if (seen.has(value)) {
    throw new Error("Circular reference detected");
  }
  seen.add(value);
  return {
    container: value,
    // null marks an array frame; object frames carry their sorted keys.
    // `sort()`'s default comparator orders by UTF-16 code unit, which is the
    // order JCS requires.
    keys: Array.isArray(value) ? null : Object.keys(value).sort(),
    // Next child to serialize; the frame resumes here after a nested
    // container's subtree completes.
    index: 0,
    // Whether no member has been emitted yet (controls comma placement).
    first: true,
    // toJSON wrappers to release from `seen` when this frame completes.
    wrappers: wrappers2
  };
}
function canonicalize(object) {
  if (object === null || typeof object !== "object") {
    return serializePrimitive(object);
  }
  const seen = /* @__PURE__ */ new Set();
  const root = enterValue(object, seen);
  if (typeof root !== "object") {
    return root;
  }
  let result = root.keys === null ? "[" : "{";
  const stack = [root];
  outer:
    while (stack.length > 0) {
      const frame = stack[stack.length - 1];
      const container = frame.container;
      if (frame.keys === null) {
        while (frame.index < container.length) {
          const i = frame.index++;
          if (i > 0) {
            result += ",";
          }
          const element = container[i];
          const value = element === void 0 || typeof element === "symbol" || typeof element === "function" ? null : element;
          if (value === null || typeof value !== "object") {
            result += serializePrimitive(value);
            continue;
          }
          const child = enterValue(value, seen);
          if (typeof child !== "object") {
            result += child === void 0 ? "null" : child;
            continue;
          }
          result += child.keys === null ? "[" : "{";
          stack.push(child);
          continue outer;
        }
        result += "]";
      } else {
        const keys = frame.keys;
        while (frame.index < keys.length) {
          const key = keys[frame.index++];
          const value = container[key];
          if (value === void 0 || typeof value === "symbol" || typeof value === "function") {
            continue;
          }
          if (value === null || typeof value !== "object") {
            if (frame.first) {
              frame.first = false;
            } else {
              result += ",";
            }
            result += serializeString(key) + ":" + serializePrimitive(value);
            continue;
          }
          const child = enterValue(value, seen);
          if (child === void 0) {
            continue;
          }
          if (frame.first) {
            frame.first = false;
          } else {
            result += ",";
          }
          result += serializeString(key) + ":";
          if (typeof child !== "object") {
            result += child;
            continue;
          }
          result += child.keys === null ? "[" : "{";
          stack.push(child);
          continue outer;
        }
        result += "}";
      }
      seen.delete(container);
      if (frame.wrappers !== null) {
        for (const wrapper of frame.wrappers) seen.delete(wrapper);
      }
      stack.pop();
    }
  return result;
}

// ../policy-engine/src/json.ts
function isPlainJson(value) {
  return isPlainJsonValue(value, /* @__PURE__ */ new WeakSet());
}
function isPlainJsonValue(value, ancestors) {
  if (value === null) return true;
  if (typeof value === "string" || typeof value === "boolean") return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (typeof value !== "object") return false;
  if (ancestors.has(value)) return false;
  ancestors.add(value);
  if (Array.isArray(value)) {
    const valid2 = value.every((item) => isPlainJsonValue(item, ancestors));
    ancestors.delete(value);
    return valid2;
  }
  const prototype = Object.getPrototypeOf(value);
  const valid = (prototype === Object.prototype || prototype === null) && Object.values(value).every((item) => isPlainJsonValue(item, ancestors));
  ancestors.delete(value);
  return valid;
}

// ../policy-engine/src/protocol.ts
var SCHEMA_VERSION = 1;
var CANONICALIZER_VERSION = 1;
var sha256 = (text) => `sha256:${createHash("sha256").update(text).digest("hex")}`;
function fingerprint(value) {
  const canonical = typeof value === "string" ? value : canonicalize(value ?? null);
  if (canonical === void 0) throw new Error("Value is not serialisable");
  return sha256(canonical);
}
function descriptorDigest(installationId, descriptor) {
  const canonical = canonicalize({
    canonicalizer: CANONICALIZER_VERSION,
    installation: installationId,
    operation: descriptor.operation,
    params: descriptor.params,
    resource: descriptor.resource,
    schema: SCHEMA_VERSION,
    tool: descriptor.tool
  });
  if (canonical === void 0)
    throw new Error("Descriptor is not serialisable");
  return sha256(canonical);
}
var actionDigest = (actionId, digest) => sha256(`nodrail:action:v1
${actionId}
${digest}`);

// ../policy-engine/src/actions.ts
var MAX_RESOURCE = 512;
var MAX_INLINE_INPUT = 16 * 1024;
var MAX_COMMAND_ID = MAX_RESOURCE - 42;
var nonEmptyText = (value) => typeof value === "string" && value ? value : null;
var REDACTED = "[redacted]";
var sensitiveName = "[A-Za-z0-9_-]*(?:token|secret|passw(?:or)?d|pwd|api[_-]?key|credential|authorization)[A-Za-z0-9_-]*";
var secretValue = `"(?![^"]*[$\`])[^"]*"|'[^']*'|(?![^\\s&;|]*[$\`])[^\\s&;|]+`;
var secretPatterns = [
  // A whole header value, whatever scheme it uses.
  [
    /\b(authorization|proxy-authorization|cookie|set-cookie|x-api-key)(\s*:\s*)[^'"\n]+/gi,
    `$1$2${REDACTED}`
  ],
  [/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi, `$1 ${REDACTED}`],
  // NAME=value and name: value, at any position.
  [
    new RegExp(`(${sensitiveName})(=|:\\s*)(${secretValue})`, "gi"),
    `$1$2${REDACTED}`
  ],
  // A value after a space only counts when the name is really a flag, so a path
  // like ./tokens can't hide the argument that follows it.
  [
    new RegExp(`(\\s--?${sensitiveName})(\\s+)(${secretValue})`, "gi"),
    `$1$2${REDACTED}`
  ],
  [/([?&](?:key|sig|signature|auth|code)=)[^&\s'"]+/gi, `$1${REDACTED}`],
  [/(\s-u\s+)[^\s:]+:\S+/g, `$1${REDACTED}`],
  [/\b(mysql|mysqldump|mariadb)\b([^|;&\n]*\s-p)[^\s]+/g, `$1$2${REDACTED}`],
  [/(\/\/)[^/\s:@]+:[^/\s@]+@/g, `$1${REDACTED}@`],
  [
    /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)\b/g,
    REDACTED
  ]
];
var redact = (value) => secretPatterns.reduce(
  (current, [pattern, replacement]) => current.replace(pattern, replacement),
  value
);
function redactCommand(line) {
  let shown = "";
  let part = "";
  let quote = null;
  for (const char of line) {
    if (quote) {
      if (char === quote) quote = null;
    } else if (char === '"' || char === "'") quote = char;
    if (!quote && ";&|\n".includes(char)) {
      shown += redact(part) + char;
      part = "";
    } else part += char;
  }
  return shown + redact(part);
}
var sensitiveKey = new RegExp(`^${sensitiveName}$`, "i");
function redactJson(value) {
  if (typeof value === "string") return redact(value);
  if (Array.isArray(value)) return value.map(redactJson);
  if (typeof value === "object" && value !== null)
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [
        key,
        sensitiveKey.test(key) ? REDACTED : redactJson(item)
      ])
    );
  return value;
}
var clip = (value, max) => value.length <= max ? value : `${value.slice(0, max)}\u2026 [shortened]`;
function commandAction(shape, original, extra) {
  const shown = redactCommand(shape.text);
  const hidden = shown !== shape.text;
  const shortened = shown.length > MAX_COMMAND_ID;
  let operation = shape.operation;
  if (hidden) operation = "command.redacted";
  else if (shortened) operation = "command.compound";
  const commandSha = fingerprint(original);
  const id = clip(shown, MAX_COMMAND_ID);
  return {
    tool: "shell",
    operation,
    resource: {
      kind: "command",
      id: hidden || shortened ? `${id} #${commandSha.slice(7, 19)}` : id
    },
    params: {
      // Reviewers read this; the fingerprint binds the exact original.
      command: clip(shown, MAX_INLINE_INPUT),
      command_sha256: commandSha,
      // A hidden part can't be judged by what is visible, so never split one.
      ...shape.parts && !hidden ? { parts: shape.parts } : {},
      ...extra
    }
  };
}
function shellCall(name, input) {
  const command = nonEmptyText(input.command);
  if (!command?.trim()) return null;
  return commandAction(classifyCommand(command), command, {
    shell: name,
    background: input.run_in_background === true
  });
}
function canonicalPath(path) {
  const missing = [];
  let existing = path;
  for (; ; ) {
    try {
      return join(realpathSync.native(existing), ...missing);
    } catch {
      const parent = dirname(existing);
      if (parent === existing) return path;
      missing.unshift(basename(existing));
      existing = parent;
    }
  }
}
var partsOf = (path) => path.split(/[\\/]/).filter(Boolean);
function fullPath(raw, cwd) {
  const expanded = /^~(?=$|\/)/.test(raw) ? `${homedir()}${raw.slice(1)}` : raw;
  if (!isAbsolute(expanded) && !cwd) return null;
  return canonicalPath(resolve(cwd ?? "/", expanded));
}
function fileCall(operation, pathField, input, cwd, content) {
  const raw = nonEmptyText(input[pathField]);
  if (!raw) return null;
  const path = fullPath(raw, cwd);
  if (!path) return null;
  return {
    tool: "files",
    operation,
    resource: { kind: "file", id: path },
    // What is written can hold secrets, so reviewers get its fingerprint.
    params: {
      path,
      path_parts: partsOf(path),
      content_sha256: fingerprint(content)
    }
  };
}
function searchCall(input, cwd) {
  const within = nonEmptyText(input.path) ?? cwd;
  const path = within ? fullPath(within, cwd) : null;
  if (!path) return null;
  return {
    tool: "files",
    operation: "file.search",
    resource: { kind: "file", id: path },
    params: {
      path,
      path_parts: partsOf(path),
      pattern: redact(nonEmptyText(input.pattern) ?? ""),
      input_sha256: fingerprint(input)
    }
  };
}
function ruleKey(value, max) {
  const plain = /^[a-z0-9_-]+$/.test(value) && !/-[0-9a-f]{8}$/.test(value);
  if (value.length > 0 && value.length <= max && plain) return value;
  const tag = fingerprint(value).slice("sha256:".length, 15);
  const readable = value.toLowerCase().replace(/[^a-z0-9_-]/g, "-").slice(0, max - tag.length - 1);
  return `${readable}-${tag}`;
}
function inputParams(input) {
  const size = Buffer.byteLength(JSON.stringify(input));
  return {
    ...size <= MAX_INLINE_INPUT ? { input: redactJson(input) } : {},
    input_sha256: fingerprint(input)
  };
}
function mcpCall(name, input) {
  const [, server, ...rest] = name.split("__");
  const tool = rest.join("__");
  if (!server || !tool) return null;
  return {
    tool: ruleKey(server, 64),
    operation: ruleKey(tool, 128),
    resource: { kind: "mcp_tool", id: `${server}.${tool}` },
    params: inputParams(input)
  };
}
var patchOperations = {
  Add: "file.write",
  Update: "file.edit",
  Delete: "file.delete"
};
var PATCH_VERBS = ["Add", "Update", "Delete"];
function patchHeaders(patch) {
  const changes = [];
  const moves = [];
  for (const line of patch.split(/\r\n|[\n\r\u2028\u2029]/)) {
    if (!line.startsWith("*** ")) continue;
    const rest = line.slice(4);
    const verb = PATCH_VERBS.find((name) => rest.startsWith(`${name} File: `));
    if (verb)
      changes.push({ verb, path: rest.slice(verb.length + 7).trimEnd() });
    else if (rest.startsWith("Move to: "))
      moves.push(rest.slice(9).trimEnd());
  }
  return { changes, moves };
}
function patchCall(input, cwd) {
  const patch = nonEmptyText(input.command) ?? nonEmptyText(input.patch);
  if (!patch) return null;
  const { changes, moves } = patchHeaders(patch);
  const paths = [...changes.map((change) => change.path), ...moves].map(
    (raw) => raw ? fullPath(raw, cwd) : null
  );
  if (paths.length === 0 || paths.some((path) => !path)) return null;
  const known = paths;
  const content_sha256 = fingerprint(patch);
  const [only] = known;
  const operation = patchOperations[changes[0]?.verb ?? ""];
  if (known.length === 1 && only && operation)
    return {
      tool: "files",
      operation,
      resource: { kind: "file", id: only },
      params: { path: only, path_parts: partsOf(only), content_sha256 }
    };
  return {
    tool: "files",
    operation: "file.patch",
    resource: { kind: "file", id: `patch:${content_sha256}` },
    params: {
      paths: known,
      path_parts: [...new Set(known.flatMap(partsOf))],
      content_sha256
    }
  };
}
function describeToolCall(name, input, cwd = null) {
  const described = (() => {
    switch (name) {
      case "Bash":
      case "PowerShell":
        return shellCall(name, input);
      case "Write":
        return fileCall("file.write", "file_path", input, cwd, input.content);
      case "Edit":
      case "MultiEdit":
        return fileCall("file.edit", "file_path", input, cwd, input);
      case "Read":
        return fileCall("file.read", "file_path", input, cwd, input);
      case "Grep":
      case "Glob":
        return searchCall(input, cwd);
      case "NotebookEdit":
        return fileCall("notebook.edit", "notebook_path", input, cwd, input);
      case "apply_patch":
        return patchCall(input, cwd);
      case "WebFetch": {
        const url = nonEmptyText(input.url);
        if (!url || !URL.canParse(url)) return null;
        const { protocol, host, pathname, search } = new URL(url);
        const normal = `${protocol}//${host}${pathname}${search}`;
        const shown = redact(normal);
        return {
          tool: "web",
          operation: shown === normal ? "fetch" : "fetch.redacted",
          resource: { kind: "url", id: shown },
          params: { url: shown, url_sha256: fingerprint(url) }
        };
      }
      case "WebSearch": {
        const query = nonEmptyText(input.query);
        if (!query) return null;
        const shown = redact(query);
        return {
          tool: "web",
          operation: shown === query ? "search" : "search.redacted",
          resource: { kind: "query", id: shown },
          params: { query: shown, query_sha256: fingerprint(query) }
        };
      }
      default:
        if (name.startsWith("mcp__")) return mcpCall(name, input);
        return {
          tool: "claude-code",
          // Claude Code's own names, which differ by more than their case.
          operation: /^[A-Za-z0-9_-]{1,128}$/.test(name) ? name.toLowerCase() : ruleKey(name, 128),
          resource: { kind: "tool", id: name },
          params: { input_sha256: fingerprint(input) }
        };
    }
  })();
  return described && described.resource.id.length <= MAX_RESOURCE ? described : null;
}
var allowQuietly = { stdout: "", stderr: "", exitCode: 0 };
function hookAnswer(decision, reason) {
  return {
    stdout: JSON.stringify({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: decision,
        permissionDecisionReason: reason
      }
    }),
    stderr: "",
    exitCode: 0
  };
}
var deny = (reason) => hookAnswer("deny", reason);

// src/blocked-text.ts
function blockedText(decision) {
  const reference = decision.reference ? ` Request ${decision.reference}.` : "";
  switch (decision.code) {
    case "APPROVAL_PENDING":
    case "UNKNOWN_PERMISSION_BLOCKED":
      return `Nodrail: still waiting for a person to review this.${reference} It stays blocked; try again after it is allowed.`;
    case "DENIED":
      return `Nodrail: this action is denied.${reference}`;
    case "EXPIRED":
      return `Nodrail: the request expired before anyone decided.${reference}`;
    case "INVALIDATED":
      return `Nodrail: the request was closed because something changed.${reference} Try again to ask for a new decision.`;
    case "NOT_CONFIGURED":
      return "Nodrail: not configured, so this action is blocked. Set NODRAIL_CREDENTIAL or save it to ~/.nodrail/credential.";
    case "UNAUTHENTICATED":
      return "Nodrail: the credential was refused, so this action is blocked.";
    case "QUOTA_EXCEEDED":
      return "Nodrail: this workspace has used its agent actions for the month, so this action is blocked.";
    case "RATE_LIMITED":
      return "Nodrail: too many calls in a short time, so this action is blocked. Try again in a minute.";
    default:
      return `Nodrail: could not confirm this action is allowed (${decision.code}), so it is blocked.`;
  }
}

// src/connection.ts
import { readFileSync } from "node:fs";
import { homedir as homedir2 } from "node:os";
import { join as join2 } from "node:path";
var DEFAULT_URL = "https://app.nodrail.com";
function savedCredential(env) {
  try {
    return readFileSync(
      join2(env.NODRAIL_HOME ?? join2(homedir2(), ".nodrail"), "credential"),
      "utf8"
    ).trim();
  } catch {
    return "";
  }
}
function resolveConnection(env) {
  return {
    url: env.NODRAIL_URL || env.CLAUDE_PLUGIN_OPTION_URL || DEFAULT_URL,
    credential: env.NODRAIL_CREDENTIAL || env.CLAUDE_PLUGIN_OPTION_CREDENTIAL || savedCredential(env) || null
  };
}
var DEFAULT_WAIT_SECONDS = 300;
function waitMsFrom(env) {
  const seconds = Number(env.NODRAIL_WAIT_SECONDS ?? DEFAULT_WAIT_SECONDS);
  return Number.isFinite(seconds) ? Math.max(0, seconds) * 1e3 : 0;
}

// src/index.ts
import { randomBytes } from "node:crypto";
var Blocked = class extends Error {
  constructor(code, reference = null, reason = null) {
    super(code);
    this.code = code;
    this.reference = reference;
    this.reason = reason;
  }
  code;
  reference;
  reason;
};
var isRecord = (value) => typeof value === "object" && value !== null && !Array.isArray(value);
var stringFields = (value, names) => names.every((name) => typeof value[name] === "string");
function asStatus(body) {
  if (!isRecord(body) || !stringFields(body, [
    "code",
    "action_id",
    "installation_id",
    "descriptor_digest",
    "action_digest",
    "reference"
  ]))
    throw new Blocked("INVALID_RESPONSE");
  return body;
}
var NodrailClient = class {
  constructor(options) {
    this.options = options;
    this.base = `${options.url.replace(/\/$/, "")}/api/v1/runtime`;
    this.timeoutMs = options.timeoutMs ?? 1e4;
    this.send = options.fetch ?? fetch;
  }
  options;
  base;
  timeoutMs;
  send;
  async request(path, init = {}) {
    let response;
    try {
      response = await this.send(`${this.base}${path}`, {
        method: init.body ? "POST" : "GET",
        headers: {
          authorization: `Bearer ${this.options.credential}`,
          ...init.body ? { "content-type": "application/json" } : {},
          ...init.headers
        },
        body: init.body ? JSON.stringify(init.body) : void 0,
        signal: AbortSignal.timeout(this.timeoutMs),
        redirect: "error"
      });
    } catch {
      throw new Blocked("UNAVAILABLE");
    }
    const body = await response.json().catch(() => null);
    if (response.ok) return body;
    const error = isRecord(body) && isRecord(body.error) ? body.error.code : null;
    throw new Blocked(typeof error === "string" ? error : "UNAVAILABLE");
  }
  heartbeat() {
    return this.request("/heartbeat", {
      body: { adapter_version: this.options.adapterVersion }
    });
  }
  async submit(descriptor, idempotencyKey) {
    return asStatus(
      await this.request("/actions", {
        body: { ...descriptor, adapter_version: this.options.adapterVersion },
        headers: { "idempotency-key": idempotencyKey }
      })
    );
  }
  async status(actionId) {
    return asStatus(await this.request(`/actions/${actionId}`));
  }
  async findByKey(idempotencyKey) {
    return asStatus(
      await this.request(
        `/actions?idempotency_key=${encodeURIComponent(idempotencyKey)}`
      )
    );
  }
  /** Verifies the answer is fresh and exactly for this call before trusting it. */
  async permit(action) {
    const nonce = randomBytes(24).toString("hex");
    const startedAt = Date.now();
    const body = await this.request(`/actions/${action.action_id}/permit`, {
      body: { action_digest: action.action_digest, nonce }
    });
    if (!isRecord(body) || body.code !== "ALLOW")
      throw new Blocked(
        isRecord(body) && typeof body.code === "string" ? body.code : "INVALID_RESPONSE",
        action.reference,
        isRecord(body) && typeof body.reason === "string" ? body.reason : null
      );
    if (!stringFields(body, ["permit_id", "issued_at", "expires_at"]) || body.action_id !== action.action_id || body.action_digest !== action.action_digest || body.installation_id !== action.installation_id || body.claim_nonce !== nonce)
      throw new Blocked("PERMIT_MISMATCH", action.reference);
    const lifetime = Date.parse(body.expires_at) - Date.parse(body.issued_at);
    if (!(lifetime > 0) || lifetime > 6e4 || Date.now() - startedAt >= lifetime)
      throw new Blocked("PERMIT_STALE", action.reference);
    return body;
  }
  report(actionId, report) {
    return this.request(`/actions/${actionId}/reports`, {
      body: {
        report_key: report.key,
        outcome: report.outcome,
        ...report.permitId ? { permit_id: report.permitId } : {},
        ...report.details ? { details: report.details } : {}
      }
    });
  }
};
var defaultSleep = (ms) => new Promise((resolve3) => setTimeout(resolve3, ms));
function assertSameCall(status, descriptor) {
  const digest = descriptorDigest(status.installation_id, descriptor);
  if (status.descriptor_digest !== digest || status.action_digest !== actionDigest(status.action_id, digest))
    throw new Blocked("DIGEST_MISMATCH", status.reference);
}
var waiting = /* @__PURE__ */ new Set(["APPROVAL_PENDING", "UNKNOWN_PERMISSION_BLOCKED"]);
async function resolve2(client, descriptor, key, { waitMs = 0, pollMs = 2e3, sleep = defaultSleep }) {
  if (!isPlainJson(descriptor.params)) throw new Blocked("INVALID_ACTION");
  let status = await client.submit(descriptor, key);
  assertSameCall(status, descriptor);
  const deadline = Date.now() + waitMs;
  while (waiting.has(status.code)) {
    if (Date.now() >= deadline)
      throw new Blocked(status.code, status.reference, status.reason);
    await sleep(pollMs);
    status = await client.status(status.action_id);
    assertSameCall(status, descriptor);
  }
  if (status.code !== "READY")
    throw new Blocked(status.code, status.reference, status.reason);
  const permit = await client.permit(status);
  return {
    allowed: true,
    actionId: permit.action_id,
    permitId: permit.permit_id
  };
}
async function authorize(client, descriptor, key, options = {}) {
  try {
    return await resolve2(client, descriptor, key, options);
  } catch (error) {
    return error instanceof Blocked ? {
      allowed: false,
      code: error.code,
      reason: error.reason,
      reference: error.reference
    } : { allowed: false, code: "CLIENT_ERROR", reason: null, reference: null };
  }
}

// src/hooks.ts
var HOOK_VERSION = "0.1.0";
var HOOK_DEADLINE_MS = 345e3;
function clientFrom(env, deps) {
  const { url, credential } = resolveConnection(env);
  if (!credential) return null;
  return new NodrailClient({
    url,
    credential,
    adapterVersion: `${deps.agent ?? "claude-code"}-hook/${HOOK_VERSION}`,
    fetch: deps.fetch
  });
}
async function beforeTool(event, env, deps) {
  const client = clientFrom(env, deps);
  if (!client)
    return deny(
      blockedText({
        allowed: false,
        code: "NOT_CONFIGURED",
        reason: null,
        reference: null
      })
    );
  const name = nonEmptyText(event.tool_name);
  const key = nonEmptyText(event.tool_use_id);
  const input = event.tool_input;
  if (!name || !key || typeof input !== "object" || input === null)
    return deny(
      "Nodrail: this call could not be identified, so it is blocked."
    );
  const descriptor = describeToolCall(name, input, nonEmptyText(event.cwd));
  if (!descriptor)
    return deny(
      "Nodrail: this call could not be described for review, so it is blocked."
    );
  let timer;
  const decision = await Promise.race([
    authorize(client, descriptor, key, {
      waitMs: waitMsFrom(env),
      sleep: deps.sleep
    }),
    new Promise((done) => {
      timer = setTimeout(
        () => done({
          allowed: false,
          code: "TIMED_OUT",
          reason: null,
          reference: null
        }),
        deps.deadlineMs ?? HOOK_DEADLINE_MS
      );
    })
  ]);
  clearTimeout(timer);
  return decision.allowed ? allowQuietly : deny(blockedText(decision));
}
function toolFailed(event) {
  if (event.hook_event_name === "PostToolUseFailure") return true;
  const response = event.tool_response;
  if (typeof response !== "object" || response === null) return false;
  const { exit_code: exitCode } = response;
  return typeof exitCode === "number" && exitCode !== 0;
}
async function afterTool(event, env, deps) {
  const client = clientFrom(env, deps);
  const key = nonEmptyText(event.tool_use_id);
  if (!client || !key) return allowQuietly;
  const failed = toolFailed(event);
  try {
    const action = await client.findByKey(key);
    await client.report(action.action_id, {
      key,
      outcome: failed ? "failure" : "success",
      permitId: action.permit_id,
      details: {
        ...typeof event.duration_ms === "number" ? { duration_ms: event.duration_ms } : {},
        ...event.hook_event_name === "PostToolUseFailure" ? { interrupted: event.is_interrupt === true } : {}
      }
    });
  } catch {
  }
  return allowQuietly;
}
var notice = (message) => ({
  stdout: `${JSON.stringify({ systemMessage: message })}
`,
  stderr: "",
  exitCode: 0
});
async function onSessionStart(env, deps) {
  const client = clientFrom(env, deps);
  if (!client)
    return notice(
      "Nodrail is not connected, so governed actions will be blocked. Set NODRAIL_CREDENTIAL or save it to ~/.nodrail/credential."
    );
  try {
    await client.heartbeat();
  } catch (error) {
    if (error instanceof Error && error.message === "UNAUTHENTICATED")
      return notice(
        "Nodrail refused this credential, so governed actions will be blocked. Create a new one under Agents in Nodrail."
      );
  }
  return allowQuietly;
}
async function runHook(stdin, env, deps = {}) {
  let event;
  try {
    event = JSON.parse(stdin);
  } catch {
    return deny(
      "Nodrail: the hook received an unreadable event, so this action is blocked."
    );
  }
  switch (event.hook_event_name) {
    case "PreToolUse":
      return beforeTool(event, env, deps);
    case "PostToolUse":
    case "PostToolUseFailure":
      return afterTool(event, env, deps);
    case "SessionStart":
      return onSessionStart(env, deps);
    default:
      return deny(
        "Nodrail: unsupported hook event, so this action is blocked."
      );
  }
}

// src/hook-main.ts
async function main() {
  const agent = process.argv[2] === "codex" ? "codex" : "claude-code";
  let stdin = "";
  for await (const chunk of process.stdin) stdin += String(chunk);
  const result = await runHook(stdin, process.env, { agent });
  if (result.stderr) process.stderr.write(result.stderr);
  if (result.stdout)
    process.stdout.write(result.stdout, () => process.exit(result.exitCode));
  else process.exit(result.exitCode);
}
main().catch(() => {
  process.stderr.write(
    "Nodrail: the hook failed, so this action is blocked.\n"
  );
  process.exit(2);
});
