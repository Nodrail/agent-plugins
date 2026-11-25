#!/usr/bin/env node

// ../policy-engine/src/secrets.ts
var SECRET_PLACES = [
  ".env",
  ".envrc",
  ".ssh",
  ".aws",
  ".gnupg",
  ".kube",
  ".docker",
  "gcloud",
  ".netrc",
  ".npmrc",
  ".pypirc",
  ".git-credentials",
  ".pgpass",
  ".vault-token",
  "id_rsa",
  "id_ecdsa",
  "id_ed25519",
  // Agents' and Nodrail's own credentials, and a process's environment.
  ".credentials.json",
  ".nodrail",
  "environ",
  // Key files, by extension.
  "*.pem",
  "*.key",
  "*.p12",
  "*.pfx"
];
var secretSet = new Set(SECRET_PLACES);
var SECRET_PAIRS = [
  { label: "GitHub CLI tokens", parts: [".config", "gh"] },
  { label: "Codex sign-in", parts: [".codex", "auth.json"] },
  // A remote URL in git's config can carry a token.
  { label: "git config", parts: [".git", "config"] }
];
function reachesSecret(params) {
  if (params.reaches_secrets === true) return true;
  const parts = Array.isArray(params.path_parts) ? params.path_parts.filter(
    (part) => typeof part === "string"
  ) : [];
  return parts.some(isSecretName) || SECRET_PAIRS.some(
    (pair) => pair.parts.every((part) => parts.includes(part))
  );
}
var KEY_EXTENSIONS = /* @__PURE__ */ new Set(["pem", "key", "p12", "pfx"]);
function nameForms(part) {
  const lower = part.toLowerCase();
  const forms = /* @__PURE__ */ new Set([part, lower]);
  const second = lower.startsWith(".") ? lower.indexOf(".", 1) : -1;
  if (second > 1) forms.add(lower.slice(0, second));
  if (/^\.env[._-]/.test(lower) || /.\.env$/.test(lower)) forms.add(".env");
  const extension = lower.slice(lower.lastIndexOf(".") + 1);
  if (lower.includes(".") && KEY_EXTENSIONS.has(extension))
    forms.add(`*.${extension}`);
  return [...forms];
}
var isSecretName = (part) => nameForms(part).some((form) => secretSet.has(form));
var MAX_GLOB = 256;
var MAX_ALTERNATIVES = 64;
function expandBraces(pattern, start = 0) {
  const open = pattern.indexOf("{", start);
  if (open < 0) return [pattern];
  const close = pattern.indexOf("}", open);
  if (close < 0) return [pattern];
  const inner = pattern.slice(open + 1, close);
  if (inner.includes("{")) return null;
  if (!inner.includes(","))
    return inner.includes("..") ? null : expandBraces(pattern, close + 1);
  const results = [];
  for (const choice of inner.split(",")) {
    const rest = expandBraces(
      pattern.slice(0, open) + choice + pattern.slice(close + 1),
      open + choice.length
    );
    if (!rest) return null;
    results.push(...rest);
    if (results.length > MAX_ALTERNATIVES) return null;
  }
  return results;
}
function tokens(pattern) {
  const result = [];
  for (let at = 0; at < pattern.length; at += 1) {
    const char = pattern[at] ?? "";
    if (char === "*") {
      if (!("any" in (result.at(-1) ?? {}))) result.push({ any: true });
    } else if (char === "?") result.push({ one: true });
    else if (char === "[") {
      const end = pattern.indexOf("]", at + 2);
      if (end < 0) result.push({ char });
      else {
        const body = pattern.slice(at + 1, end);
        const negate = body.startsWith("!") || body.startsWith("^");
        result.push({ set: negate ? body.slice(1) : body, negate });
        at = end;
      }
    } else result.push({ char });
  }
  return result;
}
function inSet(set, char) {
  for (let at = 0; at < set.length; at += 1) {
    const low = set[at] ?? "";
    if (set[at + 1] === "-" && at + 2 < set.length) {
      const high = set[at + 2] ?? "";
      if (char >= low && char <= high) return true;
      at += 2;
    } else if (char === low) return true;
  }
  return false;
}
function fits(token, char) {
  if ("one" in token) return true;
  if ("set" in token) return inSet(token.set, char) !== token.negate;
  return "char" in token && token.char === char;
}
function matchesPart(pattern, name) {
  let row = Array.from({ length: name.length + 1 }, (_, at) => at === 0);
  for (const token of pattern) {
    const next = Array.from({ length: name.length + 1 }, () => false);
    if ("any" in token)
      for (let at = 0; at <= name.length; at += 1)
        next[at] = (row[at] ?? false) || at > 0 && (next[at - 1] ?? false);
    else
      for (let at = 1; at <= name.length; at += 1)
        next[at] = (row[at - 1] ?? false) && fits(token, name[at - 1] ?? "");
    row = next;
  }
  return row[name.length] ?? false;
}
var secretExamples = SECRET_PLACES.flatMap((place) => {
  if (place.startsWith("*.")) return [`server${place.slice(1)}`];
  if (place === ".env") return [".env", ".env.local", ".env-prod", "prod.env"];
  return place.startsWith(".") ? [place, `${place}.local`] : [place];
});
function globCouldReachSecret(glob) {
  if (glob.length > MAX_GLOB) return true;
  const alternatives = expandBraces(glob);
  if (!alternatives) return true;
  return alternatives.some(
    (alternative) => alternative.split(/[\\/]/).filter(Boolean).some((part) => {
      if (part === "**") return false;
      if (!/[*?[]/.test(part)) return isSecretName(part);
      const pattern = tokens(part.toLowerCase());
      return secretExamples.some((name) => matchesPart(pattern, name));
    })
  );
}

// ../policy-engine/src/commands.ts
var rtkPrograms = new Set(
  `git gh glab aws psql pnpm docker kubectl oc curl wget cargo go deno bun bunx
   npx dotnet tsc jest vitest playwright prisma prettier ruff mypy pytest rspec
   rubocop rake ls tree find grep rg ast-grep wc gt`.split(/\s+/)
);
var rtkRunners = /* @__PURE__ */ new Set([
  "bypass",
  "proxy",
  "err",
  "test",
  "summary",
  "run"
]);
var rtkOwn = new Set(
  `gain discover session cc-economics hook-audit methods pipeline plugins tasks
   telemetry config init trust untrust verify read smart json deps env log learn
   recall rewrite help -h --help -V --version`.split(/\s+/)
);
function unwrapRtk(words) {
  let at = 1;
  while (/^(?:-v{1,3}|--verbose|--skip-env)$/.test(words[at] ?? "")) at += 1;
  const sub = words[at] ?? "";
  if (rtkOwn.has(sub)) return { words, via: [] };
  if (rtkPrograms.has(sub))
    return { words: words.slice(at), via: words.slice(0, at) };
  if (!rtkRunners.has(sub)) return null;
  at += 1;
  while (words[at] === "--skip-env") at += 1;
  if (words[at]?.startsWith("-")) return null;
  return { words: words.slice(at), via: words.slice(0, at) };
}
function prefixLength(words) {
  const [program, ...args] = words;
  const flags = (pattern) => {
    let at = 0;
    while (pattern.test(args[at] ?? "")) at += 1;
    return at + 1;
  };
  switch (program) {
    case "nohup":
      return 1;
    case "time":
      return flags(/^-p$/);
    case "caffeinate":
      return flags(/^-[dimsu]+$/);
    case "nice":
      if (/^-\d{1,2}$/.test(args[0] ?? "")) return 2;
      return args[0] === "-n" && /^-?\d{1,2}$/.test(args[1] ?? "") ? 3 : 1;
    case "timeout": {
      const at = flags(/^--(?:preserve-status|foreground)$/) - 1;
      return /^\d{1,6}(?:\.\d{1,3})?[smhd]?$/.test(args[at] ?? "") ? at + 2 : null;
    }
    default:
      return 0;
  }
}
var MAX_WRAPPERS = 4;
function unwrap(words) {
  let rest = words;
  const via = [];
  for (let depth = 0; depth <= MAX_WRAPPERS; depth += 1) {
    let next;
    if (rest[0] === "rtk") next = unwrapRtk(rest);
    else {
      const taken = prefixLength(rest);
      if (taken === null) return null;
      next = { words: rest.slice(taken), via: rest.slice(0, taken) };
    }
    if (!next) return null;
    if (!next.via.length) return { words: rest, via };
    if (!next.words.length || next.words[0]?.startsWith("-")) return null;
    via.push(...next.via);
    rest = next.words;
  }
  return null;
}
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
   podman kubectl pkexec runuser sg`.split(/\s+/)
);
var python = /^python[0-9.]*$/;
var riskyArgument = /^(?:-c|-e|-exec|-execdir|-ok|-okdir|-delete|-fprint.*|-fls|--eval|--expression(?:=.*)?|--(?:exec|output|rsh|to-command|checkpoint-action|use-compress-program|upload-pack|receive-pack|open-files-in-pager|pre|config-env|compress-program|unzip-command|pager)(?:=.*)?)$/;
var packageManagerFlags = /^--(?:script-shell|shell|config\..+|prefix|dir|userconfig|globalconfig|node-options|call|workspace-root)(?:=.*)?$/;
var riskyByProgram = new Map(
  Object.entries({
    // -u is clone's --upload-pack; --config and --template can set a command or
    // install hooks that run on the next git command.
    git: /^(?:-x|-O.*|-u.*|--config(?:=.*)?|--template(?:=.*)?)$/,
    zip: /^(?:-TT.*|--unzip-command(?:=.*)?)$/,
    man: /^(?:-P.*|--pager(?:=.*)?|-H.*|--html(?:=.*)?)$/,
    tar: /^(?:-I.*|-[a-zA-Z]*I)$/,
    rsync: /^-e.*$/,
    curl: /^(?:-[oOKTdF].*|--(?:output|remote-name|config|upload-file|data.*|form.*|json)(?:=.*)?)$/,
    wget: /^(?:-[oO].*|--(?:output-document|output-file|post-file)(?:=.*)?)$/,
    dd: /^of=/,
    make: /^(?:-[fC].*|--(?:file|makefile|directory|eval)(?:=.*)?)$/,
    // Settings that swap the shell scripts run in, or where config comes from.
    npm: packageManagerFlags,
    pnpm: packageManagerFlags,
    yarn: packageManagerFlags
  })
);
var riskySubcommands = new Map(
  Object.entries({
    git: /^(?:bisect|submodule|filter-branch|difftool|mergetool|config|alias|credential|hook)$/,
    npm: /^(?:exec|x)$/,
    pnpm: /^(?:exec|dlx)$/,
    yarn: /^(?:exec|dlx)$/
  })
);
var namesASecret = (words) => words.slice(1).some((word) => word.split(/[:=]/).some(fragmentReachesSecret));
function fragmentReachesSecret(fragment) {
  if (fragment.length <= 256) return globCouldReachSecret(fragment);
  return fragment.split(/[\\/]/).some(isSecretName);
}
var hidesItsProgram = (words) => assignment.test(words[0] ?? "") || runsAnotherCommand(words);
function runsAnotherCommand(words) {
  if (namesASecret(words)) return true;
  const first = words[0] ?? "";
  if (computedProgram.test(first)) return true;
  const program = (first.split("/").pop() ?? "").toLowerCase();
  if (wrappers.has(program) || python.test(program)) return true;
  const args = words.slice(1);
  if (program === "git" && args[0]?.startsWith("-")) return true;
  if (riskySubcommands.get(program)?.test(args[0] ?? "")) return true;
  const specific = riskyByProgram.get(program);
  return args.some(
    (word) => riskyArgument.test(word) || specific?.test(word) === true
  );
}
function splitWords(line, breaks = " 	") {
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
    } else if (breaks.includes(char)) {
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
function separatorLength(text, index) {
  const char = text[index] ?? "";
  const doubled = text[index + 1] === char;
  if (char === "&" && !doubled) return null;
  if (doubled && (char === ";" || char === "\n")) return null;
  return doubled ? 2 : 1;
}
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
    const length = separatorLength(text, index);
    if (length === null) return null;
    index += length - 1;
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
  const split = splitWords(text);
  if (!split?.length || assignment.test(split[0] ?? "")) return compound;
  const inner = unwrap(split);
  if (!inner || hidesItsProgram(inner.words)) return compound;
  return simpleShape(inner);
}
var simpleShape = ({ words, via }) => ({
  operation: "command.run",
  text: render(words),
  ...via.length ? { via: render(via) } : {}
});
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
var shellWords = (line) => splitWords(line, " 	\r\n;&|<>()`");
function programWords(line) {
  const text = trimShellSpace(line);
  return (splitChain(text) ?? text.split(/[;&|\n]+/)).flatMap((part) => {
    const words = shellWords(part) ?? part.split(/[\s'"]+/).filter(Boolean);
    if (!words.length) return [];
    return [unwrap(words)?.words ?? words];
  });
}
var hasOption = (args, letters, long) => args.some(
  (word) => /^-[^-]/.test(word) && letters.test(word.slice(1)) || long.some((name) => word === name || word.startsWith(`${name}=`))
);
function makesLink(words) {
  const program = (words[0] ?? "").split("/").pop() ?? "";
  if (program === "ln" || program === "link") return true;
  return program === "cp" && hasOption(words.slice(1), /s/, ["--symbolic-link"]);
}
function classifyCommand(line) {
  const text = trimShellSpace(line);
  const parts = chainParts(text);
  if (parts && programWords(text).some(makesLink))
    return { operation: "command.compound", text };
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

// ../policy-engine/src/names.ts
function agentName(text) {
  const name = text.trim().toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^[-_]+/, "").slice(0, 63);
  return name || "unnamed";
}

// ../policy-engine/src/text.ts
var nonEmptyText = (value) => typeof value === "string" && value ? value : null;

// ../policy-engine/src/codex-actions.ts
function codexSubagentCall(input) {
  const name = agentName(nonEmptyText(input.agent_type) ?? "default");
  return {
    tool: "codex",
    operation: "agent",
    resource: { kind: "agent", id: name },
    params: { agent_type: name, input_sha256: fingerprint(input) }
  };
}
function codexCollaborationCall(name, input) {
  return {
    tool: "codex",
    operation: name.replace(/^collaboration/, ""),
    resource: { kind: "tool", id: name },
    params: { input_sha256: fingerprint(input) }
  };
}
var CODEX_COLLABORATION = [
  "wait_agent",
  "send_input",
  "send_message",
  "followup_task",
  "resume_agent",
  "interrupt_agent",
  "close_agent",
  "list_agents"
];
var codexDescribers = [
  ["collaborationspawn_agent", codexSubagentCall],
  ["spawn_agent", codexSubagentCall],
  ...CODEX_COLLABORATION.flatMap((name) => [
    [`collaboration${name}`, (input) => codexCollaborationCall(name, input)],
    [name, (input) => codexCollaborationCall(name, input)]
  ])
];

// ../policy-engine/src/redact.ts
var MAX_INLINE_INPUT = 16 * 1024;
var REDACTED = "[redacted]";
var sensitiveWord = /token|secret|passw(?:or)?d|pwd|api[_-]?key|[_-]keys?$|credential|authorization/i;
var secretValue = `"(?![^"]*[$\`])[^"]*"|'[^']*'|(?![^\\s&;|]*[$\`])[^\\s&;|]+`;
var secretPatterns = [
  // A whole header value, whatever scheme it uses.
  [
    /\b(authorization|proxy-authorization|cookie|set-cookie|x-api-key)(\s*:\s*)[^'"\n]+/gi,
    `$1$2${REDACTED}`
  ],
  [/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi, `$1 ${REDACTED}`],
  [/([?&](?:key|sig|signature|auth|code)=)[^&\s'"]+/gi, `$1${REDACTED}`],
  [/(\s-u\s+)[^\s:]+:\S+/g, `$1${REDACTED}`],
  [/\b(mysql|mysqldump|mariadb)\b([^|;&\n]*\s-p)[^\s]+/g, `$1$2${REDACTED}`],
  [/(\/\/)[^/\s:@]+:[^/\s@]+@/g, `$1${REDACTED}@`],
  // Known token shapes, found anywhere: a shell joins 0'ghp_…'_ into one word,
  // and the token must still be found inside it.
  [
    /(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)/g,
    REDACTED
  ],
  // sk- and sk_ are common inside ordinary words (task-…), so they need no
  // letter or digit just before them.
  [/(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{20,}/g, REDACTED],
  // Stripe, GitLab, Google and npm.
  [/(?<![A-Za-z0-9])[sr]k_(?:live|test)_[A-Za-z0-9]{10,}/g, REDACTED],
  [
    /glpat-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{35}|npm_[A-Za-z0-9]{36}/g,
    REDACTED
  ]
];
var nameChars = /[A-Za-z0-9_-]+/g;
var assignmentAt = /=|:\s*/y;
var spaceAt = /\s+/y;
var valueAt = new RegExp(`(?:${secretValue})`, "y");
function redactNamedValues(text) {
  let shown = "";
  let copied = 0;
  for (const word of text.matchAll(nameChars)) {
    const start = word.index;
    if (start < copied || !sensitiveWord.test(word[0])) continue;
    let at = start + word[0].length;
    assignmentAt.lastIndex = at;
    const assignment2 = assignmentAt.exec(text);
    if (assignment2) at += assignment2[0].length;
    else {
      const isFlag = word[0].startsWith("-") && (start === 0 || /\s/.test(text[start - 1] ?? ""));
      spaceAt.lastIndex = at;
      const space = isFlag ? spaceAt.exec(text) : null;
      if (!space) continue;
      at += space[0].length;
    }
    valueAt.lastIndex = at;
    const value = valueAt.exec(text);
    if (!value) continue;
    shown += text.slice(copied, at) + REDACTED;
    copied = at + value[0].length;
  }
  return shown + text.slice(copied);
}
var MAX_REDACTED = MAX_INLINE_INPUT;
function bounded(value) {
  if (value.length <= MAX_REDACTED) return value;
  const head = value.slice(0, MAX_REDACTED);
  const space = head.search(/\s\S*$/);
  return `${space > 0 ? head.slice(0, space) : ""} \u2026 [shortened]`;
}
var redact = (value) => secretPatterns.reduce(
  (current, [pattern, replacement]) => current.replace(pattern, replacement),
  redactNamedValues(bounded(value))
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
var isSensitiveKey = (key) => /^[A-Za-z0-9_-]+$/.test(key) && sensitiveWord.test(key);
function redactJson(value) {
  if (typeof value === "string") return redact(value);
  if (Array.isArray(value)) return value.map(redactJson);
  if (typeof value === "object" && value !== null)
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [
        key,
        isSensitiveKey(key) ? REDACTED : redactJson(item)
      ])
    );
  return value;
}

// ../policy-engine/src/paths.ts
import { lstatSync, readlinkSync, realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import native, {
  basename,
  dirname,
  isAbsolute,
  join,
  resolve,
  win32
} from "node:path";
function canonicalPath(path, hops = 0) {
  const missing = [];
  let existing = path;
  for (; ; ) {
    try {
      return join(realpathSync.native(existing), ...[...missing].reverse());
    } catch {
      const target = linkTarget(existing);
      if (target !== null && hops < MAX_LINKS)
        return canonicalPath(
          join(resolve(dirname(existing), target), ...[...missing].reverse()),
          hops + 1
        );
      const parent = dirname(existing);
      if (parent === existing) return path;
      missing.push(basename(existing));
      existing = parent;
    }
  }
}
var MAX_LINKS = 40;
function linkTarget(path) {
  try {
    return lstatSync(path).isSymbolicLink() ? readlinkSync(path) : null;
  } catch {
    return null;
  }
}
var partsOf = (path) => [
  ...new Set(path.split(/[\\/]/).filter(Boolean).flatMap(nameForms))
];
var fileName = (path) => path.split(/[\\/]/).pop() ?? "";
var MAX_PATH = 4096;
var MAX_DEPTH = 256;
var separator = native === win32 ? /[\\/]/ : /\//;
var pathWithinLimits = (path) => path.length <= MAX_PATH && path.split(separator).filter(Boolean).length <= MAX_DEPTH;
function fullPath(raw, cwd) {
  if (!pathWithinLimits(raw)) return null;
  const expanded = (native === win32 ? /^~(?=$|[\\/])/ : /^~(?=$|\/)/).test(raw) ? `${homedir()}${raw.slice(1)}` : raw;
  if (!isAbsolute(expanded) && !cwd) return null;
  const absolute = resolve(cwd ?? "/", expanded);
  if (!pathWithinLimits(absolute)) return null;
  return canonicalPath(absolute);
}
function insideCwd(path, cwd) {
  const root = cwd ? fullPath(cwd, null) : null;
  return root ? { inside_cwd: isWithinOnDisk(path, root) } : {};
}
function withoutNamespace(path) {
  return path.replace(/^[\\/]{2}\?[\\/]UNC[\\/]/i, "\\\\").replace(/^[\\/]{2}\?[\\/](?=[a-z]:[\\/])/i, "");
}
function relativePath(root, path, flavor = native) {
  if (flavor === win32) {
    root = withoutNamespace(root);
    path = withoutNamespace(path);
  }
  const result = flavor.relative(root, path);
  return result === ".." || result.startsWith(`..${flavor.sep}`) || flavor.isAbsolute(result) ? null : result;
}
function isWithin(path, root, flavor = native) {
  return relativePath(root, path, flavor) !== null;
}
function isWithinOnDisk(path, root, flavor = native) {
  const relative = relativePath(root, path, flavor);
  if (relative === null) return false;
  if (flavor !== win32) return true;
  let ancestor = win32.normalize(withoutNamespace(path));
  for (const _ of relative.split("\\").filter(Boolean))
    ancestor = win32.dirname(ancestor);
  try {
    const candidate = statSync(ancestor, { bigint: true });
    const project = statSync(withoutNamespace(root), { bigint: true });
    return candidate.isDirectory() && project.isDirectory() && project.ino !== 0n && candidate.dev === project.dev && candidate.ino === project.ino;
  } catch {
    return false;
  }
}
function insideAll(paths, cwd) {
  const root = cwd ? fullPath(cwd, null) : null;
  return root ? { inside_cwd: paths.every((path) => isWithinOnDisk(path, root)) } : {};
}
function containsHome(path) {
  const home = canonicalPath(homedir());
  return isWithin(home, path);
}

// ../policy-engine/src/actions.ts
var MAX_RESOURCE = 512;
var MAX_COMMAND_ID = MAX_RESOURCE - 42;
var clip = (value, max) => value.length <= max ? value : `${value.slice(0, max)}\u2026 [shortened]`;
function commandAction(shape, original, extra) {
  const visible = bounded(shape.text);
  const shown = redactCommand(visible);
  const hidden = shown !== visible;
  const shortened = shape.text.length > MAX_COMMAND_ID;
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
      // Reviewers see what ran it; rules judge the command itself.
      ...shape.via ? { via: shape.via } : {},
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
var MAX_PATCH_FILES = 1e3;
function fileCall({ operation, pathField, content }, input, cwd) {
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
      file_name: fileName(path),
      ...insideCwd(path, cwd),
      content_sha256: fingerprint(content(input))
    }
  };
}
function globRoot(pattern) {
  const fixed2 = [];
  for (const part of pattern.split(/[\\/]/)) {
    if (/[*?[\]{}]/.test(part)) break;
    fixed2.push(part);
  }
  return fixed2.join("/");
}
function searchCall(input, cwd, filePattern) {
  const within2 = nonEmptyText(input.path) ?? cwd;
  const base = within2 ? fullPath(within2, cwd) : null;
  if (!base) return null;
  const glob = nonEmptyText(filePattern);
  const root = glob ? globRoot(glob) : "";
  const path = root ? fullPath(root, base) : base;
  if (!path) return null;
  return {
    tool: "files",
    operation: "file.search",
    resource: { kind: "file", id: path },
    params: {
      path,
      path_parts: [.../* @__PURE__ */ new Set([...partsOf(path), ...partsOf(glob ?? "")])],
      ...insideCwd(path, cwd),
      // A wildcard such as .env* can pick out a secret without naming it, and a
      // search of the home folder, or above it, reaches every secret there.
      reaches_secrets: (glob ? globCouldReachSecret(glob) : false) || containsHome(path),
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
    else if (rest.startsWith("Move to: ")) moves.push(rest.slice(9).trimEnd());
  }
  return { changes, moves };
}
function patchCall(input, cwd) {
  const patch = nonEmptyText(input.command) ?? nonEmptyText(input.patch);
  if (!patch) return null;
  const { changes, moves } = patchHeaders(patch);
  if (changes.length + moves.length > MAX_PATCH_FILES) return null;
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
      params: {
        path: only,
        path_parts: partsOf(only),
        file_name: fileName(only),
        ...insideCwd(only, cwd),
        content_sha256
      }
    };
  return {
    tool: "files",
    operation: "file.patch",
    resource: { kind: "file", id: `patch:${content_sha256}` },
    params: {
      paths: known,
      path_parts: [...new Set(known.flatMap(partsOf))],
      ...insideAll(known, cwd),
      content_sha256
    }
  };
}
function webFetchCall(input) {
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
function webSearchCall(input) {
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
function otherToolCall(name, input) {
  if (name.startsWith("mcp__")) return mcpCall(name, input);
  return {
    tool: "claude-code",
    // Claude Code's own names, which differ by more than their case.
    operation: /^[A-Za-z0-9_-]{1,128}$/.test(name) ? name.toLowerCase() : ruleKey(name, 128),
    resource: { kind: "tool", id: name },
    params: { input_sha256: fingerprint(input) }
  };
}
function subagentCall(input) {
  const name = agentName(
    nonEmptyText(input.subagent_type) ?? "general-purpose"
  );
  return {
    tool: "claude-code",
    operation: "agent",
    resource: { kind: "agent", id: name },
    params: { subagent_type: name, input_sha256: fingerprint(input) }
  };
}
function skillCall(input) {
  const parts = (nonEmptyText(input.skill) ?? "unnamed").split(":");
  const name = parts.map(agentName).join(":");
  return {
    tool: "claude-code",
    operation: "skill",
    resource: { kind: "skill", id: name },
    params: { skill: name, input_sha256: fingerprint(input) }
  };
}
var whatIsWritten = (input) => input.content;
var wholeInput = (input) => input;
var describers = new Map([
  ["Bash", (input, _cwd, name) => shellCall(name, input)],
  ["Agent", (input) => subagentCall(input)],
  // Claude Code's earlier name for Agent, with the same subagent_type.
  ["Task", (input) => subagentCall(input)],
  ["Skill", (input) => skillCall(input)],
  ...codexDescribers,
  ["PowerShell", (input, _cwd, name) => shellCall(name, input)],
  [
    "Write",
    (input, cwd) => fileCall(
      {
        operation: "file.write",
        pathField: "file_path",
        content: whatIsWritten
      },
      input,
      cwd
    )
  ],
  [
    "Edit",
    (input, cwd) => fileCall(
      { operation: "file.edit", pathField: "file_path", content: wholeInput },
      input,
      cwd
    )
  ],
  [
    "MultiEdit",
    (input, cwd) => fileCall(
      { operation: "file.edit", pathField: "file_path", content: wholeInput },
      input,
      cwd
    )
  ],
  [
    "Read",
    (input, cwd) => fileCall(
      { operation: "file.read", pathField: "file_path", content: wholeInput },
      input,
      cwd
    )
  ],
  [
    "NotebookEdit",
    (input, cwd) => fileCall(
      {
        operation: "notebook.edit",
        pathField: "notebook_path",
        content: wholeInput
      },
      input,
      cwd
    )
  ],
  ["Grep", (input, cwd) => searchCall(input, cwd, input.glob)],
  ["Glob", (input, cwd) => searchCall(input, cwd, input.pattern)],
  ["apply_patch", (input, cwd) => patchCall(input, cwd)],
  ["WebFetch", (input) => webFetchCall(input)],
  ["WebSearch", (input) => webSearchCall(input)]
]);
function describeToolCall(name, input, cwd = null) {
  const describe = describers.get(name);
  const described = describe ? describe(input, cwd, name) : otherToolCall(name, input);
  return described && described.resource.id.length <= MAX_RESOURCE ? described : null;
}
var allowQuietly = { stdout: "", stderr: "", exitCode: 0 };
function deny(reason) {
  return {
    stdout: JSON.stringify({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny",
        permissionDecisionReason: reason
      }
    }),
    stderr: "",
    exitCode: 0
  };
}

// ../policy-engine/src/receipt-block.ts
var MAX_RECEIPT_TEXT = 8192;
var SCAN = 16 * 1024;
var openings = {
  "nodrail-receipt": /(?:^|\n)(`{3,}|~{3,})[ \t]*nodrail-receipt[ \t]*\n/g,
  "nodrail-brief": /(?:^|\n)(`{3,}|~{3,})[ \t]*nodrail-brief[ \t]*\n/g
};
function lastOpening(message, kind, scan) {
  const from = Math.max(0, message.length - scan);
  const tail = message.slice(from);
  const cutMidLine = from > 0 && message[from - 1] !== "\n";
  let last;
  for (const match of tail.matchAll(openings[kind]))
    if (match.index > 0 || match[0].startsWith("\n") || !cutMidLine)
      last = match;
  if (!last) return null;
  const newline = last[0].startsWith("\n") ? 1 : 0;
  return {
    start: from + last.index + newline,
    after: from + last.index + last[0].length,
    fence: last[1] ?? "```"
  };
}
function readReceiptBlock(message, max = MAX_RECEIPT_TEXT) {
  return readLastBlock(message, "nodrail-receipt", max, SCAN);
}
function readLastBlock(message, kind, max, scan) {
  const opening = lastOpening(message, kind, scan);
  if (!opening) return null;
  const text = message.slice(opening.start);
  if (text.length > max) return null;
  const rest = message.slice(opening.after).trimEnd();
  if (!rest.endsWith(opening.fence)) return null;
  const body = rest.slice(0, rest.length - opening.fence.length);
  return { text, body: body.endsWith("\n") ? body.slice(0, -1) : body };
}
function receiptBlock(message) {
  return readReceiptBlock(message)?.text ?? null;
}

// ../policy-engine/src/shapes/receipt-header.ts
var SCAN2 = 16 * 1024;
var ENTRY = /^\s*(?:[-*]\s+)?([a-z][a-z0-9_-]*):\s*(.*)$/;
var UNKNOWN = /^\s*(?:[-*]\s+)?[^\n]*:.*$/;
var BULLET = /^\s*[-*]\s+\S/;
var BULLET_MARK = /^\s*[-*]\s+/;
var FENCE = /^\s*(?:`{3,}|~{3,})/;
var AGENT = "([A-Za-z0-9_-]{1,64})";
var matcher = (pattern) => (line) => pattern.exec(line)?.[1] ?? null;
var anyHeader = matcher(
  new RegExp(
    `^\\s*\\**\\s*[A-Z][A-Z0-9_-]*(?:[ \\t]+[A-Z][A-Z0-9_-]*)*[ \\t]+${AGENT}\\s*\\**\\s*$`
  )
);
var BOLD = /^\s*\**\s*(.*?)\s*\**\s*$/;
var TITLE_HEAD = /^[A-Z][A-Z0-9 \t_-]*$/;
var AGENT_TEXT = /^[A-Za-z0-9_-]{1,64}$/;
var MAX_HEADER_LINE = 128;
function headerNaming(agent) {
  const wanted = agentName(agent);
  return (line) => {
    if (line.length > MAX_HEADER_LINE) return null;
    const inner = BOLD.exec(line)?.[1] ?? "";
    for (let cut = inner.length - 1; cut > 0; cut -= 1) {
      const said = inner.slice(cut);
      if (!AGENT_TEXT.test(said)) break;
      const head = inner.slice(0, cut);
      if (TITLE_HEAD.test(head) && agentName(said) === wanted) return said;
    }
    return null;
  };
}
function nextTexts(lines) {
  const next = Array.from({ length: lines.length }, () => "");
  let found = "";
  for (let index = lines.length - 1; index >= 0; index -= 1) {
    next[index] = found;
    if (lines[index].trim()) found = lines[index];
  }
  return next;
}
function consume(line, index, next, scan) {
  if (FENCE.test(line)) return true;
  if (!line.trim())
    return ENTRY.test(next) || UNKNOWN.test(next) || FENCE.test(next);
  const entry = ENTRY.exec(line);
  if (entry) {
    const value = entry[2].trim();
    scan.entries.push([entry[1], value]);
    scan.open = value ? null : scan.entries.length - 1;
  } else if (UNKNOWN.test(line)) scan.open = null;
  else if (scan.open !== null && BULLET.test(line)) {
    const held = scan.entries[scan.open];
    const item = line.replace(BULLET_MARK, "").trim();
    held[1] = held[1] ? `${held[1]}; ${item}` : item;
  } else return false;
  scan.last = index;
  return true;
}
function blockAt({ lines, next, match }, head, agent) {
  const scan = { entries: [], open: null, last: head };
  for (let index = head + 1; index < lines.length; index += 1)
    if (!consume(lines[index], index, next[index], scan)) break;
  for (const rest of lines.slice(scan.last + 1)) {
    const text = rest.trim();
    if (!text || FENCE.test(text)) continue;
    if (match(rest) === agent) continue;
    return null;
  }
  return scan.entries;
}
function readHeaderBlock(message, match, max = MAX_RECEIPT_TEXT) {
  const from = Math.max(0, message.length - SCAN2);
  const lines = message.slice(from).split("\n");
  if (from > 0 && message[from - 1] !== "\n") lines[0] = "";
  const view = { lines, next: nextTexts(lines), match };
  for (let head = lines.length - 1; head >= 0; head -= 1) {
    const agent = match(lines[head]);
    if (agent === null) continue;
    const entries = blockAt(view, head, agent);
    if (!entries?.length) continue;
    const text = lines.slice(head).join("\n").trimEnd();
    return text.length > max ? null : { agent, text, entries };
  }
  return null;
}

// ../policy-engine/src/run-key.ts
import { spawnSync } from "node:child_process";
import { createHash as createHash2 } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir as homedir2 } from "node:os";
import { basename as basename2, isAbsolute as isAbsolute2, join as join2, resolve as resolve2 } from "node:path";
var MAX_KEY = 200;
var GIT_TIMEOUT_MS = 5e3;
function git(cwd, args) {
  const result = spawnSync("git", args, {
    cwd,
    encoding: "utf8",
    timeout: GIT_TIMEOUT_MS
  });
  if (result.error?.code === "ETIMEDOUT")
    throw new Error(
      `git didn't answer within ${GIT_TIMEOUT_MS / 1e3} s, so the run's history can't be found.`
    );
  return result.status === 0 ? result.stdout.trim() : "";
}
function nodrailDirectory(cwd, env = process.env) {
  const common = git(cwd, ["rev-parse", "--git-common-dir"]);
  if (!common) return join2(env.HOME || homedir2(), ".nodrail");
  return join2(isAbsolute2(common) ? common : resolve2(cwd, common), "nodrail");
}
function sessionsDirectory(cwd, env) {
  if (env.NODRAIL_LEDGER)
    return join2(resolve2(cwd, env.NODRAIL_LEDGER), "sessions");
  return join2(nodrailDirectory(cwd, env), "sessions");
}
function repositoryName(remote) {
  let text = remote.trim();
  if (/^[a-z]:[\\/]/i.test(text)) return null;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(text)) {
    const scp = /^(?:[^@/]+@)?([^/:]+):(?!\/)(.+)$/.exec(text);
    if (!scp) return null;
    text = `ssh://${scp[1]}/${scp[2]}`;
  }
  if (!URL.canParse(text)) return null;
  const { hostname, pathname } = new URL(text);
  const path = pathname.split("/").filter(Boolean).join("/").replace(/\.git$/, "");
  if (!hostname || !path) return null;
  return `${hostname.toLowerCase()}/${path}`;
}
function isDefaultBranch(cwd, branch) {
  const head = git(cwd, [
    "symbolic-ref",
    "--quiet",
    "refs/remotes/origin/HEAD"
  ]);
  if (head) return head === `refs/remotes/origin/${branch}`;
  return branch === "main" || branch === "master";
}
function computeKey(cwd, sessionId) {
  const session = sessionId ? `session:${sessionId}` : null;
  const branch = git(cwd, ["branch", "--show-current"]);
  if (!branch || isDefaultBranch(cwd, branch)) return session;
  const remote = repositoryName(git(cwd, ["remote", "get-url", "origin"]));
  const repo = remote ?? basename2(git(cwd, ["rev-parse", "--show-toplevel"]));
  return repo ? `${repo}/${branch}` : branch;
}
function pinned(file, key) {
  try {
    const kept = readFileSync(file, "utf8").trim();
    if (kept) return kept.slice(0, MAX_KEY);
  } catch {
  }
  const computed = key()?.slice(0, MAX_KEY) ?? null;
  if (!computed) return null;
  try {
    writeFileSync(file, computed, { flag: "wx" });
    return computed;
  } catch {
    try {
      return readFileSync(file, "utf8").trim().slice(0, MAX_KEY) || computed;
    } catch {
      return computed;
    }
  }
}
function runKey(cwd, sessionId, env = process.env) {
  const named = env.NODRAIL_RUN?.trim();
  if (named) return named.slice(0, MAX_KEY);
  if (!sessionId) return computeKey(cwd, null)?.slice(0, MAX_KEY) ?? null;
  const directory = sessionsDirectory(cwd, env);
  try {
    mkdirSync(directory, { recursive: true });
  } catch {
  }
  const name = createHash2("sha256").update(sessionId).digest("hex");
  return pinned(
    join2(directory, name.slice(0, 32)),
    () => computeKey(cwd, sessionId)
  );
}

// ../policy-engine/src/hook-runs.ts
var HANDBACK_TOOL = "SubagentHandback";
function receiptText(message, agent) {
  const fenced = receiptBlock(message);
  if (fenced !== null) return fenced;
  return readHeaderBlock(message, headerNaming(agent))?.text ?? null;
}

// src/blocked-text.ts
var why = {
  gate: " A gate in your rules holds it until the steps it waits for, such as QA or review, have finished with an accepted verdict after the last change. Run those steps, then try again.",
  budget: " A budget in your rules for this run or step is used up.",
  no_rule: " No rule covers this call. If it should run, add a rule that allows it, then try again.",
  agent_paused: " This agent is paused in Nodrail."
};
var fixed = {
  NOT_CONFIGURED: "Nodrail: not configured, so this action is blocked. Set NODRAIL_CREDENTIAL or save it to ~/.nodrail/credential.",
  INSECURE_URL: "Nodrail: its address must use https (plain http only for this machine), so the credential isn't sent and this action is blocked.",
  UNAUTHENTICATED: "Nodrail: the credential was refused, so this action is blocked.",
  QUOTA_EXCEEDED: "Nodrail: this workspace has used its agent actions for the month, so this action is blocked.",
  RATE_LIMITED: "Nodrail: too many calls in a short time, so this action is blocked. Try again in a minute.",
  CONTRACT_REFUSED: "Nodrail: this call doesn't follow its declared contract, so it is blocked."
};
function blockedText(decision) {
  if (decision.code === "CONTRACT_REFUSED" && decision.reason)
    return decision.reason;
  const constant = fixed[decision.code];
  if (constant) return constant;
  const reference = decision.reference ? ` Request ${decision.reference}.` : "";
  const because = (decision.reason && why[decision.reason]) ?? "";
  switch (decision.code) {
    case "DENIED":
      return `Nodrail: this action is denied.${reference}${because}`;
    case "EXPIRED":
      return `Nodrail: the request expired before it was used.${reference} Try again.`;
    case "INVALIDATED":
      return `Nodrail: the request was closed because something changed.${reference} Try again to ask for a new decision.`;
    default:
      return `Nodrail: could not confirm this action is allowed (${decision.code}), so it is denied.${reference}${because}`;
  }
}

// src/connection.ts
import { readFileSync as readFileSync2 } from "node:fs";
import { homedir as homedir3 } from "node:os";
import { join as join3 } from "node:path";
var DEFAULT_URL = "https://app.nodrail.com";
function savedCredential(env) {
  try {
    return readFileSync2(
      join3(env.NODRAIL_HOME ?? join3(homedir3(), ".nodrail"), "credential"),
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

// src/setup.ts
var localReadTools = ["Read", "Glob", "Grep"];
var localReadMatcher = `^(${localReadTools.join("|")})$`;

// ../policy-engine/src/revision.ts
import { spawnSync as spawnSync2 } from "node:child_process";
import { createHash as createHash3 } from "node:crypto";
var TOTAL_MS = 5e3;
var MAX_OUTPUT = 32 * 1024 * 1024;
var MAX_UNTRACKED = 2e3;
function reader(cwd) {
  const deadline = Date.now() + TOTAL_MS;
  return (args, input) => {
    const left = deadline - Date.now();
    if (left <= 0) return null;
    const result = spawnSync2("git", args, {
      cwd,
      encoding: "buffer",
      timeout: left,
      maxBuffer: MAX_OUTPUT,
      // A Buffer: Node encodes string input with `encoding`, and "buffer"
      // isn't one, so a string here would make every untracked file unknown.
      ...input === void 0 ? {} : { input: Buffer.from(input, "utf8") }
    });
    if (result.error || result.status !== 0) return null;
    return result.stdout;
  };
}
function untracked(git2) {
  const others = git2(["ls-files", "--others", "--exclude-standard", "-z"]);
  if (!others) return null;
  const names = others.toString("utf8").split("\0").filter(Boolean);
  if (names.length > MAX_UNTRACKED || names.some((name) => name.includes("\n")))
    return null;
  if (!names.length) return [others];
  const contents = git2(
    ["hash-object", "--stdin-paths", "--no-filters"],
    `${names.join("\n")}
`
  );
  return contents ? [others, contents] : null;
}
function workRevision(cwd) {
  const top = reader(cwd)(["rev-parse", "--show-toplevel"]);
  const root = top?.toString("utf8").replace(/\n$/, "");
  if (!root) return null;
  const git2 = reader(root);
  const head = git2(["rev-parse", "--verify", "HEAD"]);
  const diff = head && git2(["diff", "HEAD", "--binary", "--no-ext-diff", "--no-color"]);
  const others = diff && untracked(git2);
  if (!head || !diff || !others) return null;
  return digestOf([head, diff, ...others]);
}
function digestOf(parts) {
  const hash = createHash3("sha256");
  for (const part of parts) hash.update(`${part.length}
`).update(part);
  return `sha256:${hash.digest("hex")}`;
}

// src/subject.ts
var REVISION = /^sha256:[0-9a-f]{64}$/;
function readSubject(reader2) {
  if (!reader2) return null;
  try {
    const read = reader2();
    return typeof read === "string" && REVISION.test(read) ? read : null;
  } catch {
    return null;
  }
}
var revisionAt = (cwd) => () => workRevision(cwd);
var MAX_MEASURED = 20;
var RESULT_PATH = /^result(?:\.[a-z][a-z0-9_]{0,62}){1,6}$/;
function checkMeasured(measured) {
  if (measured.length > MAX_MEASURED) return null;
  const seen = /* @__PURE__ */ new Set();
  const checked = [];
  for (const item of measured) {
    if (typeof item !== "object" || item === null) return null;
    const { path, value } = item;
    if (typeof path !== "string" || !RESULT_PATH.test(path)) return null;
    if (seen.has(path)) return null;
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0)
      return null;
    seen.add(path);
    checked.push({ path, value });
  }
  return checked;
}

// src/hook-contracts.ts
import { existsSync, readFileSync as readFileSync3 } from "node:fs";
import { dirname as dirname2, join as join4, resolve as resolve3 } from "node:path";
var CONTRACTS_FILE = ".nodrail/contracts.json";
var MAX_BYTES = 1024 * 1024;
var MAX_DEPTH2 = 32;
var loadChecker = () => {
  const specifier = import.meta.url.endsWith(".ts") ? "./contract-fields.ts" : "./nodrail-hook-contracts.mjs";
  return import(specifier);
};
function findContractsFile(cwd, env) {
  const project = env.CLAUDE_PROJECT_DIR?.trim();
  if (project) {
    const file = join4(resolve3(project), CONTRACTS_FILE);
    return existsSync(file) ? file : null;
  }
  let folder = resolve3(cwd);
  for (let depth = 0; depth < MAX_DEPTH2; depth += 1) {
    const file = join4(folder, CONTRACTS_FILE);
    if (existsSync(file)) return file;
    const parent = dirname2(folder);
    if (parent === folder) return null;
    folder = parent;
  }
  return null;
}
var isRecord = (value) => typeof value === "object" && value !== null && !Array.isArray(value);
function readContracts(file) {
  let raw;
  try {
    const text = readFileSync3(file, "utf8");
    if (Buffer.byteLength(text) > MAX_BYTES) return "it is too large";
    raw = JSON.parse(text);
  } catch (error) {
    return error.message;
  }
  if (!isRecord(raw) || raw.version !== 1) return "it isn't version 1";
  const { briefs, inputs } = raw;
  if (briefs !== void 0 && !isRecord(briefs) || inputs !== void 0 && !isRecord(inputs))
    return "its briefs or inputs aren't objects";
  return {
    ...briefs ? { briefs } : {},
    ...inputs ? { inputs } : {}
  };
}
function covers(contracts, action) {
  const starts = (action.tool === "claude-code" || action.tool === "codex") && action.operation === "agent" && action.resource.kind === "agent";
  if (starts && Object.hasOwn(contracts.briefs ?? {}, action.resource.id))
    return true;
  return Object.hasOwn(
    contracts.inputs ?? {},
    `${action.tool}.${action.operation}`
  );
}
var refused = (why2) => ({
  refusal: `Nodrail: ${why2}, so this action is blocked.`
});
async function hookContractFields(action, input, where, load = loadChecker) {
  const file = findContractsFile(where.cwd, where.env);
  if (!file) return { action };
  const contracts = readContracts(file);
  if (typeof contracts === "string")
    return refused(
      `${CONTRACTS_FILE} can't be read (${contracts}); run nodrail apply`
    );
  if (!covers(contracts, action)) return { action };
  let checker;
  try {
    checker = await load();
  } catch {
    return refused(
      "this call has a declared contract and the hook couldn't load its checker"
    );
  }
  return checker.withContractFields(action, input, contracts);
}

// src/errors.ts
var Blocked = class extends Error {
  constructor(code, reference = null, reason = null, status = null) {
    super(code);
    this.code = code;
    this.reference = reference;
    this.reason = reason;
    this.status = status;
  }
  code;
  reference;
  reason;
  status;
};
var transient = (error) => error instanceof Blocked && (error.code === "UNAVAILABLE" || error.code === "RATE_LIMITED" || error.status !== null && error.status >= 500);
var alreadyIn = (error) => error instanceof Blocked && (error.status === 409 || error.code === "IDEMPOTENCY_CONFLICT");
var refusedNewFields = (error) => error instanceof Blocked && error.code === "INVALID_INPUT";
var REPORT_RETRY_MS = [200, 800];
var defaultSleep = (ms) => new Promise((resolve5) => setTimeout(resolve5, ms));

// src/authorize.ts
function assertSameCall(status, descriptor) {
  const digest = descriptorDigest(status.installation_id, descriptor);
  if (status.descriptor_digest !== digest || status.action_digest !== actionDigest(status.action_id, digest))
    throw new Blocked("DIGEST_MISMATCH", status.reference);
}
async function resolve4(client, descriptor, key, { run, subject }) {
  if (!isPlainJson(descriptor.params)) throw new Blocked("INVALID_ACTION");
  const read = () => run && subject !== void 0 ? readSubject(subject) : void 0;
  const status = await client.submit(descriptor, key, run, read());
  assertSameCall(status, descriptor);
  if (status.code !== "READY")
    throw new Blocked(status.code, status.reference, status.reason);
  const permit = await client.permit(status, read());
  return {
    allowed: true,
    actionId: permit.action_id,
    permitId: permit.permit_id
  };
}
async function authorize(client, descriptor, key, options = {}) {
  try {
    return await resolve4(client, descriptor, key, options);
  } catch (error) {
    return error instanceof Blocked ? {
      allowed: false,
      code: error.code,
      reason: error.reason,
      reference: error.reference
    } : { allowed: false, code: "CLIENT_ERROR", reason: null, reference: null };
  }
}

// src/client.ts
import { randomBytes } from "node:crypto";
var isRecord2 = (value) => typeof value === "object" && value !== null && !Array.isArray(value);
var stringFields = (value, names) => names.every((name) => typeof value[name] === "string");
function asStatus(body) {
  if (!isRecord2(body) || !stringFields(body, [
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
function isSafeUrl(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (parsed.protocol === "https:") return true;
  if (parsed.protocol !== "http:") return false;
  const host = parsed.hostname.replace(/^\[|\]$/g, "");
  return host === "localhost" || host.endsWith(".localhost") || host === "::1" || /^127(?:\.\d{1,3}){3}$/.test(host);
}
var NodrailClient = class {
  constructor(options) {
    this.options = options;
    this.base = `${options.url.replace(/\/$/, "")}/api/v1/runtime`;
    this.timeoutMs = options.timeoutMs ?? 1e4;
    this.send = options.fetch ?? fetch;
    this.secure = isSafeUrl(options.url);
  }
  options;
  base;
  timeoutMs;
  send;
  secure;
  async response(path, init = {}) {
    if (!this.secure) throw new Blocked("INSECURE_URL");
    try {
      return await this.send(`${this.base}${path}`, {
        method: init.body ? "POST" : "GET",
        headers: {
          authorization: `Bearer ${this.options.credential}`,
          ...init.body ? { "content-type": "application/json" } : {},
          ...init.headers
        },
        body: init.body ? JSON.stringify(init.body) : void 0,
        signal: AbortSignal.timeout(init.timeoutMs ?? this.timeoutMs),
        redirect: "error"
      });
    } catch {
      throw new Blocked("UNAVAILABLE");
    }
  }
  async request(path, init) {
    return this.responseBody(await this.response(path, init));
  }
  async responseBody(response) {
    const body = await response.json().catch(() => null);
    if (response.ok) return body;
    const error = isRecord2(body) && isRecord2(body.error) ? body.error.code : null;
    throw new Blocked(
      typeof error === "string" ? error : "UNAVAILABLE",
      null,
      null,
      response.status
    );
  }
  heartbeat() {
    return this.request("/heartbeat", {
      body: { adapter_version: this.options.adapterVersion }
    });
  }
  /**
   * The live policy of this credential's environment (`policy:read`): its
   * revision, the project and lock it came from, and the file it was
   * published from with its SHA-256, null when it was made on screen. A
   * host compares the digest with its own lock's.
   */
  async policy() {
    return await this.request("/policy");
  }
  /** Read the live policy conditionally using an ETag from a previous response. */
  async policyIfChanged(etag) {
    const response = await this.response("/policy", {
      headers: etag ? { "if-none-match": etag } : {}
    });
    if (response.status === 304 && etag)
      return { changed: false, etag };
    return {
      changed: true,
      etag: response.headers.get("etag"),
      policy: await this.responseBody(response)
    };
  }
  /**
   * The run is context for the decision; it is not part of the digest. With
   * a run, `subject` is the work revision it is at (null: unknown), which a
   * gate on the revision checks evidence against.
   */
  async submit(descriptor, idempotencyKey, run, subject) {
    const send = (withSubject2) => this.request("/actions", {
      body: {
        ...descriptor,
        ...run ? { run: withSubject2 ? { ...run, subject: subject ?? null } : run } : {},
        adapter_version: this.options.adapterVersion
      },
      headers: { "idempotency-key": idempotencyKey }
    });
    const withSubject = run !== void 0 && subject !== void 0;
    return asStatus(await this.compatible(send, withSubject));
  }
  /** Sends with the Wave 3 fields, and once without them to a server that refuses them. */
  async compatible(send, withNew) {
    if (!withNew) return send(false);
    try {
      return await send(true);
    } catch (error) {
      if (!refusedNewFields(error)) throw error;
      return send(false);
    }
  }
  /**
   * Calls the hook decided on this host (`decisions:write`), for Nodrail to
   * record in their runs and Activity; it never decides them again. At most
   * 100 per call. Each answer, in order, is the row's id or why that item
   * wasn't recorded; a retry with the same keys answers the same rows.
   */
  async decisions(batch) {
    const body = await this.request("/decisions", {
      body: { decisions: batch }
    });
    if (!isRecord2(body) || !Array.isArray(body.results))
      throw new Blocked("INVALID_RESPONSE");
    return body.results;
  }
  /** A step of a run starting or finishing. Grants nothing by itself. */
  step(event) {
    return this.request("/steps", { body: event });
  }
  async findByKey(idempotencyKey) {
    return asStatus(
      await this.request(
        `/actions?idempotency_key=${encodeURIComponent(idempotencyKey)}`
      )
    );
  }
  /**
   * Verifies the answer is fresh and exactly for this call before trusting
   * it. `subject`: the work revision at permit time (null: unknown), sent
   * again because the work may have changed since the call was submitted.
   */
  async permit(action, subject) {
    const nonce = randomBytes(24).toString("hex");
    const startedAt = Date.now();
    const body = await this.compatible(
      (withSubject) => this.request(`/actions/${action.action_id}/permit`, {
        body: {
          action_digest: action.action_digest,
          nonce,
          ...withSubject ? { subject: subject ?? null } : {}
        }
      }),
      subject !== void 0
    );
    if (!isRecord2(body) || body.code !== "ALLOW")
      throw new Blocked(
        isRecord2(body) && typeof body.code === "string" ? body.code : "INVALID_RESPONSE",
        action.reference,
        isRecord2(body) && typeof body.reason === "string" ? body.reason : null
      );
    if (!stringFields(body, ["permit_id", "issued_at", "expires_at"]) || body.action_id !== action.action_id || body.action_digest !== action.action_digest || body.installation_id !== action.installation_id || body.claim_nonce !== nonce)
      throw new Blocked("PERMIT_MISMATCH", action.reference);
    const lifetime = Date.parse(body.expires_at) - Date.parse(body.issued_at);
    if (!(lifetime > 0) || lifetime > 6e4 || Date.now() - startedAt >= lifetime)
      throw new Blocked("PERMIT_STALE", action.reference);
    return body;
  }
  /**
   * What happened to an action. `key` makes it idempotent: a transient
   * failure is sent again with the same key a bounded number of times, and
   * a key the server already has means the report is in. `measured`: the
   * amounts the result measured, for budgets that sum them; refused whole
   * when any is unusable (see checkMeasured).
   */
  async report(actionId, report, options = {}) {
    const measured = report.measured === void 0 ? void 0 : checkMeasured(report.measured);
    if (measured === null)
      throw new TypeError(
        "Nodrail: measured takes result. paths with whole, non-negative amounts, each path once."
      );
    const send = (withMeasured) => this.request(`/actions/${actionId}/reports`, {
      body: {
        report_key: report.key,
        outcome: report.outcome,
        ...report.permitId ? { permit_id: report.permitId } : {},
        ...report.details ? { details: report.details } : {},
        ...withMeasured && measured ? { measured } : {}
      }
    });
    const sleep = options.sleep ?? defaultSleep;
    for (let attempt = 0; ; attempt += 1) {
      try {
        return await this.compatible(send, Boolean(measured?.length));
      } catch (error) {
        if (alreadyIn(error)) return { recorded: true };
        const pause = REPORT_RETRY_MS[attempt];
        if (!transient(error) || pause === void 0) throw error;
        await sleep(pause);
      }
    }
  }
};

// src/hooks.ts
var HOOK_VERSION = "0.8.0";
var HOOK_DEADLINE_MS = 25e3;
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
function stepOf(event) {
  const id = nonEmptyText(event.agent_id);
  if (!id) return void 0;
  return {
    id: id.slice(0, 200),
    agent: agentName(nonEmptyText(event.agent_type) ?? "unnamed")
  };
}
function runOf(event, env) {
  const key = runKey(
    nonEmptyText(event.cwd) ?? process.cwd(),
    nonEmptyText(event.session_id),
    env
  );
  if (!key) return void 0;
  const step = stepOf(event);
  return step ? { key, step } : { key };
}
var readTools = new Set(localReadTools);
function checkReadLocally(name, event) {
  const input = event.tool_input;
  const action = typeof input === "object" && input !== null ? describeToolCall(name, input, nonEmptyText(event.cwd)) : null;
  if (!action)
    return deny("Nodrail: this read could not be described, so it is blocked.");
  if (reachesSecret(action.params))
    return deny(
      "Nodrail: this reads a place where credentials live, so it is blocked."
    );
  return { exitCode: 0, stdout: "", stderr: "" };
}
var timedOut = {
  allowed: false,
  code: "TIMED_OUT",
  reason: null,
  reference: null
};
async function within(work, ms) {
  let timer;
  try {
    return await Promise.race([
      work,
      new Promise((done) => {
        timer = setTimeout(() => done(null), ms);
      })
    ]);
  } finally {
    clearTimeout(timer);
  }
}
async function decideInTime(ask, deadlineMs) {
  return await within(ask, deadlineMs) ?? timedOut;
}
async function beforeTool(event, env, deps) {
  const toolName = nonEmptyText(event.tool_name);
  if (toolName && readTools.has(toolName))
    return checkReadLocally(toolName, event);
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
    return deny("Nodrail: this call could not be described, so it is blocked.");
  let run;
  try {
    run = runOf(event, env);
  } catch (error) {
    return deny(
      `Nodrail: ${error.message} So this action is blocked.`
    );
  }
  const fields = await hookContractFields(descriptor, input, {
    cwd: nonEmptyText(event.cwd) ?? process.cwd(),
    env
  });
  if ("refusal" in fields) return deny(fields.refusal);
  const decision = await decideInTime(
    authorize(client, fields.action, key, {
      run,
      // The work the agent's session is in, as the runtime reads it.
      subject: revisionAt(nonEmptyText(event.cwd) ?? process.cwd())
    }),
    deps.deadlineMs ?? HOOK_DEADLINE_MS
  );
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
  const interrupted = event.hook_event_name === "PostToolUseFailure" && event.is_interrupt === true;
  try {
    const action = await client.findByKey(key);
    await client.report(action.action_id, {
      key,
      outcome: interrupted ? "unknown" : failed ? "failure" : "success",
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
async function onStep(event, env, deps) {
  const client = clientFrom(env, deps);
  let run;
  try {
    run = runOf(event, env);
  } catch {
    return allowQuietly;
  }
  const step = run?.step;
  if (!client || !run || !step) return allowQuietly;
  const body = { run: { key: run.key }, step, event: "started" };
  if (event.hook_event_name === "SubagentStop") {
    body.event = "finished";
    const block = receiptOf(nonEmptyText(event.last_assistant_message), step.agent);
    if (block) body.receipt = { text: block };
  }
  try {
    await client.step(body);
  } catch {
  }
  return allowQuietly;
}
var receiptOf = (message, agent) => receiptText(message ?? "", agent);
function refusedReceipt(answer) {
  if (typeof answer !== "object" || answer === null) return null;
  const { receipt } = answer;
  if (typeof receipt !== "object" || receipt === null) return null;
  const { state, reason } = receipt;
  if (state !== "invalid" && state !== "missing") return null;
  return typeof reason === "string" && reason ? reason.slice(0, 500) : state;
}
async function onHandback(event, env, deps) {
  const started = Date.now();
  const client = clientFrom(env, deps);
  let run;
  try {
    run = runOf(event, env);
  } catch {
    run = void 0;
  }
  const step = run?.step;
  if (client && run && step) {
    const input = event.tool_input;
    const message = typeof input?.message === "string" ? input.message : "";
    const block = receiptOf(message, step.agent);
    const body = {
      run: { key: run.key },
      step,
      event: "finished",
      ...block ? { receipt: { text: block } } : {}
    };
    let answer = null;
    try {
      answer = await client.step(body);
    } catch {
    }
    const refused2 = refusedReceipt(answer);
    if (refused2)
      return deny(
        `Nodrail: your receipt can't be accepted: ${refused2}. Hand back again with the same report, ending with a receipt that follows your contract.`
      );
  }
  const deadlineMs = (deps.deadlineMs ?? HOOK_DEADLINE_MS) - (Date.now() - started);
  return beforeTool(event, env, {
    ...deps,
    deadlineMs: Math.max(0, deadlineMs)
  });
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
      return event.tool_name === HANDBACK_TOOL && nonEmptyText(event.agent_id) ? onHandback(event, env, deps) : beforeTool(event, env, deps);
    case "PostToolUse":
    case "PostToolUseFailure":
      return afterTool(event, env, deps);
    case "SessionStart":
      return onSessionStart(env, deps);
    case "SubagentStart":
    case "SubagentStop":
      return onStep(event, env, deps);
    default:
      return deny(
        "Nodrail: unsupported hook event, so this action is blocked."
      );
  }
}

// src/hook-main.ts
var failure = 2;
var fail = () => {
  process.stderr.write(
    failure ? "Nodrail: the hook failed, so this action is blocked.\n" : "Nodrail: the hook failed; nothing was recorded.\n"
  );
  process.exit(failure);
};
process.on("uncaughtException", fail);
process.on("unhandledRejection", fail);
function isToolCall(stdin) {
  try {
    return JSON.parse(stdin).hook_event_name === "PreToolUse";
  } catch {
    return true;
  }
}
async function main() {
  const agent = process.argv[2] === "codex" ? "codex" : "claude-code";
  let stdin = "";
  for await (const chunk of process.stdin) stdin += String(chunk);
  if (!isToolCall(stdin)) failure = 0;
  const result = await runHook(stdin, process.env, { agent });
  if (result.stderr) process.stderr.write(result.stderr);
  if (result.stdout)
    process.stdout.write(result.stdout, () => process.exit(result.exitCode));
  else process.exit(result.exitCode);
}
main().catch(fail);
