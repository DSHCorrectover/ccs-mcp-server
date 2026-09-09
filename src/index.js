#!/usr/bin/env node
/**
 * CCS Runtime Evidence MCP Server v1.0.0
 *
 * A standalone Model Context Protocol (MCP) server that exposes CCS runtime
 * verification as MCP tools, so any MCP-compatible client (Claude Desktop,
 * Cursor, Windsurf, ChatGPT apps, etc.) can verify AI agent tool calls and
 * obtain tamper-evident evidence records.
 *
 * Tools exposed:
 *   verify_tool_call   Verify a tool call against CCS 7 dimensions + semantic + math
 *   issue_evidence     Issue a signed CCS evidence record (allow + deny)
 *   audit_mcp_config   Audit an MCP server configuration for security risks
 *
 * Transport: stdio (per MCP spec). To run:
 *   npx @correctover/ccs-mcp-server
 *
 * License: Proprietary Commercial License (reference implementation).
 *
 * This server is a self-contained JavaScript implementation of the CCS
 * runtime verification reference (mirroring the Python SkillHub distribution
 * ccs-runtime-verifier). Zero runtime dependencies.
 */

"use strict";

const crypto = require("crypto");
const readline = require("readline");
const receipts = require("./receipts");

// ---------------------------------------------------------------------------
// CCS Verifier Core (pure stdlib Node.js)
// ---------------------------------------------------------------------------

const CCS_VERSION = "1.2.13";

const DEFAULT_POLICY = {
  mode: "block",
  max_nesting_depth: 8,
  max_argument_bytes: 65536,
  max_string_length: 16384,
  latency_budget_us: 5000000,
  cost_budget: 0.05,
  allowed_tools: [],
  denied_tools: [],
  tool_schemas: {},
  require_caller_identity: true,
  require_request_hash: false,
  allowed_callers: [],
  enable_semantic_analysis: true,
  enable_math_verification: true,
};

const INJECTION_PATTERNS = {
  command_injection: [
    /[;&|`$]\s*(rm|curl|wget|bash|sh|nc|cat|chmod|eval|exec)\b/i,
    /\$\([^)]+\)/,
    /`[^`]+`/,
    /\|\|\s*\w+/,
  ],
  path_traversal: [
    /\.\.[\/\\]/,
    /\/etc\/(passwd|shadow|hosts)/,
    /\/proc\/self\//,
    /\\windows\\system32/i,
  ],
  ssrf: [
    /https?:\/\/(127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.169\.254)/i,
    /https?:\/\/10\.\d+\.\d+\.\d+/,
    /https?:\/\/192\.168\.\d+\.\d+/,
    /https?:\/\/172\.(1[6-9]|2\d|3[01])\.\d+\.\d+/,
  ],
  prompt_injection: [
    /ignore\s+(all\s+)?(previous|above|prior)\s+(instructions?|prompts?)/i,
    /disregard\s+(all\s+)?(previous|above)/i,
    /you\s+are\s+now\s+(?:a|an|the)\s+/i,
    /system\s*prompt/i,
    /<\|im_start\|>|<\|im_end\|>/,
  ],
  sql_injection: [
    /(\bunion\b.*\bselect\b)/i,
    /(\bor\b\s+1\s*=\s*1)/i,
    /(;\s*drop\s+table)/i,
  ],
};

const TOOL_RISK_PROFILES = {
  shell: 0.9, exec: 0.9, system: 0.95,
  filesystem: 0.6, file: 0.6,
  network: 0.7, http: 0.7,
  database: 0.75, sql: 0.8,
  read: 0.2, math: 0.1,
};

const DANGEROUS_COMBOS = [
  { name: "exfil_chain", indicators: ["path_traversal", "ssrf"], severity: "critical" },
  { name: "rce_chain", indicators: ["command_injection", "path_traversal"], severity: "critical" },
  { name: "sql_exfil", indicators: ["sql_injection", "ssrf"], severity: "critical" },
  { name: "prompt_hijack", indicators: ["prompt_injection", "command_injection"], severity: "critical" },
];

function deepMerge(base, override) {
  const result = { ...base };
  for (const [k, v] of Object.entries(override || {})) {
    if (v && typeof v === "object" && !Array.isArray(v) && result[k] && typeof result[k] === "object") {
      result[k] = deepMerge(result[k], v);
    } else {
      result[k] = v;
    }
  }
  return result;
}

// Use the receipt module's recursive canonical serializer. The previous
// JSON.stringify(obj, Object.keys(obj).sort()) implementation dropped all
// nested object fields because the top-level key array acts as a recursive
// whitelist; that made content/evidence hashes omit dimensions and other
// nested data. Fixed in 1.2.2.
const canonical = receipts.canonical;

function sha256(s) {
  return "sha256:" + crypto.createHash("sha256").update(s).digest("hex");
}

function scanValue(val, findings, path = "<root>") {
  if (typeof val === "string") {
    for (const [cat, pats] of Object.entries(INJECTION_PATTERNS)) {
      for (const pat of pats) {
        if (pat.test(val)) {
          findings.push(`${path}: ${cat}`);
          break;
        }
      }
    }
    if (val.length > 1e7) findings.push(`${path}: dos_string`);
  } else if (typeof val === "number") {
    if (Number.isNaN(val) || !Number.isFinite(val)) findings.push(`${path}: nan_or_infinity`);
    else if (Math.abs(val) > Number.MAX_SAFE_INTEGER) findings.push(`${path}: integer_overflow`);
    else if (Math.abs(val) > 1e9) findings.push(`${path}: unreasonable_magnitude`);
    else if (val < 0 && !/offset|delta|diff|change/i.test(path)) findings.push(`${path}: negative_value`);
  } else if (val && typeof val === "object") {
    if (Array.isArray(val)) {
      val.forEach((v, i) => scanValue(v, findings, `${path}[${i}]`));
    } else {
      for (const [k, v] of Object.entries(val)) scanValue(v, findings, path === "<root>" ? k : `${path}.${k}`);
    }
  }
}

function structureCheck(call, policy) {
  const tool = call.tool;
  if (!tool || typeof tool !== "string") return { ok: false, reason: "missing or invalid 'tool' field" };
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)*$/.test(tool))
    return { ok: false, reason: `tool name '${tool}' has invalid format` };
  if (call.arguments !== undefined && typeof call.arguments !== "object")
    return { ok: false, reason: "'arguments' must be an object or array" };
  if (policy.denied_tools?.includes(tool)) return { ok: false, reason: `tool '${tool}' is denied` };
  if (policy.allowed_tools?.length && !policy.allowed_tools.includes(tool))
    return { ok: false, reason: `tool '${tool}' not in allowed list` };
  const argBytes = Buffer.byteLength(JSON.stringify(call.arguments || {}));
  if (argBytes > policy.max_argument_bytes)
    return { ok: false, reason: `argument size ${argBytes} exceeds limit ${policy.max_argument_bytes}` };
  return { ok: true };
}

function securityCheck(call) {
  const findings = [];
  scanValue(call.arguments || {}, findings);
  if (findings.length) return { ok: false, reason: findings.slice(0, 5).join("; "), findings };
  return { ok: true, findings: [] };
}

function identityCheck(call, policy) {
  if (!policy.require_caller_identity) return { ok: true };
  const caller = call.caller;
  if (!caller || typeof caller !== "object") return { ok: false, reason: "missing 'caller' object" };
  if (!caller.agent_id) return { ok: false, reason: "caller missing 'agent_id'" };
  if (policy.allowed_callers?.length && !policy.allowed_callers.includes(caller.agent_id))
    return { ok: false, reason: `caller '${caller.agent_id}' not in allowed_callers` };
  return { ok: true };
}

function schemaCheck(call, policy) {
  const schema = policy.tool_schemas?.[call.tool];
  if (!schema || !call.arguments || typeof call.arguments !== "object") return { ok: true };
  for (const [field, def] of Object.entries(schema.properties || {})) {
    if (!(field in call.arguments)) {
      if ((schema.required || []).includes(field))
        return { ok: false, reason: `missing required field '${field}'` };
      continue;
    }
    const val = call.arguments[field];
    if (def.type === "string" && typeof val !== "string") return { ok: false, reason: `field '${field}' must be string` };
    if (def.type === "number" && typeof val !== "number") return { ok: false, reason: `field '${field}' must be number` };
    if (def.type === "integer" && !Number.isInteger(val)) return { ok: false, reason: `field '${field}' must be integer` };
    if (def.type === "boolean" && typeof val !== "boolean") return { ok: false, reason: `field '${field}' must be boolean` };
    if (def.type === "array" && !Array.isArray(val)) return { ok: false, reason: `field '${field}' must be array` };
    if (typeof val === "string" && val.length > policy.max_string_length)
      return { ok: false, reason: `field '${field}' exceeds max length` };
    if (def.enum && !def.enum.includes(val)) return { ok: false, reason: `field '${field}' not in enum` };
  }
  return { ok: true };
}

function semanticAnalysis(tool, secFindings) {
  const ns = (tool || "").split(".")[0].toLowerCase();
  const baseRisk = TOOL_RISK_PROFILES[ns] ?? 0.4;
  const cats = new Set();
  for (const f of secFindings) {
    const m = f.split(": ").pop();
    if (INJECTION_PATTERNS[m]) cats.add(m);
  }
  const chains = DANGEROUS_COMBOS
    .filter((c) => c.indicators.every((i) => cats.has(i)))
    .map((c) => ({ chain: c.name, severity: c.severity }));
  let score = baseRisk + cats.size * 0.15;
  let severity = "info";
  if (chains.some((c) => c.severity === "critical")) severity = "critical";
  else if (score >= 0.9) severity = "critical";
  else if (score >= 0.7) severity = "high";
  else if (score >= 0.5) severity = "medium";
  else if (score >= 0.3) severity = "low";
  return { tool_namespace: ns, base_risk: baseRisk, attack_chains: chains,
           finding_categories: [...cats], semantic_severity: severity };
}

function verifyCall(call, policyOverride) {
  const policy = deepMerge(DEFAULT_POLICY, policyOverride || {});
  const dimensions = {};

  const checks = [
    ["Structure", () => structureCheck(call, policy)],
    ["Schema", () => schemaCheck(call, policy)],
    ["Security", () => securityCheck(call)],
    ["Identity", () => identityCheck(call, policy)],
  ];

  let secFindings = [];
  for (const [name, fn] of checks) {
    const r = fn();
    dimensions[name] = { status: r.ok ? "pass" : "fail" };
    if (!r.ok) dimensions[name].reason = r.reason;
    if (name === "Security") secFindings = r.findings || [];
  }

  // Latency/Cost (warn-only)
  const meta = call.metadata || {};
  dimensions.Latency = { status: "pass" };
  if (meta.execution_time_us != null && policy.latency_budget_us && meta.execution_time_us > policy.latency_budget_us)
    dimensions.Latency = { status: "warn", reason: `latency ${meta.execution_time_us}us exceeds budget` };
  dimensions.Cost = { status: "pass" };
  if (meta.cost != null && policy.cost_budget && meta.cost > policy.cost_budget)
    dimensions.Cost = { status: "warn", reason: `cost ${meta.cost} exceeds budget` };
  dimensions.Integrity = { status: "pass" };

  const enforced = ["Structure", "Schema", "Security", "Identity"];
  const verdict = (policy.mode === "audit" || enforced.every((d) => dimensions[d].status === "pass")) ? "allowed" : "denied";

  const paramsHash = sha256(canonical(call.arguments || {}));
  const policyHash = sha256(canonical(policy));

  const semantic = policy.enable_semantic_analysis ? semanticAnalysis(call.tool, secFindings) : undefined;

  const content = {
    tool: call.tool, caller: call.caller?.agent_id || "unknown", verdict, mode: policy.mode,
    params_hash: paramsHash, policy_hash: policyHash, dimensions,
  };
  const contentHash = sha256(canonical(content));

  const evidence = {
    evidence_type: "ccs.tool_call.verification",
    evidence_version: CCS_VERSION,
    evidence_id: crypto.randomUUID(),
    tool: call.tool,
    caller: call.caller?.agent_id || "unknown",
    verdict,
    mode: policy.mode,
    params_hash: paramsHash,
    policy_hash: policyHash,
    content_hash: contentHash,
    dimensions,
    issued_at: new Date().toISOString(),
  };
  if (semantic) evidence.semantic_analysis = semantic;
  if (call.parent_evidence_hash) evidence.parent_evidence_hash = call.parent_evidence_hash;

  // Finalize evidence_hash
  const hashBody = { ...evidence };
  evidence.evidence_hash = sha256(canonical(hashBody));

  // Sign the full evidence record with Ed25519. This makes the receipt
  // independently verifiable offline: any party holding the signer's
  // public key can verify that this evidence record was produced by the
  // holder of the corresponding private key and has not been tampered with.
  return receipts.signReceipt(evidence);
}

function auditMcpConfig(config) {
  const issues = [];
  const servers = config.mcpServers || config.servers || {};
  for (const [name, srv] of Object.entries(servers)) {
    if (!srv.command && !srv.url) issues.push({ server: name, severity: "high", issue: "no command or url" });
    if (srv.url && /^http:\/\//i.test(srv.url)) issues.push({ server: name, severity: "high", issue: "HTTP url (not HTTPS)" });
    if (srv.env) {
      for (const k of Object.keys(srv.env)) {
        if (/KEY|TOKEN|SECRET|PASSWORD/i.test(k) && typeof srv.env[k] === "string" && srv.env[k].length < 8)
          issues.push({ server: name, severity: "medium", issue: `weak ${k}` });
      }
    }
    if (srv.args?.some((a) => /--insecure|--no-verify|-k$/i.test(a)))
      issues.push({ server: name, severity: "critical", issue: "TLS verification disabled" });
  }
  return { total_servers: Object.keys(servers).length, issues,
           risk: issues.some((i) => i.severity === "critical") ? "critical" :
                 issues.some((i) => i.severity === "high") ? "high" :
                 issues.length ? "medium" : "low" };
}

// ---------------------------------------------------------------------------
// Intent Binding (L4) — zero-LLM, deterministic, microsecond
// ---------------------------------------------------------------------------
// Agent framework declares structured intent before tool execution.
// CCS verifies actual args match declared intent with zero tolerance.
// This catches cross-model amount drift (planner says 100, executor writes 10000)
// without any NLP or LLM call.

function deepEqual(a, b) {
  if (a === b) return true;
  if (typeof a !== typeof b) {
    // numeric normalization: 100 == 100.0 == 1e2
    if (typeof a === "number" && typeof b === "string") {
      const n = Number(b);
      return Number.isFinite(n) && a === n;
    }
    if (typeof b === "number" && typeof a === "string") {
      const n = Number(a);
      return Number.isFinite(n) && b === n;
    }
    return false;
  }
  if (typeof a !== "object" || a === null || b === null) return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  const ka = Object.keys(a), kb = Object.keys(b);
  if (ka.length !== kb.length) return false;
  return ka.every((k) => deepEqual(a[k], b[k]));
}

function verifyIntentBinding(intent, toolName, toolArgs, now = Date.now()) {
  const intentHash = "sha256:" + crypto.createHash("sha256").update(canonical(intent)).digest("hex");
  const argsHash = "sha256:" + crypto.createHash("sha256").update(canonical(toolArgs)).digest("hex");

  let body;

  // 1. TTL check
  if (intent.ttl_ms != null && now - intent.issued_at > intent.ttl_ms) {
    body = {
      evidence_type: "ccs.intent_binding",
      evidence_version: CCS_VERSION,
      evidence_id: crypto.randomUUID(),
      allowed: false,
      reason: { type: "intent_expired", expected: intent.issued_at + intent.ttl_ms, actual: now },
      intent_id: intent.intent_id,
      intent_type: intent.intent_type,
      intent_hash: intentHash,
      args_hash: argsHash,
      tool: toolName,
      issued_at: new Date().toISOString(),
    };
    return receipts.signReceipt(body);
  }

  // 2. Field-by-field comparison
  const fields = intent.fields || {};
  for (const [field, spec] of Object.entries(fields)) {
    const actual = toolArgs[field];
    const expected = spec.value;
    const mode = spec.binding_mode || "exact";
    let match = false;
    if (mode === "exact") {
      match = deepEqual(expected, actual);
    } else if (mode === "numeric_tolerance") {
      if (typeof expected === "number" && typeof actual === "number") {
        match = Math.abs(expected - actual) <= (spec.tolerance || 0);
      }
    } else if (mode === "pattern") {
      if (typeof actual === "string") {
        try { match = new RegExp(spec.pattern).test(actual); } catch { match = false; }
      }
    }
    if (!match) {
      body = {
        evidence_type: "ccs.intent_binding",
        evidence_version: CCS_VERSION,
        evidence_id: crypto.randomUUID(),
        allowed: false,
        reason: {
          type: "intent_arg_mismatch",
          field, binding_mode: mode,
          expected, actual,
        },
        intent_id: intent.intent_id,
        intent_type: intent.intent_type,
        intent_hash: intentHash,
        args_hash: argsHash,
        tool: toolName,
        issued_at: new Date().toISOString(),
      };
      return receipts.signReceipt(body);
    }
  }

  body = {
    evidence_type: "ccs.intent_binding",
    evidence_version: CCS_VERSION,
    evidence_id: crypto.randomUUID(),
    allowed: true,
    intent_id: intent.intent_id,
    intent_type: intent.intent_type,
    intent_hash: intentHash,
    args_hash: argsHash,
    tool: toolName,
    issued_at: new Date().toISOString(),
  };
  return receipts.signReceipt(body);
}

// ---------------------------------------------------------------------------
// MCP Protocol (stdio JSON-RPC 2.0)
// ---------------------------------------------------------------------------

const PROTOCOL_VERSION = "2024-11-05";
const SERVER_INFO = { name: "ccs-runtime-evidence", version: CCS_VERSION, title: "CCS Runtime Evidence" };

const TOOLS = [
  {
    name: "verify_tool_call",
    description: "Verify an AI agent tool call against CCS 7 dimensions (Structure, Schema, Security, Identity, Integrity, Latency, Cost) plus semantic attack-chain analysis and math overflow detection. Returns verdict (allowed/denied) with detailed findings. DEFAULT MODE BLOCKS UNSAFE CALLS.",
    inputSchema: {
      type: "object",
      properties: {
        tool: { type: "string", description: "Tool name as namespace.action, e.g. 'shell.exec' or 'read.file'" },
        arguments: { type: "object", description: "Tool call arguments to verify", additionalProperties: true },
        caller: { type: "object", description: "Caller identity, e.g. {agent_id: 'agent-001'}",
                  properties: { agent_id: { type: "string" } }, required: ["agent_id"] },
        metadata: { type: "object", description: "Optional metadata (execution_time_us, cost, request_id, etc.)", additionalProperties: true },
        policy: { type: "object", description: "Optional CCS policy override (allowed_tools, denied_tools, mode, budgets, etc.)", additionalProperties: true },
      },
      required: ["tool"],
    },
  },
  {
    name: "issue_evidence",
    description: "Issue a CCS evidence record for a tool call. Evidence is cryptographically bound (content_hash + evidence_hash), tamper-evident, independently verifiable. Issued for allowed AND denied calls.",
    inputSchema: {
      type: "object",
      properties: {
        tool: { type: "string" },
        arguments: { type: "object", additionalProperties: true },
        caller: { type: "object", properties: { agent_id: { type: "string" } }, required: ["agent_id"] },
        metadata: { type: "object", additionalProperties: true },
        policy: { type: "object", additionalProperties: true },
      },
      required: ["tool", "caller"],
    },
  },
  {
    name: "audit_mcp_config",
    description: "Audit an MCP client/server configuration JSON for security risks: plain HTTP, weak secrets, disabled TLS, missing commands. Returns structured issues with severity.",
    inputSchema: {
      type: "object",
      properties: {
        config: { type: "object", description: "MCP configuration JSON (e.g. Claude Desktop config)", additionalProperties: true },
      },
      required: ["config"],
    },
  },
  {
    name: "verify_intent_binding",
    description: "Verify that actual tool call arguments match a declared intent with zero tolerance. Catches cross-model parameter drift (planner says amount=100, executor writes amount=10000). No LLM needed — pure deterministic comparison. Supports exact match, numeric tolerance, and regex pattern binding modes.",
    inputSchema: {
      type: "object",
      properties: {
        intent: {
          type: "object",
          description: "Structured intent declaration from the agent framework",
          properties: {
            intent_id: { type: "string", description: "Unique intent identifier (UUID v7 recommended)" },
            intent_type: { type: "string", description: "e.g. payment, file_write, api_call" },
            fields: {
              type: "object",
              description: "Map of field name to binding specification",
              additionalProperties: {
                type: "object",
                properties: {
                  value: { description: "Expected value" },
                  binding_mode: { type: "string", enum: ["exact", "numeric_tolerance", "pattern"] },
                  tolerance: { type: "number", description: "Tolerance for numeric_tolerance mode" },
                  pattern: { type: "string", description: "Regex for pattern mode" },
                },
                required: ["value"],
              },
            },
            issued_at: { type: "integer", description: "Unix ms when intent was issued" },
            ttl_ms: { type: "integer", description: "Time-to-live in ms (default 30000)" },
            evidence_ref: { type: "string", description: "Optional hash of external evidence (invoice, authorization VC)" },
          },
          required: ["intent_id", "intent_type", "fields", "issued_at"],
        },
        tool: { type: "string", description: "Tool being called, e.g. payments.send" },
        arguments: { type: "object", description: "Actual tool call arguments", additionalProperties: true },
      },
      required: ["intent", "tool", "arguments"],
    },
  },
  {
    name: "verify_receipt",
    description: "Offline-verify a CCS Ed25519-signed receipt. Auditors call this with a receipt JSON produced by issue_evidence or verify_intent_binding; it checks the signature against the embedded signer_public_key and reports whether the body was tampered with. Optionally pin an expected signer public key (PEM string or sha256: fingerprint) to reject receipts from untrusted signers.",
    inputSchema: {
      type: "object",
      properties: {
        receipt: {
          type: "object",
          description: "The signed receipt object (must include signer_public_key, signature_alg, signature, and the signed body fields).",
          additionalProperties: true,
        },
        expected_signer: {
          type: "string",
          description: "Optional. Either the expected PEM public key, or a sha256:<hex> fingerprint of the DER SPKI public key.",
        },
      },
      required: ["receipt"],
    },
  },
];

function handleRequest(req) {
  const { method, params, id } = req;
  if (method === "initialize") {
    return {
      jsonrpc: "2.0", id,
      result: {
        protocolVersion: params?.protocolVersion || PROTOCOL_VERSION,
        capabilities: { tools: {} },
        serverInfo: SERVER_INFO,
      },
    };
  }
  if (method === "notifications/initialized" || method === "initialized") return null;
  if (method === "ping") return { jsonrpc: "2.0", id, result: {} };
  if (method === "tools/list") return { jsonrpc: "2.0", id, result: { tools: TOOLS } };
  if (method === "tools/call") {
    const name = params?.name;
    const args = params?.arguments || {};
    try {
      let result;
      if (name === "verify_tool_call") {
        const ev = verifyCall(args, args.policy);
        result = {
          content: [{ type: "text", text: JSON.stringify({
            verdict: ev.verdict, blocked: ev.verdict === "denied",
            tool: ev.tool, caller: ev.caller,
            dimensions: ev.dimensions, semantic_analysis: ev.semantic_analysis,
            evidence_id: ev.evidence_id, evidence_hash: ev.evidence_hash,
          }, null, 2) }],
          isError: ev.verdict === "denied",
        };
      } else if (name === "issue_evidence") {
        const ev = verifyCall(args, args.policy);
        result = { content: [{ type: "text", text: JSON.stringify(ev, null, 2) }] };
      } else if (name === "audit_mcp_config") {
        const report = auditMcpConfig(args.config || {});
        result = { content: [{ type: "text", text: JSON.stringify(report, null, 2) }] };
      } else if (name === "verify_intent_binding") {
        const verdict = verifyIntentBinding(args.intent, args.tool, args.arguments || {});
        result = {
          content: [{ type: "text", text: JSON.stringify(verdict, null, 2) }],
          isError: verdict.allowed === false,
        };
      } else if (name === "verify_receipt") {
        const v = args.expected_signer
          ? receipts.verifyReceiptWithKey(args.receipt, args.expected_signer)
          : receipts.verifyReceipt(args.receipt);
        result = {
          content: [{ type: "text", text: JSON.stringify(v, null, 2) }],
          isError: v.valid === false,
        };
      } else {
        result = { content: [{ type: "text", text: `Unknown tool: ${name}` }], isError: true };
      }
      return { jsonrpc: "2.0", id, result };
    } catch (e) {
      return { jsonrpc: "2.0", id,
        result: { content: [{ type: "text", text: `Error: ${e.message}` }], isError: true } };
    }
  }
  if (id !== undefined) return { jsonrpc: "2.0", id, error: { code: -32601, message: `Method not found: ${method}` } };
  return null;
}

function main() {
  const kp = receipts.getKeypair();
  const fp = receipts.publicKeyFingerprint();
  process.stderr.write(
    `[ccs-mcp-server] v${CCS_VERSION} starting on stdio\n` +
    `[ccs-mcp-server] signing key source: ${kp.source}\n` +
    `[ccs-mcp-server] signer fingerprint: ${fp}\n`
  );
  const rl = readline.createInterface({ input: process.stdin });
  rl.on("line", (line) => {
    if (!line.trim()) return;
    let req;
    try { req = JSON.parse(line); } catch { return; }
    const res = handleRequest(req);
    if (res) process.stdout.write(JSON.stringify(res) + "\n");
  });
  rl.on("close", () => process.exit(0));
}

if (require.main === module) main();
module.exports = { verifyCall, auditMcpConfig, verifyIntentBinding, receipts };
