# CCS Runtime Evidence MCP Server

[![IETF Internet-Draft](https://img.shields.io/badge/IETF-draft--correctover--ccs-blue)](https://datatracker.ietf.org/doc/draft-correctover-ccs/)
[![npm version](https://img.shields.io/npm/v/ccs-mcp-server.svg)](https://www.npmjs.com/package/ccs-mcp-server)

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server that brings **CCS runtime verification** to any MCP-compatible client — Claude Desktop, Cursor, Windsurf, and more.

It verifies AI agent tool calls at runtime, blocks unsafe ones by default, issues **tamper-evident evidence records** for every decision, and verifies that actual tool arguments match the agent's declared intent — catching cross-model parameter drift.

> **Runtime evidence layer, not a static scanner.** Every decision is enforced at call time and produces independently verifiable cryptographic evidence.

## ⚡ Quick Start — running in 30 seconds

```bash
npx -y ccs-mcp-server
```

Add it to any MCP client — paste this into your `mcpServers` config in Claude Desktop, Cursor or Cline:

```json
{
  "mcpServers": {
    "ccs-runtime-evidence": {
      "command": "npx",
      "args": ["-y", "ccs-mcp-server"]
    }
  }
}
```

Or install from the official MCP Registry: search **"Correctover"** inside your client, or open [registry.modelcontextprotocol.io](https://registry.modelcontextprotocol.io/) and find `io.github.Correctover/ccs`.

No API key, no account, no environment variables required — an Ed25519 signing key is generated automatically on first run (set `CCS_KEY_DIR`, or `CCS_PRIVATE_KEY`/`CCS_PUBLIC_KEY`, only if you want to pin a persistent key). Zero dependencies. Pure Node.js stdlib (Node ≥ 18). No install scripts.

## Tools

| Tool | Purpose |
|---|---|
| `verify_tool_call` | 7-dimension runtime verification (Structure/Schema/Security/Identity/Integrity/Latency/Cost) + semantic attack-chain analysis + math overflow detection. **Blocks by default.** |
| `issue_evidence` | Issue a tamper-evident evidence record (`content_hash` + `evidence_hash`, chainable). Produced for allowed AND denied calls. |
| `audit_mcp_config` | Audit MCP configuration JSON for security risks. |
| `verify_intent_binding` | Verify actual tool arguments match a declared intent — zero tolerance, zero LLM calls. Catches cross-model parameter drift (planner says `amount: 100`, executor writes `amount: 10000` → DENIED). |
| `verify_receipt` | Offline-verify a CCS Ed25519-signed receipt: checks the signature against the embedded signer public key, reports tampering, and optionally pins an expected signer key or fingerprint. |

## Intent Binding — Cross-Model Drift Detection

Agent planners (Claude, GPT) declare one thing; executors (Qwen, DeepSeek) sometimes write another. No existing protocol verifies that actual tool call arguments match the agent's declared intent:

- **AP2** signs human authorization — not LLM intent
- **AgentPay** does baseline tolerance (1%) — not zero-tolerance equivalence
- **ACS** runs policy decisions — not argument-level equivalence
- **VAP** (draft-samal-vap-00) explicitly excludes argument semantics from its wire schema

CCS Intent Binding fills this layer. The agent framework declares a structured intent before execution; CCS verifies actual arguments against it in sub-millisecond, zero-LLM time.

### Example: amount drift

```json
// Intent declared by planner
{
  "intent_id": "int-001",
  "intent_type": "payment",
  "fields": {
    "amount": { "value": 100, "binding_mode": "exact" },
    "recipient": { "value": "Alice", "binding_mode": "exact" }
  },
  "issued_at": 1755000000000,
  "ttl_ms": 30000
}

// Actual arguments from executor
{ "amount": 10000, "recipient": "Alice" }

// Result: DENIED — intent_arg_mismatch
// field: amount, expected: 100, actual: 10000
```

### Three binding modes

| Mode | Behavior | Example |
|------|----------|---------|
| `exact` | Deep equality with math normalization | `100`, `100.0`, `1e2` all match; `10000` does not |
| `numeric_tolerance` | Absolute tolerance | `100 ± 0.01` matches `100.005` |
| `pattern` | Regex match on string fields | `^[A-Z]{3}$` matches `"USD"` |

No intent declared? Falls through to standard 7-dimension verification. Zero breaking changes.

## What It Detects

- **Command injection**: shell metacharacters, `curl|sh`, `rm -rf`, `eval()`
- **Path traversal**: `../`, `/etc/passwd`, `/proc/self/`
- **SSRF**: `169.254.169.254` (cloud metadata), localhost, private ranges — across any tool
- **Cross-tool attack chains**: read sensitive file → network exfil = `exfil_chain`
- **Environment variable exfiltration**: API keys, secrets, credentials
- **Obfuscation**: hex encoding, base64, privilege escalation signals
- **Math safety**: integer overflow (>2^53-1), NaN/Infinity
- **MCP config risks**: plain HTTP, weak secrets, `--insecure`, TLS disabled

## Evidence Chain

Every decision produces evidence with dual hashes (`content_hash` + `evidence_hash`) and chain linkage (`parent_evidence_hash`). Any third party can independently verify that evidence has not been tampered with — without trusting the operator.

```
evidence 1: allowed  (fs.read_file)       parent: null
evidence 2: denied   (shell.exec curl|sh) parent: ev1
evidence 3: denied   (http.fetch SSRF)    parent: ev2
evidence 4: denied   (fs + curl exfil)    parent: ev3
```

Receipts are Ed25519-signed and JSON-based: verify them offline with the built-in `verify_receipt` tool, or independently with any Ed25519 library. Cross-tool receipt verification (same crypto, chain linkage, field mapping) is designed to work without this package installed.

## The 7 CCS Dimensions

1. **Structure** — valid tool name, argument format, nesting depth, payload size
2. **Schema** — type, required fields, enums, ranges, string lengths
3. **Security** — injection, traversal, SSRF, env exfiltration, obfuscation + semantic attack chains
4. **Identity** — caller agent ID verification
5. **Integrity** — request hash validation
6. **Latency** — execution time budget
7. **Cost** — cost budget

## Protocol Context

- **IETF**: [draft-correctover-ccs](https://datatracker.ietf.org/doc/draft-correctover-ccs/) — an individual Internet-Draft; not an RFC or IETF endorsement, and the Datatracker page is authoritative for revision and status
- **Complements**: [VAP draft-samal-vap-00](https://datatracker.ietf.org/doc/draft-samal-vap/) (scope/budget/purpose), [Microsoft ACS](https://github.com/microsoft/agent-governance-toolkit) (policy decisions), AP2 (human authorization)
- **Does not replace**: authentication, payment networks, policy engines

## Links

- npm: https://www.npmjs.com/package/ccs-mcp-server
- GitHub: https://github.com/DSHCorrectover/ccs-mcp-server
- IETF Draft: https://datatracker.ietf.org/doc/draft-correctover-ccs/
- PyPI (full verifier): https://pypi.org/project/ccs-verifier/

## License

Elastic License 2.0 (ELv2). See [LICENSE](LICENSE).
