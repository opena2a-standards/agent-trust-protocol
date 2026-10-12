# MCP + ATP Integration Guide

How to verify an MCP server's trust before connecting and executing tools.

## Overview

MCP (Model Context Protocol) servers expose tools, resources, and prompts to AI clients. Before connecting to an MCP server -- especially one that accesses the filesystem, runs code, or makes network requests -- a client should verify the server's trust level through ATP.

**Flow:**
1. Client discovers an MCP server (from config, registry, or recommendation)
2. Client queries the ATP authority for the server's trust proof
3. If trust level meets the threshold, client connects to the server
4. Client caches the proof and re-checks periodically

The proof endpoint answers an envelope, `{"proof": {...}, "algorithm": ..., "publicKey": ...}`. The trust fields (`trustLevel`, `verdict`, `trustScore`, `expiresAt`) sit under `proof`, and the samples below that fetch a proof read them there. A sample that cannot read an integer trust level from 0 to 4 refuses the connection.

The Python samples need Python 3.11 or later: `datetime.fromisoformat` reads the authority's nanosecond timestamps from 3.11 on.

---

## Quick Check: cURL

```bash
# Check trust before connecting to an MCP server
curl -s "https://api.oa2a.org/api/v1/trust/proof?did=did:opena2a:mcp_server:@modelcontextprotocol/server-filesystem" \
  | jq '.proof | {trustLevel: .trustLevel, verdict: .verdict, score: .trustScore, expires: .expiresAt}'
```

Example response (the reference authority's answer for this server, recorded 2026-10-12 UTC):

```json
{
  "trustLevel": 2,
  "verdict": "listed",
  "score": 0.7432,
  "expires": "2026-10-13T02:57:21.581346834Z"
}
```

---

## Python: Trust-Gated MCP Connection

```python
from datetime import datetime, timezone

import requests


def check_mcp_trust(server_name: str, min_level: int = 2) -> dict:
    """
    Query ATP for an MCP server's trust before connecting.

    Args:
        server_name: Package name (e.g., "@modelcontextprotocol/server-filesystem")
        min_level: Minimum trust level to allow connection (default: 2)

    Returns:
        {"allowed": True/False, "trustLevel": int or None, "reason": str}
    """
    did = f"did:opena2a:mcp_server:{server_name}"

    resp = requests.get(
        "https://api.oa2a.org/api/v1/trust/proof",
        params={"did": did},
        timeout=10,
    )

    if resp.status_code == 404:
        return {"allowed": False, "trustLevel": None, "reason": "Server not found in registry"}

    resp.raise_for_status()
    # The trust fields sit under "proof", not at the top level of the response
    proof = resp.json().get("proof") or {}

    # A level that is not an integer 0-4 refuses the connection
    trust_level = proof.get("trustLevel")
    if type(trust_level) is not int or not 0 <= trust_level <= 4:
        return {"allowed": False, "trustLevel": None, "reason": "No readable trust level in the proof"}

    # Blocked servers: always refuse
    if trust_level == 0:
        return {
            "allowed": False,
            "trustLevel": 0,
            "reason": f"BLOCKED: {proof.get('verdict', 'unknown')}",
        }

    # Expired proofs: refuse, and fetch a fresh proof before trying again
    expires = datetime.fromisoformat(proof["expiresAt"].replace("Z", "+00:00"))
    if expires <= datetime.now(timezone.utc):
        return {"allowed": False, "trustLevel": trust_level, "reason": "Trust proof expired"}

    # Check minimum trust level
    if trust_level < min_level:
        return {
            "allowed": False,
            "trustLevel": trust_level,
            "reason": f"Trust level {trust_level} below minimum {min_level}",
        }

    return {"allowed": True, "trustLevel": trust_level, "reason": "ok"}


# --- Usage ---

result = check_mcp_trust("@modelcontextprotocol/server-filesystem")

if result["allowed"]:
    print(f"Safe to connect (trust level {result['trustLevel']})")
    # Proceed with MCP connection
else:
    print(f"Connection refused: {result['reason']}")
```

---

## TypeScript: Trust-Gated MCP Connection

```typescript
interface McpTrustResult {
  allowed: boolean;
  trustLevel: number | null;
  reason: string;
}

async function checkMcpTrust(
  serverName: string,
  minLevel = 2
): Promise<McpTrustResult> {
  const did = `did:opena2a:mcp_server:${serverName}`;
  const url = `https://api.oa2a.org/api/v1/trust/proof?did=${encodeURIComponent(did)}`;

  const resp = await fetch(url);

  if (resp.status === 404) {
    return { allowed: false, trustLevel: null, reason: "Server not found in registry" };
  }
  if (!resp.ok) {
    throw new Error(`ATP authority answered HTTP ${resp.status}`);
  }

  // The trust fields sit under "proof", not at the top level of the response
  const { proof } = await resp.json();
  const level = proof?.trustLevel;

  // A level that is not an integer 0-4 refuses the connection
  if (!Number.isInteger(level) || level < 0 || level > 4) {
    return { allowed: false, trustLevel: null, reason: "No readable trust level in the proof" };
  }

  if (level === 0) {
    return { allowed: false, trustLevel: 0, reason: `BLOCKED: ${proof.verdict}` };
  }

  // Date.parse returns NaN for a missing or unreadable expiresAt, which also refuses
  if (!(Date.parse(proof.expiresAt) > Date.now())) {
    return { allowed: false, trustLevel: level, reason: "Trust proof expired" };
  }

  if (level < minLevel) {
    return {
      allowed: false,
      trustLevel: level,
      reason: `Trust level ${level} below minimum ${minLevel}`,
    };
  }

  return { allowed: true, trustLevel: level, reason: "ok" };
}

// --- Usage ---

const result = await checkMcpTrust("@modelcontextprotocol/server-filesystem");
if (result.allowed) {
  console.log(`Safe to connect (trust level ${result.trustLevel})`);
  // Connect to MCP server
} else {
  console.log(`Connection refused: ${result.reason}`);
}
```

---

## Batch Check: Multiple MCP Servers

When an MCP client config references multiple servers, use the batch endpoint (ATP-SPEC Section 7.2) to verify them all in one request:

```python
import requests


def check_mcp_servers_batch(server_names: list[str], min_level: int = 2) -> dict:
    """
    Batch-verify multiple MCP servers against ATP.

    Returns a dict mapping server name to trust result. A server the answer
    leaves out, or answers without an integer level 0-4, is not allowed.
    """
    dids = {name: f"did:opena2a:mcp_server:{name}" for name in server_names}

    resp = requests.post(
        "https://api.oa2a.org/api/v1/trust/batch",
        json={"agents": [{"did": did} for did in dids.values()]},
        timeout=15,
    )
    resp.raise_for_status()

    # Match answers by DID, not by position
    answers = {answer.get("did"): answer for answer in resp.json().get("results", [])}

    results = {}
    for name, did in dids.items():
        answer = answers.get(did, {})
        trust_level = answer.get("trustLevel")
        readable = type(trust_level) is int and 0 <= trust_level <= 4
        verdict = answer.get("verdict", "unknown")
        results[name] = {
            "allowed": readable
            and trust_level != 0
            and verdict != "blocked"
            and trust_level >= min_level,
            "trustLevel": trust_level if readable else None,
            "verdict": verdict,
        }

    return results


# --- Usage ---

servers = [
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-github",
    "some-unknown-server",
]

results = check_mcp_servers_batch(servers)
for name, result in results.items():
    status = "OK" if result["allowed"] else "BLOCKED"
    print(f"  {name}: {status} (level {result['trustLevel']})")
```

---

## MCP Config with Trust Policy

An MCP client can define trust policies per server in its configuration:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/user"],
      "atp": {
        "did": "did:opena2a:mcp_server:@modelcontextprotocol/server-filesystem",
        "minTrustLevel": 3,
        "blockOnFailure": true
      }
    },
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_TOKEN": "${GITHUB_TOKEN}"
      },
      "atp": {
        "did": "did:opena2a:mcp_server:@modelcontextprotocol/server-github",
        "minTrustLevel": 2,
        "blockOnFailure": false
      }
    }
  }
}
```

| Policy Field | Default | Description |
|-------------|---------|-------------|
| `minTrustLevel` | 2 | Minimum ATP trust level to allow connection |
| `blockOnFailure` | false | If true, refuse connection when ATP is unreachable |

---

## Sensitive Tool Gating

Some MCP tools warrant higher trust than others. A filesystem server that only reads files is lower risk than one that writes or deletes. Clients can gate individual tools by trust level:

```python
TOOL_TRUST_REQUIREMENTS = {
    "read_file": 2,      # Listed is sufficient for read-only
    "write_file": 3,     # Scanned required for writes
    "delete_file": 4,    # Verified required for destructive operations
    "execute_command": 4, # Verified required for code execution
}


def can_use_tool(tool_name: str, server_trust_level: int | None) -> bool:
    required = TOOL_TRUST_REQUIREMENTS.get(tool_name, 3)
    # An unread level (None) allows no tool
    return type(server_trust_level) is int and server_trust_level >= required
```

---

## Related

- [A2A Integration Guide](a2a-integration.md) -- trust proofs in A2A agent cards
- [CI/CD Integration Guide](ci-cd-integration.md) -- trust gates in deployment pipelines
- [ATP Specification](../ATP-SPEC.md) -- full protocol specification
