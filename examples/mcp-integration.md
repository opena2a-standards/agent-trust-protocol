# MCP + ATP Integration Guide

How to verify an MCP server's trust before connecting and executing tools.

## Overview

MCP (Model Context Protocol) servers expose tools, resources, and prompts to AI clients. Before connecting to an MCP server -- especially one that accesses the filesystem, runs code, or makes network requests -- a client should verify the server's trust level through ATP.

**Flow:**
1. Client discovers an MCP server (from config, registry, or recommendation)
2. Client queries the ATP authority for the server's trust proof
3. If trust level meets the threshold, client connects to the server
4. Client caches the proof and re-checks periodically

---

## Quick Check: cURL

```bash
# Check trust before connecting to an MCP server
curl -s "https://api.oa2a.org/api/v1/trust/proof?did=did:opena2a:mcp_server:@modelcontextprotocol/server-filesystem" \
  | jq '{trustLevel: .trustLevel, verdict: .verdict, score: .trustScore, expires: .expiresAt}'
```

Example response:

```json
{
  "trustLevel": 3,
  "verdict": "passed",
  "score": 0.85,
  "expires": "2026-03-23T14:00:00Z"
}
```

---

## Python: Trust-Gated MCP Connection

```python
import requests


def check_mcp_trust(server_name: str, min_level: int = 2) -> dict:
    """
    Query ATP for an MCP server's trust before connecting.

    Args:
        server_name: Package name (e.g., "@modelcontextprotocol/server-filesystem")
        min_level: Minimum trust level to allow connection (default: 2)

    Returns:
        {"allowed": True/False, "trustLevel": int, "reason": str}
    """
    did = f"did:opena2a:mcp_server:{server_name}"

    resp = requests.get(
        "https://api.oa2a.org/api/v1/trust/proof",
        params={"did": did},
        timeout=10,
    )

    if resp.status_code == 404:
        return {"allowed": False, "trustLevel": -1, "reason": "Server not found in registry"}

    resp.raise_for_status()
    proof = resp.json()

    # Blocked servers: always refuse
    if proof.get("trustLevel", 0) == 0:
        return {
            "allowed": False,
            "trustLevel": 0,
            "reason": f"BLOCKED: {proof.get('verdict', 'unknown')}",
        }

    # Check minimum trust level
    trust_level = proof.get("trustLevel", 0)
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
  trustLevel: number;
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
    return { allowed: false, trustLevel: -1, reason: "Server not found in registry" };
  }

  const proof = await resp.json();

  if (proof.trustLevel === 0) {
    return { allowed: false, trustLevel: 0, reason: `BLOCKED: ${proof.verdict}` };
  }

  if (proof.trustLevel < minLevel) {
    return {
      allowed: false,
      trustLevel: proof.trustLevel,
      reason: `Trust level ${proof.trustLevel} below minimum ${minLevel}`,
    };
  }

  return { allowed: true, trustLevel: proof.trustLevel, reason: "ok" };
}

// --- Usage ---

const result = await checkMcpTrust("@modelcontextprotocol/server-filesystem");
if (result.allowed) {
  // Connect to MCP server
}
```

---

## Batch Check: Multiple MCP Servers

When an MCP client config references multiple servers, use the batch endpoint to verify them all in one request:

```python
import requests


def check_mcp_servers_batch(server_names: list[str], min_level: int = 2) -> dict:
    """
    Batch-verify multiple MCP servers against ATP.

    Returns a dict mapping server name to trust result.
    """
    agents = [
        {"did": f"did:opena2a:mcp_server:{name}"} for name in server_names
    ]

    resp = requests.post(
        "https://api.oa2a.org/api/v1/trust/batch",
        json={"agents": agents},
        timeout=15,
    ).json()

    results = {}
    for name, answer in zip(server_names, resp.get("results", [])):
        trust_level = answer.get("trustLevel", -1)
        results[name] = {
            "allowed": trust_level >= min_level and trust_level != 0,
            "trustLevel": trust_level,
            "verdict": answer.get("verdict", "unknown"),
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


def can_use_tool(tool_name: str, server_trust_level: int) -> bool:
    required = TOOL_TRUST_REQUIREMENTS.get(tool_name, 3)
    return server_trust_level >= required
```

---

## Related

- [A2A Integration Guide](a2a-integration.md) -- trust proofs in A2A agent cards
- [CI/CD Integration Guide](ci-cd-integration.md) -- trust gates in deployment pipelines
- [ATP Specification](../ATP-SPEC.md) -- full protocol specification
