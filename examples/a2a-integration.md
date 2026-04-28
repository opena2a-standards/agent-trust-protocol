# A2A + ATP Integration Guide

How to embed ATP trust proofs in A2A agent cards and verify them before delegating tasks.

## Overview

The [Google A2A Protocol](https://github.com/google/A2A) defines how agents discover each other via agent cards served at `/.well-known/agent.json`. ATP extends this by adding a cryptographically signed trust proof to the card, so an agent receiving a task delegation can verify the sender's trust before accepting work.

**Flow:**
1. Agent A publishes its agent card with an embedded ATP trust proof
2. Agent B fetches A's agent card before delegating a task
3. Agent B verifies the trust proof against the ATP authority
4. If verification passes and trust level meets the minimum, Agent B accepts the task

---

## A2A Agent Card with ATP Trust Proof

An A2A agent card with ATP trust embedded in the `atp` field:

```json
{
  "name": "Weather Agent",
  "description": "Provides weather forecasts",
  "url": "https://weather.example.com",
  "version": "1.0.0",
  "capabilities": {
    "streaming": false,
    "pushNotifications": false
  },
  "skills": [
    {
      "id": "weather_lookup",
      "name": "Weather Lookup",
      "description": "Get current weather for a location"
    }
  ],
  "atp": {
    "did": "did:opena2a:a2a_agent:weather-agent",
    "trustLevel": 3,
    "trustProof": {
      "did": "did:opena2a:a2a_agent:weather-agent",
      "trustLevel": 3,
      "trustScore": 0.82,
      "verdict": "passed",
      "issuedAt": "2026-03-22T14:00:00Z",
      "expiresAt": "2026-03-23T14:00:00Z",
      "issuerDid": "did:opena2a:authority:opena2a.org",
      "signatures": [
        {
          "keyId": "did:opena2a:authority:opena2a.org#key-v3",
          "algorithm": "Ed25519",
          "value": "base64-signature"
        }
      ],
      "transparencyLogIndex": 1847293
    },
    "verifyAt": "https://api.oa2a.org/api/v1/trust/verify"
  }
}
```

### Field Reference

| Field | Required | Description |
|-------|----------|-------------|
| `atp.did` | Yes | The agent's ATP DID (see [ATP-SPEC Section 3](../ATP-SPEC.md#3-agent-identifiers)) |
| `atp.trustLevel` | Yes | Current trust level (0-4) |
| `atp.trustProof` | Yes | The signed trust proof object |
| `atp.verifyAt` | No | Override URL for proof verification (defaults to the issuer's well-known endpoint) |

The `trustProof` object is the exact format defined in [ATP-SPEC Section 4.2](../ATP-SPEC.md#42-trust-proof-format). It is self-contained: a verifier does not need to fetch the proof separately if it is embedded in the agent card.

---

## Verification: Python

```python
import requests
from datetime import datetime, timezone


def verify_a2a_agent(agent_card_url: str, min_trust_level: int = 3) -> dict:
    """
    Fetch an A2A agent card and verify its ATP trust proof.

    Returns:
        {"trusted": True/False, "trustLevel": int, "score": float, "reason": str}
    """
    # 1. Fetch the agent card
    resp = requests.get(agent_card_url, timeout=10)
    resp.raise_for_status()
    card = resp.json()

    # 2. Check for ATP trust proof
    atp = card.get("atp")
    if not atp or "trustProof" not in atp:
        return {"trusted": False, "reason": "No ATP trust proof in agent card"}

    proof = atp["trustProof"]

    # 3. Check expiry locally before making a network call
    expires = datetime.fromisoformat(proof["expiresAt"].replace("Z", "+00:00"))
    if expires < datetime.now(timezone.utc):
        return {"trusted": False, "reason": "Trust proof expired"}

    # 4. Verify the trust proof against the ATP authority
    verify_url = atp.get("verifyAt", "https://api.oa2a.org/api/v1/trust/verify")
    verification = requests.post(
        verify_url,
        json=proof,
        headers={"Content-Type": "application/json"},
        timeout=10,
    ).json()

    if not verification.get("valid"):
        return {"trusted": False, "reason": verification.get("error", "Verification failed")}

    # 5. Check trust level meets minimum
    trust_level = atp.get("trustLevel", 0)
    if trust_level < min_trust_level:
        return {
            "trusted": False,
            "reason": f"Trust level {trust_level} below minimum {min_trust_level}",
        }

    return {
        "trusted": True,
        "trustLevel": trust_level,
        "score": proof.get("trustScore", 0),
    }


# --- Usage ---

result = verify_a2a_agent("https://weather.example.com/.well-known/agent.json")

if result["trusted"]:
    print(f"Agent trusted (level {result['trustLevel']}, score {result['score']})")
    # Safe to delegate tasks to this agent
else:
    print(f"Agent not trusted: {result['reason']}")
    # Refuse task delegation
```

### Delegating with trust context

When Agent B delegates a task to Agent A, it can include its own trust proof so that Agent A can verify the caller:

```python
def delegate_task(target_agent_url: str, task: dict, my_proof: dict) -> dict:
    """Send a task to another A2A agent, including our own trust proof."""
    return requests.post(
        f"{target_agent_url}/tasks/send",
        json={
            "jsonrpc": "2.0",
            "method": "tasks/send",
            "params": {
                "message": task,
                "metadata": {
                    "atp": {
                        "callerProof": my_proof,
                    }
                },
            },
        },
        timeout=30,
    ).json()
```

---

## Verification: TypeScript

```typescript
interface VerifyResult {
  trusted: boolean;
  trustLevel?: number;
  score?: number;
  reason?: string;
}

async function verifyA2AAgent(
  agentCardUrl: string,
  minTrustLevel = 3
): Promise<VerifyResult> {
  // 1. Fetch the agent card
  const card = await fetch(agentCardUrl).then((r) => r.json());

  // 2. Check for ATP trust proof
  if (!card.atp?.trustProof) {
    return { trusted: false, reason: "No ATP trust proof in agent card" };
  }

  const { atp } = card;
  const proof = atp.trustProof;

  // 3. Check expiry locally
  if (new Date(proof.expiresAt) < new Date()) {
    return { trusted: false, reason: "Trust proof expired" };
  }

  // 4. Verify against the ATP authority
  const verifyUrl = atp.verifyAt || "https://api.oa2a.org/api/v1/trust/verify";
  const verification = await fetch(verifyUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(proof),
  }).then((r) => r.json());

  if (!verification.valid) {
    return { trusted: false, reason: verification.error || "Verification failed" };
  }

  // 5. Check trust level
  if (atp.trustLevel < minTrustLevel) {
    return {
      trusted: false,
      reason: `Trust level ${atp.trustLevel} below minimum ${minTrustLevel}`,
    };
  }

  return { trusted: true, trustLevel: atp.trustLevel, score: proof.trustScore };
}

// --- Usage ---

const result = await verifyA2AAgent(
  "https://weather.example.com/.well-known/agent.json"
);

if (result.trusted) {
  console.log(`Trusted: level ${result.trustLevel}, score ${result.score}`);
  // Proceed with task delegation
} else {
  console.log(`Not trusted: ${result.reason}`);
  // Refuse delegation
}
```

---

## Verification: cURL

For quick manual checks or shell scripts:

```bash
# Fetch the agent card
curl -s https://weather.example.com/.well-known/agent.json | jq '.atp'

# Extract and verify the trust proof
curl -s https://weather.example.com/.well-known/agent.json \
  | jq '.atp.trustProof' \
  | curl -s -X POST https://api.oa2a.org/api/v1/trust/verify \
    -H "Content-Type: application/json" \
    -d @- \
  | jq '.'
```

---

## Trust Level Decision Matrix

How to handle each trust level when deciding whether to delegate a task:

| Trust Level | Name | Recommended Action |
|-------------|------|--------------------|
| 0 (Blocked) | Blocked | Refuse. Log the attempt. |
| 1 (Warning) | Warning | Refuse for sensitive tasks. Allow read-only with user consent. |
| 2 (Listed) | Listed | Allow low-risk tasks. Require user confirmation for anything else. |
| 3 (Scanned) | Scanned | Allow most tasks. Automated delegation is safe. |
| 4 (Verified) | Verified | Full trust. Multi-authority verified. |

---

## Refreshing Trust Proofs

Trust proofs expire after 24 hours (see [ATP-SPEC Section 10.2](../ATP-SPEC.md#102-trust-proof-validity)). Agents serving an agent card with an embedded proof SHOULD refresh the proof before it expires:

```python
import threading

def refresh_proof_periodically(did: str, interval_seconds: int = 3600):
    """Fetch a fresh trust proof every hour and update the agent card."""
    def refresh():
        proof = requests.get(
            f"https://api.oa2a.org/api/v1/trust/proof?did={did}",
            timeout=10,
        ).json()
        # Update the in-memory agent card with the new proof
        update_agent_card_proof(proof)
        threading.Timer(interval_seconds, refresh).start()

    refresh()
```

---

## Related

- [MCP Integration Guide](mcp-integration.md) -- verifying MCP server trust before connecting
- [CI/CD Integration Guide](ci-cd-integration.md) -- trust gates in deployment pipelines
- [ATP Specification](../ATP-SPEC.md) -- full protocol specification
