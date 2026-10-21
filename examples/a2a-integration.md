# A2A + ATP Integration Guide

How to embed ATP trust proofs in A2A agent cards and verify them before delegating tasks.

## Overview

The [Google A2A Protocol](https://github.com/google/A2A) defines how agents discover each other via agent cards served at `/.well-known/agent-card.json`. ATP extends this by adding a cryptographically signed trust proof to the card, so an agent receiving a task delegation can verify the sender's trust before accepting work.

**Flow:**
1. Agent A publishes its agent card with an embedded ATP trust proof
2. Agent B fetches A's agent card before delegating a task
3. Agent B checks that the trust proof is about the DID the card names, and verifies it against the ATP authority
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
    "did": "did:opena2a:agent:weather-agent",
    "trustLevel": 3,
    "trustProof": {
      "did": "did:opena2a:agent:weather-agent",
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
| `atp.did` | Yes | The agent's ATP DID (see [ATP-SPEC Section 3](../ATP-SPEC.md#3-agent-identifiers)). The samples below refuse a card without it, or whose `trustProof` has another `did` |
| `atp.trustLevel` | Yes | Current trust level (0-4), an unsigned copy for display. Verifiers read the level from `trustProof`, which the authority signed |
| `atp.trustProof` | Yes | The signed trust proof object |
| `atp.verifyAt` | No | Verification URL suggested by the card's publisher. The samples below do not use it: they verify against the authority the verifier is configured with (by default `https://api.oa2a.org/api/v1/trust/verify`), because the card is unverified input and a card that named its own verifier could name one that always answers valid |

The `trustProof` object is the exact format defined in [ATP-SPEC Section 4.2](../ATP-SPEC.md#42-trust-proof-format), the object under `proof` in the authority's `GET /api/v1/trust/proof` response, not that whole response. It is self-contained: a verifier does not need to fetch the proof separately if it is embedded in the agent card.

The Python samples need Python 3.11 or later: `datetime.fromisoformat` reads the authority's nanosecond timestamps from 3.11 on.

No sample follows a redirect. [ATP-SPEC Section 7.1](../ATP-SPEC.md#71-well-known-endpoint) forbids a client to follow a redirect to a URL that is not `https`, and `requests` and `fetch` follow redirects by default, so the Python samples pass `allow_redirects=False` and fail on a redirect answer, and the TypeScript samples pass `redirect: "error"`, under which `fetch` rejects a redirect. The samples treat a redirect from the agent the same way as one from the authority. The cURL commands pass no `-L`, so curl follows no redirect.

---

## Verification: Python

```python
import requests
from datetime import datetime, timezone


def verify_a2a_agent(
    agent_card_url: str,
    min_trust_level: int = 3,
    verify_url: str = "https://api.oa2a.org/api/v1/trust/verify",
) -> dict:
    """
    Fetch an A2A agent card and verify its ATP trust proof.

    Returns:
        {"trusted": True/False, "trustLevel": int, "score": float, "reason": str}
    """
    # 1. Fetch the agent card
    resp = requests.get(agent_card_url, timeout=10, allow_redirects=False)
    resp.raise_for_status()
    if resp.is_redirect:
        raise requests.HTTPError(f"Agent card URL redirects to {resp.headers['Location']}")
    card = resp.json()

    # 2. Check for ATP trust proof
    atp = card.get("atp")
    if not atp or "trustProof" not in atp:
        return {"trusted": False, "reason": "No ATP trust proof in agent card"}

    proof = atp["trustProof"]

    # 3. The signed proof must be about the agent the card names: a valid proof
    #    of another agent, copied into this card, says nothing about this one.
    if not atp.get("did") or proof.get("did") != atp["did"]:
        return {"trusted": False, "reason": "Trust proof is not about the agent the card names"}

    # 4. Check expiry locally before making a network call
    expires = datetime.fromisoformat(proof["expiresAt"].replace("Z", "+00:00"))
    if expires < datetime.now(timezone.utc):
        return {"trusted": False, "reason": "Trust proof expired"}

    # 5. Verify the trust proof against the authority this verifier trusts.
    #    The card's own atp.verifyAt is not used: the card chose it.
    check = requests.post(
        verify_url,
        json=proof,
        headers={"Content-Type": "application/json"},
        timeout=10,
        allow_redirects=False,
    )
    if check.is_redirect:
        return {"trusted": False, "reason": f"Verifier redirects to {check.headers['Location']}"}
    verification = check.json()

    if not verification.get("valid"):
        return {"trusted": False, "reason": verification.get("error", "Verification failed")}

    # 6. Read the level from the signed proof, not the card's unsigned atp.trustLevel.
    #    A level that is not an integer 0-4 is not trusted.
    trust_level = proof.get("trustLevel")
    if type(trust_level) is not int or not 0 <= trust_level <= 4:
        return {"trusted": False, "reason": "Trust proof carries no readable trust level"}
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

result = verify_a2a_agent("https://weather.example.com/.well-known/agent-card.json")

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
    resp = requests.post(
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
        allow_redirects=False,
    )
    if resp.is_redirect:
        raise requests.HTTPError(f"{target_agent_url} redirects to {resp.headers['Location']}")
    return resp.json()
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
  minTrustLevel = 3,
  verifyUrl = "https://api.oa2a.org/api/v1/trust/verify"
): Promise<VerifyResult> {
  // 1. Fetch the agent card
  const card = await fetch(agentCardUrl, { redirect: "error" }).then((r) => r.json());

  // 2. Check for ATP trust proof
  if (!card.atp?.trustProof) {
    return { trusted: false, reason: "No ATP trust proof in agent card" };
  }

  const proof = card.atp.trustProof;

  // 3. The signed proof must be about the agent the card names: a valid proof
  //    of another agent, copied into this card, says nothing about this one.
  if (!card.atp.did || proof.did !== card.atp.did) {
    return { trusted: false, reason: "Trust proof is not about the agent the card names" };
  }

  // 4. Check expiry locally; Date.parse returns NaN for a missing expiresAt, which also refuses
  if (!(Date.parse(proof.expiresAt) > Date.now())) {
    return { trusted: false, reason: "Trust proof expired" };
  }

  // 5. Verify against the authority this verifier trusts.
  //    The card's own atp.verifyAt is not used: the card chose it.
  const verification = await fetch(verifyUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(proof),
    redirect: "error",
  }).then((r) => r.json());

  if (!verification.valid) {
    return { trusted: false, reason: verification.error || "Verification failed" };
  }

  // 6. Read the level from the signed proof, not the card's unsigned atp.trustLevel.
  //    A level that is not an integer 0-4 is not trusted.
  const level = proof.trustLevel;
  if (!Number.isInteger(level) || level < 0 || level > 4) {
    return { trusted: false, reason: "Trust proof carries no readable trust level" };
  }
  if (level < minTrustLevel) {
    return {
      trusted: false,
      reason: `Trust level ${level} below minimum ${minTrustLevel}`,
    };
  }

  return { trusted: true, trustLevel: level, score: proof.trustScore };
}

// --- Usage ---

const result = await verifyA2AAgent(
  "https://weather.example.com/.well-known/agent-card.json"
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
curl -s https://weather.example.com/.well-known/agent-card.json | jq '.atp'

# Extract and verify the trust proof
curl -s https://weather.example.com/.well-known/agent-card.json \
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

import requests


def refresh_proof_periodically(did: str, interval_seconds: int = 3600):
    """Fetch a fresh trust proof every hour and update the agent card."""
    def refresh():
        try:
            resp = requests.get(
                "https://api.oa2a.org/api/v1/trust/proof",
                params={"did": did},
                timeout=10,
                allow_redirects=False,
            )
            resp.raise_for_status()
            if resp.is_redirect:
                raise requests.HTTPError(f"ATP authority redirects to {resp.headers['Location']}")
            # The response wraps the proof: {"proof": {...}, "algorithm": ..., "publicKey": ...}.
            # The card carries the proof itself, the object POST /api/v1/trust/verify accepts.
            update_agent_card_proof(resp.json()["proof"])
        finally:
            # Schedule the next refresh even when this one failed
            timer = threading.Timer(interval_seconds, refresh)
            timer.daemon = True
            timer.start()

    refresh()
```

`update_agent_card_proof` is your own function: it replaces `atp.trustProof` in the served card (and `atp.trustLevel`, the display copy, with the proof's `trustLevel`).

---

## Related

- [MCP Integration Guide](mcp-integration.md) -- verifying MCP server trust before connecting
- [CI/CD Integration Guide](ci-cd-integration.md) -- trust gates in deployment pipelines
- [ATP Specification](../ATP-SPEC.md) -- full protocol specification
