# CI/CD + ATP Integration Guide

How to add ATP trust gates to deployment pipelines so that untrusted agents and MCP servers cannot reach production.

## Overview

A CI/CD trust gate queries ATP before deploying or connecting to an agent. If the agent's trust level is below the required threshold, the pipeline fails and the deployment is blocked.

This prevents three categories of risk:
1. Deploying an agent that has been **blocked** (trust level 0) due to a known vulnerability
2. Connecting to an MCP server that has **never been scanned** (trust level 2)
3. Delegating tasks to an A2A agent whose trust has **expired** or been **revoked**

The gate script below checks all three, and it fails closed: an answer it cannot read refuses the agent instead of passing it.

---

## The Trust Gate Script

Save this in your repository as `scripts/atp-trust-gate.sh`. Every workflow in this guide runs it, so the checks live in one place. It needs `bash`, `curl` and `jq`.

```bash
#!/usr/bin/env bash
# atp-trust-gate.sh -- fail a pipeline unless an agent's ATP trust proof clears a threshold
# Usage: bash atp-trust-gate.sh <did> [min_trust_level]
# Exit codes: 0 passed, 1 refused, 2 ATP authority unreachable (see "Exit Codes")

set -euo pipefail

DID="${1:?Usage: atp-trust-gate.sh <did> [min_trust_level]}"
MIN_LEVEL="${2:-3}"
ATP_URL="${ATP_URL:-https://api.oa2a.org}"
BODY=$(mktemp)
trap 'rm -f "$BODY"' EXIT

refuse() { echo "Trust gate refused ${DID}: $*" >&2; exit 1; }
unreachable() { echo "Trust gate could not reach the ATP authority for ${DID}: $*" >&2; exit 2; }

case "$MIN_LEVEL" in
  [0-4]) ;;
  *) refuse "min_trust_level must be an integer 0-4, got ${MIN_LEVEL}" ;;
esac

# 1. Fetch the trust proof. A 404 is an answer (not in the registry); no answer is exit 2.
STATUS=$(curl -s -o "$BODY" -w '%{http_code}' "${ATP_URL}/api/v1/trust/proof?did=${DID}") \
  || unreachable "no response from ${ATP_URL}"
case "$STATUS" in
  200) ;;
  404) refuse "not in the registry" ;;
  *) unreachable "HTTP ${STATUS} from ${ATP_URL}" ;;
esac

# 2. Read the proof. The response is {"proof": {...}, "algorithm": ..., "publicKey": ...}:
#    the trust fields sit under .proof, not at the top level.
PROOF=$(jq -ce '.proof | objects' "$BODY" 2>/dev/null) || refuse "response carries no trust proof"
LEVEL=$(jq -r '.trustLevel | if type == "number" and . == floor and . >= 0 and . <= 4 then . else "unreadable" end' <<<"$PROOF")
VERDICT=$(jq -r '.verdict | strings' <<<"$PROOF")
echo "${DID}: trust level ${LEVEL}, verdict ${VERDICT:-none}"

# 3. A level that is not an integer 0-4 refuses the agent; so do blocked and below-threshold.
if [ "$LEVEL" = unreadable ]; then refuse "trust level is not an integer 0-4"; fi
if [ "$LEVEL" -eq 0 ] || [ "$VERDICT" = blocked ]; then refuse "blocked (verdict ${VERDICT:-none})"; fi
if [ "$LEVEL" -lt "$MIN_LEVEL" ]; then refuse "trust level ${LEVEL} below threshold ${MIN_LEVEL}"; fi

# 4. Expiry. jq's date parser takes whole seconds, so the fraction is dropped first.
if ! jq -e '.expiresAt | sub("\\.[0-9]+"; "") | fromdateiso8601 > now' <<<"$PROOF" >/dev/null 2>&1; then
  refuse "trust proof expired or carries no readable expiresAt"
fi

# 5. Revocation (ATP-SPEC Section 8.1). A proof is valid for at most 24 hours (Section 10.2),
#    so the revocations of the last 24 hours cover every proof that has not expired.
SINCE=$(jq -rn 'now - 86400 | todateiso8601')
STATUS=$(curl -s -o "$BODY" -w '%{http_code}' "${ATP_URL}/api/v1/trust/revocations?since=${SINCE}") \
  || unreachable "no response from the revocation list"
if [ "$STATUS" != 200 ]; then unreachable "revocation list answered HTTP ${STATUS}"; fi
REVOKED=$(jq -r --arg did "$DID" '.revocations | if type == "array" then any(.[]; .agentDid == $did) else "unreadable" end' "$BODY" 2>/dev/null) \
  || REVOKED=unreadable
case "$REVOKED" in
  false) ;;
  true) refuse "revoked" ;;
  *) refuse "revocation list unreadable" ;;
esac

echo "Trust gate passed: ${DID} at level ${LEVEL} (threshold ${MIN_LEVEL})"
```

Set `ATP_URL` to query a trust authority other than the reference one.

---

## GitHub Actions: Trust Gate

GitHub expressions (`${{ ... }}`) are passed to the script through `env:`, never written into the `run:` text, so a value cannot inject shell syntax.

### Basic trust check

```yaml
name: Agent Trust Gate
on: [push]

jobs:
  verify-trust:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Check agent trust
        env:
          DID: did:opena2a:mcp_server:${{ vars.MCP_SERVER_NAME }}
        run: |
          bash scripts/atp-trust-gate.sh "$DID" 3
```

### Multiple agents with configurable threshold

```yaml
name: Trust Gate (Multi-Agent)
on:
  pull_request:
    branches: [main]

env:
  MIN_TRUST_LEVEL: 3

jobs:
  verify-all-agents:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        agent:
          - did: "did:opena2a:mcp_server:@modelcontextprotocol/server-filesystem"
            label: "Filesystem MCP"
          - did: "did:opena2a:mcp_server:@modelcontextprotocol/server-github"
            label: "GitHub MCP"
          - did: "did:opena2a:agent:weather-agent"
            label: "Weather Agent"
    steps:
      - uses: actions/checkout@v4

      - name: Verify ${{ matrix.agent.label }}
        env:
          DID: ${{ matrix.agent.did }}
        run: |
          bash scripts/atp-trust-gate.sh "$DID" "$MIN_TRUST_LEVEL"
```

---

## Batch Verification Script

For pipelines with many agent dependencies, use the batch endpoint (ATP-SPEC Section 7.2) to verify all agents in a single API call. A batch answer is a query result, not a signed proof, so it carries no expiry to check; a pipeline that needs the signed proof runs `atp-trust-gate.sh` per agent instead.

```bash
#!/usr/bin/env bash
# verify-agents.sh -- Batch trust verification for CI/CD
# Usage: bash verify-agents.sh agents.json [min_trust_level]
# Exit codes: 0 passed, 1 one or more refused, 2 ATP authority unreachable (see "Exit Codes")

set -euo pipefail

AGENTS_FILE="${1:?Usage: verify-agents.sh agents.json [min_trust_level]}"
MIN_LEVEL="${2:-3}"
ATP_URL="${ATP_URL:-https://api.oa2a.org}"
BODY=$(mktemp)
trap 'rm -f "$BODY"' EXIT

case "$MIN_LEVEL" in
  [0-4]) ;;
  *) echo "min_trust_level must be an integer 0-4, got ${MIN_LEVEL}" >&2; exit 1 ;;
esac

# Build the batch request from a JSON array of DIDs
PAYLOAD=$(jq -c '{agents: [.[] | {did: .}]}' "$AGENTS_FILE")

STATUS=$(curl -s -o "$BODY" -w '%{http_code}' -X POST "${ATP_URL}/api/v1/trust/batch" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD") \
  || { echo "No response from ${ATP_URL}" >&2; exit 2; }
if [ "$STATUS" != 200 ]; then
  echo "Batch query answered HTTP ${STATUS}: $(head -c 200 "$BODY")" >&2
  exit 2
fi

# Revocations of the last 24 hours (ATP-SPEC Section 8.1)
SINCE=$(jq -rn 'now - 86400 | todateiso8601')
REVOCATIONS=$(curl -sf "${ATP_URL}/api/v1/trust/revocations?since=${SINCE}") \
  || { echo "Revocation list unavailable from ${ATP_URL}" >&2; exit 2; }

# Check every requested DID, matched by DID; an agent the answer leaves out fails.
# The loop reads from a process substitution, not a pipe, so FAILED set inside it
# is still set after it.
FAILED=0
while read -r DID; do
  RESULT=$(jq -c --arg did "$DID" 'first(.results[]? | select(.did == $did)) // {}' "$BODY")
  LEVEL=$(jq -r '.trustLevel | if type == "number" and . == floor and . >= 0 and . <= 4 then . else "unreadable" end' <<<"$RESULT")
  VERDICT=$(jq -r '.verdict | strings' <<<"$RESULT")
  REVOKED=$(jq -r --arg did "$DID" '.revocations | if type == "array" then any(.[]; .agentDid == $did) else "unreadable" end' <<<"$REVOCATIONS")

  if [ "$LEVEL" = unreadable ]; then
    echo "FAIL: ${DID} -- no readable trust level in the batch answer"
    FAILED=1
  elif [ "$REVOKED" != false ]; then
    echo "FAIL: ${DID} -- revoked, or the revocation list is unreadable"
    FAILED=1
  elif [ "$LEVEL" -eq 0 ] || [ "$VERDICT" = blocked ] || [ "$LEVEL" -lt "$MIN_LEVEL" ]; then
    echo "FAIL: ${DID} -- level ${LEVEL}, verdict ${VERDICT:-none}"
    FAILED=1
  else
    echo "PASS: ${DID} -- level ${LEVEL}"
  fi
done < <(jq -r '.[]' "$AGENTS_FILE")

exit "$FAILED"
```

With an `agents.json` file:

```json
[
  "did:opena2a:mcp_server:@modelcontextprotocol/server-filesystem",
  "did:opena2a:mcp_server:@modelcontextprotocol/server-github",
  "did:opena2a:agent:weather-agent"
]
```

---

## GitLab CI

The job image needs `bash`, `curl` and `jq` for the gate script:

```yaml
trust-gate:
  stage: verify
  image: alpine:3.20
  before_script:
    - apk add --no-cache bash curl jq
  script:
    - bash scripts/atp-trust-gate.sh "did:opena2a:mcp_server:${MCP_SERVER_NAME}" 3
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

---

## Docker Build with Trust Verification

Verify the trust of every MCP server in the project's MCP config before building. Each server names its DID in an `atp` block (see the [MCP Integration Guide](mcp-integration.md#mcp-config-with-trust-policy)); a server without one stops the build instead of being skipped.

```yaml
name: Build with Trust Gate
on:
  push:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Verify the MCP servers in mcp-config.json
        run: |
          DIDS=$(jq -r '.mcpServers | to_entries[] | .value.atp.did // error("\(.key) has no atp.did")' mcp-config.json)
          for DID in $DIDS; do
            bash scripts/atp-trust-gate.sh "$DID" 3
          done

      - name: Build and push
        run: docker build -t myapp:latest .
```

---

## Monitoring Trust Changes in CI

Re-run the gate on a schedule for the agents your pipeline depends on, so a trust drop, an expired proof or a revocation since the last push fails a scheduled run. The second step lists the authority's advisories of the last day; the advisories endpoint (`advisories` in the authority's discovery document) takes `since` as a date, `YYYY-MM-DD`, and answers OSV records.

```yaml
name: Trust Monitor
on:
  schedule:
    - cron: "0 */6 * * *"  # Every 6 hours

jobs:
  check-trust:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Re-check every agent in agents.json
        run: |
          DIDS=$(jq -r '.[]' agents.json)
          WORST=0
          for DID in $DIDS; do
            CODE=0
            bash scripts/atp-trust-gate.sh "$DID" 3 || CODE=$?
            if [ "$CODE" -gt "$WORST" ]; then WORST=$CODE; fi
          done
          exit "$WORST"

      - name: List advisories from the last day
        if: always()
        run: |
          SINCE=$(jq -rn 'now - 86400 | strftime("%Y-%m-%d")')
          ADVISORIES=$(curl -sf "https://api.oa2a.org/api/v1/trust/advisories?since=${SINCE}")
          jq -r '.advisories[] | "::warning::\(.id): \(.summary)"' <<<"$ADVISORIES"
```

---

## Exit Codes

`atp-trust-gate.sh` and `verify-agents.sh` exit with these codes, and the workflows above end with the code of the gate that failed:

| Exit Code | Meaning |
|-----------|---------|
| 0 | All agents meet the trust threshold: not blocked, not revoked, and (for the gate script) holding an unexpired proof |
| 1 | One or more agents refused: below threshold, blocked, expired, revoked, not in the registry, or without a readable trust level |
| 2 | ATP authority unreachable: no response, or an HTTP error other than 404 |

---

## Related

- [A2A Integration Guide](a2a-integration.md) -- trust proofs in A2A agent cards
- [MCP Integration Guide](mcp-integration.md) -- verifying MCP server trust before connecting
- [ATP Specification](../ATP-SPEC.md) -- full protocol specification
