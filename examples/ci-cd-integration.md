# CI/CD + ATP Integration Guide

How to add ATP trust gates to deployment pipelines so that untrusted agents and MCP servers cannot reach production.

## Overview

A CI/CD trust gate queries ATP before deploying or connecting to an agent. If the agent's trust level is below the required threshold, the pipeline fails and the deployment is blocked.

This prevents three categories of risk:
1. Deploying an agent that has been **blocked** (trust level 0) due to a known vulnerability
2. Connecting to an MCP server that has **never been scanned** (trust level 2)
3. Delegating tasks to an A2A agent whose trust has **expired** or been **revoked**

---

## GitHub Actions: Trust Gate

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
        run: |
          DID="did:opena2a:mcp_server:${{ vars.MCP_SERVER_NAME }}"
          PROOF=$(curl -sf "https://api.oa2a.org/api/v1/trust/proof?did=${DID}")

          if [ $? -ne 0 ]; then
            echo "::error::Failed to fetch trust proof for ${DID}"
            exit 1
          fi

          LEVEL=$(echo "$PROOF" | jq -r '.trustLevel')
          VERDICT=$(echo "$PROOF" | jq -r '.verdict')

          echo "Trust level: ${LEVEL}, verdict: ${VERDICT}"

          if [ "$LEVEL" -lt 3 ]; then
            echo "::error::Trust level ${LEVEL} below threshold 3. Verdict: ${VERDICT}"
            exit 1
          fi

          echo "Trust gate passed."
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
      matrix:
        agent:
          - did: "did:opena2a:mcp_server:@modelcontextprotocol/server-filesystem"
            label: "Filesystem MCP"
          - did: "did:opena2a:mcp_server:@modelcontextprotocol/server-github"
            label: "GitHub MCP"
          - did: "did:opena2a:a2a_agent:weather-agent"
            label: "Weather Agent"
    steps:
      - name: Verify ${{ matrix.agent.label }}
        run: |
          PROOF=$(curl -sf "https://api.oa2a.org/api/v1/trust/proof?did=${{ matrix.agent.did }}")

          if [ $? -ne 0 ]; then
            echo "::error::Trust proof unavailable for ${{ matrix.agent.label }}"
            exit 1
          fi

          LEVEL=$(echo "$PROOF" | jq -r '.trustLevel')

          if [ "$LEVEL" -lt "$MIN_TRUST_LEVEL" ]; then
            echo "::error::${{ matrix.agent.label }}: trust level ${LEVEL} < ${MIN_TRUST_LEVEL}"
            exit 1
          fi

          echo "${{ matrix.agent.label }}: level ${LEVEL} -- passed"
```

---

## Batch Verification Script

For pipelines with many agent dependencies, use the batch endpoint to verify all agents in a single API call:

```bash
#!/usr/bin/env bash
# verify-agents.sh -- Batch trust verification for CI/CD
# Usage: ./verify-agents.sh agents.json [min_trust_level]

set -euo pipefail

AGENTS_FILE="${1:?Usage: verify-agents.sh agents.json [min_level]}"
MIN_LEVEL="${2:-3}"
ATP_URL="https://api.oa2a.org/api/v1/trust/batch"

# Build the batch request from a JSON array of DIDs
PAYLOAD=$(jq '{agents: [.[] | {did: .}]}' "$AGENTS_FILE")

RESPONSE=$(curl -sf -X POST "$ATP_URL" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD")

# Check each result
FAILED=0
echo "$RESPONSE" | jq -c '.results[]' | while read -r result; do
  DID=$(echo "$result" | jq -r '.did')
  LEVEL=$(echo "$result" | jq -r '.trustLevel')
  VERDICT=$(echo "$result" | jq -r '.verdict')

  if [ "$LEVEL" -lt "$MIN_LEVEL" ]; then
    echo "FAIL: ${DID} -- level ${LEVEL}, verdict ${VERDICT}"
    FAILED=1
  else
    echo "PASS: ${DID} -- level ${LEVEL}"
  fi
done

exit $FAILED
```

With an `agents.json` file:

```json
[
  "did:opena2a:mcp_server:@modelcontextprotocol/server-filesystem",
  "did:opena2a:mcp_server:@modelcontextprotocol/server-github",
  "did:opena2a:a2a_agent:weather-agent"
]
```

---

## GitLab CI

```yaml
trust-gate:
  stage: verify
  image: curlimages/curl:latest
  script:
    - |
      DID="did:opena2a:mcp_server:${MCP_SERVER_NAME}"
      PROOF=$(curl -sf "https://api.oa2a.org/api/v1/trust/proof?did=${DID}")
      LEVEL=$(echo "$PROOF" | jq -r '.trustLevel')
      if [ "$LEVEL" -lt 3 ]; then
        echo "Trust gate failed: level ${LEVEL}"
        exit 1
      fi
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

---

## Docker Build with Trust Verification

Verify the trust of MCP servers or agents referenced in a Dockerfile before building:

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

      - name: Extract agent references from config
        id: agents
        run: |
          # Extract MCP server names from the project config
          SERVERS=$(jq -r '.mcpServers | keys[]' mcp-config.json 2>/dev/null || echo "")
          echo "servers=${SERVERS}" >> "$GITHUB_OUTPUT"

      - name: Verify agent trust
        run: |
          for SERVER in ${{ steps.agents.outputs.servers }}; do
            DID="did:opena2a:mcp_server:${SERVER}"
            LEVEL=$(curl -sf "https://api.oa2a.org/api/v1/trust/proof?did=${DID}" | jq -r '.trustLevel')

            if [ "$LEVEL" -lt 3 ]; then
              echo "::error::${SERVER} trust level ${LEVEL} below threshold"
              exit 1
            fi
          done

      - name: Build and push
        run: docker build -t myapp:latest .
```

---

## Monitoring Trust Changes in CI

Subscribe to trust change events for agents your pipeline depends on. If an agent's trust drops or gets revoked, trigger a new pipeline run:

```yaml
name: Trust Monitor
on:
  schedule:
    - cron: "0 */6 * * *"  # Every 6 hours

jobs:
  check-trust:
    runs-on: ubuntu-latest
    steps:
      - name: Check for trust changes
        run: |
          # Fetch recent advisories (last 24 hours)
          SINCE=$(date -u -d "24 hours ago" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)
          ADVISORIES=$(curl -sf "https://api.oa2a.org/api/v1/trust/advisories?since=${SINCE}")

          COUNT=$(echo "$ADVISORIES" | jq '.advisories | length')
          if [ "$COUNT" -gt 0 ]; then
            echo "::warning::${COUNT} trust advisories in the last 24 hours"
            echo "$ADVISORIES" | jq '.advisories[] | "\(.agentDid): \(.trustLevel) (\(.reason))"'
          fi
```

---

## Exit Codes

All trust gate scripts follow the same convention:

| Exit Code | Meaning |
|-----------|---------|
| 0 | All agents meet the trust threshold |
| 1 | One or more agents below threshold or blocked |
| 2 | ATP authority unreachable (network error) |

---

## Related

- [A2A Integration Guide](a2a-integration.md) -- trust proofs in A2A agent cards
- [MCP Integration Guide](mcp-integration.md) -- verifying MCP server trust before connecting
- [ATP Specification](../ATP-SPEC.md) -- full protocol specification
