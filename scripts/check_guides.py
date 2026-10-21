#!/usr/bin/env python3
"""Run the code blocks of the integration guides in examples/ and of
ATP-SPEC.md Appendix B.1 and B.2 against recorded authority responses, so an
example that drifts from what the authority answers fails this check.
Run: python3 scripts/check_guides.py

No workflow in .github/workflows runs it (validate.yml runs
scripts/validate_examples.py and scripts/gen_registries.py --check, and
spec-drift.yml the family drift gate), so run it after changing a guide,
Appendix B.1 or B.2, or scripts/guide_responses.json.

Every fenced block in the three guides and in Appendix B.1 and B.2 is run by a
case below or read by one as an input (agents.json, mcp-config.json, the agent
card, the quick check's example output). A block no case uses is an error, so
a new block cannot land unchecked. Appendix B.3 runs the opena2a CLI, which no
stub here answers for, and is not run.

While the recorded responses hold the reference authority's refusal of the
Section 7.2 batch body (batchRejection), the two batch sections say that it
answers that body with HTTP 400; once a recording no longer holds the refusal,
a section that still says so is an error.

No request leaves the machine. Bash blocks and the shell steps of the YAML
workflows run with a curl stub first on PATH, Python blocks with a requests
stub beside them, TypeScript blocks with a fetch stub; all three answer from
the case's scenario, built from scripts/guide_responses.json. A request to any
other host fails as a refused connection, so a block that follows a URL it
should not follow fails its case.

A scenario can list URLs under "redirect"; the stub answers a request to one
with a 301 whose Location is the same URL under http. The requests and fetch
stubs follow a redirect as requests and fetch do by default (a POST answered
301 is sent again as a GET), unless the block passes allow_redirects=False or
redirect: "error" (fetch then rejects, as Node.js does) or "manual"; the curl
stub, like curl without -L, does not follow one. Every request a block sends
is logged, and a block that sends one to a URL that is not https fails its
case, whatever it does with the refused connection: Section 7.1 forbids the
request.

Needs bash, jq, and Node.js 22.6 or later (the TypeScript blocks run with
type stripping).
"""
import copy
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
GUIDES = {
    "ci": ROOT / "examples" / "ci-cd-integration.md",
    "mcp": ROOT / "examples" / "mcp-integration.md",
    "a2a": ROOT / "examples" / "a2a-integration.md",
    "spec": ROOT / "ATP-SPEC.md",
}
SPEC_EXAMPLES = ("\n### B.1 ", "\n### B.3 ")
RECORDED = json.loads((SCRIPTS / "guide_responses.json").read_text(encoding="utf-8"))
AUTHORITY = "api.oa2a.org"
SCENARIO_ENV = "ATP_GUIDE_SCENARIO"
REQUEST_LOG = ".requests.log"
REDIRECT_STATUSES = (301, 302, 303, 307, 308)
TIMEOUT = 60

FS = "did:opena2a:mcp_server:@modelcontextprotocol/server-filesystem"
GH = "did:opena2a:mcp_server:@modelcontextprotocol/server-github"
WEATHER = "did:opena2a:agent:weather-agent"
REQUESTER = "did:opena2a:agent:requester-agent"
CARD_URL = "https://weather.example.com/.well-known/agent-card.json"
TASKS_URL = "https://weather.example.com/tasks/send"
PROOF_URL = f"https://{AUTHORITY}/api/v1/trust/proof"
VERIFY_URL = f"https://{AUTHORITY}/api/v1/trust/verify"
BATCH_URL = f"https://{AUTHORITY}/api/v1/trust/batch"
RFC3339 = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})")
DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


# --- Guide blocks -----------------------------------------------------------

@dataclass
class Block:
    lang: str
    body: str


def parse_blocks(text):
    """Map (heading, n) to the n-th fenced block under that heading."""
    found = {}
    heading = None
    counts = {}
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        opening = re.match(r"^(`{3,}|~{3,})\s*([\w+-]*)\s*$", line)
        if opening:
            fence, lang = opening.group(1), opening.group(2)
            closing = re.compile(re.escape(fence[0]) + "{%d,}" % len(fence))
            body = []
            i += 1
            while i < len(lines) and not closing.fullmatch(lines[i].strip()):
                body.append(lines[i])
                i += 1
            n = counts.get(heading, 0)
            counts[heading] = n + 1
            found[(heading, n)] = Block(lang, "\n".join(body) + "\n")
        elif re.match(r"^#{1,6} ", line):
            heading = line.strip()
        i += 1
    return found


def block_scalar(lines, start, parent_indent):
    """The dedented text of a YAML `|` scalar starting at lines[start]."""
    body = []
    i = start
    while i < len(lines) and (not lines[i].strip() or indent_of(lines[i]) > parent_indent):
        body.append(lines[i])
        i += 1
    while body and not body[-1].strip():
        body.pop()
    width = min((indent_of(line) for line in body if line.strip()), default=0)
    return "\n".join(line[width:] for line in body) + "\n", i


def indent_of(line):
    return len(line) - len(line.lstrip(" "))


def shell_steps(yaml_text):
    """The shell text of each `run:` step (GitHub) and `script:` item (GitLab), in order."""
    lines = yaml_text.splitlines()
    steps = []
    i = 0
    while i < len(lines):
        line = lines[i]
        run = re.match(r"^(\s*)(?:- )?run: ?(.*)$", line)
        script = re.match(r"^(\s*)script:\s*$", line)
        if run:
            value = run.group(2).strip()
            if value in ("|", "|-"):
                body, i = block_scalar(lines, i + 1, indent_of(line))
                steps.append(body)
                continue
            steps.append(value + "\n")
        elif script:
            i += 1
            while i < len(lines) and indent_of(lines[i]) > indent_of(line) and lines[i].strip().startswith("- "):
                item = lines[i].strip()[2:].strip()
                if item in ("|", "|-"):
                    body, i = block_scalar(lines, i + 1, indent_of(lines[i]))
                    steps.append(body)
                else:
                    steps.append(item + "\n")
                    i += 1
            continue
        i += 1
    return steps


class Blocks:
    def __init__(self, texts):
        self.parsed = {key: parse_blocks(text) for key, text in texts.items()}

    def get(self, ref):
        guide, heading, n = ref
        block = self.parsed.get(guide, {}).get((heading, n))
        if block is None:
            raise LookupError(f"{GUIDES[guide].name}: no block {n} under {heading!r}")
        return block

    def all_refs(self):
        return {(guide, heading, n) for guide, found in self.parsed.items() for heading, n in found}


# --- Scenario: what the stub authority answers ------------------------------

def stamp(moment):
    """An RFC 3339 UTC timestamp with nanoseconds, the form the authority sends."""
    return moment.strftime("%Y-%m-%dT%H:%M:%S") + ".581346834Z"


def proof(expired=False, **changes):
    """The recorded proof, re-dated to be valid now (or expired an hour ago), with changes."""
    now = datetime.now(timezone.utc)
    issued = now - timedelta(hours=25 if expired else 1)
    result = copy.deepcopy(RECORDED["proof"]["body"]["proof"])
    result.update(issuedAt=stamp(issued), expiresAt=stamp(issued + timedelta(hours=24)))
    result.update(changes)
    return result


def recorded_proof():
    """The recorded proof as recorded, dates included."""
    return copy.deepcopy(RECORDED["proof"]["body"]["proof"])


def card(blocks, card_level=None, verify_at=None, expired=False, without_did=False,
         **proof_changes):
    """The guide's own agent card, its embedded proof re-dated to be valid now."""
    result = json.loads(blocks.get(CARD).body)
    embedded = result["atp"]["trustProof"]
    redated = proof(expired=expired)
    embedded.update(issuedAt=redated["issuedAt"], expiresAt=redated["expiresAt"])
    embedded.update(proof_changes)
    if card_level is not None:
        result["atp"]["trustLevel"] = card_level
    if verify_at is not None:
        result["atp"]["verifyAt"] = verify_at
    if without_did:
        del result["atp"]["did"]
    return result


def batch_result(did, level, verdict):
    return {"did": did, "trustLevel": level, "verdict": verdict}


def reply(name, **body_changes):
    recorded = RECORDED[name]
    body = copy.deepcopy(recorded["body"])
    body.update(body_changes)
    return recorded["status"], json.dumps(body, separators=(",", ":"))


def answer(scenario, method, url, data):
    """The stub authority: (status, body text), or None for a refused connection.
    A URL the scenario redirects is answered 301; location() names where to."""
    parts = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qs(parts.query)
    if parts.scheme != "https":
        return None
    if location(scenario, url) is not None:
        return 301, ""
    if parts.netloc == AUTHORITY and not scenario.get("unreachable"):
        route = (method, parts.path)
        if route == ("GET", "/api/v1/trust/proof"):
            found = scenario.get("proofs", {}).get(query.get("did", [""])[0])
            if found is None:
                return reply("proofNotFound")
            return reply("proof", proof=found)
        if route == ("POST", "/api/v1/trust/verify"):
            body = parse_json(data)
            if isinstance(body, dict) and body.get("did") and body.get("signatures"):
                return reply("verifyAccepted")
            return reply("verifyRejected")
        if route == ("POST", "/api/v1/trust/batch"):
            results = scenario.get("batch")
            if results is None:
                return reply("batchRejection")
            body = parse_json(data)
            agents = body.get("agents") if isinstance(body, dict) else None
            if not isinstance(agents, list):
                return 400, json.dumps({"error": "agents array is required"})
            asked = {agent.get("did") for agent in agents if isinstance(agent, dict)}
            answered = [result for result in results if result["did"] in asked]
            return reply("batchAnswerShape", results=answered, total=len(answered))
        if route == ("GET", "/api/v1/trust/revocations"):
            if not RFC3339.fullmatch(query.get("since", [""])[0]):
                return 400, json.dumps({"error": "since must be an RFC 3339 timestamp"})
            revoked_at = stamp(datetime.now(timezone.utc) - timedelta(minutes=30))
            entries = [
                {
                    "agentDid": did,
                    "revokedAt": revoked_at,
                    "reason": "security_incident",
                    "revokedByKeyId": "did:opena2a:registry:opena2a.org#key-1",
                }
                for did in scenario.get("revoked", [])
            ]
            return reply("revocations", revocations=entries)
        if route == ("GET", "/api/v1/trust/advisories"):
            if not DATE.fullmatch(query.get("since", [""])[0]):
                return reply("advisoriesBadSince")
            return reply("advisories")
        return 404, json.dumps({"error": "not found"})
    served = scenario.get("cards", {}).get(urllib.parse.urlunsplit(parts._replace(query="", fragment="")))
    if served is not None and method == "GET":
        return 200, json.dumps(served)
    return None


def parse_json(data):
    try:
        return json.loads(data)
    except (TypeError, ValueError):
        return None


def location(scenario, url):
    """The Location of the stub's answer to url: the same URL under http when
    url is https and the scenario lists it, without its query, under
    "redirect"; else None."""
    parts = urllib.parse.urlsplit(url)
    listed = urllib.parse.urlunsplit(parts._replace(query="", fragment=""))
    if parts.scheme == "https" and listed in scenario.get("redirect", ()):
        return urllib.parse.urlunsplit(parts._replace(scheme="http"))
    return None


def answer_from_env(method, url, data):
    """The stub's answer to one request of a guide block, from the case's
    scenario: (status, body text, Location or None), or None for a refused
    connection. The request is first appended to the case's request log."""
    scenario_file = Path(os.environ[SCENARIO_ENV])
    with scenario_file.with_name(REQUEST_LOG).open("a", encoding="utf-8") as log:
        log.write(f"{method} {url}\n")
    scenario = json.loads(scenario_file.read_text(encoding="utf-8"))
    result = answer(scenario, method, url, data)
    return None if result is None else (*result, location(scenario, url))


def exchange(method, url, data, follow):
    """One call of the HTTP client of a guide block: the stub's last answer, as
    answer_from_env gives it, and the URL that gave it (None and the refused
    URL for a refused connection). With follow, a redirect is followed as
    requests and fetch follow one by default: the request goes to the Location,
    a POST answered 301, 302 or 303 as a GET without its body. The stub
    redirects only to http URLs, which it refuses, so no chain loops."""
    while True:
        result = answer_from_env(method, url, data)
        if result is None or not follow or result[0] not in REDIRECT_STATUSES or not result[2]:
            return result, url
        if method == "POST" and result[0] in (301, 302, 303):
            method, data = "GET", ""
        url = urllib.parse.urljoin(url, result[2])


def requests_not_https(work):
    """The requests a case run in work sent to a URL that is not https, as the
    "METHOD URL" lines of its request log."""
    log = work / REQUEST_LOG
    sent = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
    return [line for line in sent if urllib.parse.urlsplit(line.partition(" ")[2]).scheme != "https"]


# --- Stubs for curl, requests and fetch -------------------------------------

def curl_main(argv):
    """A curl stand-in for the options the guides use; anything else is an error."""
    fail = silent = False
    method = data = out = write_out = url = None
    takes_value = {
        "-X": "method", "--request": "method", "-H": None, "--header": None,
        "-d": "data", "--data": "data", "-o": "out", "--output": "out",
        "-w": "write_out", "--write-out": "write_out", "-m": None, "--max-time": None,
    }
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in takes_value:
            if i + 1 >= len(argv):
                return curl_error(2, f"option {arg} needs a value")
            name = takes_value[arg]
            if name == "method":
                method = argv[i + 1]
            elif name == "data":
                data = argv[i + 1]
            elif name == "out":
                out = argv[i + 1]
            elif name == "write_out":
                write_out = argv[i + 1]
            i += 2
            continue
        if arg in ("--silent", "--fail", "--show-error"):
            fail = fail or arg == "--fail"
            silent = silent or arg == "--silent"
        elif re.fullmatch(r"-[sSf]+", arg):
            fail = fail or "f" in arg
            silent = silent or "s" in arg
        elif arg.startswith("-"):
            return curl_error(2, f"the guide check's curl stub does not support {arg}")
        else:
            url = arg
        i += 1
    if url is None:
        return curl_error(2, "no URL")
    if data is not None and data.startswith("@"):
        source = data[1:]
        raw = sys.stdin.read() if source == "-" else Path(source).read_text(encoding="utf-8")
        data = raw.replace("\r", "").replace("\n", "")
    method = method or ("POST" if data is not None else "GET")
    result = answer_from_env(method, url, data or "")
    if result is None:
        if write_out:
            sys.stdout.write(expand_write_out(write_out, 0))
        return curl_error(7, f"Failed to connect to {urllib.parse.urlsplit(url).netloc}", silent)
    status, text = result[:2]  # without -L, which the stub refuses, curl follows no redirect
    if fail and status >= 400:
        return curl_error(22, f"The requested URL returned error: {status}", silent)
    if out:
        Path(out).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    if write_out:
        sys.stdout.write(expand_write_out(write_out, status))
    return 0


def expand_write_out(template, status):
    text = template.replace("%{http_code}", f"{status:03d}").replace("\\n", "\n")
    if "%{" in text:
        raise SystemExit(f"curl stub: unsupported --write-out variable in {template!r}")
    return text


def curl_error(code, message, silent=False):
    if not silent or code == 2:
        sys.stderr.write(f"curl: ({code}) {message}\n")
    return code


REQUESTS_STUB = '''"""requests stand-in for the guide check: answers from the case scenario."""
import json as _json
import sys as _sys
import urllib.parse as _parse

_sys.path.insert(0, {scripts!r})
import check_guides as _guides  # noqa: E402


class RequestException(Exception):
    pass


class ConnectionError(RequestException):
    pass


class HTTPError(RequestException):
    pass


class Response:
    def __init__(self, url, status, text, location=None):
        self.url = url
        self.status_code = status
        self.text = text
        self.ok = status < 400
        self.headers = {{"Location": location}} if location else {{}}
        self.is_redirect = bool(location) and status in _guides.REDIRECT_STATUSES

    def json(self):
        return _json.loads(self.text)

    def raise_for_status(self):
        if self.status_code >= 400:
            raise HTTPError(f"{{self.status_code}} Error for url: {{self.url}}")


def request(method, url, params=None, json=None, data=None, headers=None, timeout=None,
            allow_redirects=True):
    if params:
        url += ("&" if "?" in url else "?") + _parse.urlencode(params)
    body = _json.dumps(json) if json is not None else (data or "")
    result, url = _guides.exchange(method, url, body, follow=allow_redirects)
    if result is None:
        raise ConnectionError(f"connection refused: {{url}}")
    return Response(url, *result)


def get(url, **kwargs):
    return request("GET", url, **kwargs)


def post(url, **kwargs):
    return request("POST", url, **kwargs)
'''

FETCH_STUB = '''import {{ execFileSync }} from "node:child_process";

globalThis.fetch = async (input, init = {{}}) => {{
  const method = (init.method || "GET").toUpperCase();
  const redirect = init.redirect || "follow";
  const out = execFileSync({python}, [{script}, "--answer", method, String(input), redirect], {{
    input: init.body ?? "",
  }});
  const result = JSON.parse(out.toString());
  if (result.refused) {{
    throw new TypeError(`fetch failed: connection refused: ${{result.url}}`);
  }}
  if (result.unexpectedRedirect) {{
    // What Node.js fetch throws for a redirect under redirect: "error"
    throw new TypeError("fetch failed", {{ cause: new Error("unexpected redirect") }});
  }}
  const headers = {{ "Content-Type": "application/json" }};
  if (result.location) headers.Location = result.location;
  return new Response(result.body, {{ status: result.status, headers }});
}};
'''


def answer_main(argv):
    """The fetch stub's call: the method, URL and redirect mode of a fetch, its
    body on stdin."""
    method, url, mode = argv
    result, url = exchange(method, url, sys.stdin.read(), follow=mode == "follow")
    if result is None:
        print(json.dumps({"refused": True, "url": url}))
    elif mode == "error" and result[0] in REDIRECT_STATUSES and result[2]:
        print(json.dumps({"unexpectedRedirect": True}))
    else:
        print(json.dumps({"status": result[0], "body": result[1], "location": result[2]}))
    return 0


# --- Cases ------------------------------------------------------------------

GATE = ("ci", "## The Trust Gate Script", 0)
BASIC = ("ci", "### Basic trust check", 0)
MATRIX = ("ci", "### Multiple agents with configurable threshold", 0)
BATCH = ("ci", "## Batch Verification Script", 0)
AGENTS = ("ci", "## Batch Verification Script", 1)
GITLAB = ("ci", "## GitLab CI", 0)
DOCKER = ("ci", "## Docker Build with Trust Verification", 0)
MONITOR = ("ci", "## Monitoring Trust Changes in CI", 0)
QUICK = ("mcp", "## Quick Check: cURL", 0)
QUICK_OUTPUT = ("mcp", "## Quick Check: cURL", 1)
MCP_PY = ("mcp", "## Python: Trust-Gated MCP Connection", 0)
MCP_TS = ("mcp", "## TypeScript: Trust-Gated MCP Connection", 0)
MCP_BATCH = ("mcp", "## Batch Check: Multiple MCP Servers", 0)
MCP_CONFIG = ("mcp", "## MCP Config with Trust Policy", 0)
TOOLS = ("mcp", "## Sensitive Tool Gating", 0)
CARD = ("a2a", "## A2A Agent Card with ATP Trust Proof", 0)
A2A_PY = ("a2a", "## Verification: Python", 0)
DELEGATE = ("a2a", "### Delegating with trust context", 0)
A2A_TS = ("a2a", "## Verification: TypeScript", 0)
A2A_CURL = ("a2a", "## Verification: cURL", 0)
REFRESH = ("a2a", "## Refreshing Trust Proofs", 0)
SPEC_PEER = ("spec", "### B.1 A2A Agent Verifying a Peer", 0)
SPEC_MCP = ("spec", "### B.2 MCP Client Checking Server Trust", 0)

GATE_FILE = {"scripts/atp-trust-gate.sh": GATE}
UNTRUSTED_VERIFIER = "https://verifier.example.net/always-valid"


@dataclass
class Case:
    name: str
    block: tuple
    expect_code: int
    expect: tuple = ()
    scenario: Callable = lambda blocks: {}
    args: tuple = ()
    env: dict = field(default_factory=dict)
    files: dict = field(default_factory=dict)
    step: int = 0
    shell: str = "bash"
    driver: str = ""
    expect_json: tuple = None
    reads: tuple = ()

    def refs(self):
        refs = {self.block, *self.files.values(), *self.reads}
        if self.expect_json:
            refs.add(self.expect_json)
        return refs


def at(level, verdict="passed", **changes):
    return proof(trustLevel=level, verdict=verdict, **changes)


# Appendix B calls functions the reader supplies; these stand in for them.
PEER_DRIVER = (
    "def reject_task(reason):\n"
    "    print('task rejected:', reason)\n\n\n"
    "def accept_task():\n"
    "    print('task accepted')\n\n\n"
    f"on_delegated_task({REQUESTER!r})\n"
)
MCP_DRIVER = (
    "class MCPClient {\n"
    "  constructor(url) {\n"
    "    console.log(`connected to ${url}`);\n"
    "  }\n"
    "}\n\n"
    "try {\n"
    "  await connectToServer(" + json.dumps(FS) + ', "https://mcp.example.com");\n'
    "} catch (error) {\n"
    "  const cause = error.cause ? ` (${error.cause.message})` : '';\n"
    "  console.log(`refused: ${error.message}${cause}`);\n"
    "}\n"
)
DELEGATE_DRIVER = (
    "import requests\n\n"
    "try:\n"
    "    delegate_task('https://weather.example.com', {'text': 'forecast'}, {})\n"
    "except requests.HTTPError as error:\n"
    "    print('delegation refused:', error)\n"
)
REFRESH_REDIRECT_DRIVER = (
    "def update_agent_card_proof(new_proof):\n"
    "    print('stored', new_proof)\n\n\n"
    "try:\n"
    f"    refresh_proof_periodically({FS!r})\n"
    "except requests.HTTPError as error:\n"
    "    print('refresh failed:', error)\n"
)


CASES = [
    # The trust gate script
    Case("gate: level 2 under threshold 3 refuses", GATE, 1,
         ("trust level 2, verdict listed", "below threshold 3"),
         lambda b: {"proofs": {FS: proof()}}, args=(FS, "3")),
    Case("gate: level 2 at threshold 2 passes", GATE, 0, ("Trust gate passed",),
         lambda b: {"proofs": {FS: proof()}}, args=(FS, "2")),
    Case("gate: string level refuses", GATE, 1, ("not an integer",),
         lambda b: {"proofs": {FS: proof(trustLevel="3")}}, args=(FS, "2")),
    Case("gate: null level refuses", GATE, 1, ("not an integer",),
         lambda b: {"proofs": {FS: proof(trustLevel=None)}}, args=(FS, "2")),
    Case("gate: blocked refuses", GATE, 1, ("blocked",),
         lambda b: {"proofs": {FS: at(0, "blocked")}}, args=(FS, "2")),
    Case("gate: level 3 blocked proof refuses", GATE, 1, ("blocked (verdict blocked)",),
         lambda b: {"proofs": {FS: at(3, "blocked")}}, args=(FS, "2")),
    Case("gate: expired proof refuses", GATE, 1, ("expired",),
         lambda b: {"proofs": {FS: proof(expired=True)}}, args=(FS, "2")),
    Case("gate: revoked agent refuses", GATE, 1, ("revoked",),
         lambda b: {"proofs": {FS: proof()}, "revoked": [FS]}, args=(FS, "2")),
    Case("gate: unknown agent refuses", GATE, 1, ("not in the registry",),
         lambda b: {}, args=(FS, "2")),
    Case("gate: unreachable authority exits 2", GATE, 2, ("could not reach",),
         lambda b: {"unreachable": True}, args=(FS, "2")),
    # GitHub and GitLab workflows around the gate
    Case("basic workflow: level 2 under threshold 3 fails the job", BASIC, 1,
         ("below threshold 3",), lambda b: {"proofs": {FS: proof()}},
         env={"DID": FS}, files=GATE_FILE),
    Case("basic workflow: level 3 passes", BASIC, 0, ("Trust gate passed",),
         lambda b: {"proofs": {FS: at(3)}}, env={"DID": FS}, files=GATE_FILE),
    Case("matrix workflow: level 2 under MIN_TRUST_LEVEL 3 fails", MATRIX, 1,
         ("below threshold 3",), lambda b: {"proofs": {FS: proof()}},
         env={"DID": FS, "MIN_TRUST_LEVEL": "3"}, files=GATE_FILE),
    Case("gitlab job: level 2 under threshold 3 fails", GITLAB, 1, ("below threshold 3",),
         lambda b: {"proofs": {FS: proof()}},
         env={"MCP_SERVER_NAME": "@modelcontextprotocol/server-filesystem"},
         files=GATE_FILE, shell="sh"),
    Case("docker workflow: a server under threshold stops the build", DOCKER, 1,
         ("below threshold 3",), lambda b: {"proofs": {FS: proof(), GH: at(3)}},
         files={**GATE_FILE, "mcp-config.json": MCP_CONFIG}),
    Case("docker workflow: every server at threshold passes", DOCKER, 0,
         ("Trust gate passed: " + FS, "Trust gate passed: " + GH),
         lambda b: {"proofs": {FS: at(3), GH: at(3)}},
         files={**GATE_FILE, "mcp-config.json": MCP_CONFIG}),
    Case("monitor: one refused agent fails the run", MONITOR, 1,
         ("Trust gate passed: " + FS, "below threshold 3", "not in the registry"),
         lambda b: {"proofs": {FS: at(3), GH: proof()}},
         files={**GATE_FILE, "agents.json": AGENTS}),
    Case("monitor: unreachable authority exits 2", MONITOR, 2, ("could not reach",),
         lambda b: {"unreachable": True}, files={**GATE_FILE, "agents.json": AGENTS}),
    Case("monitor: advisories are listed", MONITOR, 0,
         ("::warning::OA2A-2026-0002: NeMo Guardrails",), step=1),
    # Batch verification script
    Case("batch: authority rejecting the request exits 2", BATCH, 2,
         ("HTTP 400", "packages array is required"), args=("agents.json", "3"),
         files={"agents.json": AGENTS}),
    Case("batch: blocked and missing agents fail", BATCH, 1,
         ("PASS: " + FS, "FAIL: " + GH + " -- level 0", "FAIL: " + WEATHER + " -- no readable"),
         lambda b: {"batch": [batch_result(FS, 3, "passed"), batch_result(GH, 0, "blocked")]},
         args=("agents.json", "3"), files={"agents.json": AGENTS}),
    Case("batch: every agent at threshold passes", BATCH, 0,
         ("PASS: " + FS, "PASS: " + GH, "PASS: " + WEATHER),
         lambda b: {"batch": [batch_result(FS, 3, "passed"), batch_result(GH, 4, "verified"),
                              batch_result(WEATHER, 3, "passed")]},
         args=("agents.json", "3"), files={"agents.json": AGENTS}),
    Case("batch: revoked agent fails", BATCH, 1, ("FAIL: " + GH + " -- revoked",),
         lambda b: {"batch": [batch_result(FS, 3, "passed"), batch_result(GH, 4, "verified"),
                              batch_result(WEATHER, 3, "passed")], "revoked": [GH]},
         args=("agents.json", "3"), files={"agents.json": AGENTS}),
    Case("batch: string level fails", BATCH, 1, ("FAIL: " + FS + " -- no readable",),
         lambda b: {"batch": [batch_result(FS, "3", "passed"), batch_result(GH, 3, "passed"),
                              batch_result(WEATHER, 3, "passed")]},
         args=("agents.json", "3"), files={"agents.json": AGENTS}),
    # MCP guide
    Case("mcp quick check prints the documented example from the recorded proof", QUICK, 0,
         scenario=lambda b: {"proofs": {FS: recorded_proof()}}, expect_json=QUICK_OUTPUT),
    Case("mcp python: listed server connects", MCP_PY, 0, ("Safe to connect (trust level 2)",),
         lambda b: {"proofs": {FS: proof()}}),
    Case("mcp python: null level refuses", MCP_PY, 0,
         ("Connection refused: No readable trust level",),
         lambda b: {"proofs": {FS: proof(trustLevel=None)}}),
    Case("mcp python: blocked server refuses", MCP_PY, 0,
         ("Connection refused: BLOCKED: blocked",),
         lambda b: {"proofs": {FS: at(0, "blocked")}}),
    Case("mcp python: expired proof refuses", MCP_PY, 0,
         ("Connection refused: Trust proof expired",),
         lambda b: {"proofs": {FS: proof(expired=True)}}),
    Case("mcp python: unknown server refuses", MCP_PY, 0,
         ("Connection refused: Server not found in registry",)),
    Case("mcp typescript: listed server connects", MCP_TS, 0,
         ("Safe to connect (trust level 2)",), lambda b: {"proofs": {FS: proof()}}),
    Case("mcp typescript: string level refuses", MCP_TS, 0,
         ("Connection refused: No readable trust level",),
         lambda b: {"proofs": {FS: proof(trustLevel="3")}}),
    Case("mcp typescript: expired proof refuses", MCP_TS, 0,
         ("Connection refused: Trust proof expired",),
         lambda b: {"proofs": {FS: proof(expired=True)}}),
    Case("mcp python: a redirect is not followed", MCP_PY, 1,
         ("HTTPError", "ATP authority redirects to http://api.oa2a.org/api/v1/trust/proof?did="),
         lambda b: {"proofs": {FS: proof()}, "redirect": [PROOF_URL]}),
    Case("mcp typescript: a redirect is not followed", MCP_TS, 1,
         ("fetch failed", "unexpected redirect"),
         lambda b: {"proofs": {FS: proof()}, "redirect": [PROOF_URL]}),
    Case("mcp batch: answers matched by DID, missing server refused", MCP_BATCH, 0,
         ("@modelcontextprotocol/server-filesystem: OK (level 3)",
          "@modelcontextprotocol/server-github: OK (level 2)",
          "some-unknown-server: BLOCKED (level None)"),
         lambda b: {"batch": [batch_result(GH, 2, "listed"), batch_result(FS, 3, "passed")]}),
    Case("mcp batch: authority rejecting the request raises", MCP_BATCH, 1,
         ("HTTPError", "400")),
    Case("mcp batch: a redirect is not followed", MCP_BATCH, 1,
         ("HTTPError", "ATP authority redirects to http://api.oa2a.org/api/v1/trust/batch"),
         lambda b: {"redirect": [BATCH_URL]}),
    Case("mcp tool gating: an unread level allows no tool", TOOLS, 0, ("True False False",),
         driver='print(can_use_tool("read_file", 2), can_use_tool("write_file", 2),'
                ' can_use_tool("read_file", None))\n'),
    # A2A guide
    Case("a2a python: the guide's card is trusted", A2A_PY, 0,
         ("Agent trusted (level 3, score 0.82)",),
         lambda b: {"cards": {CARD_URL: card(b)}}, reads=(CARD,)),
    Case("a2a python: the level comes from the signed proof", A2A_PY, 0,
         ("Agent not trusted: Trust level 1 below minimum 3",),
         lambda b: {"cards": {CARD_URL: card(b, card_level=4, trustLevel=1)}}, reads=(CARD,)),
    Case("a2a python: the card's verifyAt is not followed", A2A_PY, 0,
         ("Agent not trusted: did and at least one signature are required",),
         lambda b: {"cards": {CARD_URL: card(b, verify_at=UNTRUSTED_VERIFIER, signatures=[])}},
         reads=(CARD,)),
    Case("a2a python: expired proof is not trusted", A2A_PY, 0,
         ("Agent not trusted: Trust proof expired",),
         lambda b: {"cards": {CARD_URL: card(b, expired=True)}}, reads=(CARD,)),
    Case("a2a python: a proof about another DID is not trusted", A2A_PY, 0,
         ("Agent not trusted: Trust proof is not about the agent the card names",),
         lambda b: {"cards": {CARD_URL: card(b, did=FS)}}, reads=(CARD,)),
    Case("a2a python: a card without atp.did is not trusted", A2A_PY, 0,
         ("Agent not trusted: Trust proof is not about the agent the card names",),
         lambda b: {"cards": {CARD_URL: card(b, without_did=True)}}, reads=(CARD,)),
    Case("a2a python: a redirect of the card request is not followed", A2A_PY, 1,
         ("HTTPError",
          "Agent card URL redirects to http://weather.example.com/.well-known/agent-card.json"),
         lambda b: {"cards": {CARD_URL: card(b)}, "redirect": [CARD_URL]}, reads=(CARD,)),
    Case("a2a python: a redirect of the verify request is not followed", A2A_PY, 0,
         ("Agent not trusted: Verifier redirects to http://api.oa2a.org/api/v1/trust/verify",),
         lambda b: {"cards": {CARD_URL: card(b)}, "redirect": [VERIFY_URL]}, reads=(CARD,)),
    Case("a2a python: delegate_task defines cleanly", DELEGATE, 0),
    Case("a2a python: delegate_task does not follow a redirect", DELEGATE, 0,
         ("delegation refused: https://weather.example.com redirects to "
          "http://weather.example.com/tasks/send",),
         lambda b: {"redirect": [TASKS_URL]}, driver=DELEGATE_DRIVER),
    Case("a2a typescript: the guide's card is trusted", A2A_TS, 0,
         ("Trusted: level 3, score 0.82",),
         lambda b: {"cards": {CARD_URL: card(b)}}, reads=(CARD,)),
    Case("a2a typescript: the level comes from the signed proof", A2A_TS, 0,
         ("Not trusted: Trust level 1 below minimum 3",),
         lambda b: {"cards": {CARD_URL: card(b, card_level=4, trustLevel=1)}}, reads=(CARD,)),
    Case("a2a typescript: the card's verifyAt is not followed", A2A_TS, 0,
         ("Not trusted: did and at least one signature are required",),
         lambda b: {"cards": {CARD_URL: card(b, verify_at=UNTRUSTED_VERIFIER, signatures=[])}},
         reads=(CARD,)),
    Case("a2a typescript: expired proof is not trusted", A2A_TS, 0,
         ("Not trusted: Trust proof expired",),
         lambda b: {"cards": {CARD_URL: card(b, expired=True)}}, reads=(CARD,)),
    Case("a2a typescript: a proof about another DID is not trusted", A2A_TS, 0,
         ("Not trusted: Trust proof is not about the agent the card names",),
         lambda b: {"cards": {CARD_URL: card(b, did=FS)}}, reads=(CARD,)),
    Case("a2a typescript: a card without atp.did is not trusted", A2A_TS, 0,
         ("Not trusted: Trust proof is not about the agent the card names",),
         lambda b: {"cards": {CARD_URL: card(b, without_did=True)}}, reads=(CARD,)),
    Case("a2a typescript: a redirect of the card request is not followed", A2A_TS, 1,
         ("fetch failed", "unexpected redirect"),
         lambda b: {"cards": {CARD_URL: card(b)}, "redirect": [CARD_URL]}, reads=(CARD,)),
    Case("a2a typescript: a redirect of the verify request is not followed", A2A_TS, 1,
         ("fetch failed", "unexpected redirect"),
         lambda b: {"cards": {CARD_URL: card(b)}, "redirect": [VERIFY_URL]}, reads=(CARD,)),
    Case("a2a curl: the card's proof verifies", A2A_CURL, 0, ('"valid": true',),
         lambda b: {"cards": {CARD_URL: card(b)}}, reads=(CARD,)),
    Case("a2a refresh: the stored proof is what verify accepts", REFRESH, 0, ("valid True",),
         lambda b: {"proofs": {FS: proof()}},
         driver=(
             "CARD = {}\n\n\n"
             "def update_agent_card_proof(new_proof):\n"
             "    CARD['trustProof'] = new_proof\n\n\n"
             f"refresh_proof_periodically({FS!r})\n"
             "check = requests.post('https://api.oa2a.org/api/v1/trust/verify',"
             " json=CARD['trustProof'], timeout=10).json()\n"
             "print('valid', check.get('valid'), check.get('error', ''))\n"
         )),
    Case("a2a refresh: a redirect is not followed", REFRESH, 0,
         ("refresh failed: ATP authority redirects to http://api.oa2a.org/api/v1/trust/proof?did=",),
         lambda b: {"proofs": {FS: proof()}, "redirect": [PROOF_URL]},
         driver=REFRESH_REDIRECT_DRIVER),
    # ATP-SPEC.md Appendix B
    Case("spec b.1: level 3 peer is accepted", SPEC_PEER, 0, ("task accepted",),
         lambda b: {"proofs": {REQUESTER: at(3, did=REQUESTER)}}, driver=PEER_DRIVER),
    Case("spec b.1: level 2 peer is rejected", SPEC_PEER, 0,
         ("task rejected: Insufficient trust: level 2, require 3+",),
         lambda b: {"proofs": {REQUESTER: proof(did=REQUESTER)}}, driver=PEER_DRIVER),
    Case("spec b.1: expired proof is rejected", SPEC_PEER, 0,
         ("task rejected: Trust proof verification failed",),
         lambda b: {"proofs": {REQUESTER: at(3, did=REQUESTER, expired=True)}},
         driver=PEER_DRIVER),
    Case("spec b.1: proof about another DID is rejected", SPEC_PEER, 0,
         ("task rejected: Trust proof verification failed",),
         lambda b: {"proofs": {REQUESTER: at(3)}}, driver=PEER_DRIVER),
    Case("spec b.1: string level is rejected", SPEC_PEER, 0,
         ("task rejected: Trust proof verification failed",),
         lambda b: {"proofs": {REQUESTER: at("3", did=REQUESTER)}}, driver=PEER_DRIVER),
    Case("spec b.1: proof the authority refuses is rejected", SPEC_PEER, 0,
         ("task rejected: Trust proof verification failed",),
         lambda b: {"proofs": {REQUESTER: at(3, did=REQUESTER, signatures=[])}},
         driver=PEER_DRIVER),
    Case("spec b.1: unknown peer is rejected", SPEC_PEER, 0,
         ("task rejected: Trust proof verification failed",), driver=PEER_DRIVER),
    Case("spec b.1: a redirect of the proof request is not followed", SPEC_PEER, 0,
         ("task rejected: Trust proof verification failed",),
         lambda b: {"proofs": {REQUESTER: at(3, did=REQUESTER)}, "redirect": [PROOF_URL]},
         driver=PEER_DRIVER),
    Case("spec b.1: a redirect of the verify request is not followed", SPEC_PEER, 0,
         ("task rejected: Trust proof verification failed",),
         lambda b: {"proofs": {REQUESTER: at(3, did=REQUESTER)}, "redirect": [VERIFY_URL]},
         driver=PEER_DRIVER),
    Case("spec b.2: listed server connects", SPEC_MCP, 0,
         ("connected to https://mcp.example.com",),
         lambda b: {"proofs": {FS: proof()}}, driver=MCP_DRIVER),
    Case("spec b.2: blocked server is refused", SPEC_MCP, 0, ("refused: BLOCKED: blocked",),
         lambda b: {"proofs": {FS: at(0, "blocked")}}, driver=MCP_DRIVER),
    Case("spec b.2: expired proof is refused", SPEC_MCP, 0,
         ("refused: MCP server trust proof invalid",),
         lambda b: {"proofs": {FS: proof(expired=True)}}, driver=MCP_DRIVER),
    Case("spec b.2: proof about another DID is refused", SPEC_MCP, 0,
         ("refused: MCP server trust proof invalid",),
         lambda b: {"proofs": {FS: at(3, did=GH)}}, driver=MCP_DRIVER),
    Case("spec b.2: null level is refused", SPEC_MCP, 0,
         ("refused: MCP server trust proof invalid",),
         lambda b: {"proofs": {FS: proof(trustLevel=None)}}, driver=MCP_DRIVER),
    Case("spec b.2: unknown server is refused", SPEC_MCP, 0,
         ("refused: MCP server trust proof invalid",), driver=MCP_DRIVER),
    Case("spec b.2: a redirect of the proof request is not followed", SPEC_MCP, 0,
         ("refused: fetch failed (unexpected redirect)",),
         lambda b: {"proofs": {FS: proof()}, "redirect": [PROOF_URL]}, driver=MCP_DRIVER),
    Case("spec b.2: a redirect of the verify request is not followed", SPEC_MCP, 0,
         ("refused: fetch failed (unexpected redirect)",),
         lambda b: {"proofs": {FS: proof()}, "redirect": [VERIFY_URL]}, driver=MCP_DRIVER),
]


# --- Runner -----------------------------------------------------------------

def node_command():
    node = shutil.which("node")
    if node is None:
        return None, "node not found; the TypeScript blocks need Node.js 22.6 or later"
    version = subprocess.run([node, "--version"], capture_output=True, text=True).stdout.strip()
    numbers = tuple(int(part) for part in re.findall(r"\d+", version)[:2])
    if numbers < (22, 6):
        return None, f"node {version} found; the TypeScript blocks need Node.js 22.6 or later"
    flags = ["--disable-warning=ExperimentalWarning"]
    if numbers < (23, 6):
        flags.insert(0, "--experimental-strip-types")
    return [node, *flags], None


def command_for(case, block, work, node):
    if block.lang == "bash":
        (work / "block.sh").write_text(block.body, encoding="utf-8")
        return ["bash", "block.sh", *case.args]
    if block.lang == "yaml":
        steps = shell_steps(block.body)
        if case.step >= len(steps):
            raise LookupError(f"the workflow has {len(steps)} shell steps, no step {case.step}")
        (work / "step.sh").write_text(steps[case.step], encoding="utf-8")
        return ["bash", "-e", "step.sh"] if case.shell == "bash" else ["sh", "-e", "step.sh"]
    if block.lang == "python":
        (work / "requests.py").write_text(REQUESTS_STUB.format(scripts=str(SCRIPTS)), encoding="utf-8")
        (work / "block.py").write_text(block.body + "\n" + case.driver, encoding="utf-8")
        return [sys.executable, "-B", "block.py"]
    if block.lang == "typescript":
        if node[0] is None:
            raise LookupError(node[1])
        stub = FETCH_STUB.format(python=json.dumps(sys.executable),
                                 script=json.dumps(str(Path(__file__).resolve())))
        (work / "block.mts").write_text(stub + "\n" + block.body + "\n" + case.driver, encoding="utf-8")
        return [*node[0], "block.mts"]
    raise LookupError(f"no runner for a {block.lang or 'plain'} block")


def run_case(case, blocks, root, node):
    work = Path(tempfile.mkdtemp(dir=root))
    try:
        block = blocks.get(case.block)
        for name, ref in case.files.items():
            target = work / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(blocks.get(ref).body, encoding="utf-8")
        scenario = work / ".scenario.json"
        scenario.write_text(json.dumps(case.scenario(blocks)), encoding="utf-8")
        command = command_for(case, block, work, node)
    except LookupError as error:
        return [f"{case.name}: {error}"]
    env = {key: os.environ[key] for key in ("HOME", "TMPDIR", "LANG", "LC_ALL") if key in os.environ}
    env.update(case.env)
    env["PATH"] = str(root / "bin") + os.pathsep + os.environ.get("PATH", "")
    env[SCENARIO_ENV] = str(scenario)
    try:
        run = subprocess.run(command, cwd=work, env=env, capture_output=True, text=True,
                             timeout=TIMEOUT, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return [f"{case.name}: no exit within {TIMEOUT}s"]
    output = run.stdout + run.stderr
    errors = []
    if run.returncode != case.expect_code:
        errors.append(f"exit {run.returncode}, expected {case.expect_code}")
    errors += [f"output lacks {text!r}" for text in case.expect if text not in output]
    errors += [
        f"sent {line}, a request to a URL that is not https (ATP-SPEC Section 7.1)"
        for line in requests_not_https(work)
    ]
    if case.expect_json:
        expected = json.loads(blocks.get(case.expect_json).body)
        printed = parse_json(run.stdout)
        if printed != expected:
            errors.append(f"printed {run.stdout.strip()!r}, the guide shows {expected!r}")
    if errors:
        excerpt = "\n".join("      | " + line for line in output.strip().splitlines()[-12:])
        return [f"{case.name}: {'; '.join(errors)}\n{excerpt}"]
    return []


def guide_texts():
    texts = {key: path.read_text(encoding="utf-8") for key, path in GUIDES.items()}
    texts["spec"] = spec_examples(texts["spec"])
    return texts


def spec_examples(text):
    """The text of Appendix B.1 and B.2, the specification's runnable examples
    (empty when B.1 is missing, so its cases fail on the missing block)."""
    first, after = SPEC_EXAMPLES
    start = text.find(first)
    if start < 0:
        return ""
    end = text.find(after, start)
    return text[start + 1:] if end < 0 else text[start + 1:end + 1]


def unchecked_blocks(texts):
    """An error line for each guide block that no case runs or reads."""
    used = set().union(*(case.refs() for case in CASES))
    return [
        f"{GUIDES[guide].name}: block {n} under {heading!r} is run by no case"
        for guide, heading, n in sorted(Blocks(texts).all_refs() - used, key=str)
    ]


BATCH_SECTIONS = (BATCH, MCP_BATCH)
BATCH_REFUSAL = "HTTP 400"


def section_prose(text, heading):
    """The lines under the heading line `heading`, up to the next heading of
    its level or a higher one, without fenced code blocks ("" when the heading
    is not there)."""
    level = len(heading) - len(heading.lstrip("#"))
    lines = text.splitlines()
    if heading not in lines:
        return ""
    prose = []
    fence = None
    for line in lines[lines.index(heading) + 1:]:
        if fence is not None:
            if fence.fullmatch(line.strip()):
                fence = None
            continue
        opening = re.match(r"^(`{3,}|~{3,})\s*([\w+-]*)\s*$", line)
        if opening:
            fence = re.compile(re.escape(opening.group(1)[0]) + "{%d,}" % len(opening.group(1)))
            continue
        found = re.match(r"^(#{1,6}) ", line)
        if found and len(found.group(1)) <= level:
            break
        prose.append(line)
    return "\n".join(prose)


def batch_note_errors(texts, recorded=RECORDED):
    """An error line for each batch section that does not say the reference
    authority answers the Section 7.2 body with HTTP 400 while the recorded
    responses hold that refusal, or that still says so once they do not."""
    refused = "batchRejection" in recorded
    errors = []
    for guide, heading, _ in BATCH_SECTIONS:
        states = BATCH_REFUSAL in section_prose(texts[guide], heading)
        if refused and not states:
            errors.append(
                f"{GUIDES[guide].name}: {heading!r} does not say that the reference authority "
                f"answers the Section 7.2 body with {BATCH_REFUSAL} (batchRejection in "
                "scripts/guide_responses.json)"
            )
        elif states and not refused:
            errors.append(
                f"{GUIDES[guide].name}: {heading!r} says the reference authority answers the "
                f"Section 7.2 body with {BATCH_REFUSAL}, which no recorded response in "
                "scripts/guide_responses.json shows"
            )
    return errors


def run(texts=None, select=None, workers=4):
    """Run the cases (those `select` accepts, or all); return the error lines.
    The checks for blocks no case uses and for the batch sections' statement
    of the recorded refusal run only with every case."""
    if texts is None:
        texts = guide_texts()
    blocks = Blocks(texts)
    cases = [case for case in CASES if select is None or select(case)]
    errors = unchecked_blocks(texts) + batch_note_errors(texts) if select is None else []
    node = node_command()
    with tempfile.TemporaryDirectory(prefix="atp-guides-") as tmp:
        root = Path(tmp)
        (root / "bin").mkdir()
        curl = root / "bin" / "curl"
        curl.write_text(
            f"#!/bin/sh\nexec {json.dumps(sys.executable)} -B "
            f"{json.dumps(str(Path(__file__).resolve()))} --curl \"$@\"\n",
            encoding="utf-8",
        )
        curl.chmod(0o755)
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for result in pool.map(lambda case: run_case(case, blocks, root, node), cases):
                errors += result
    return errors


def main(argv):
    if argv[:1] == ["--curl"]:
        return curl_main(argv[1:])
    if argv[:1] == ["--answer"]:
        return answer_main(argv[1:])
    errors = run()
    if errors:
        for error in errors:
            print(f"guides FAIL  {error}")
        return 1
    print(f"guides OK  {len(CASES)} cases run against recorded responses")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
