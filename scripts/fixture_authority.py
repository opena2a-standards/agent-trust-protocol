#!/usr/bin/env python3
"""A fixture ATP authority for testing conformance/level1.sh and level2.sh.

It serves the specification's own examples: the Section 7.1 discovery
document, the Section 3.2 DID document, the Section 4.2 trust proof (issued
for the requested DID, re-dated to the current time so it has not expired), a
verification result, the Section 5.1 log entry, and the Section 8.1
revocation response.

`overrides` changes what one endpoint serves, so a test can remove or corrupt
one member and expect the test that checks it to fail. Keys are the endpoint
names below; a value is a function that edits the example in place, a string
served as the body, or an integer HTTP status served with an empty body.
`requests` lists the method and path of every request received.

Run: python3 scripts/fixture_authority.py [port]. It exits 1 with one error
line when ATP-SPEC.md is not UTF-8, lacks one of the examples or holds one
that is not JSON, when the port is not a number from 0 to 65535, and when it
cannot listen on the port, as when another process holds it.
"""
import copy
import json
import sys
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))

import validate_examples  # noqa: E402

SPEC = validate_examples.ROOT / "ATP-SPEC.md"
EXAMPLES = {
    "discovery": "### 7.1 Well-Known Endpoint",
    "did": "### 3.2 DID Document",
    "proof": "### 4.2 Trust Proof Format",
    "log": "### 5.1 Structure",
    "revocations": "### 8.1 Trust Proof Revocation",
}


def timestamp(when: datetime) -> str:
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


class CannotServe(Exception):
    """The fixture authority cannot start. The message is one line that names
    what stops it: ATP-SPEC.md and the example it lacks or holds as a block
    that is not JSON, or the port, which is not a number from 0 to 65535 or
    which it cannot listen on."""


def spec_examples() -> dict:
    """The example each endpoint serves, keyed by endpoint name. Raises
    CannotServe when ATP-SPEC.md is not UTF-8, lacks one of the headings or
    its ```json block, or holds a block that is not JSON."""
    examples = {}
    for name, heading in EXAMPLES.items():
        try:
            examples[name] = json.loads(validate_examples.extract_block(SPEC, heading))
        except validate_examples.NoExample as exc:
            raise CannotServe(f"ATP-SPEC.md: {exc}") from None
        except json.JSONDecodeError as exc:
            raise CannotServe(
                f"ATP-SPEC.md: the ```json block after {heading!r} is not JSON: {exc}"
            ) from None
    return examples


class FixtureAuthority(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port: int = 0):
        # Read first, so a specification without an example leaves no socket open.
        examples = spec_examples()
        try:
            super().__init__(("127.0.0.1", port), Handler)
        except OSError as exc:
            raise CannotServe(f"port {port}: {exc.strerror or exc}") from None
        self.examples = examples
        self.overrides = {}
        self.requests = []
        self.url = f"http://127.0.0.1:{self.server_address[1]}"

    def body(self, endpoint: str, query: dict):
        if endpoint == "verify":
            body = {"valid": True}
        elif endpoint == "log":
            body = {"entries": [copy.deepcopy(self.examples["log"])]}
        else:
            body = copy.deepcopy(self.examples[endpoint])
        did = query.get("did", [""])[0]
        if endpoint == "proof":
            now = datetime.now(timezone.utc).replace(microsecond=0)
            body.update(did=did, issuedAt=timestamp(now - timedelta(hours=1)),
                        expiresAt=timestamp(now + timedelta(hours=17)))
        override = self.overrides.get(endpoint)
        if isinstance(override, int):
            return override, ""
        if isinstance(override, str):
            return 200, override
        if override is not None:
            override(body)
        return 200, json.dumps(body)


class Handler(BaseHTTPRequestHandler):
    ROUTES = {
        "/.well-known/atp": "discovery",
        "/api/v1/trust/proof": "proof",
        "/api/v1/transparency/trust-proofs": "log",
        "/api/v1/trust/revocations": "revocations",
    }

    def respond(self, endpoint):
        self.server.requests.append(f"{self.command} {self.path}")
        if endpoint is None:
            status, body = 404, ""
        else:
            status, body = self.server.body(endpoint, parse_qs(urlsplit(self.path).query))
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path.startswith("/api/v1/did/"):
            self.respond("did")
        else:
            self.respond(self.ROUTES.get(path))

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        path = urlsplit(self.path).path
        self.respond("verify" if path == "/api/v1/trust/verify" else None)

    def log_message(self, format, *args):
        pass


def serve(port: int = 0) -> FixtureAuthority:
    """Start a fixture authority on a background thread; call shutdown() when done."""
    authority = FixtureAuthority(port)
    threading.Thread(target=authority.serve_forever, daemon=True).start()
    return authority


def port_number(text: str) -> int:
    """The port a command-line argument names. Raises CannotServe when it is
    not a number from 0 to 65535."""
    try:
        port = int(text)
    except ValueError:
        # Not a number, or one with more digits than int() reads.
        port = -1
    if not 0 <= port <= 65535:
        raise CannotServe(
            f"port {text!r} is not a number from 0 to 65535; "
            "run: python3 scripts/fixture_authority.py [port]"
        )
    return port


if __name__ == "__main__":
    try:
        authority = FixtureAuthority(port_number(sys.argv[1] if len(sys.argv) > 1 else "8080"))
    except CannotServe as exc:
        sys.exit(f"error: {exc}")
    print(f"fixture authority at {authority.url}")
    authority.serve_forever()
