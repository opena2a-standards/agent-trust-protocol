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

Run: python3 scripts/fixture_authority.py [port]
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


class FixtureAuthority(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port: int = 0):
        super().__init__(("127.0.0.1", port), Handler)
        self.examples = {
            name: json.loads(validate_examples.extract_block(SPEC, heading))
            for name, heading in EXAMPLES.items()
        }
        self.overrides = {}
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


if __name__ == "__main__":
    authority = FixtureAuthority(int(sys.argv[1]) if len(sys.argv) > 1 else 8080)
    print(f"fixture authority at {authority.url}")
    authority.serve_forever()
