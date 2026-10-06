#!/usr/bin/env python3
"""Validate the spec's inline JSON examples against the repo's JSON Schemas.

Reads schemas/examples-map.json, a list of entries:
    { "file": "core.md",
      "heading": "### 1.1 ATX schema",
      "schema": "schemas/atx-credential-v1.1.schema.json" }

For each entry: find the heading line in the file, take the first fenced
```json block after it, parse it, and validate it against the schema.
Also metaschema-checks every schemas/*.schema.json.

Formats (date-time, uuid) are treated as annotations, not assertions, matching
library defaults across implementations; structural keywords (type, enum,
pattern, required) carry the contract.

A rule JSON Schema cannot express runs after a schema-valid example: a trust
proof example must declare a validity window a verifier accepts (Section 4.4
step 5, the Section 10.2 24-hour maximum).

The revocation schema's `reason` is checked against the Section 8.1.1 registry:
its codes are the table's, and free text is refused.

Exit code 0 = all schemas well-formed and all mapped examples valid.
"""

import json
import pathlib
import sys
from datetime import datetime, timedelta

try:
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
except ImportError:
    print("error: the 'jsonschema' package is required (pip install jsonschema)")
    sys.exit(2)

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Section 10.2: a trust proof is valid for at most 24 hours, which a verifier
# enforces as Section 4.4 step 5 with no skew tolerance.
MAX_PROOF_WINDOW = timedelta(hours=24)


def trust_proof_window_errors(proof: dict) -> list[str]:
    """Section 4.4 step 5: issuedAt before expiresAt, and expiresAt no more
    than the Section 10.2 maximum after issuedAt."""
    try:
        issued = datetime.fromisoformat(proof["issuedAt"].replace("Z", "+00:00"))
        expires = datetime.fromisoformat(proof["expiresAt"].replace("Z", "+00:00"))
        window = expires - issued
    except (KeyError, AttributeError, TypeError, ValueError) as exc:
        return [f"issuedAt/expiresAt are not comparable RFC 3339 timestamps: {exc}"]
    if window <= timedelta(0):
        return [f"issuedAt {proof['issuedAt']} is not before expiresAt {proof['expiresAt']}"]
    if window > MAX_PROOF_WINDOW:
        return [
            f"validity window {window} (issuedAt {proof['issuedAt']}, expiresAt "
            f"{proof['expiresAt']}) exceeds the Section 10.2 maximum of 24 hours"
        ]
    return []


# Checks a schema cannot express, keyed by the schema an example is mapped to.
SEMANTIC_CHECKS = {
    "schemas/trust-proof-v1.schema.json": trust_proof_window_errors,
}

# Section 8.1.1: values the revocation schema must refuse as a `reason`: the
# pre-1.1 example's prose, operator text, an unregistered bare code, and
# malformed private-use codes.
NOT_A_REASON = [
    "Supply chain compromise detected",
    "Revoked by J. Smith after a customer call",
    "",
    "supply_chain_compromise",
    "x-",
    "x-with space",
    "X-UPPER",
    "x-" + "a" * 33,
]


def revocation_reason_errors() -> list[str]:
    """Section 8.1.1: the revocation schema's `reason` admits the registered
    codes and the private-use grammar, and no free text."""
    schema = json.loads(
        (ROOT / "schemas" / "revocation-list-v1.schema.json").read_text(encoding="utf-8")
    )
    reason = schema["properties"]["revocations"]["items"]["properties"]["reason"]
    validator = Draft202012Validator(reason)
    errors = [
        f"reason {value!r} is accepted; Section 8.1.1 admits no free text"
        for value in NOT_A_REASON
        if validator.is_valid(value)
    ]
    if not validator.is_valid("x-private_use"):
        errors.append("private-use reason 'x-private_use' is refused")
    registry = ROOT / "registries" / "revocation-reasons.json"
    if not registry.is_file():
        return errors + [f"{registry.relative_to(ROOT)} is missing (run scripts/gen_registries.py)"]
    registered = [row["Reason"] for row in json.loads(registry.read_text(encoding="utf-8"))["rows"]]
    codes = next((branch["enum"] for branch in reason.get("anyOf", []) if "enum" in branch), [])
    if sorted(codes) != sorted(registered):
        errors.append(
            f"schema codes {sorted(codes)} differ from the Section 8.1.1 table {sorted(registered)}"
        )
    return errors


def local_registry() -> Registry:
    """Every repo schema, keyed by its $id, so cross-schema $refs (e.g. the
    inclusion/consistency proofs embedding signed-tree-head-v1) resolve
    locally — never over the network."""
    resources = []
    for sf in sorted((ROOT / "schemas").glob("*.schema.json")):
        doc = json.loads(sf.read_text(encoding="utf-8"))
        if "$id" in doc:
            resources.append((doc["$id"], Resource.from_contents(doc)))
    return Registry().with_resources(resources)


def extract_block(md_path: pathlib.Path, heading: str) -> str:
    lines = md_path.read_text(encoding="utf-8").splitlines()
    try:
        start = next(i for i, l in enumerate(lines) if l.strip() == heading)
    except StopIteration:
        raise SystemExit(f"error: heading {heading!r} not found in {md_path}")
    in_block = False
    block: list[str] = []
    for line in lines[start + 1:]:
        if not in_block and line.strip() == "```json":
            in_block = True
            continue
        if in_block:
            if line.strip() == "```":
                return "\n".join(block)
            block.append(line)
        elif line.startswith("#") and not block:
            raise SystemExit(
                f"error: no ```json block between {heading!r} and the next heading in {md_path}"
            )
    raise SystemExit(f"error: unterminated ```json block after {heading!r} in {md_path}")


def main() -> int:
    failures = 0

    schema_files = sorted((ROOT / "schemas").glob("*.schema.json"))
    if not schema_files:
        print("error: no schemas/*.schema.json found")
        return 1
    for sf in schema_files:
        schema = json.loads(sf.read_text(encoding="utf-8"))
        try:
            Draft202012Validator.check_schema(schema)
            print(f"schema OK      {sf.relative_to(ROOT)}")
        except Exception as exc:  # noqa: BLE001 - report and fail
            print(f"schema INVALID {sf.relative_to(ROOT)}: {exc}")
            failures += 1

    reason_errors = revocation_reason_errors()
    if reason_errors:
        print("reasons FAIL   schemas/revocation-list-v1.schema.json vs Section 8.1.1")
        for err in reason_errors:
            print(f"    {err}")
        failures += 1
    else:
        print("reasons OK     schemas/revocation-list-v1.schema.json vs Section 8.1.1")

    map_path = ROOT / "schemas" / "examples-map.json"
    entries = json.loads(map_path.read_text(encoding="utf-8")) if map_path.exists() else []
    for entry in entries:
        md = ROOT / entry["file"]
        schema_path = ROOT / entry["schema"]
        raw = extract_block(md, entry["heading"])
        try:
            instance = json.loads(raw)
        except json.JSONDecodeError as exc:
            print(f"example INVALID JSON  {entry['file']} @ {entry['heading']!r}: {exc}")
            failures += 1
            continue
        validator = Draft202012Validator(
            json.loads(schema_path.read_text(encoding="utf-8")), registry=local_registry()
        )
        errors = [
            f"{err.json_path}: {err.message}"
            for err in sorted(validator.iter_errors(instance), key=lambda e: e.json_path)
        ]
        if not errors and entry["schema"] in SEMANTIC_CHECKS:
            errors = [f"$: {msg}" for msg in SEMANTIC_CHECKS[entry["schema"]](instance)]
        if errors:
            print(f"example FAIL   {entry['file']} @ {entry['heading']!r} vs {entry['schema']}")
            for err in errors:
                print(f"    {err}")
            failures += 1
        else:
            print(f"example OK     {entry['file']} @ {entry['heading']!r}")

    if failures:
        print(f"\n{failures} failure(s)")
        return 1
    print("\nall schemas and mapped examples valid")
    return 0


if __name__ == "__main__":
    sys.exit(main())
