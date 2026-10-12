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

The revocation schema admits an entry without `transparencyLogIndex` (Section
8.1: an identity revoked before the authority logged anything for it), refuses
an index that is not an integer >= 0, and requires every other entry member.

Every defense in the Section 10.1 threat model table cites the section that
defines it, and that section is a numbered heading of ATP-SPEC.md, so the table
cannot list a defense the specification never defines.

The Section 4.3 table of served timestamps gives, for each, the form the
canonical string carries (UTC, whole seconds with fractional seconds dropped,
`Z` suffix), and includes a served timestamp with fractional seconds, so the
string a verifier builds from a served proof is the one the authority signed.

Every command in a README.md code block that requests a well-known URI
requests the Section 7.1 normative path `/.well-known/atp`; the legacy
`/.well-known/opena2a` may be named in a comment only.

The README states signing as Section 4.3 does: Ed25519 is required and ML-DSA-65
is the second signature of the optional hybrid mode, so a README sentence that
names ML-DSA-65 also names hybrid mode. A prose sentence may wrap across lines;
the lines of a paragraph are joined before it is split into sentences. Lines of
a ```json block are wire data, such as a sample response's algorithm name, and
are not sentences; lines of other code blocks are checked one by one.

A README line that links ATP-SPEC.md and names a version names the version in
the specification's `**Version:**` header.

The reference implementation's source is not public, so README.md and ATP-SPEC.md
link to no repository an anonymous reader cannot open, and every Appendix A row
maps its component to a public endpoint of the reference authority (an `/api/` or
`/.well-known/` path) instead of a source file.

A sentence of ATP-SPEC.md saying "Section N shows `field` in its example" names
only members of that section's JSON example, and every media type Section 11
names is the Content-Type of a request or response elsewhere in the spec.

Federation (Section 6) is what makes a trust response decentralized, and no
second authority co-signs proofs yet, so a README.md or ATP-SPEC.md paragraph
that calls ATP or its response decentralized also says federation is not yet
demonstrated. Headings and table rows naming the Level 3 conformance level, and
"Decentralized Identifier", are not claims.

A code block opens on a line of three or more backticks or tildes and closes
only on a line of the same character at least as long, as in CommonMark, so a
fence inside a longer fence does not flip prose and code for the rest of the
README.

The README ATX table lists the fields of the Section 4.6 schema table with the
same status, the example file carries every ATX v1.1 field, the trust-proof
schema describes an ATX v1.1 member as ATX v1.1, and none of the three labels
a v1.1 field "Proposed" (the status Section 4.6 retired).

Section 2.1 lists the requirements no fixture covers yet and says that list is
authoritative: the suite's `notCovered` list can lag it. The suite's
revocation-list-valid fixture carries a free-text `reason` from before the
Section 8.1.1 codes, which the revocation schema refuses and a client processes
as `unspecified`, so every prose sentence in ATP-SPEC.md or the README, and
every sentence of the revocation schema's description, that cites the fixture
names Section 8.1.1.

Exit code 0 = all schemas well-formed and all mapped examples valid.
"""

import json
import pathlib
import re
import sys
from bisect import bisect_right
from datetime import datetime, timedelta, timezone

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


# Section 8.1: an entry for an agent the authority logged nothing for. It has
# no transparencyLogIndex and is still a revocation every client applies.
UNLOGGED_REVOCATION = {
    "agentDid": "did:opena2a:agent:revoked_before_first_proof",
    "revokedAt": "2026-03-22T15:00:00Z",
    "reason": "security_incident",
    "revokedByKeyId": "did:opena2a:authority:opena2a.org#key-v3",
}


def revocation_index_errors(schema: dict | None = None) -> list[str]:
    """Section 8.1: `transparencyLogIndex` is OPTIONAL per entry. A schema that
    refused an entry without it would have a client drop the revocation and
    keep the agent trusted. When present it is a log index, and the other
    entry members stay required."""
    if schema is None:
        schema = json.loads(
            (ROOT / "schemas" / "revocation-list-v1.schema.json").read_text(encoding="utf-8")
        )
    validator = Draft202012Validator(schema)

    def accepts(entry: dict) -> bool:
        return validator.is_valid({"revocations": [entry], "nextSince": "2026-03-22T15:00:00Z"})

    errors = []
    if not accepts(UNLOGGED_REVOCATION):
        errors.append("an entry without transparencyLogIndex is refused; Section 8.1 makes it OPTIONAL")
    for index in (0, 1847300):
        if not accepts({**UNLOGGED_REVOCATION, "transparencyLogIndex": index}):
            errors.append(f"an entry with transparencyLogIndex {index} is refused")
    # One probe per JSON value that is not an integer >= 0: a negative integer,
    # a number, a string, null, a boolean, an array and an object.
    for index in (-1, 1.5, "1847300", None, True, [], {}):
        if accepts({**UNLOGGED_REVOCATION, "transparencyLogIndex": index}):
            errors.append(f"transparencyLogIndex {index!r} is accepted; it is an integer >= 0")
    for member in UNLOGGED_REVOCATION:
        if accepts({k: v for k, v in UNLOGGED_REVOCATION.items() if k != member}):
            errors.append(f"an entry without {member} is accepted; Section 8.1 requires it")
    return errors


WELL_KNOWN = re.compile(r"/\.well-known/([A-Za-z0-9._-]+)")
FENCE = re.compile(r"^\s*(`{3,}|~{3,})(.*)$")
SPEC_VERSION = re.compile(r"^\*\*Version:\*\*\s*(\S+)\s*$", re.MULTILINE)
VERSION = re.compile(r"\bv?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)\b")
# A line that starts a new Markdown block, so it never continues the paragraph
# above it: a heading, list item, table row or block quote.
BLOCK_START = re.compile(r"^\s*(#{1,6}\s|[-*+]\s|\d+[.)]\s|\||>)")
SENTENCE_BREAK = re.compile(r"(?<=[.!?])\s+")
# "decentralized" as a claim about ATP; "Decentralized Identifier(s)" names DIDs.
DECENTRALIZED = re.compile(r"\bdecentrali[sz]ed\b(?!\s+identifier)", re.IGNORECASE)
# A heading or table row, where "Decentralized Trust" names conformance Level 3.
LEVEL_NAME_LINE = re.compile(r"^\s*(#{1,6}\s|\|)")
NOT_DEMONSTRATED = "not yet demonstrated"

# Section 4.6: the schema table is the one home of each ATX field's status.
SPEC_ATX_HEADING = "### 4.6 Agent Trust eXtension (ATX)"
README_ATX_HEADING = "## Agent Trust eXtension (ATX)"
ATX_V11_STATUS = "ATX v1.1"
# The second whitespace run only follows a "(", so a run of spaces after
# "proposed" has one way to match, not one per split point (linear time).
RETIRED_STATUS = re.compile(r"\bproposed\s*(?:\(\s*)?v1\.1\b", re.IGNORECASE)

# Section 2.1: the spec's own list of requirements no fixture covers yet.
COVERAGE_LIST = "Not yet covered by fixtures"
COVERAGE_AUTHORITY = "this list is authoritative"
# The suite's Section 8.1 fixture, byte-pinned with a pre-8.1.1 free-text reason.
REVOCATION_FIXTURE = "revocation-list-valid"


def markdown_lines(text: str):
    """Yield (line number, line, kind) for each line, kind being "fence" for a
    code-block delimiter, "code" inside a block and "prose" outside one. A
    block closes only on a fence of its own character at least as long as the
    opening fence, with nothing after it."""
    fence = None
    for number, line in enumerate(text.splitlines(), start=1):
        match = FENCE.match(line)
        if fence is None:
            if match and not (match.group(1)[0] == "`" and "`" in match.group(2)):
                fence = match.group(1)
                yield number, line, "fence"
            else:
                yield number, line, "prose"
        elif (
            match
            and match.group(1)[0] == fence[0]
            and len(match.group(1)) >= len(fence)
            and not match.group(2).strip()
        ):
            fence = None
            yield number, line, "fence"
        else:
            yield number, line, "code"


def discovery_path_errors(text: str) -> list[str]:
    """Section 7.1: consumers SHOULD request `/.well-known/atp`, so a README
    command that a reader copies requests that path. Comment lines in a code
    block may name the legacy alias."""
    errors = []
    for number, line, kind in markdown_lines(text):
        if kind != "code" or line.lstrip().startswith("#"):
            continue
        for name in WELL_KNOWN.findall(line):
            if name != "atp":
                errors.append(
                    f"README.md:{number} requests /.well-known/{name}; "
                    "Section 7.1 makes /.well-known/atp the discovery path"
                )
    return errors


def readme_units(text: str):
    """Yield each prose paragraph, and each code line on its own, as a list of
    (line number, line). A blank line, a fence or a new block ends a
    paragraph. Lines of a ```json block are wire data, not sentences, and are
    not yielded."""
    paragraph: list[tuple[int, str]] = []
    info = None  # the open code block's info string; None outside a block
    for number, line, kind in markdown_lines(text):
        if kind == "prose" and line.strip() and not (paragraph and BLOCK_START.match(line)):
            paragraph.append((number, line))
            continue
        if paragraph:
            yield paragraph
            paragraph = []
        if kind == "fence":
            info = FENCE.match(line).group(2).strip() if info is None else None
        elif kind == "code" and info.split()[:1] != ["json"]:
            yield [(number, line)]
        elif kind == "prose" and line.strip():
            paragraph.append((number, line))
    if paragraph:
        yield paragraph


def sentences(text: str):
    """Yield (offset, sentence) for each sentence of a joined paragraph."""
    begin = 0
    for match in SENTENCE_BREAK.finditer(text):
        yield begin, text[begin:match.start()]
        begin = match.end()
    yield begin, text[begin:]


def unit_sentences(unit):
    """Yield (line number, sentence) for each sentence of a unit from
    readme_units, the line number being the one the sentence starts on."""
    starts, parts, offset = [], [], 0
    for _, line in unit:
        starts.append(offset)
        parts.append(line.strip())
        offset += len(parts[-1]) + 1
    for begin, sentence in sentences(" ".join(parts)):
        yield unit[bisect_right(starts, begin) - 1][0], sentence


def join_unit(unit: list[tuple[int, str]]) -> tuple[str, list[int]]:
    """A unit's lines joined by single spaces, and the offset of each line in
    the joined text, so a match maps back to the line it starts on."""
    starts, parts, offset = [], [], 0
    for _, line in unit:
        starts.append(offset)
        parts.append(line.strip())
        offset += len(parts[-1]) + 1
    return " ".join(parts), starts


def readme_signing_errors(text: str) -> list[str]:
    """Section 4.3: Ed25519 MUST, hybrid Ed25519 + ML-DSA-65 SHOULD. A README
    sentence naming ML-DSA-65 without hybrid mode reads as a mandatory second
    signature. Reported at the line the sentence starts on."""
    errors = []
    for unit in readme_units(text):
        for lineno, sentence in unit_sentences(unit):
            if "ML-DSA-65" in sentence and "hybrid" not in sentence.lower():
                errors.append(
                    f"README.md:{lineno}: names ML-DSA-65 without hybrid mode: {sentence.strip()!r}"
                )
    return errors


def status_table(text: str, heading: str) -> dict[str, tuple[int, str]] | None:
    """The first table after `heading` as {field cell: (line number, status
    cell)}, the header and delimiter rows skipped; None when the heading is
    absent."""
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if line.strip() == heading), None)
    if start is None:
        return None
    table: list[tuple[int, list[str]]] = []
    for number, line in enumerate(lines[start + 1:], start=start + 2):
        if line.lstrip().startswith("|"):
            table.append((number, [cell.strip() for cell in line.strip().strip("|").split("|")]))
        elif table:
            break
    return {cells[0]: (number, cells[1] if len(cells) > 1 else "") for number, cells in table[2:]}


def atx_status_errors(spec: str, readme: str, example: str | None, schema: str) -> list[str]:
    """Section 4.6 is the one home of the ATX field statuses. The README table
    restates its rows with the same status, the example file shows every ATX
    v1.1 field, the trust-proof schema describes an ATX v1.1 member as ATX
    v1.1, and no file labels a v1.1 field with the retired "Proposed" status.
    An example that is missing (None) or not JSON is one error, not one per
    field."""
    spec_rows = status_table(spec, SPEC_ATX_HEADING)
    if not spec_rows:
        return [f"ATP-SPEC.md: no schema table under {SPEC_ATX_HEADING!r}"]
    atx_fields = [
        field for field, (_, status) in spec_rows.items() if status.startswith(ATX_V11_STATUS)
    ]
    if not atx_fields:
        return ["ATP-SPEC.md: the Section 4.6 schema table has no ATX v1.1 row"]
    errors = []

    readme_rows = status_table(readme, README_ATX_HEADING)
    if not readme_rows:
        errors.append(f"README.md: no ATX table under {README_ATX_HEADING!r}")
        readme_rows = {}
    for field, (_, status) in spec_rows.items():
        if field not in readme_rows:
            errors.append(f"README.md: the ATX table has no {field} row; Section 4.6 lists it as {status!r}")
        elif readme_rows[field][1] != status:
            number, found = readme_rows[field]
            errors.append(f"README.md:{number}: {field} is {found!r}; Section 4.6 says {status!r}")
    for field, (number, _) in readme_rows.items():
        if field not in spec_rows:
            errors.append(f"README.md:{number}: the ATX table lists {field}, which Section 4.6 does not")

    parsed = False
    if example is None:
        errors.append(
            "examples/atx-example.json: missing; Section 4.6 says the example shows every ATX v1.1 field"
        )
    else:
        try:
            example_doc = json.loads(example)
            parsed = True
        except json.JSONDecodeError as exc:
            errors.append(f"examples/atx-example.json: not JSON: {exc}")
    if parsed:
        if not isinstance(example_doc, dict):
            example_doc = {}
        for field in atx_fields:
            if field not in example_doc:
                errors.append(
                    f"examples/atx-example.json: no {field} member; Section 4.6 says the example shows every ATX v1.1 field"
                )

    properties = json.loads(schema).get("properties", {})
    for field in atx_fields:
        description = properties.get(field, {}).get("description", ATX_V11_STATUS)
        if not description.startswith(ATX_V11_STATUS):
            errors.append(
                f"schemas/trust-proof-v1.schema.json: {field} is described as {description!r}; "
                f"Section 4.6 says {ATX_V11_STATUS}"
            )

    for name, text in (
        ("README.md", readme),
        ("examples/atx-example.json", example or ""),
        ("schemas/trust-proof-v1.schema.json", schema),
    ):
        for number, line in enumerate(text.splitlines(), start=1):
            if RETIRED_STATUS.search(line):
                errors.append(f"{name}:{number}: labels a field \"Proposed\" v1.1, a status Section 4.6 retired")
    return errors


def fixture_coverage_errors(spec: str, readme: str, schema: str) -> list[str]:
    """Section 2.1's list of requirements no fixture covers yet is the spec's
    own, so it says it is authoritative rather than deferring to the suite's
    `notCovered` list, which can lag it. The revocation-list-valid fixture's
    free-text `reason` predates the Section 8.1.1 codes: the revocation schema
    refuses it and a client processes it as `unspecified`. A sentence citing
    the fixture names Section 8.1.1, so it never reads as a body the schema
    accepts. Code blocks are not checked."""
    errors = []
    coverage = [
        unit for unit in readme_units(spec) if unit[0][1].startswith(COVERAGE_LIST)
    ]
    if not coverage:
        errors.append(f"ATP-SPEC.md: no {COVERAGE_LIST!r} list in Section 2.1")
    elif COVERAGE_AUTHORITY not in " ".join(line.strip() for _, line in coverage[0]):
        errors.append(
            f"ATP-SPEC.md:{coverage[0][0][0]}: the {COVERAGE_LIST!r} list does not say "
            f"{COVERAGE_AUTHORITY!r}; the suite's notCovered list can lag the spec"
        )

    for name, text in (("ATP-SPEC.md", spec), ("README.md", readme)):
        code = {number for number, _, kind in markdown_lines(text) if kind != "prose"}
        for unit in readme_units(text):
            if unit[0][0] in code:
                continue
            for lineno, sentence in unit_sentences(unit):
                if REVOCATION_FIXTURE in sentence and "8.1.1" not in sentence:
                    errors.append(
                        f"{name}:{lineno}: cites {REVOCATION_FIXTURE} without Section 8.1.1, "
                        f"whose codes its free-text reason predates: {sentence.strip()!r}"
                    )

    description = json.loads(schema).get("description", "")
    for _, sentence in sentences(description):
        if REVOCATION_FIXTURE in sentence and "8.1.1" not in sentence:
            errors.append(
                "schemas/revocation-list-v1.schema.json: the description cites "
                f"{REVOCATION_FIXTURE} without section 8.1.1: {sentence.strip()!r}"
            )
    return errors


# Repositories an anonymous reader cannot open: GitHub answers 404 for them.
NOT_PUBLIC_REPOSITORIES = ("opena2a-org/opena2a-registry",)
# The name may carry `.git` and may end a sentence; a dot followed by a word
# character continues it into another repository's name.
NOT_PUBLIC_LINK = re.compile(
    r"github\.com/(" + "|".join(re.escape(repo) for repo in NOT_PUBLIC_REPOSITORIES)
    + r")(?:\.git)?(?![\w-]|\.\w)",
    re.IGNORECASE,
)
APPENDIX_A = "## Appendix A: Reference Implementation"


def unpublished_link_errors(text: str, name: str) -> list[str]:
    """A link into a repository that is not public is a dead end for a reader;
    the reference implementation is shown through its public endpoints
    (Appendix A) instead."""
    return [
        f"{name}:{number} links to github.com/{match.group(1)}, which is not public; "
        "cite the reference authority's public endpoints (ATP-SPEC Appendix A)"
        for number, line in enumerate(text.splitlines(), start=1)
        for match in NOT_PUBLIC_LINK.finditer(line)
    ]


def reference_endpoint_errors(text: str) -> list[str]:
    """Appendix A maps each reference-implementation component to the public
    endpoint that demonstrates it: every table row's second cell names an
    `/api/` or `/.well-known/` path, never a file in the unpublished source."""
    lines = text.splitlines()
    try:
        start = next(i for i, line in enumerate(lines) if line.strip() == APPENDIX_A)
    except StopIteration:
        return [f"ATP-SPEC.md: heading {APPENDIX_A!r} not found"]
    rows = []
    for number, line in enumerate(lines[start + 1:], start=start + 2):
        if line.startswith("## "):
            break
        if line.lstrip().startswith("|"):
            rows.append((number, [cell.strip() for cell in line.strip().strip("|").split("|")]))
    # The first table line is the header and the second its delimiter row.
    body = rows[2:]
    if not body:
        return ["ATP-SPEC.md: Appendix A has no component table"]
    errors = []
    for number, cells in body:
        target = cells[1] if len(cells) > 1 else ""
        if "/api/" not in target and "/.well-known/" not in target:
            errors.append(
                f"ATP-SPEC.md:{number} Appendix A maps {cells[0]!r} to {target!r}, "
                "which names no public /api/ or /.well-known/ endpoint"
            )
    return errors


SHOWN_IN_EXAMPLE = re.compile(r"Section (\d+(?:\.\d+)+) shows (.+?) in its example")
CODE_SPAN = re.compile(r"`([^`]+)`")


def section_example(text: str, section: str):
    """The first ```json block between the heading numbered `section` and the
    next heading, parsed; None when there is no such block or it is not JSON."""
    heading = re.compile(r"#{2,6} " + re.escape(section) + r"\s")
    found, block = False, None
    for _, line, kind in markdown_lines(text):
        if kind == "prose" and line.startswith("#"):
            if found:
                return None
            found = bool(heading.match(line))
        elif found and kind == "fence":
            if block is not None:
                try:
                    return json.loads("\n".join(block))
                except json.JSONDecodeError:
                    return None
            if line.strip() == "```json":
                block = []
        elif found and kind == "code" and block is not None:
            block.append(line)
    return None


def example_claim_errors(text: str) -> list[str]:
    """A sentence saying "Section N shows `field` in its example" names only
    top-level members of that section's JSON example (the Section 4.6 note
    once said Section 4.2 shows `scanSummary`, which its example omits)."""
    errors = []
    for unit in readme_units(text):
        joined, starts = join_unit(unit)
        for match in SHOWN_IN_EXAMPLE.finditer(joined):
            lineno = unit[bisect_right(starts, match.start()) - 1][0]
            section = match.group(1)
            example = section_example(text, section)
            if not isinstance(example, dict):
                errors.append(f"ATP-SPEC.md:{lineno}: Section {section} has no JSON object example")
                continue
            errors.extend(
                f"ATP-SPEC.md:{lineno}: says Section {section} shows `{field}` in its "
                "example, which has no such member"
                for field in CODE_SPAN.findall(match.group(2))
                if field not in example
            )
    return errors


IANA = "## 11. IANA Considerations"
MEDIA_TYPE = re.compile(r"`(application/[A-Za-z0-9.+-]+)`")
CONTENT_TYPE = re.compile(r"Content-Type:\s*(application/[A-Za-z0-9.+-]+)", re.IGNORECASE)


def media_type_errors(text: str) -> list[str]:
    """Section 11 names only media types the spec uses: each one is the
    `Content-Type` of a request or response in another section (it once
    defined `application/atp+json`, which nothing served or sent)."""
    lines = text.splitlines()
    try:
        start = next(i for i, line in enumerate(lines) if line.strip() == IANA)
    except StopIteration:
        return [f"ATP-SPEC.md: heading {IANA!r} not found"]
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")), len(lines))
    used = {
        media.lower()
        for line in lines[:start] + lines[end:]
        for media in CONTENT_TYPE.findall(line)
    }
    return [
        f"ATP-SPEC.md:{number} Section 11 names media type {media!r}, which no "
        "Content-Type in the specification carries"
        for number in range(start + 1, end + 1)
        for media in MEDIA_TYPE.findall(lines[number - 1])
        if media.lower() not in used
    ]


def readme_spec_version_errors(text: str, spec: str) -> list[str]:
    """A README line that links ATP-SPEC.md and names a version names the
    version in the specification's `**Version:**` header."""
    header = SPEC_VERSION.search(spec)
    if header is None:
        return ["ATP-SPEC.md: no **Version:** header line"]
    errors = []
    for number, line, kind in markdown_lines(text):
        if kind != "prose" or "ATP-SPEC.md" not in line:
            continue
        for version in VERSION.findall(line):
            if version != header.group(1):
                errors.append(
                    f"README.md:{number}: names the specification v{version}; "
                    f"ATP-SPEC.md is {header.group(1)}"
                )
    return errors


def section_table(text: str, heading: str) -> list[tuple[int, str]]:
    """(line number, line) for each row, header and delimiter included, of the
    first table under the heading line `heading` and before the next heading.
    Lines in code blocks are not rows."""
    rows, state = [], "before"
    for number, line, kind in markdown_lines(text):
        if kind != "prose":
            continue
        if state == "before" and line.strip() == heading:
            state = "section"
        elif state in ("section", "table") and line.lstrip().startswith("|"):
            state = "table"
            rows.append((number, line))
        elif state == "table" or (state == "section" and line.startswith("#")):
            state = "after"
    return rows


SIGNING_HEADING = "### 4.3 Signing"
SERVED_TIME = re.compile(
    r"^([0-9]{4}-[0-9]{2}-[0-9]{2})[Tt]([0-9]{2}:[0-9]{2}:[0-9]{2})(\.[0-9]+)?([Zz]|[+-][0-9]{2}:[0-9]{2})$"
)


def signed_time(served: str) -> str:
    """Section 4.3: the form a served `issuedAt` or `expiresAt` takes in the
    canonical string: the instant in UTC, fractional seconds dropped (not
    rounded), with a `Z` suffix."""
    match = SERVED_TIME.match(served)
    if not match:
        raise ValueError(f"{served!r} is not an RFC 3339 timestamp")
    date, clock, _, zone = match.groups()
    offset = "+00:00" if zone in ("Z", "z") else zone
    when = datetime.fromisoformat(f"{date}T{clock}{offset}")
    return when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def signed_timestamp_errors(text: str) -> list[str]:
    """Section 4.3: each row of the table under the heading pairs a served
    timestamp with the form signed_time() gives it, and one row serves
    fractional seconds, the case a verifier working from the text alone
    otherwise gets wrong. Reported at the line of the row."""
    rows = section_table(text, SIGNING_HEADING)
    if len(rows) < 3:
        return [f"ATP-SPEC.md: no timestamp rows in a table under {SIGNING_HEADING!r}"]
    errors, fractional = [], False
    for number, line in rows[2:]:
        cells = [cell.strip().strip("`") for cell in line.strip().strip("|").split("|")]
        if len(cells) < 2:
            errors.append(f"ATP-SPEC.md:{number}: row has no signed form: {line.strip()!r}")
            continue
        served, signed = cells[0], cells[1]
        try:
            expected = signed_time(served)
        except ValueError as exc:
            errors.append(f"ATP-SPEC.md:{number}: {exc}")
            continue
        if signed != expected:
            errors.append(
                f"ATP-SPEC.md:{number}: served {served!r} is signed as {expected!r}, not {signed!r}"
            )
        fractional = fractional or "." in served
    if not fractional:
        errors.append(
            f"ATP-SPEC.md: no row shows a served timestamp with fractional seconds under "
            f"{SIGNING_HEADING!r}"
        )
    return errors


THREAT_MODEL_HEADING = "### 10.1 Threat Model"
SECTION_HEADING = re.compile(r"^#{2,6} (\d+(?:\.\d+)*)\.? ")
SECTION_CITATION = re.compile(r"\bSection (\d+(?:\.\d+)*)")


def threat_model_errors(text: str) -> list[str]:
    """Section 10.1: every defense in the threat model table cites the section
    that defines it, and every cited section is a numbered heading of the
    specification. A defense the specification never defines has no section
    to cite. Reported at the line of the row."""
    headings = set()
    for _, line, kind in markdown_lines(text):
        match = SECTION_HEADING.match(line) if kind == "prose" else None
        if match:
            headings.add(match.group(1))
    rows = section_table(text, THREAT_MODEL_HEADING)
    if len(rows) < 3:
        return [f"ATP-SPEC.md: no threat rows in a table under {THREAT_MODEL_HEADING!r}"]
    errors = []
    for number, line in rows[2:]:
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 2:
            errors.append(f"ATP-SPEC.md:{number}: row has no defense cell: {line.strip()!r}")
            continue
        threat, defense = cells[0], cells[1]
        cited = SECTION_CITATION.findall(defense)
        if not cited:
            errors.append(
                f"ATP-SPEC.md:{number}: the defense for {threat!r}, {defense!r}, cites no section"
            )
        for section in cited:
            if section not in headings:
                errors.append(
                    f"ATP-SPEC.md:{number}: the defense for {threat!r} cites Section {section}, "
                    "which is not a heading of the specification"
                )
    return errors


def federation_claim_errors(text: str, name: str = "README.md") -> list[str]:
    """Section 6 federation is what makes a trust response decentralized, and
    no second authority co-signs proofs yet (Section 2.1 lists the Level 3
    cosignature as not covered by fixtures). A prose paragraph calling ATP or
    its response decentralized also says federation is not yet demonstrated.
    Headings and table rows that name the Level 3 conformance level, code
    lines, and "Decentralized Identifier" (a DID) are not claims. Reported at
    the line the sentence starts on."""
    code = {number for number, _, kind in markdown_lines(text) if kind != "prose"}
    errors = []
    for unit in readme_units(text):
        if unit[0][0] in code or LEVEL_NAME_LINE.match(unit[0][1]):
            continue
        if NOT_DEMONSTRATED in " ".join(line.strip() for _, line in unit).lower():
            continue
        for lineno, sentence in unit_sentences(unit):
            if DECENTRALIZED.search(sentence):
                errors.append(
                    f"{name}:{lineno}: calls ATP decentralized without saying federation "
                    f"is {NOT_DEMONSTRATED}: {sentence.strip()!r}"
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
        start = next(i for i, line in enumerate(lines) if line.strip() == heading)
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

    index_errors = revocation_index_errors()
    if index_errors:
        print("index FAIL     schemas/revocation-list-v1.schema.json vs Section 8.1")
        for err in index_errors:
            print(f"    {err}")
        failures += 1
    else:
        print("index OK       schemas/revocation-list-v1.schema.json vs Section 8.1")

    spec = (ROOT / "ATP-SPEC.md").read_text(encoding="utf-8")
    timestamp_errors = signed_timestamp_errors(spec)
    if timestamp_errors:
        print("timestamp FAIL ATP-SPEC.md Section 4.3 served vs signed timestamps")
        for err in timestamp_errors:
            print(f"    {err}")
        failures += 1
    else:
        print("timestamp OK   ATP-SPEC.md Section 4.3 served vs signed timestamps")

    threat_errors = threat_model_errors(spec)
    if threat_errors:
        print("threats FAIL   ATP-SPEC.md Section 10.1 defenses vs the spec's sections")
        for err in threat_errors:
            print(f"    {err}")
        failures += 1
    else:
        print("threats OK     ATP-SPEC.md Section 10.1 defenses vs the spec's sections")

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    discovery_errors = discovery_path_errors(readme)
    if discovery_errors:
        print("discovery FAIL README.md vs Section 7.1")
        for err in discovery_errors:
            print(f"    {err}")
        failures += 1
    else:
        print("discovery OK   README.md vs Section 7.1")

    signing_errors = readme_signing_errors(readme)
    if signing_errors:
        print("signing FAIL   README.md vs Section 4.3")
        for err in signing_errors:
            print(f"    {err}")
        failures += 1
    else:
        print("signing OK     README.md vs Section 4.3")

    spec = (ROOT / "ATP-SPEC.md").read_text(encoding="utf-8")
    example_path = ROOT / "examples" / "atx-example.json"
    atx_errors = atx_status_errors(
        spec,
        readme,
        example_path.read_text(encoding="utf-8") if example_path.is_file() else None,
        (ROOT / "schemas" / "trust-proof-v1.schema.json").read_text(encoding="utf-8"),
    )
    if atx_errors:
        print("atx FAIL       README.md, example and schema vs Section 4.6")
        for err in atx_errors:
            print(f"    {err}")
        failures += 1
    else:
        print("atx OK         README.md, example and schema vs Section 4.6")

    coverage_errors = fixture_coverage_errors(
        spec,
        readme,
        (ROOT / "schemas" / "revocation-list-v1.schema.json").read_text(encoding="utf-8"),
    )
    if coverage_errors:
        print("fixtures FAIL  Section 2.1, README.md and revocation schema vs Section 8.1.1")
        for err in coverage_errors:
            print(f"    {err}")
        failures += 1
    else:
        print("fixtures OK    Section 2.1, README.md and revocation schema vs Section 8.1.1")

    reference_errors = (
        unpublished_link_errors(readme, "README.md")
        + unpublished_link_errors(spec, "ATP-SPEC.md")
        + reference_endpoint_errors(spec)
    )
    if reference_errors:
        print("reference FAIL README.md and ATP-SPEC.md vs Appendix A")
        for err in reference_errors:
            print(f"    {err}")
        failures += 1
    else:
        print("reference OK   README.md and ATP-SPEC.md vs Appendix A")

    claim_errors = example_claim_errors(spec) + media_type_errors(spec)
    if claim_errors:
        print("claims FAIL    ATP-SPEC.md example claims and Section 11 vs the specification")
        for err in claim_errors:
            print(f"    {err}")
        failures += 1
    else:
        print("claims OK      ATP-SPEC.md example claims and Section 11 vs the specification")

    version_errors = readme_spec_version_errors(readme, spec)
    if version_errors:
        print("version FAIL   README.md vs ATP-SPEC.md header")
        for err in version_errors:
            print(f"    {err}")
        failures += 1
    else:
        print("version OK     README.md vs ATP-SPEC.md header")

    for doc in ("README.md", "ATP-SPEC.md"):
        federation_errors = federation_claim_errors((ROOT / doc).read_text(encoding="utf-8"), doc)
        if federation_errors:
            print(f"federation FAIL {doc} vs Section 6")
            for err in federation_errors:
                print(f"    {err}")
            failures += 1
        else:
            print(f"federation OK  {doc} vs Section 6")

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
