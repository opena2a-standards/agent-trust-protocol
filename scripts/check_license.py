#!/usr/bin/env python3
"""Check that LICENSE is the canonical Apache License 2.0 text.

The one permitted change from https://www.apache.org/licenses/LICENSE-2.0.txt
is the appendix copyright line, which names the year and owner instead of the
`[yyyy] [name of copyright owner]` placeholder. That line is put back to the
placeholder and the result is compared, by SHA-256, with the canonical file.
Any other edit (a reworded clause, a rewrapped line, a dropped blank line)
fails. python3 standard library only.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CANONICAL_URL = "https://www.apache.org/licenses/LICENSE-2.0.txt"
# SHA-256 of the canonical file served at CANONICAL_URL.
CANONICAL_SHA256 = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
PLACEHOLDER = "   Copyright [yyyy] [name of copyright owner]"
COPYRIGHT_LINE = re.compile(r"^   Copyright .+$", re.MULTILINE)


def check(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    lines = COPYRIGHT_LINE.findall(text)
    if len(lines) != 1:
        return [f"{path.name}: expected one appendix copyright line, found {len(lines)}"]
    normalized = COPYRIGHT_LINE.sub(lambda _: PLACEHOLDER, text)
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    if digest != CANONICAL_SHA256:
        return [
            f"{path.name}: text differs from the canonical Apache License 2.0 "
            f"beyond the copyright line (sha256 {digest}, expected {CANONICAL_SHA256}). "
            f"See the difference with: curl -fsSL {CANONICAL_URL} | diff - {path.name}"
        ]
    return []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("path", nargs="?", type=Path, default=ROOT / "LICENSE")
    args = parser.parse_args()
    errors = check(args.path)
    for error in errors:
        print(error, file=sys.stderr)
    if errors:
        return 1
    print(f"{args.path.name}: canonical Apache License 2.0, copyright line only")
    return 0


if __name__ == "__main__":
    sys.exit(main())
