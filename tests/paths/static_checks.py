#!/usr/bin/env python3
from pathlib import Path
import sys


root = Path(sys.argv[1])
errors = []

code_suffixes = {".cpp", ".h", ".hpp", ".cc"}
for base in ("fic", "fic-cli", "fic-dick", "fic-gui", "fic-session-agent", "fic-common"):
    for path in (root / base).rglob("*"):
        if path.suffix not in code_suffixes or "build" in path.parts:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for literal in ("/opt/fic", "/run/fic"):
            if literal in text:
                errors.append(f"{path.relative_to(root)} contains {literal}")

for path in (root / "packaging").rglob("build-fic-*.sh"):
    text = path.read_text(encoding="utf-8", errors="replace")
    stale_sources = (
        "src/scripts/service/fic.service",
        "src/scripts/service/fic-device.service",
        "src/scripts/tmpfiles/fic.conf",
        "src/scripts/udev/99-fic-devices.rules",
    )
    for source in stale_sources:
        if source in text:
            errors.append(f"{path.relative_to(root)} bypasses CMake layout: {source}")

if errors:
    print("\n".join(errors), file=sys.stderr)
    raise SystemExit(1)
