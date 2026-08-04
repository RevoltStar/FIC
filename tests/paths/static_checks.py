#!/usr/bin/env python3
from pathlib import Path
import sys


root = Path(sys.argv[1])
errors = []

tmpfiles_config = (root / "fic/src/scripts/tmpfiles/fic.conf.in").read_text(
    encoding="utf-8"
).strip()
if tmpfiles_config != "d @FIC_RUNTIME_DIR@ 0755 root root -":
    errors.append(
        "fic tmpfiles config must keep the runtime directory root:root 0755"
    )

admin_socket = (root / "fic-common/fic-ipc/src/FicAdminSocket.cpp").read_text(
    encoding="utf-8"
)
for expected in (
    "::chown(runtimeDir.c_str(), 0, 0)",
    "::chmod(runtimeDir.c_str(), 0755)",
    "verifyPath(runtimeDir, S_IFDIR, 0755, 0, 0",
    "socketMode = 0660",
):
    if expected not in admin_socket:
        errors.append(f"production admin socket metadata check is missing: {expected}")

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
