#!/usr/bin/env python3
from pathlib import Path
import sys


root = Path(sys.argv[1])
errors = []

required_layout = (
    "fic-common/fic-core/include/fic/core/config",
    "fic-common/fic-core/include/fic/core/fs",
    "fic-common/fic-core/include/fic/core/process",
    "fic-common/fic-core/include/fic/core/runtime",
    "fic/src/daemon",
    "fic/src/policy/execution",
    "fic/src/policy/registry",
    "fic/src/resources",
    "fic-gui/src/app",
    "fic-gui/src/shared/i18n",
    "fic-gui/src/features/policies",
    "fic-gui/src/features/devices",
    "fic-gui/src/features/logs",
    "fic-dick/src/daemon",
    "fic-dick/src/device",
    "fic-dick/src/policy",
    "fic-dick/src/enforcement",
    "fic-dick/src/collectors",
    "tests/common",
    "tests/fic",
    "tests/fic-dick",
    "tests/fic-gui",
    "tests/integration",
)
for relative_path in required_layout:
    if not (root / relative_path).is_dir():
        errors.append(f"required source layout directory is missing: {relative_path}")

forbidden_layout = (
    "fic/src/core",
    "fic/src/scripts",
    "fic-dick/src/core",
    "fic-dick/src/modules",
    "fic-gui/src/models",
    "fic-gui/src/services",
    "fic-gui/src/widgets",
    "fic-gui/src/pages",
)
for relative_path in forbidden_layout:
    if (root / relative_path).exists():
        errors.append(f"obsolete source layout remains: {relative_path}")

for submodules_path in (root / "fic/src/modules").rglob("submodules"):
    if submodules_path.is_dir():
        errors.append(
            f"obsolete source layout remains: {submodules_path.relative_to(root)}"
        )

tmpfiles_config = (root / "fic/src/resources/tmpfiles/fic.conf.in").read_text(
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
        "src/resources/service/fic.service",
        "src/resources/service/fic-device.service",
        "src/resources/tmpfiles/fic.conf",
        "src/resources/udev/99-fic-devices.rules",
    )
    for source in stale_sources:
        if source in text:
            errors.append(f"{path.relative_to(root)} bypasses CMake layout: {source}")

if errors:
    print("\n".join(errors), file=sys.stderr)
    raise SystemExit(1)
