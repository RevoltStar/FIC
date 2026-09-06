#!/usr/bin/env python3
from pathlib import Path, PurePosixPath
import subprocess
import sys


root = Path(sys.argv[1])
errors = []

try:
    tracked_result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        check=False,
        capture_output=True,
        text=True,
    )
except OSError as error:
    print(f"could not execute git ls-files: {error}", file=sys.stderr)
    raise SystemExit(2)
if tracked_result.returncode != 0:
    detail = tracked_result.stderr.strip() or "unknown git error"
    print(f"could not obtain Git-tracked paths: {detail}", file=sys.stderr)
    raise SystemExit(2)
tracked_paths = tuple(
    path for path in tracked_result.stdout.split("\0") if path
)

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
    if any(
        path == relative_path or path.startswith(relative_path + "/")
        for path in tracked_paths
    ):
        errors.append(f"obsolete source layout remains: {relative_path}")

obsolete_submodules_paths = set()
for tracked_path in tracked_paths:
    parts = PurePosixPath(tracked_path).parts
    if parts[:3] != ("fic", "src", "modules") or "submodules" not in parts[3:]:
        continue
    component_index = parts.index("submodules", 3)
    obsolete_submodules_paths.add("/".join(parts[:component_index + 1]))
for relative_path in sorted(obsolete_submodules_paths):
    errors.append(f"obsolete source layout remains: {relative_path}")

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
    "socketMode = 0622",
):
    if expected not in admin_socket:
        errors.append(f"production admin socket metadata check is missing: {expected}")

fic_cmake = (root / "fic/CMakeLists.txt").read_text(encoding="utf-8")
fic_main = (root / "fic/src/main.cpp").read_text(encoding="utf-8")
fic_service = (root / "fic/src/resources/service/fic.service.in").read_text(
    encoding="utf-8"
)
device_service = (
    root / "fic/src/resources/service/fic-device.service.in"
).read_text(encoding="utf-8")
for expected in (
    "pkg_check_modules(FIC_LIBSYSTEMD REQUIRED IMPORTED_TARGET libsystemd)",
    "PkgConfig::FIC_LIBSYSTEMD",
):
    if expected not in fic_cmake:
        errors.append(f"fic does not link systemd notification support: {expected}")
if "Type=notify" not in fic_service or "Type=simple" in fic_service:
    errors.append("fic.service must use Type=notify")
if "TimeoutStartSec=600s" not in fic_service or "TimeoutStartSec=infinity" in fic_service:
    errors.append("fic.service must have a finite 600 second startup timeout")
if "Type=simple" not in device_service or "Type=notify" in device_service:
    errors.append("fic-device.service must remain Type=simple")
for dependency in ("After=fic.service", "Requires=fic.service"):
    if dependency not in device_service:
        errors.append(f"fic-device.service lost its readiness dependency: {dependency}")
if "fic-device.service" in fic_service:
    errors.append("fic.service introduces a dependency cycle with fic-device.service")

daemon_startup = fic_main[fic_main.index("int main(int argc, char* argv[])"):]
startup_markers = (
    'STATUS=Validating startup configuration',
    'STATUS=Initializing policy registry',
    'STATUS=Applying startup policies',
    'run_daemon_apply_all_pass(',
    'STATUS=Creating administrative socket',
    'create_admin_server_socket(socketOptions)',
    'STATUS=Creating session event socket',
    'create_admin_server_socket(eventSocketOptions)',
    'READY=1\\nSTATUS=Running',
)
cursor = 0
for marker in startup_markers:
    position = daemon_startup.find(marker, cursor)
    if position < 0:
        errors.append(f"fic readiness lifecycle is missing or misordered: {marker}")
        break
    cursor = position + len(marker)
if daemon_startup.count("READY=1") != 2:
    errors.append("fic must notify readiness only through the two startup-result statuses")
if "NOTIFY_SOCKET" in fic_main or "sd_notify(0" not in daemon_startup:
    errors.append("fic must rely on non-fatal sd_notify semantics outside systemd")

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
