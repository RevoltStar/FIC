#!/usr/bin/env python3
"""Static checks for the authoritative incident-state package lifecycle."""

from pathlib import Path
import os
import re
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]
DEB = ROOT / "packaging/deb/build-fic-debian12-deb.sh"
RPM = ROOT / "packaging/rpm/build-fic-alt-p11-rpm.sh"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def check_generator(path: Path) -> None:
    source = path.read_text()
    require(source.count("--maintenance incident-init") == 1,
            f"{path}: only main package may call incident-init")
    require(not re.search(r"(?:printf|echo)\s+['\"]?[01](?:\\n)?['\"]?\s*>\s*/opt/fic/lockstatus", source),
            f"{path}: legacy lockstatus write")
    require(not re.search(r"(?:printf|echo)\s+['\"]?UNLOCKED", source),
            f"{path}: direct UNLOCKED write")
    require("chown -R root:fic /opt/fic" not in source,
            f"{path}: recursive ownership repairs lockstatus")
    require("mkdir -p /opt/fic/config" not in source,
            f"{path}: package hooks must not recreate recovery authority")
    require(not re.search(r"find /opt/fic -type f -exec chmod", source),
            f"{path}: generic file chmod repairs lockstatus")
    require("-path /opt/fic/lockstatus -prune" in source,
            f"{path}: ownership normalization must exclude lockstatus")
    require("-path /opt/fic/config -prune -o -type f ! -path /opt/fic/lockstatus ! -links +1 -exec chmod" in source,
            f"{path}: mode normalization must exclude the config tree")
    direct_parent_writes = re.findall(r"^\s*(?:chown|chmod)\s+[^\n]*\s/opt/fic(?:\s|$)",
                                      source, re.MULTILINE)
    require(len(direct_parent_writes) == 2 and
            any("chown root:fic /opt/fic" in item for item in direct_parent_writes) and
            any("chmod 2750 /opt/fic" in item for item in direct_parent_writes),
            f"{path}: only the two guarded first-install parent writes are allowed")
    for line in source.splitlines():
        if "find /opt/fic" not in line or "-exec" not in line:
            continue
        if "chown root:fic" not in line and "chmod 2750" not in line:
            continue
        require("find /opt/fic -mindepth 1" in line,
                f"{path}: generic normalization must exclude parent: {line}")
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp) / "fic"
            parent.mkdir()
            (parent / "lockstatus").write_text("HARD\n")
            (parent / "child").mkdir()
            (parent / "config").mkdir()
            (parent / "config/GLOBAL.conf").write_text("unsafe")
            (parent / "config/DAC.conf").write_text("ordinary")
            (parent / "global-hardlink").hardlink_to(
                parent / "config/GLOBAL.conf")
            (parent / "global-symlink").symlink_to(
                parent / "config/GLOBAL.conf")
            expression = line.strip().split(" || ")[0].replace("/opt/fic", str(parent))
            expression = re.sub(r"-exec (?:chown root:fic|chmod 2750) \{\} (?:\+|\\+;)",
                                "-print", expression)
            result = subprocess.run(shlex.split(expression),
                                    capture_output=True, text=True)
            require(result.returncode == 0, f"{path}: invalid find expression: {line}")
            selected = result.stdout.splitlines()
            require(str(parent) not in selected and str(parent / "child") in selected and
                    str(parent / "config") not in selected and
                    str(parent / "config/GLOBAL.conf") not in selected and
                    str(parent / "global-hardlink") not in selected and
                    str(parent / "global-symlink") not in selected and
                    str(parent / "config/DAC.conf") not in selected,
                    f"{path}: parent selected or child skipped: {line}")
    with tempfile.TemporaryDirectory() as temp:
        parent = Path(temp) / "fic"
        config = parent / "config"
        config.mkdir(parents=True)
        global_config = config / "GLOBAL.conf"
        ordinary_config = config / "DAC.conf"
        global_config.write_text("lock_exempt_fic_members.status=ENABLE\n")
        ordinary_config.write_text("ordinary")
        (parent / "global-hardlink").hardlink_to(global_config)
        (parent / "global-symlink").symlink_to(global_config)
        (parent / "bin").mkdir()
        (parent / "bin/global-hardlink").hardlink_to(global_config)
        config.chmod(0o777)
        global_config.chmod(0o666)
        ordinary_config.chmod(0o666)
        for line in source.splitlines():
            if "find /opt/fic" not in line or "-exec chmod" not in line:
                continue
            expression = line.strip().split(" || ")[0].replace(
                "/opt/fic", str(parent)).replace("\\\\;", "\\;")
            result = subprocess.run(expression, shell=True, executable="/bin/bash",
                                    capture_output=True, text=True)
            require(result.returncode == 0,
                    f"{path}: normalization command failed: {line}")
        require((config.stat().st_mode & 0o7777) == 0o777 and
                (global_config.stat().st_mode & 0o7777) == 0o666 and
                ((parent / "global-hardlink").stat().st_mode & 0o7777) == 0o666 and
                ((parent / "bin/global-hardlink").stat().st_mode & 0o7777) == 0o666 and
                global_config.read_text() ==
                "lock_exempt_fic_members.status=ENABLE\n" and
                (ordinary_config.stat().st_mode & 0o7777) == 0o666,
                f"{path}: normalization laundered recovery authority")
        if os.geteuid() == 0:
            os.chown(config, 65534, 65534)
            os.chown(global_config, 65534, 65534)
            os.chown(ordinary_config, 65534, 65534)
            for line in source.splitlines():
                if "find /opt/fic -" not in line or "-exec chown" not in line:
                    continue
                expression = line.strip().split(" || ")[0].replace(
                    "/opt/fic", str(parent)).replace(
                    "chown root:fic", "chown 0:0").replace("\\\\;", "\\;")
                result = subprocess.run(expression, shell=True,
                                        executable="/bin/bash",
                                        capture_output=True, text=True)
                require(result.returncode == 0,
                        f"{path}: ownership command failed: {line}")
            require(config.stat().st_uid == 65534 and
                    config.stat().st_gid == 65534 and
                    global_config.stat().st_uid == 65534 and
                    global_config.stat().st_gid == 65534 and
                    ordinary_config.stat().st_uid == 65534 and
                    ordinary_config.stat().st_gid == 65534,
                    f"{path}: ownership normalization laundered recovery authority")


def main() -> None:
    cmake = (ROOT / "fic/CMakeLists.txt").read_text()
    require('install(DIRECTORY DESTINATION "${FIC_CONFIG_DIR}"' not in cmake,
            "staged package must not own recovery config directory")
    for generator in (DEB, RPM):
        check_generator(generator)

    deb = DEB.read_text()
    rpm = RPM.read_text()
    require('if [ "\\${1:-}" = "configure" ] && [ -z "\\${2:-}" ]; then' in deb and
            '[ ! -e /opt/fic/config ] && [ ! -L /opt/fic/config ]' in deb,
            "Debian bootstrap must run only on initial configure")
    require('if [ "\\${1:-}" -eq 1 ]; then' in rpm and
            '[ ! -e /opt/fic/config ] && [ ! -L /opt/fic/config ]' in rpm,
            "RPM bootstrap must run only with one installed instance")
    require(re.search(r'/opt/fic\|/opt/fic/config\)\s*#.*RPM must not restore.*?;;\s*/opt/fic/\*\)',
                      rpm, re.DOTALL),
            "RPM file manifest must not own /opt/fic itself")
    manifest_function = re.search(r'^write_file_list\(\) \{.*?^\}',
                                  rpm, re.MULTILINE | re.DOTALL)
    require(manifest_function is not None, "RPM manifest generator missing")
    with tempfile.TemporaryDirectory() as temp:
        package_root = Path(temp) / "package"
        (package_root / "opt/fic/bin").mkdir(parents=True)
        (package_root / "opt/fic/config").mkdir()
        (package_root / "opt/fic/bin/fic").write_text("fixture")
        manifest = Path(temp) / "manifest"
        subprocess.run(["bash", "-c", manifest_function.group(0) +
                        '\nwrite_file_list "$1" "$2"', "bash",
                        str(package_root), str(manifest)], check=True)
        listed = manifest.read_text().splitlines()
        require("%dir /opt/fic" not in listed and
                "%dir /opt/fic/config" not in listed and
                "%dir /opt/fic/bin" in listed and "/opt/fic/bin/fic" in listed,
                "RPM manifest must leave security parent unowned and retain children")
    for name, source in (("Debian", deb), ("RPM", rpm)):
        first_install = source.index('[ ! -e /opt/fic/config ] && [ ! -L /opt/fic/config ]')
        initialize = source.index('/opt/fic/bin/fic --maintenance incident-init')
        require(first_install < source.index('chown root:fic /opt/fic', first_install) <
                source.index('chmod 2750 /opt/fic', first_install) < initialize,
                f"{name}: parent bootstrap must precede incident-init")

    daemon = (ROOT / "fic/src/main.cpp").read_text()
    require('command == "incident-init"' in daemon and
            'ensureTargetDurable' in daemon and 'store.read()' in daemon,
            "bootstrap must prove durable state with the daemon parser")


if __name__ == "__main__":
    main()
