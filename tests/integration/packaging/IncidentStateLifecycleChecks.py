#!/usr/bin/env python3
"""Static checks for the authoritative incident-state package lifecycle."""

from pathlib import Path
import re
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
    require(not re.search(r"find /opt/fic -type f -exec chmod", source),
            f"{path}: generic file chmod repairs lockstatus")
    require("-path /opt/fic/lockstatus -prune" in source,
            f"{path}: ownership normalization must exclude lockstatus")
    require("! -path /opt/fic/lockstatus -exec chmod" in source,
            f"{path}: mode normalization must exclude lockstatus")
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
            expression = line.strip().split(" || ")[0].replace("/opt/fic", str(parent))
            expression = re.sub(r"-exec (?:chown root:fic|chmod 2750) \{\} (?:\+|\\+;)",
                                "-print", expression)
            result = subprocess.run(expression.split(),
                                    capture_output=True, text=True)
            require(result.returncode == 0, f"{path}: invalid find expression: {line}")
            selected = result.stdout.splitlines()
            require(str(parent) not in selected and str(parent / "child") in selected,
                    f"{path}: parent selected or child skipped: {line}")


def main() -> None:
    for generator in (DEB, RPM):
        check_generator(generator)

    deb = DEB.read_text()
    rpm = RPM.read_text()
    require('if [ "\\${1:-}" = "configure" ] && [ -z "\\${2:-}" ]; then' in deb and
            'if [ ! -e /opt/fic/lockstatus ] && [ ! -L /opt/fic/lockstatus ]; then' in deb,
            "Debian bootstrap must run only on initial configure")
    require('if [ "\\${1:-}" -eq 1 ]; then' in rpm and
            'if [ ! -e /opt/fic/lockstatus ] && [ ! -L /opt/fic/lockstatus ]; then' in rpm,
            "RPM bootstrap must run only with one installed instance")
    require(re.search(r'/opt/fic\)\s*#.*RPM must not restore.*?;;\s*/opt/fic/\*\)',
                      rpm, re.DOTALL),
            "RPM file manifest must not own /opt/fic itself")
    manifest_function = re.search(r'^write_file_list\(\) \{.*?^\}',
                                  rpm, re.MULTILINE | re.DOTALL)
    require(manifest_function is not None, "RPM manifest generator missing")
    with tempfile.TemporaryDirectory() as temp:
        package_root = Path(temp) / "package"
        (package_root / "opt/fic/bin").mkdir(parents=True)
        (package_root / "opt/fic/bin/fic").write_text("fixture")
        manifest = Path(temp) / "manifest"
        subprocess.run(["bash", "-c", manifest_function.group(0) +
                        '\nwrite_file_list "$1" "$2"', "bash",
                        str(package_root), str(manifest)], check=True)
        listed = manifest.read_text().splitlines()
        require("%dir /opt/fic" not in listed and
                "%dir /opt/fic/bin" in listed and "/opt/fic/bin/fic" in listed,
                "RPM manifest must leave security parent unowned and retain children")
    for name, source in (("Debian", deb), ("RPM", rpm)):
        first_install = source.index('if [ ! -e /opt/fic/lockstatus ] && [ ! -L /opt/fic/lockstatus ]; then')
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
