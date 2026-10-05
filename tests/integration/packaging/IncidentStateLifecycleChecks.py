#!/usr/bin/env python3
"""Static checks for the authoritative incident-state package lifecycle."""

from pathlib import Path
import re

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


def main() -> None:
    for generator in (DEB, RPM):
        check_generator(generator)

    deb = DEB.read_text()
    rpm = RPM.read_text()
    require('if [ "\\${1:-}" = "configure" ] && [ -z "\\${2:-}" ]; then\n    /opt/fic/bin/fic --maintenance incident-init' in deb,
            "Debian bootstrap must run only on initial configure")
    require('if [ "\\${1:-}" -eq 1 ]; then\n    /opt/fic/bin/fic --maintenance incident-init' in rpm,
            "RPM bootstrap must run only with one installed instance")

    daemon = (ROOT / "fic/src/main.cpp").read_text()
    require('command == "incident-init"' in daemon and
            'ensureTargetDurable' in daemon and 'store.read()' in daemon,
            "bootstrap must prove durable state with the daemon parser")


if __name__ == "__main__":
    main()
