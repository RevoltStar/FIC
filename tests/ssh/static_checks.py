#!/usr/bin/env python3
from pathlib import Path
import sys


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def parse_properties(path):
    properties = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        require(separator, f"{path}: malformed property: {raw_line}")
        properties[key] = value
    return properties


def main():
    if len(sys.argv) != 2:
        print("usage: static_checks.py <repo-root>", file=sys.stderr)
        return 2

    root = Path(sys.argv[1])
    registry = (root / "fic/src/core/main_function.cpp").read_text(encoding="utf-8")
    require(
        "std::make_unique<NET_ssh_pubkey_auth>()" in registry,
        "ssh_pubkey_auth must be registered in init_policyMap",
    )

    config = parse_properties(root / "fic/src/scripts/config/NET.conf")
    require(
        config.get("ssh_pubkey_auth.status") == "DISABLE",
        "ssh_pubkey_auth must be shipped disabled by default",
    )
    require(
        config.get("ssh_pubkey_auth.value") == "yes",
        "ssh_pubkey_auth must enforce PubkeyAuthentication yes",
    )

    for language in ("ru", "en"):
        localization = (root / f"fic/src/scripts/lang/{language}.lang").read_text(
            encoding="utf-8"
        )
        prefix = "[module:NET][policy:ssh_pubkey_auth]"
        require(
            "\n" + prefix + "=" in "\n" + localization,
            f"{language}.lang lacks ssh_pubkey_auth title",
        )
        require(
            "\n" + prefix + "[description]=" in "\n" + localization,
            f"{language}.lang lacks ssh_pubkey_auth description",
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
