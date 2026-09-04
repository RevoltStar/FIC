#!/usr/bin/env python3
"""Verify the source archive set required by official binary releases."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_artifact_path(source_dir: Path, relative_text: object, purpose: str) -> Path:
    if not isinstance(relative_text, str) or not relative_text:
        raise ValueError(f"{purpose} path is missing")
    relative = Path(relative_text)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"unsafe {purpose} path: {relative}")
    candidate = source_dir / relative
    resolved = candidate.resolve()
    if resolved == source_dir or source_dir not in resolved.parents:
        raise ValueError(f"{purpose} escapes source directory: {candidate}")
    if not candidate.is_file():
        raise ValueError(f"{purpose} is missing or is not a regular file: {candidate}")
    return candidate


def verify_hash(path: Path, expected: object, purpose: str) -> None:
    if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError(f"invalid {purpose} SHA-256: {path}")
    if sha256(path) != expected:
        raise ValueError(f"{purpose} SHA-256 mismatch: {path}")


def parse_debian_control(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8", errors="strict")
    if text.startswith("-----BEGIN PGP SIGNED MESSAGE-----"):
        _, separator, text = text.partition("\n\n")
        if not separator:
            raise ValueError(f"invalid clear-signed Debian descriptor: {path}")
        text = text.partition("\n-----BEGIN PGP SIGNATURE-----")[0]

    fields: dict[str, str] = {}
    current = ""
    for line in text.splitlines():
        if line.startswith((" ", "\t")):
            if current:
                fields[current] += "\n" + line.strip()
            continue
        if not line:
            current = ""
            continue
        name, separator, value = line.partition(":")
        if separator and re.fullmatch(r"[A-Za-z0-9-]+", name):
            current = name
            fields[current] = value.strip()
    return fields


def find_matching_dsc(
    source_dir: Path, source_package: str, source_version: str
) -> list[Path]:
    matches = []
    for candidate in source_dir.rglob("*.dsc"):
        if not candidate.is_file():
            continue
        resolved = candidate.resolve()
        if source_dir not in resolved.parents:
            raise ValueError(f"Debian descriptor escapes source directory: {candidate}")
        try:
            fields = parse_debian_control(candidate)
        except (OSError, UnicodeError, ValueError):
            continue
        if fields.get("Source") == source_package and fields.get("Version") == source_version:
            matches.append(candidate)
    return matches


def validate_debian_source(
    source_dir: Path, entry: dict[str, object], identity: tuple[str, str, str]
) -> None:
    _, source_package, source_version = identity
    descriptor = entry.get("descriptor")
    if not isinstance(descriptor, dict):
        raise ValueError(f"Debian source entry has no descriptor: {entry!r}")
    descriptor_path = safe_artifact_path(
        source_dir, descriptor.get("file"), "Debian descriptor"
    )
    if descriptor_path.suffix != ".dsc":
        raise ValueError(f"Debian descriptor is not a .dsc file: {descriptor_path}")
    verify_hash(descriptor_path, descriptor.get("sha256"), "Debian descriptor")

    matching = find_matching_dsc(source_dir, source_package, source_version)
    if len(matching) != 1 or matching[0].resolve() != descriptor_path.resolve():
        raise ValueError(
            f"expected exactly one matching .dsc for {source_package} {source_version}; "
            f"found {[str(path) for path in matching]}"
        )

    fields = parse_debian_control(descriptor_path)
    if fields.get("Source") != source_package:
        raise ValueError(
            f"Debian Source mismatch: expected {source_package}, got {fields.get('Source')!r}"
        )
    if fields.get("Version") != source_version:
        raise ValueError(
            f"Debian Version mismatch: expected {source_version}, got {fields.get('Version')!r}"
        )
    checksums = [
        line for line in fields.get("Checksums-Sha256", "").splitlines() if line.strip()
    ]
    if not checksums:
        raise ValueError(f"Debian descriptor has no Checksums-Sha256: {descriptor_path}")
    for checksum_line in checksums:
        parts = checksum_line.split(maxsplit=2)
        if len(parts) != 3 or not parts[1].isdigit():
            raise ValueError(f"invalid Checksums-Sha256 line: {checksum_line!r}")
        expected_hash, expected_size, artifact_name = parts
        artifact_relative = descriptor_path.parent.relative_to(source_dir) / artifact_name
        artifact_path = safe_artifact_path(
            source_dir, str(artifact_relative), "Debian source artifact"
        )
        if artifact_path.stat().st_size != int(expected_size):
            raise ValueError(f"Debian source artifact size mismatch: {artifact_path}")
        verify_hash(artifact_path, expected_hash, "Debian source artifact")


def validate_rpm_source(
    source_dir: Path, entry: dict[str, object], identity: tuple[str, str, str]
) -> None:
    _, source_package, source_version = identity
    source_rpm = entry.get("source_rpm")
    if not isinstance(source_rpm, dict):
        raise ValueError(f"RPM source entry has no source_rpm: {entry!r}")
    rpm_path = safe_artifact_path(source_dir, source_rpm.get("file"), "source RPM")
    verify_hash(rpm_path, source_rpm.get("sha256"), "source RPM")
    try:
        query = subprocess.check_output(
            [
                "rpm",
                "-qp",
                "--queryformat",
                "%{NAME}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCEPACKAGE}",
                str(rpm_path),
            ],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (FileNotFoundError, subprocess.CalledProcessError) as error:
        raise ValueError(f"invalid source RPM: {rpm_path}") from error
    name, version, release, architecture, source_package_flag = (
        query.split("\t") + [""] * 5
    )[:5]
    if (
        source_package_flag != "1"
        or not rpm_path.name.endswith(".src.rpm")
        or architecture not in ("src", "noarch", "x86_64")
    ):
        raise ValueError(
            f"RPM artifact is not a source RPM: {rpm_path} "
            f"(arch={architecture}, source={source_package_flag})"
        )
    if name != source_package:
        raise ValueError(f"source RPM name mismatch: expected {source_package}, got {name}")
    actual_source_version = f"{version}-{release}"
    if actual_source_version != source_version:
        raise ValueError(
            f"source RPM version mismatch: expected {source_version}, "
            f"got {actual_source_version}"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-dir", required=True)
    parser.add_argument("--manifest", action="append", default=[])
    args = parser.parse_args()

    source_dir = Path(args.source_dir).resolve()
    index_path = source_dir / "corresponding-source.json"
    if not index_path.is_file():
        print(f"Corresponding Source index is missing: {index_path}", file=sys.stderr)
        return 1

    try:
        index = json.loads(index_path.read_text(encoding="utf-8"))
        if index.get("schema_version") != 1:
            raise ValueError("unsupported corresponding-source schema_version")
        required = set()
        for manifest_name in args.manifest:
            manifest = json.loads(Path(manifest_name).read_text(encoding="utf-8"))
            required.update(
                (
                    entry["source_family"],
                    entry["source_package"],
                    entry["source_version"],
                )
                for entry in manifest["components"]
            )

        sources = index.get("sources")
        if not isinstance(sources, list) or not sources:
            raise ValueError("Corresponding Source index has no sources")

        covered = set()
        for source in sources:
            if not isinstance(source, dict):
                raise ValueError(f"invalid source entry: {source!r}")
            identity = (
                source.get("family"),
                source.get("source_package"),
                source.get("source_version"),
            )
            if not all(identity):
                raise ValueError(f"invalid source entry: {source!r}")
            if identity in covered:
                raise ValueError(f"duplicate source identity: {identity}")
            if identity[0] == "deb":
                validate_debian_source(source_dir, source, identity)
            elif identity[0] == "rpm":
                validate_rpm_source(source_dir, source, identity)
            else:
                raise ValueError(f"unsupported source family: {identity[0]!r}")
            covered.add(identity)

        missing = sorted(required - covered)
        if missing:
            raise ValueError(f"source index does not cover bundled components: {missing}")
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(f"Corresponding Source contract error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
