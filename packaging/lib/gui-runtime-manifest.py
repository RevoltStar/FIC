#!/usr/bin/env python3
"""Generate and verify the fic-gui bundled-runtime compliance manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


DOC_ROOT = Path("usr/share/doc/fic-gui")
QT_ROOT = Path("opt/fic/qt")
MANIFEST_NAME = "third-party-components.json"


def run(*args: str) -> str:
    return subprocess.check_output(args, text=True, stderr=subprocess.DEVNULL).strip()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def deb_owner(source_path: Path) -> str:
    candidates = [str(source_path)]
    if str(source_path).startswith("/usr/"):
        candidates.append(str(source_path)[4:])
    for candidate in candidates:
        try:
            return run("dpkg-query", "-S", candidate).splitlines()[0].split(": ", 1)[0]
        except (subprocess.CalledProcessError, IndexError):
            pass
    raise RuntimeError(f"no Debian package owns {source_path}")


def deb_metadata(source_path: Path) -> dict[str, str]:
    owner_line = deb_owner(source_path)
    package = owner_line
    fields = run(
        "dpkg-query",
        "-W",
        "-f=${Version}\t${source:Package}\t${source:Version}",
        package,
    ).split("\t")
    version, source_package, source_version = (fields + [""] * 3)[:3]
    source_package = source_package or package.split(":", 1)[0]
    source_version = source_version or version
    copyright_path = Path("/usr/share/doc") / package.split(":", 1)[0] / "copyright"
    if not copyright_path.exists():
        raise RuntimeError(f"missing Debian copyright file for {package}: {copyright_path}")
    license_values = []
    for line in copyright_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("License:"):
            value = line.partition(":")[2].strip()
            if value and value not in license_values:
                license_values.append(value)
                break
    return {
        "package": package,
        "version": version,
        "source_package": source_package,
        "source_version": source_version,
        "package_license_summary": (
            "; ".join(license_values) or "unknown; see packaged copyright file"
        ),
        "license_metadata_scope": "distribution-package-summary",
        "notice_sources": [str(copyright_path.resolve())],
    }


def rpm_metadata(source_path: Path) -> dict[str, str]:
    fields = run(
        "rpm",
        "-qf",
        "--queryformat",
        "%{NAME}\t%{VERSION}-%{RELEASE}\t%{LICENSE}\t%{SOURCERPM}",
        str(source_path),
    ).split("\t")
    package, version, license_value, source_rpm = (fields + [""] * 4)[:4]
    related_packages = []
    for line in run("rpm", "-qa", "--queryformat", "%{NAME}\t%{SOURCERPM}\\n").splitlines():
        related_name, _, related_source_rpm = line.partition("\t")
        if related_source_rpm == source_rpm:
            related_packages.append(related_name)
    notice_sources = []
    for related_package in related_packages:
        for path_text in run("rpm", "-ql", related_package).splitlines():
            path = Path(path_text)
            if path.is_file() and re.search(r"(?:license|copying)", path.name, re.IGNORECASE):
                resolved = str(path.resolve())
                if resolved not in notice_sources:
                    notice_sources.append(resolved)
    if not notice_sources:
        raise RuntimeError(f"missing RPM license file for {package}")
    source_match = re.fullmatch(r"(qt6-base)-(.+)\.src\.rpm", source_rpm)
    source_package = source_match.group(1) if source_match else source_rpm.removesuffix(".src.rpm")
    source_version = source_match.group(2) if source_match else version
    return {
        "package": package,
        "version": version,
        "source_package": source_package,
        "source_version": source_version,
        "package_license_summary": license_value or "unknown; see packaged license file",
        "license_metadata_scope": "rpm-package-metadata",
        "notice_sources": notice_sources,
    }


def license_text(family: str, name: str) -> Path:
    candidates = {
        "LGPL-3.0-only.txt": [
            "/usr/share/common-licenses/LGPL-3",
            "/usr/share/license/common/LGPLv3",
            "/usr/share/license/LGPL-3.0-only",
            "/usr/share/licenses/common/LGPL-3.0-only.txt",
        ],
        "GPL-3.0-only.txt": [
            "/usr/share/common-licenses/GPL-3",
            "/usr/share/license/common/GPLv3",
            "/usr/share/license/GPL-3.0-only",
            "/usr/share/licenses/common/GPL-3.0-only.txt",
        ],
    }[name]
    for candidate in candidates:
        path = Path(candidate)
        if path.is_file():
            return path
    wanted = name
    for base in (Path("/usr/share/license"), Path("/usr/share/licenses")):
        if base.is_dir():
            matches = sorted(base.rglob(wanted))
            if matches:
                return matches[0]
    raise RuntimeError(f"{family} build environment has no canonical {name} text")


def assert_qt_base_component(metadata: dict[str, str], installed_path: str) -> None:
    source = metadata["source_package"].lower()
    if not (source == "qt6-base" or source.startswith("qt6-base-")):
        raise RuntimeError(
            f"{installed_path} comes from unexpected Qt source package {metadata['source_package']!r}"
        )


def copy_notice(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def generate(args: argparse.Namespace) -> None:
    package_root = Path(args.package_root).resolve()
    doc_root = package_root / DOC_ROOT
    licenses_root = doc_root / "licenses"
    package_notices = licenses_root / "packages"
    package_notices.mkdir(parents=True, exist_ok=True)

    copy_notice(Path(args.project_license), licenses_root / "FIC-SUL-1.0.txt")
    for name in ("LGPL-3.0-only.txt", "GPL-3.0-only.txt"):
        copy_notice(license_text(args.family, name), licenses_root / name)

    metadata_cache: dict[str, dict[str, str]] = {}
    entries_by_path: dict[str, dict[str, object]] = {}
    notices_by_digest: dict[str, Path] = {}
    metadata_reader = deb_metadata if args.family == "deb" else rpm_metadata

    for raw_line in Path(args.mapping).read_text(encoding="utf-8").splitlines():
        if not raw_line:
            continue
        installed_path, source_path_text, kind = raw_line.split("\t")
        source_path = Path(source_path_text).resolve()
        cache_key = str(source_path)
        metadata = metadata_cache.setdefault(cache_key, metadata_reader(source_path))
        assert_qt_base_component(metadata, installed_path)
        if metadata["package_license_summary"].startswith("unknown"):
            print(
                f"warning: no machine-readable license declaration for {metadata['package']}; "
                "packaged notice is authoritative",
                file=sys.stderr,
            )

        notice_stem = re.sub(r"[^A-Za-z0-9_.+-]", "_", metadata["source_package"])
        notice_relatives = []
        for notice_source_text in metadata["notice_sources"]:
            notice_source = Path(notice_source_text)
            notice_digest = sha256(notice_source)
            notice_relative = notices_by_digest.get(notice_digest)
            if notice_relative is None:
                source_name = re.sub(r"[^A-Za-z0-9_.+-]", "_", notice_source.name)
                notice_relative = Path("licenses/packages") / f"{notice_stem}-{source_name}"
                notice_destination = doc_root / notice_relative
                if notice_destination.exists() and sha256(notice_destination) != notice_digest:
                    notice_relative = Path("licenses/packages") / (
                        f"{notice_stem}-{notice_digest[:12]}-{source_name}"
                    )
                    notice_destination = doc_root / notice_relative
                if not notice_destination.exists():
                    copy_notice(notice_source, notice_destination)
                notices_by_digest[notice_digest] = notice_relative
            notice_relatives.append(notice_relative)

        installed_file = package_root / installed_path.lstrip("/")
        real_installed_file = installed_file.resolve()
        entries_by_path[installed_path] = {
            "name": installed_file.name,
            "kind": kind,
            "installed_path": installed_path,
            "source_path": str(source_path),
            "package": metadata["package"],
            "version": metadata["version"],
            "package_license_summary": metadata["package_license_summary"],
            "license_metadata_scope": metadata["license_metadata_scope"],
            "source_package": metadata["source_package"],
            "source_version": metadata["source_version"],
            "source_family": args.family,
            "license_files": [
                {
                    "path": f"/usr/share/doc/fic-gui/{path.as_posix()}",
                    "sha256": sha256(doc_root / path),
                }
                for path in notice_relatives
            ],
            "sha256": sha256(real_installed_file),
        }

    components = [entries_by_path[path] for path in sorted(entries_by_path)]
    if not components:
        raise RuntimeError("Qt runtime mapping is empty")

    manifest = {
        "schema_version": 1,
        "package": "fic-gui",
        "fic_license": "SUL-1.0",
        "third_party_scope": "/opt/fic/qt",
        "components": components,
    }
    manifest_path = doc_root / MANIFEST_NAME
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    source_pairs = sorted({(e["source_package"], e["source_version"]) for e in components})
    source_lines = "\n".join(f"- `{package}` version `{version}`" for package, version in source_pairs)
    offer = f"""# Corresponding Source for bundled fic-gui components

This binary package contains dynamically linked third-party Qt components. FIC
itself remains licensed under SUL-1.0. The exact source package identities for
this build are:

{source_lines}

The publisher of a public FIC release must retain and distribute a corresponding
source artifact set matching these exact versions, including downstream patches
and package build metadata. A link to a generic upstream Qt download is not a
substitute for that artifact set.

For Debian-family build repositories, a maintainer can retrieve a recorded
version with `apt-get source SOURCE_PACKAGE=SOURCE_VERSION` after enabling the
matching `deb-src` repository. For ALT package repositories, use the matching
source RPM named by `source_package` in `third-party-components.json`.

The official release workflow requires a separately supplied, checksummed
corresponding-source index before it can publish binary package artifacts. See
`docs/third-party-licensing.md` in the FIC source tree for that release contract.
"""
    (doc_root / "SOURCE_OFFER.md").write_text(offer, encoding="utf-8")
    verify(argparse.Namespace(package_root=str(package_root)))


def payload_paths(package_root: Path) -> set[str]:
    root = package_root / QT_ROOT
    return {
        "/" + str(path.relative_to(package_root))
        for path in root.rglob("*")
        if path.is_file() or path.is_symlink()
    }


def package_path(package_root: Path, path_text: object, purpose: str) -> Path:
    if not isinstance(path_text, str):
        raise RuntimeError(f"{purpose} path is not a string: {path_text!r}")
    path = Path(path_text)
    if not path.is_absolute() or ".." in path.parts:
        raise RuntimeError(f"unsafe {purpose} path: {path_text!r}")
    candidate = package_root.joinpath(*path.parts[1:])
    resolved = candidate.resolve()
    if resolved == package_root or package_root not in resolved.parents:
        raise RuntimeError(f"{purpose} path escapes package root: {path_text!r}")
    return candidate


def verify(args: argparse.Namespace) -> None:
    package_root = Path(args.package_root).resolve()
    doc_root = package_root / DOC_ROOT
    mandatory = [
        doc_root / MANIFEST_NAME,
        doc_root / "SOURCE_OFFER.md",
        doc_root / "licenses/FIC-SUL-1.0.txt",
        doc_root / "licenses/LGPL-3.0-only.txt",
        doc_root / "licenses/GPL-3.0-only.txt",
    ]
    missing = [str(path) for path in mandatory if not path.is_file()]
    if missing:
        raise RuntimeError("missing compliance payload: " + ", ".join(missing))

    manifest = json.loads((doc_root / MANIFEST_NAME).read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 1:
        raise RuntimeError("unsupported runtime manifest schema_version")
    entries = manifest.get("components", [])
    if not isinstance(entries, list) or not entries:
        raise RuntimeError("runtime manifest has no components")
    manifest_paths = {entry["installed_path"] for entry in entries}
    if len(manifest_paths) != len(entries):
        raise RuntimeError("runtime manifest contains duplicate installed paths")
    actual_paths = payload_paths(package_root)
    if manifest_paths != actual_paths:
        missing_entries = sorted(actual_paths - manifest_paths)
        stale_entries = sorted(manifest_paths - actual_paths)
        raise RuntimeError(
            f"runtime manifest mismatch; unlisted={missing_entries}, absent={stale_entries}"
        )
    for entry in entries:
        for field in (
            "name",
            "kind",
            "installed_path",
            "source_path",
            "package",
            "version",
            "package_license_summary",
            "license_metadata_scope",
            "source_package",
            "source_version",
            "source_family",
            "sha256",
        ):
            if not entry.get(field):
                raise RuntimeError(f"manifest entry {entry!r} has empty {field}")
        if entry["kind"] not in ("library", "plugin"):
            raise RuntimeError(f"manifest entry has invalid kind: {entry!r}")
        if entry["source_family"] not in ("deb", "rpm"):
            raise RuntimeError(f"manifest entry has invalid source_family: {entry!r}")
        installed_file = package_path(
            package_root, entry["installed_path"], "component"
        )
        if not installed_file.is_file():
            raise RuntimeError(f"manifest component is missing: {entry['installed_path']}")
        if not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]):
            raise RuntimeError(f"invalid component SHA-256: {entry['installed_path']}")
        if sha256(installed_file.resolve()) != entry["sha256"]:
            raise RuntimeError(f"component SHA-256 mismatch: {entry['installed_path']}")
        license_files = entry.get("license_files")
        if not isinstance(license_files, list) or not license_files:
            raise RuntimeError(
                f"manifest entry has no authoritative license_files: {entry!r}"
            )
        for notice in license_files:
            if not isinstance(notice, dict):
                raise RuntimeError(f"invalid component notice entry: {notice!r}")
            notice_path = package_path(
                package_root, notice.get("path"), "component notice"
            )
            if not notice_path.is_file() or notice_path.is_symlink():
                raise RuntimeError(f"missing component notice {notice.get('path')}")
            notice_hash = notice.get("sha256", "")
            if not isinstance(notice_hash, str) or not re.fullmatch(
                r"[0-9a-f]{64}", notice_hash
            ):
                raise RuntimeError(f"invalid component notice SHA-256: {notice!r}")
            if sha256(notice_path.resolve()) != notice_hash:
                raise RuntimeError(
                    f"component notice SHA-256 mismatch: {notice.get('path')}"
                )


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    generate_parser = subparsers.add_parser("generate")
    generate_parser.add_argument("--family", choices=("deb", "rpm"), required=True)
    generate_parser.add_argument("--package-root", required=True)
    generate_parser.add_argument("--mapping", required=True)
    generate_parser.add_argument("--project-license", required=True)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--package-root", required=True)
    args = parser.parse_args()
    try:
        if args.command == "generate":
            generate(args)
        else:
            verify(args)
    except (OSError, RuntimeError, subprocess.CalledProcessError, ValueError, json.JSONDecodeError) as error:
        print(f"fic-gui runtime compliance error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
