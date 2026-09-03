#!/usr/bin/env python3
"""Verify the source archive set required by official binary releases."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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
        required = set()
        for manifest_name in args.manifest:
            manifest = json.loads(Path(manifest_name).read_text(encoding="utf-8"))
            required.update(
                (entry["source_package"], entry["source_version"])
                for entry in manifest["components"]
            )

        covered = set()
        for source in index.get("sources", []):
            identity = (source.get("source_package"), source.get("source_version"))
            artifacts = source.get("artifacts", [])
            if not all(identity) or not artifacts:
                raise ValueError(f"invalid source entry: {source!r}")
            for artifact in artifacts:
                relative = Path(artifact["file"])
                if relative.is_absolute() or ".." in relative.parts:
                    raise ValueError(f"unsafe source artifact path: {relative}")
                artifact_path = source_dir / relative
                if not artifact_path.is_file():
                    raise ValueError(f"source artifact is missing: {artifact_path}")
                if source_dir not in artifact_path.resolve().parents:
                    raise ValueError(f"source artifact escapes source directory: {artifact_path}")
                expected_hash = artifact.get("sha256", "")
                if not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
                    raise ValueError(f"invalid source artifact SHA-256: {artifact_path}")
                if sha256(artifact_path) != expected_hash:
                    raise ValueError(f"source artifact hash mismatch: {artifact_path}")
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
