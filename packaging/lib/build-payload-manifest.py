#!/usr/bin/env python3
"""Generate payload evidence from a staged package, never from installed state.

Output must be outside the staged tree. Runtime metadata is added separately;
native package-file-list completeness checks remain mandatory for admission.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

PACKAGES = {"fic", "fic-runtime", "fic-dick", "fic-cli", "fic-gui", "fic-session-agent", "fic-prelogin"}
SLOTS = {"/etc/pam.d/" + name for name in (
    "fic-faillock-preauth", "fic-faillock-authfail", "fic-faillock-authsucc", "fic-faillock-account",
    "fic-password-quality", "fic-password-history", "fic-password-history-initial")}


def fingerprint(source, expected):
    def identity(value):
        return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
                value.st_uid, value.st_gid, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        if identity(os.fstat(descriptor)) != identity(expected):
            raise ValueError("payload changed before digest")
        digest = hashlib.sha256()
        count = 0
        while block := os.read(descriptor, 1024 * 1024):
            count += len(block)
            if count > expected.st_size:
                raise ValueError("payload grew while digesting")
            digest.update(block)
        if count != expected.st_size or identity(os.fstat(descriptor)) != identity(expected) or identity(source.lstat()) != identity(expected):
            raise ValueError("payload changed while digesting")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def build(root, package, version):
    if package not in PACKAGES or not version or len(version) > 128 or any(ord(c) < 32 or ord(c) == 127 for c in version):
        raise ValueError("invalid package manifest identity")
    rows = []
    budget = 256 * 1024 * 1024
    for directory, subdirs, files in os.walk(root, followlinks=False):
        for name in sorted([*subdirs, *files]):
            source = Path(directory) / name
            relative = source.relative_to(root)
            if relative.parts[0] == "DEBIAN":
                continue
            metadata = source.lstat()
            if stat.S_ISDIR(metadata.st_mode):
                continue
            path = "/" + relative.as_posix()
            if len(path) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in path):
                raise ValueError("invalid payload path")
            row = {"path": path, "group": "root"}
            if stat.S_ISLNK(metadata.st_mode):
                identity = os.readlink(source)
                if not identity or len(identity) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in identity):
                    raise ValueError("invalid payload symlink")
                row.update(kind="symlink", mode=0, identity=identity)
            elif stat.S_ISREG(metadata.st_mode):
                if metadata.st_nlink != 1 or metadata.st_size > min(budget, 64 * 1024 * 1024):
                    raise ValueError("aliased or oversized payload")
                budget -= metadata.st_size
                mode = stat.S_IMODE(metadata.st_mode)
                if mode & 0o7022 or not mode & 0o400:
                    raise ValueError("unsafe payload mode")
                if path.startswith("/opt/fic/"):
                    row["group"] = "fic"
                    mode = 0o750 if path.startswith("/opt/fic/bin/") else 0o640
                if path in SLOTS or path == "/etc/security/fic-pwhistory.conf":
                    if package != "fic" or mode != 0o644:
                        raise ValueError("managed PAM payload belongs only to fic")
                    row.update(kind="managed-pam-slot" if path in SLOTS else "managed-pam-provider", identity="")
                else:
                    row.update(kind="file", identity=fingerprint(source, metadata))
                row["mode"] = mode
            else:
                raise ValueError("unsupported payload object")
            rows.append(row)
            if len(rows) > 8192:
                raise ValueError("payload file count exceeded")
        if "DEBIAN" in subdirs and Path(directory) == root:
            subdirs.remove("DEBIAN")
    if not rows:
        raise ValueError("empty payload manifest")
    result = json.dumps({"schema": 1, "package": package, "version": version,
                         "files": sorted(rows, key=lambda row: row["path"])}, sort_keys=True) + "\n"
    if len(result.encode()) > 1024 * 1024:
        raise ValueError("payload manifest byte budget exceeded")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("package")
    parser.add_argument("version")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    if not root.is_dir() or root == Path("/"):
        raise ValueError("a staged package directory is required")
    output = args.output.absolute()
    if root == output or root in output.parents:
        raise ValueError("manifest output must be outside staged payload")
    content = build(root, args.package, args.version)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=output.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(content)
            stream.flush()
            os.fchmod(stream.fileno(), 0o644)
            os.fsync(stream.fileno())
        os.replace(temporary, output)
        directory = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
