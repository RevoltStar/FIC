#!/usr/bin/env python3
"""Download exact distro source descriptors and verify their declared SHA256s.
No package install, build or host security mutation. dpkg-source applies distro patches.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import urllib.request

BASE = "https://deb.debian.org/debian/pool/main/o/openssh/"
VERSIONS = {"debian12": "9.2p1-2+deb12u10", "debian13": "10.0p1-7+deb13u4"}
DESCRIPTOR_SHA256 = {
    "debian12": "af8cfb3ce783604abd28183a52aa0bde8c6bc603cc35758035db48d1dac5f2e2",
    "debian13": "73fed3fd77d60925ed342bcb0afd3c037e4ea0d39333107bf617aa90f859910f",
}

def fetch(url, path):
    if not path.exists():
        with urllib.request.urlopen(url, timeout=90) as response:
            path.write_bytes(response.read())
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    root = Path(sys.argv[1]); root.mkdir(parents=True, exist_ok=True)
    evidence = {}
    for distro, version in VERSIONS.items():
        dest = root / distro; dest.mkdir(exist_ok=True)
        name = "openssh_" + version + ".dsc"
        descriptor = dest / name
        descriptor_sha = fetch(BASE + name, descriptor)
        assert descriptor_sha == DESCRIPTOR_SHA256[distro], 'exact descriptor reference changed'
        checks = descriptor.read_text().split("Checksums-Sha256:\n", 1)[1].split("\nFiles:", 1)[0]
        files = []
        for expected, size, filename in re.findall(r"^ ([0-9a-f]{64}) (\d+) ([^\s]+)$", checks, re.M):
            assert Path(filename).name == filename, 'invalid archive filename'
            target = dest / filename
            actual = fetch(BASE + filename, target)
            assert actual == expected and target.stat().st_size == int(size), filename
            files.append({"url": BASE + filename, "sha256": actual, "size": int(size)})
        tree = dest / "tree"
        if not tree.exists():
            subprocess.run(["dpkg-source", "-x", str(descriptor), str(tree)], check=True, stdout=subprocess.DEVNULL)
        evidence[distro] = {"version": version, "descriptor": BASE + name, "descriptor_sha256": descriptor_sha, "files": files,
                            "series": (tree / "debian/patches/series").read_text(),
                            "patches": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (tree / "debian/patches").glob("*.patch")}}
    (root / "source-evidence.json").write_text(json.dumps(evidence, indent=2))

if __name__ == "__main__": main()
