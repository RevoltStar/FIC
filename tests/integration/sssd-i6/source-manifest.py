#!/usr/bin/env python3
"""Source binding for real I6 daemon/CLI/packages, independent of I1–I5 reports."""
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
def manifest():
    paths={ROOT/'CMakeLists.txt'}
    for folder in ('fic','fic-cli','fic-dick','fic-common','fic-gui','fic-session-agent','fic-prelogin','cmake','packaging'):
        paths.update(p for p in (ROOT/folder).rglob('*') if p.is_file() and p.suffix in ('.cpp','.h','.c','.cmake','.txt','.in','.conf','.lang','.sh','.py','.qrc'))
    # Maintainer scripts, PAM slots and installed executables often have no
    # conventional source suffix; they are real package-build inputs too.
    for folder in ('packaging','fic/src/resources'):
        paths.update(p for p in (ROOT/folder).rglob('*') if p.is_file() and p.suffix!='.md' and not p.name.startswith('Dockerfile'))
    for name in ('build-deb.sh','build-rpm.sh'):
        paths.add(ROOT/'tests/integration/package-lifecycle'/name)
    return {str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}
def harness_manifest():
    paths={p for p in Path(__file__).resolve().parent.iterdir() if p.is_file() and p.suffix in ('.py','.sh')}
    paths|={Path(__file__).resolve().parent/'Containerfile',ROOT/'tests/integration/sssd-research/common.py'}
    return {str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}
if __name__=='__main__':
    current=harness_manifest() if "--harness" in sys.argv else manifest()
    sys.argv=[a for a in sys.argv if a!="--harness"]
    if len(sys.argv)==3 and sys.argv[1]=='check':
        assert current==json.loads(Path(sys.argv[2]).read_text()),'source changed during I6 native build/run; discard result'
    else:print(json.dumps(current,indent=2)+'\n',end='')
