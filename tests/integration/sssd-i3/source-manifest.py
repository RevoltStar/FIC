#!/usr/bin/env python3
"""Inputs for the isolated I3 probe/fixture build; no authority over production."""
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
def manifest():
 paths=set((ROOT/'fic/src/service').glob('VerifiedConfig*.cpp'))|set((ROOT/'fic/src/service').glob('VerifiedConfig*.h'))|set((ROOT/'fic/src/service/sssd').glob('*'))
 paths|={ROOT/'tests/integration'/p for p in ('sssd-i3/Driver.cpp','sssd-i3/CMakeLists.txt','sssd-i3/native.py','sssd-i3/run-native.sh','sssd-i3/source-manifest.py','sssd-research/common.py','sssd-research/r2_auth.py','sssd-research/pam-probe.py')}
 return {str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths) if p.is_file()}
if __name__=='__main__':
 current=manifest()
 if len(sys.argv)==3 and sys.argv[1]=='check':assert current==json.loads(Path(sys.argv[2]).read_text()),'source changed during native build/run; discard result'
 else:print(json.dumps(current,indent=2))
