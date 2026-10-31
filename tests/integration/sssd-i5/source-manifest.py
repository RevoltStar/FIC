#!/usr/bin/env python3
"""Inputs for the isolated I5 probe/fixture build; no authority over production."""
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
def manifest():
 paths=set((ROOT/'fic/src/service').glob('VerifiedConfig*.cpp'))|set((ROOT/'fic/src/service').glob('VerifiedConfig*.h'))|set((ROOT/'fic/src/service/sssd').glob('*'))
 paths|={p for folder in ('fic-common/fic-core','fic-common/fic-policy','fic/src/platform') for p in (ROOT/folder).rglob('*') if p.is_file() and p.suffix in ('.h','.cpp','.in','.txt')}
 paths|=set((ROOT/'cmake').glob('*.cmake'))
 paths|={ROOT/p for p in ('fic/src/modules/identity_access/sssd/SssdConfiguration.h','fic/src/modules/identity_access/sssd/SssdConfiguration.cpp','fic/src/modules/identity_access/shared/configuration/PreparedFileChange.cpp','fic/src/modules/identity_access/composite/ConfigurationTransaction.cpp','tests/fic/service/SssdProvenRemovalTests.cpp','tests/fic/service/SssdTransactionTests.cpp','tests/CMakeLists.txt','tests/integration/user_creation/CMakeLists.txt')}
 paths|=set((ROOT/'fic/src/rollback').glob('Mutation*'))|{ROOT/'fic/src/rollback/SssdJournalPayload.h'}
 paths|={ROOT/'tests/integration'/p for p in ('sssd-i5/Driver.cpp','sssd-i4/StagedWriteCrash.cpp','sssd-i5/CMakeLists.txt','sssd-i5/native.py','sssd-i5/run-native.sh','sssd-i5/source-manifest.py','sssd-research/common.py')}
 return {str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths) if p.is_file()}
if __name__=='__main__':
 current=manifest()
 if len(sys.argv)==3 and sys.argv[1]=='check':assert current==json.loads(Path(sys.argv[2]).read_text()),'source changed during native build/run; discard result'
 else:print(json.dumps(current,indent=2))
