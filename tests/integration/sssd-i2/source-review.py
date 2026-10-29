#!/usr/bin/env python3
"""Extract versioned source semantics; source observations are not runtime proof."""
import hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
r2=json.loads((HERE.parent/'sssd-research/source-r2.json').read_text())
rules={
 'src/confdb/confdb.c':[(r'^static errno_t get_entry_as_bool\(',42),(r'^static errno_t init_cached_auth_timeout\(',55),
                       (r'^int confdb_get_enabled_domain_list\(',85),(r'^static int confdb_get_domain_enabled\(',70),
                       (r'&domain->cache_credentials',5),(r'val = strtol\(values\[0\], &endptr, 0\)',5)],
 'src/providers/data_provider/dp_targets.c':[(r'^static const char \*dp_target_default_module\(',23)],
 'src/providers/ldap/ldap_options.c':[(r'account_cache_expiration',6),(r'cred_expiration',8)],
 'src/providers/ldap/ldap_opts.c':[(r'account_cache_expiration',1)],
}
out={}
for platform,review in r2.items():
 source=ROOT/'build-sssd-research'/platform/'source'/review['source_tree'];files={}
 for rel,patterns in rules.items():
  p=source/rel;data=p.read_bytes();digest=hashlib.sha256(data).hexdigest()
  if rel in review['files']:assert digest==review['files'][rel]['sha256'],(platform,rel)
  lines=data.decode().splitlines();indices=set()
  for pattern,count in patterns:
   for i,line in enumerate(lines):
    if re.search(pattern,line):indices.update(range(max(0,i-3),min(len(lines),i+count)))
  assert indices,(platform,rel)
  files[rel]={'sha256':digest,'excerpts':[{'line':i+1,'text':lines[i]} for i in sorted(indices)]}
 out[platform]={'provenance':'unchanged R1 source archives/patches and R2 audited tree','source_tree':review['source_tree'],'files':files,'status':'SOURCE_CONFIRMED; not functional AD/IPA/cleanup proof'}
(HERE/'source-review.json').write_text(json.dumps(out,indent=2)+'\n')
print('I2 versioned source review exported for five platforms')
