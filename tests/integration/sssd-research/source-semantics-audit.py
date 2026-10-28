#!/usr/bin/env python3
"""Versioned source navigation for R2; no runtime claim inferred from a grep."""
from pathlib import Path
import hashlib,json,re
ROOT=Path(__file__).resolve().parents[3]
rules={
 'src/confdb/confdb.c':r'init_cached_auth_timeout|CONFDB_DOMAIN_CACHE_CREDS,|cred_expiration|CONFDB_PAM_CRED_TIMEOUT|domain->cache_credentials|enabled',
 'src/db/sysdb_ops.c':r'!domain->cache_credentials|SYSDB_LAST_ONLINE_AUTH,|CONFDB_PAM_CRED_TIMEOUT|expire_date = lastLogin|SYSDB_CACHEDPWD|SYSDB_LAST_LOGIN,|s3crypt_sha512',
 'src/db/sysdb_subdomains.c':r'cache_credentials|cached_auth_timeout',
 'src/providers/ldap/ldap_options.c':r'account_cache_expiration|offline_credentials_expiration|ret = EINVAL',
 'src/providers/ldap/ldap_opts.c':r'account_cache_expiration',
 'src/providers/ldap/ldap_id_cleanup.c':r'account_cache_expiration|SYSDB_LAST_LOGIN|sysdb_delete_user|still logged in|SYSDB_CACHE_EXPIRE',
 'src/providers/ldap/ldap_auth.c':r'cache_credentials|sysdb_cache_password',
 'src/providers/krb5/krb5_auth.c':r'cache_credentials|sysdb_cache_password|SSS_AUTHTOK_TYPE_SC|SSS_AUTHTOK_TYPE_PASSKEY',
 'src/providers/proxy/proxy_auth.c':r'cache_credentials|sysdb_cache_password',
 'src/providers/ad/ad_common.c':r'ad_create_sdap_options|dp_get_options|ad_def_ldap_opts',
 'src/providers/ipa/ipa_common.c':r'ipa_get_id_options|dp_get_options|ipa_def_ldap_opts',
 'src/providers/ad/ad_opts.c':r'account_cache_expiration',
 'src/providers/ipa/ipa_opts.c':r'account_cache_expiration',
 'src/providers/ad/ad_init.c':r'sdap_id_setup_tasks|ad_get_id_options',
 'src/providers/ipa/ipa_init.c':r'ipa_get_id_options|ldap_id_setup_tasks',
 'src/providers/ldap/ldap_common.c':r'sdap_id_setup_tasks|ldap_id_setup_tasks|ldap_id_cleanup|ldap_id_cleanup_create',
 'src/responder/pam/pamsrv_cmd.c':r'domain->cache_credentials|domain->cached_auth_timeout|sysdb_cache_auth|last_login \+ cached_auth_timeout|SYSDB_LAST_ONLINE_AUTH,|SYSDB_LAST_ONLINE_AUTH_WITH_CURR_TOKEN|local_auth_policy|cert_auth_local|BUILD_PASSKEY',
 'src/man/sssd.conf.5.xml':r'<term>(offline_credentials_expiration|cache_credentials \(|account_cache_expiration|cached_auth_timeout|enabled \()',
}
result={}
for profile in ('debian-12','debian-13','ubuntu-24.04','ubuntu-26.04','alt-p11'):
 cache=ROOT/'build-sssd-research'/profile/'source'
 src=next(p for p in cache.glob('sssd-*') if p.is_dir());files={}
 for rel,regex in rules.items():
  p=src/rel;lines=p.read_text().splitlines();selected=set()
  for i,line in enumerate(lines):
   if re.search(regex,line):selected.update(range(max(0,i-4),min(len(lines),i+(33 if rel.endswith('.xml') else 9))))
  files[rel]={'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'excerpts':[{'line':i+1,'text':lines[i]} for i in sorted(selected)]}
 calls=[];relations=[];cleanup=[];specific=[]
 for p in sorted((src/'src/providers').rglob('*.c')):
  for i,line in enumerate(p.read_text().splitlines()):
   if re.search(r'\bldap_get_options\s*\(',line):calls.append({'path':str(p.relative_to(src)),'line':i+1,'text':line})
   if 'account_cache_expiration' in line:relations.append({'path':str(p.relative_to(src)),'line':i+1,'text':line})
   if re.search(r'\b(?:ldap_id_setup_tasks|sdap_id_setup_tasks|ldap_id_cleanup)\s*\(',line):cleanup.append({'path':str(p.relative_to(src)),'line':i+1,'text':line})
 for provider in ('ad','ipa'):
  for p in sorted((src/'src/providers'/provider).rglob('*')):
   if not p.is_file() or p.suffix not in ('.c','.h'):continue
   for i,line in enumerate(p.read_text().splitlines()):
    if re.search(r'SDAP_ACCOUNT_CACHE_EXPIRATION|CONFDB_PAM_CRED_TIMEOUT|\bldap_get_options\s*\(',line):specific.append({'path':str(p.relative_to(src)),'line':i+1,'text':line})
 result[profile]={'source_tree':src.name,'archive_provenance':'source-r1.json', 'files':files,
                  'ldap_get_options_references':calls,'account_option_references':relations,'cleanup_setup_references':cleanup,
                  'ad_ipa_specific_relation_symbol_search':{'patterns':['SDAP_ACCOUNT_CACHE_EXPIRATION','CONFDB_PAM_CRED_TIMEOUT','ldap_get_options('],'scope':'src/providers/{ad,ipa}/**/*.[ch]','matches':specific}}
(ROOT/'tests/integration/sssd-research/source-r2.json').write_text(json.dumps(result,indent=2)+'\n')
