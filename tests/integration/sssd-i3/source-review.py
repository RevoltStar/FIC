#!/usr/bin/env python3
"""Extract versioned distribution source anchors; not a runtime proof alone."""
import hashlib,json,re
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
patterns={
 'src/monitor/monitor.c':r'confdb_setup\(|notify_startup|start_service\(|start_backend|service_startup_handler',
 'src/confdb/confdb_setup.c':r'confdb_setup\(|confdb_read_ini\(|confdb_create_base',
 'src/confdb/confdb.c':r'confdb_get_domain_internal|CONFDB_DOMAIN_CACHE_CREDS|CONFDB_DOMAIN_CACHED_AUTH_TIMEOUT|CONFDB_PAM_CRED_TIMEOUT|cached_auth_timeout|cache_credentials',
 'src/providers/data_provider_be.c':r'confdb_get_domain|dp_init_send|dp_init_recv|dp_initialized|sss_monitor_service_init|be_process_init|dp_init\(|sss_monitor_register_service',
 'src/providers/data_provider/dp_iface_backend.c':r'dp_backend_is_online|be_is_offline|domain',
 'src/sss_iface/sss_iface.c':r'sss_sbus_connect|sss_monitor_register_service|SSS_BUS_ADDRESS',
 'src/sbus/server/sbus_server_interface.c':r'GetNameOwner|GetConnectionUnixProcessID|sbus_server_bus_get_connection_unix_process_id',
 'src/providers/data_provider/dp.c':r'dp_init_send|dp_init_targets|dp_init_done|dp_init_recv|dp_init\(|sss_sbus_connect',
 'src/providers/ldap/ldap_options.c':r'account_cache_expiration|offline_credentials_expiration|sdap_get_options|SDAP_ACCOUNT_CACHE_EXPIRATION',
 'src/providers/ldap/ldap_id_cleanup.c':r'account_cache_expiration|SDAP_ACCOUNT_CACHE_EXPIRATION|ldap_id_cleanup',
 'src/responder/common/responder_common.c':r'sss_process_init|confdb_get_domains|sss_monitor_service_init|sss_cmd_get_version|SSS_GET_VERSION',
 'src/responder/pam/pamsrv.c':r'pam_process_init|sss_process_init|sss_monitor_service_init|server_loop|pam_process_init',
 'src/responder/pam/pamsrv_cmd.c':r'cached_auth_timeout|cache_credentials|offline_credentials_expiration|CONFDB_PAM_CRED_TIMEOUT|pam_cache_auth',
 'src/db/sysdb_ops.c':r'CONFDB_PAM_CRED_TIMEOUT|offline_credentials_expiration|cached_auth_timeout|sysdb_cache_auth',
 'src/util/sss_monitor.c':r'sss_monitor_service_init|sbus_connect|RegisterService',
}
r1=json.loads((HERE.parent/'sssd-research/source-r1.json').read_text())
result={}
for platform in sorted(r1):
 src=next(p for p in (ROOT/'build-sssd-research'/platform/'source').glob('sssd-*') if p.is_dir())
 files={}
 for path,pattern in patterns.items():
  f=src/path
  if not f.exists():continue
  data=f.read_bytes();lines=data.decode().splitlines();anchors=[]
  for i,line in enumerate(lines):
   if re.search(pattern,line):anchors.append({'line':i+1,'text':'\n'.join(lines[max(0,i-2):i+5])})
  if anchors:files[path]={'sha256':hashlib.sha256(data).hexdigest(),'anchors':anchors}
 assert 'src/providers/data_provider_be.c' in files and 'src/confdb/confdb.c' in files
 for path,entry in r1[platform]['files'].items():
  if path in files:assert files[path]['sha256']==entry['sha256']
 result[platform]={'source_tree':src.name,'archive_provenance':'../sssd-research/source-r1.json','files':files}
(HERE/'source-review.json').write_text(json.dumps(result,indent=2)+'\n')
print('I3 versioned source anchors collected; causal argument is reviewed separately')
