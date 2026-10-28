from pathlib import Path
import re,json,hashlib
root=Path(__file__).resolve().parents[3]
rules={
'src/monitor/monitor.c':r'notify_startup|sd_notify|started_services ==|socket_activated|confdb_setup\(|confdb_read_ini\(|CONFDB_DEFAULT_CONFIG_DIR|monitor_hup',
'src/util/sss_ini.c':r'sss_ini_read_sssd_conf|sss_ini_add_snippets|INI_MV[12]S_OVERWRITE|ini_config_augment|access_check_ini|sss_ini_access_check|CONFDB_FALLBACK_CONFIG|ERR_INI_EMPTY_CONFIG',
'src/confdb/confdb.h':r'SSSD_CONFIG_FILE|CONFDB_DEFAULT_CONFIG_DIR|CONFDB_FALLBACK_CONFIG',
'src/tools/sssctl/sssctl_config.c':r'sssctl_config_snippet_path|config_snippet_path =|sss_ini_read_sssd_conf|sss_ini_get_cfgobj',
'src/confdb/confdb_setup.c':r'confdb_read_ini|sss_ini_read_sssd_conf|confdb_setup|confdb_create|confdb_write|config.ldb',
}
audit={}
for profile in ('debian-12','debian-13','ubuntu-24.04','ubuntu-26.04','alt-p11'):
 cache=root/'build-sssd-research'/profile/'source';src=next(p for p in cache.glob('sssd-*') if p.is_dir())
 files={}
 for rel,regex in rules.items():
  p=src/rel; lines=p.read_text().splitlines(); hits=[i for i,l in enumerate(lines) if re.search(regex,l)];selected=set()
  for i in hits:selected.update(range(max(0,i-2),min(len(lines),i+6)))
  files[rel]={'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'excerpts':[{'line':i+1,'text':lines[i]} for i in sorted(selected)]}
 archives={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in cache.iterdir() if p.is_file() and (p.name.endswith(('.dsc','.src.rpm','.tar.gz','.tar.xz','.tar','.patch')))}
 audit[profile]={'source_tree':src.name,'archives':archives,'distribution_patches':'debian/patches applied by apt-get source' if profile!='alt-p11' else 'sssd.spec %prep: %setup; %patch -p1 (applied)', 'files':files}
(root/'tests/integration/sssd-research/source-r1.json').write_text(json.dumps(audit,indent=2)+'\n')
