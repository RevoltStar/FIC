#!/usr/bin/env python3
"""Actual Debian12 FIC packages, CLI and package uninstall in disposable runtime."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
assert os.environ.get('FIC_SYSCTL_NATIVE')=='1' and Path('/.dockerenv').exists()
assert Path('/proc/1/comm').read_text().strip()=='systemd'
assert os.stat('/proc/self/ns/net').st_ino!=int(os.environ['FIC_HOST_NET'])
assert os.statvfs('/proc/sys/kernel').f_flag & os.ST_RDONLY
assert not os.statvfs('/proc/sys/net').f_flag & os.ST_RDONLY
out=Path('/var/tmp/sysctl-package-results');out.mkdir(exist_ok=True)
report={'platform':'debian-12','events':[]}
def save():(out/'results.json').write_text(json.dumps(report,indent=2)+'\n')
def run(args,check=True):
 p=subprocess.run(args,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=600)
 report['events'].append({'command':args,'exit_code':p.returncode,'output':p.stdout});save()
 print(p.returncode,' '.join(args),flush=True)
 if check:assert p.returncode==0,p.stdout
 return p
cli='/opt/fic/bin/fic-cli';policy='ipv4_packet_forwarding_disable'
def command(*args):return run([cli,*args])
def config():return {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in Path('/opt/fic/config').glob('*') if p.is_file()}
def journal():return json.loads(Path('/opt/fic/db/mutation-journal.json').read_text())
def owned():return [r for r in journal()['records'] if r['backend']=='sysctl' and r['status']=='applied']
try:
 # Native fixture: readonly sysfs would otherwise disable udev sockets needed
 # by the actual device-daemon package. No production unit is changed.
 for unit in ('systemd-udevd.service','systemd-udevd-control.socket','systemd-udevd-kernel.socket'):
  d=Path('/etc/systemd/system')/(unit+'.d');d.mkdir(exist_ok=True)
  (d/'readonly-test.conf').write_text('[Unit]\nConditionPathIsReadWrite=\n')
 run(['systemctl','daemon-reload'])
 run(['systemctl','start','systemd-udevd-control.socket','systemd-udevd-kernel.socket','systemd-udevd.service'])
 for directory in ('/etc/sysctl.d','/run/sysctl.d','/usr/local/lib/sysctl.d','/usr/lib/sysctl.d','/lib/sysctl.d'):
  root=Path(directory)
  if root.exists():
   for p in root.glob('*.conf'):p.unlink()
 foreign=Path('/etc/sysctl.d/10-administrator.conf');foreign.write_text('net.ipv4.ip_forward = 1\nnet.ipv4.ip_forward_use_pmtu = 1\n')
 baseline=foreign.read_bytes();live=Path('/proc/sys/net/ipv4/ip_forward');other=Path('/proc/sys/net/ipv4/ip_forward_use_pmtu')
 live.write_text('1');other.write_text('0')
 packages=sorted(Path('/var/tmp/fic-packages').glob('*.deb'));assert len(packages)==3,packages
 report['packages']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in packages}
 run(['dpkg','-i',*map(str,packages)])
 report['daemon_elf_sha256']=hashlib.sha256(Path('/opt/fic/bin/fic').read_bytes()).hexdigest()
 assert report['daemon_elf_sha256']==os.environ['FIC_EXPECTED_DAEMON_SHA256'],'package ELF differs from explicitly built daemon'
 assert Path('/var/lib/fic-lifecycle/status').read_text()=='INSTALLED\n'
 command('policy','enable','SYSCTL',policy);command('policy','apply','SYSCTL',policy)
 managed=Path('/etc/sysctl.d/zzzz-fic.conf')
 assert managed.exists() and 'net.ipv4.ip_forward = 0' in managed.read_text() and live.read_text().strip()=='0'
 assert len(owned())==1 and owned()[0]['undo']['sysctl']['container_created']
 saved=journal();content=managed.read_bytes();ino=managed.stat().st_ino
 command('policy','apply','SYSCTL',policy)
 assert journal()==saved and managed.read_bytes()==content and managed.stat().st_ino==ino
 live.write_text('1');command('policy','apply','SYSCTL',policy)
 assert journal()==saved and live.read_text().strip()=='0'
 configuration=config();command('prepare-uninstall');command('policy','rollback','all')
 assert not managed.exists() and not owned() and live.read_text().strip()=='1' and other.read_text().strip()=='0'
 assert config()==configuration and foreign.read_bytes()==baseline
 run(['dpkg','--remove','fic-cli','fic','fic-dick'])
 assert Path('/var/lib/fic-lifecycle/status').read_text()=='REMOVED\n' and config()==configuration
 run(['dpkg','--purge','fic-cli','fic','fic-dick'])
 assert not Path('/opt/fic/db/mutation-journal.json').exists() and foreign.read_bytes()==baseline
 report.update(status='PASS',actual_packages=True,cli_owned_apply=True,no_op=True,runtime_only=True,
  prepare_uninstall=True,rollback_all=True,native_foreign_value=True,no_unrelated_write=True,remove=True,purge=True,configuration_unchanged=True)
 save()
finally:
 report['diagnostics']=run(['journalctl','-u','fic.service','-u','fic-device.service','-n','100','--no-pager'],False).stdout;save()
