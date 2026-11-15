"""Actual A2 daemon startup; only disposable systemd, RO sysfs/proc-sys."""
import ast
import json
import os
from pathlib import Path
import re
import shutil
import socket
import sqlite3
import struct
import sys
import subprocess
import threading
import time

assert os.environ.get('FIC_PACKAGE_LIFECYCLE_NATIVE') == '1'
assert Path('/proc/1/comm').read_text().strip() == 'systemd'
assert os.stat('/proc/self/ns/mnt').st_ino != int(os.environ['FIC_HOST_MNT_INODE'])
assert {p.name for p in Path('/sys/class/net').iterdir()} == {'lo'}
assert os.statvfs('/sys').f_flag & os.ST_RDONLY
assert os.statvfs('/proc/sys').f_flag & os.ST_RDONLY
OUT=Path('/var/tmp/fic-package-results');OUT.mkdir(exist_ok=True)
group=os.environ.get('FIC_A2_TEST_GROUP','all');assert group in ('all','remaining','restart')
report={'commands':[],'cases':[],'group':group}
def save(): (OUT/'startup-results.json').write_text(json.dumps(report,indent=2))
def run(args,timeout=180,check=True,input=None):
    start=time.monotonic();p=subprocess.run(args,input=input,text=True,capture_output=True,timeout=timeout)
    r={'argv':args,'exit':p.returncode,'seconds':round(time.monotonic()-start,3),'stdout':p.stdout,'stderr':p.stderr}
    report['commands'].append(r);save()
    if check:assert p.returncode==0,r
    return r
def ctl(*args,check=True):return run(['systemctl',*args],check=check)
def request(command,device=False,**fields):
    with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as s:
        s.settimeout(70);s.connect('/run/fic/fic-device.sock' if device else '/run/fic/fic.sock')
        s.send(json.dumps(dict(api_version=1,command=command,**fields)).encode());data=b''
        while True:
            frame=s.recv(1024*1024);magic,total,off,n=struct.unpack('!4I',frame[:16])
            assert magic==0x00464943 and off==len(data) and len(frame)==16+n and total<16*1024*1024
            data+=frame[16:]
            if len(data)==total:return json.loads(data)
def state(unit):
    p=ctl('show',unit,'--property=MainPID,InvocationID,ActiveState,SubState,Type,After,Requires,Wants,StatusText,NotifyAccess,TimeoutStartUSec')
    return dict(x.split('=',1) for x in p['stdout'].splitlines() if '=' in x)
def journal(unit='fic.service'):
    inv=state(unit)['InvocationID']
    return [json.loads(x).get('MESSAGE','') for x in run(['journalctl','--no-pager','-o','json','_SYSTEMD_INVOCATION_ID='+inv])['stdout'].splitlines() if x]
def prelogin():
    s=request('prelogin_status')
    p=run(['/usr/local/bin/startup-readiness-tests','--prelogin-status'],input=json.dumps(s))
    return s,json.loads(p['stdout'])['may_auto_handoff']
def graph():
    main=state('fic.service');dev=state('fic-device.service')
    assert 'fic-device.service' in main['Wants'].split() and 'fic.service' in dev['Requires'].split()
    assert 'fic-device.service' not in main['After'].split() and 'fic.service' not in dev['After'].split()
    assert main['Type']==dev['Type']=='notify' and main['NotifyAccess']==dev['NotifyAccess']=='main'
    assert main['TimeoutStartUSec']==dev['TimeoutStartUSec']=='10min'
    return {'main':main,'device':dev}
def stop():ctl('stop','fic.service','fic-device.service');ctl('reset-failed','fic.service','fic-device.service')
def wait_device():return run(['/opt/fic/bin/fic-dick','wait-daemon','20'])
def case(name,units=('fic.service','fic-device.service'),success=True):
    start=ctl('start',*units,check=success);run(['/opt/fic/bin/fic','--maintenance','wait-daemon','20'])
    s,auto=prelogin();events=[]
    for line in journal():
        if line.startswith('{'):
            e=json.loads(line)
            if e.get('event')=='policy_apply_pass' and e.get('reason')=='startup':events.append(e)
    assert len(events)==1,events
    e=events[0];assert e['result']['ok']==s['startup_apply_ok']==success,(name,e,s)
    assert s['startup_apply_started'] and s['startup_apply_completed'] and s['startup_lifecycle_completed']
    assert auto==success,(name,s,auto)
    assert e['result']['startup_device_ipc_ready']==success
    assert e['result']['device_reconciliation_attempted']==success
    if success:assert e['result']['device_reconciliation'] and e['summary']['failed']==0
    else:assert not e['result']['device_reconciliation'] and 'deadline' in s['diagnostic']
    r={'name':name,'start':start,'status':s,'auto_handoff':auto,'event':e,'graph':graph() if success else {'main':state('fic.service'),'device':state('fic-device.service')}};report['cases'].append(r);save();print(name,'PASS',start['seconds'],flush=True);return r

ctl('mask','--runtime','--now','getty@tty1.service','console-getty.service',check=False)
packages=sorted(map(str,Path('/var/tmp/fic-packages').glob('*.deb')));assert len(packages)==3
run(['dpkg','-i',*packages],timeout=300);stop()
for p in Path('/opt/fic/config').glob('*.conf'):
    text=re.sub(r'(?m)^(\w+\.status)=ENABLE$',r'\1=DISABLE',p.read_text())
    if p.name=='GLOBAL.conf':
        for k in ('lang','incident_response_mode','lock_exempt_fic_members'):text=text.replace(k+'.status=DISABLE',k+'.status=ENABLE')
        text=re.sub(r'(?m)^incident_response_mode.value=.*$','incident_response_mode.value=PASSIVE',text)
    if p.name=='DC.conf':text=text.replace('permanent_device_missing_severity.status=DISABLE','permanent_device_missing_severity.status=ENABLE')
    p.write_text(text)
graph()
if group=='restart':
    case('restart-group-initial')
    before={'main':state('fic.service'),'device':state('fic-device.service')}
    restart=ctl('restart','fic.service')
    r=case('explicit-main-restart',('fic.service',));r['restart']=restart;r['before']=before
    assert before['main']['MainPID']!=r['graph']['main']['MainPID']
    wait_device();stop()
    assert state('fic.service')['ActiveState']=='inactive' and state('fic-device.service')['ActiveState']=='inactive'
    report['stopped_writers']={'main':state('fic.service'),'device':state('fic-device.service')}
    report['result']='PASS';save();print('explicit restart/stop suite PASS',flush=True);sys.exit(0)
if group=='all':
    case('cold-both-all-block-disabled');stop()
    case('main-only',('fic.service',));stop();case('device-only',('fic-device.service',));stop()
# Only the device ELF receives the existing deterministic post-socket delay shim.
module=ast.parse(Path('/var/tmp/slow_init_native.py').read_text())
shim=next(ast.literal_eval(n.value) for n in module.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='SLOW_OPEN_SHIM' for t in n.targets))
Path('/var/tmp/slow.c').write_text(shim);run(['gcc','-shared','-fPIC','/var/tmp/slow.c','-ldl','-o','/var/tmp/slow.so'])
drop=Path('/etc/systemd/system/fic-device.service.d/a2-test.conf');drop.parent.mkdir(exist_ok=True,parents=True)
def delay(seconds):
    Path('/var/tmp/fic-slow-init.log').unlink(missing_ok=True)
    drop.write_text('[Service]\nEnvironment=LD_PRELOAD=/var/tmp/slow.so\nEnvironment=SLOW_INIT_SLEEP_SECONDS='+str(seconds)+'\n');ctl('daemon-reload')
p=Path('/opt/fic/config/DC.conf');disabled=p.read_text();p.write_text(disabled.replace('block_usb_storage.status=DISABLE','block_usb_storage.status=ENABLE').replace('block_usb_storage.value=all','block_usb_storage.value=new'))
if group=='all':
    delay(45);r=case('slow45-enabled-DC');assert r['event']['result']['startup_device_wait_ms']<60000
    r['injection']=Path('/var/tmp/fic-slow-init.log').read_text()
    stamps=dict(re.findall(r'(started_at_ns|finished_at_ns)=(\d+)',r['injection']))
    assert int(stamps['finished_at_ns'])-int(stamps['started_at_ns'])>=44_000_000_000
    assert int(stamps['started_at_ns'])>Path('/run/fic/fic-device.sock').stat().st_mtime_ns
    save();stop();drop.unlink();ctl('daemon-reload')
# A wrong-version root server responds successfully to status but MUST NOT get writes.
ctl('mask','--runtime','fic-device.service');sock=Path('/run/fic/fic-device.sock');sock.unlink(missing_ok=True)
listener=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);listener.bind(str(sock));listener.listen(16);listener.settimeout(.1)
finished=threading.Event();commands=[]
def serve():
    while not finished.is_set():
        try:c,_=listener.accept()
        except socket.timeout:continue
        with c:
            data=c.recv(65536)
            if not data:continue
            commands.append(json.loads(data)['command']);payload=json.dumps(dict(api_version=1,ok=True,message='ready',product_version='INCOMPATIBLE_SECRET',database_schema_version=2)).encode()
            try:c.send(struct.pack('!4I',0x00464943,len(payload),0,len(payload))+payload)
            except BrokenPipeError:pass
thread=threading.Thread(target=serve,daemon=True);thread.start()
r=case('incompatible-device-nonfatal',('fic.service',),False)
assert r['event']['summary']['applied']>=4 and r['event']['summary']['failed']==1
assert commands and set(commands)=={'status'} and 'INCOMPATIBLE_SECRET' not in r['status']['diagnostic']
finished.set();thread.join();listener.close();sock.unlink(missing_ok=True)
ctl('unmask','--runtime','fic-device.service');ctl('start','fic-device.service');wait_device();assert request('apply_all')['ok'];s,auto=prelogin();assert not s['startup_apply_ok'] and not auto
r['after_late_success']=s;r['commands_received']=sorted(set(commands));save();stop()
# Real missing endpoint, crash-before-ready and udev publication failure, each with production 60s budget.
ctl('mask','--runtime','fic-device.service');r=case('missing-device-nonfatal',('fic.service',),False);assert 59<=r['start']['seconds']<90;stop();ctl('unmask','--runtime','fic-device.service')
db=Path('/opt/fic/db/devices.db');backup=db.read_bytes();db.write_bytes(b'corrupt native fixture')
try:case('device-init-failure-nonfatal',('fic.service',),False);assert state('fic-device.service')['ActiveState']!='active'
finally:stop();db.write_bytes(backup)
bad=Path('/etc/udev/rules.d/99-fic-devices.rules.tmp');bad.mkdir()
try:case('device-policy-activation-failure-nonfatal',('fic.service',),False);assert state('fic-device.service')['ActiveState']!='active'
finally:stop();bad.rmdir()
p.write_text(disabled)
# Existing detector sends a real fact; no fabricated main-daemon event request.
database=sqlite3.connect(db);database.execute("INSERT INTO devices(device_hash,devpath,subsystem,device_type,control_level,control_explicit,boot_id) VALUES(?,?,?,?,?,?,?)",('a2-native-permanent','/devices/fic-a2-absent','usb','device','permanent',1,'old-boot'));database.commit();database.close()
case('missing-permanent-startup');wait_device();ack=request('device_check_permanent',True);assert ack['ok'] and ack['missing'] and not ack['retry_required'];report['permanent_ack']=ack;save()
ctl('restart','fic-device.service');wait_device();assert request('status',True)['ok'];stop();case('main-after-restart');stop()
# Early ACTIVE block and crash severity are tested BEFORE waiting; no ACTIVE auth claim.
ctl('start','fic.service');run(['/opt/fic/bin/fic-cli','incident','raise','isolate']);stop()
global_file=Path('/opt/fic/config/GLOBAL.conf');passive=global_file.read_text();global_file.write_text(passive.replace('incident_response_mode.value=PASSIVE','incident_response_mode.value=ACTIVE'))
ctl('start','ssh.service');ctl('mask','--runtime','fic-device.service');ctl('start','--no-block','fic.service')
deadline=time.monotonic()+60
while state('fic.service')['StatusText']!='Waiting for device administrative IPC':
    assert time.monotonic()<deadline;time.sleep(.05)
active={'main':state('fic.service'),'ssh':state('ssh.service'),'lockstatus':Path('/opt/fic/lockstatus').read_text(),
        'ruleset':json.loads(run(['nft','-j','list','ruleset'])['stdout'])}
assert active['lockstatus']=='ISOLATE\n'
assert any(x.get('chain',{}).get('table')=='fic_incident_quarantine' and
           x['chain'].get('policy')=='drop' for x in active['ruleset']['nftables'])
assert active['main']['ActiveState']=='activating' and active['ssh']['ActiveState']=='inactive' and not Path('/run/fic/fic.sock').exists()
start=time.monotonic();ctl('stop','fic.service');active['stop_seconds']=time.monotonic()-start;assert active['stop_seconds']<3
assert not any('"event":"policy_apply_pass"' in x for x in journal())
report['active_early_protection_and_SIGTERM']=active;save()
global_file.write_text(passive);ctl('unmask','--runtime','fic-device.service');case('recovery-passive');request('incident_clear');stop()
# Uninstall mode must not perform this wait or apply/reconcile.
ctl('start','fic.service');assert request('prepare_uninstall')['ok'];stop();ctl('start','fic.service');s=request('status');assert s['ok']
assert state('fic.service')['ActiveState']=='active' and state('fic-device.service')['ActiveState']!='active'
report['uninstall_mode']={'main':state('fic.service'),'device':state('fic-device.service')};stop();save()
run(['dpkg','--audit']);report['result']='PASS';save();print('A2 real startup suite PASS',flush=True)
