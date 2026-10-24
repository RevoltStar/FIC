#!/usr/bin/env python3
"""Native research, not a production activator or a policy acceptance gate."""
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import time

ROOT=Path('/run/fic-socket-research')
OUT=ROOT/'results'
MAIN=Path('/etc/ssh/sshd_config')
DROP=Path('/etc/ssh/sshd_config.d')
GEN='/usr/lib/systemd/system-generators/sshd-socket-generator'

def run(args, check=True):
    p=subprocess.run(args,capture_output=True,text=True,timeout=25)
    if check and p.returncode: raise RuntimeError(f'{args[0]}: {p.returncode} {p.stderr[:1000]}')
    return p

def ctl(*args,check=True): return run(['systemctl',*args],check)
def props(unit):
    raw=ctl('show',unit).stdout
    # Keep only public launch/runtime properties, no environment secrets.
    wanted={'Id','Names','UnitFileState','ActiveState','SubState','MainPID','InvocationID','Job','Result','Listen','Accept','BindIPv6Only','FreeBind','Service','Triggers','TriggeredBy','Type','NotifyAccess','FragmentPath','DropInPaths','Requires','After','Before','ExecStart','ExecStartPre','NConnections','NRestarts','ControlGroup'}
    out={}
    for line in raw.splitlines():
        if '=' not in line:continue
        k,v=line.split('=',1)
        if k not in wanted:continue
        if k=='Listen':out.setdefault(k,[]).append(v)
        else:out[k]=v
    return out

def listeners():
    out=[]
    for name,family in [('tcp',socket.AF_INET),('tcp6',socket.AF_INET6)]:
        for row in Path('/proc/net/'+name).read_text().splitlines()[1:]:
            a=row.split()
            if a[3]!='0A': continue
            h,p=a[1].split(':')
            raw=bytes.fromhex(h)
            raw=raw[::-1] if family==socket.AF_INET else b''.join(raw[i:i+4][::-1] for i in range(0,16,4))
            out.append({'family':4 if family==socket.AF_INET else 6,'address':socket.inet_ntop(family,raw),'port':int(p,16),'inode':int(a[9])})
    return sorted(out,key=lambda x:(x['port'],x['family'],x['address']))

def fds(pid):
    result={}
    if not pid: return result
    for path in Path(f'/proc/{pid}/fd').glob('*'):
        try: link=os.readlink(path)
        except FileNotFoundError: continue
        match=re.fullmatch(r'socket:\[(\d+)\]',link)
        if match: result[path.name]=int(match[1])
    return result

def snapshot():
    service=props('ssh.service');sock=props('ssh.socket')
    return {'service':service,'socket':sock,'listeners':listeners(),'manager_socket_fds':fds(1),'service_socket_fds':fds(int(service.get('MainPID','0'))),
            'generated':{str(p):p.read_text() for p in Path('/run/systemd/generator').glob('ssh*.d/*') if p.is_file()}}

def config(port=2222, family='any', extra=''):
    addresses=['ListenAddress 127.0.0.1'] if family=='inet' else ['ListenAddress ::1'] if family=='inet6' else ['ListenAddress 127.0.0.1','ListenAddress ::1']
    return '\n'.join([f'Port {port}',f'AddressFamily {family}',*addresses,'PermitRootLogin no','PubkeyAuthentication yes','UsePAM yes','MaxAuthTries 3',extra,''])

def wait_service():
    deadline=time.monotonic()+10
    while time.monotonic()<deadline:
        p=props('ssh.service')
        if p.get('ActiveState')=='active' and p.get('SubState')=='running': return p
        if p.get('ActiveState')=='failed': raise RuntimeError('service failed: '+str(p))
        time.sleep(.02)
    raise RuntimeError('bounded native readiness wait expired')

def connect(port,family=socket.AF_INET):
    s=socket.socket(family);s.settimeout(5)
    s.connect(('127.0.0.1' if family==socket.AF_INET else '::1',port))
    banner=s.recv(256)
    assert banner.startswith(b'SSH-2.0-'),banner
    wait_service()
    return s

def manual_generator(label):
    d=ROOT/label
    d.mkdir()
    for name in ('normal','early','late'): (d/name).mkdir()
    p=run([GEN,str(d/'normal'),str(d/'early'),str(d/'late')],False)
    return {'returncode':p.returncode,'stderr':p.stderr[:1000],'files':{str(f.relative_to(d)):f.read_text() for f in d.rglob('*') if f.is_file()}}

def guard():
    assert os.geteuid()==0 and os.environ.get('FIC_SOCKET_RESEARCH') and Path('/.dockerenv').exists()
    assert Path('/proc/1/comm').read_text()=='systemd\n'
    st=os.stat('/proc/self/ns/mnt');one=os.stat('/proc/1/ns/mnt')
    assert (st.st_dev,st.st_ino)==(one.st_dev,one.st_ino)
    assert f'{st.st_dev}:{st.st_ino}'!=os.environ['FIC_SOCKET_HOST_NS']
    assert [p.name for p in Path('/sys/class/net').iterdir()]==['lo']

def main():
    guard()
    OUT.mkdir(parents=True)
    report={'packages':run(['dpkg-query','-W','openssh-server','systemd']).stdout,'os_release':Path('/etc/os-release').read_text(),'kernel':os.uname().release,'cases':{}}
    def save(): (OUT/'report.json').write_text(json.dumps(report,indent=2))
    report['vendor_units']={u:Path('/usr/lib/systemd/system/'+u).read_text() for u in ('ssh.service','ssh.socket')}
    report['generator_sha256']=hashlib.sha256(Path(GEN).read_bytes()).hexdigest()
    try:
        ctl('stop','ssh.service','ssh.socket',check=False)
        # Fixture administrative provisioning only; production must never do this.
        ctl('disable','ssh.service',check=False);ctl('enable','ssh.socket')
        for p in DROP.iterdir():
            assert p.is_file() and not p.is_symlink();p.unlink()
        Path('/etc/default/ssh').write_text('SSHD_OPTS=\n')
        run(['ip','link','set','lo','up'])
        runtime_directory=Path('/run/sshd')
        if runtime_directory.exists(): runtime_directory.rmdir()
        report['cases']['native-probe-without-runtime-directory']={
            flag:{'returncode':p.returncode,'stderr':p.stderr.strip()} for flag in ('-T','-t')
            for p in [run(['/usr/sbin/sshd',flag],False)]}
        assert all(x['returncode']!=0 for x in report['cases']['native-probe-without-runtime-directory'].values())
        MAIN.write_text('UsePAM yes\n')
        report['cases']['default-generator']=manual_generator('default')
        MAIN.write_text('AddressFamily inet\nUsePAM yes\n')
        report['cases']['default-generator-inet']=manual_generator('default-inet')
        MAIN.write_text('AddressFamily inet6\nUsePAM yes\n')
        report['cases']['default-generator-inet6']=manual_generator('default-inet6')
        MAIN.write_text(config());Path('/run/sshd').mkdir(exist_ok=True);run(['/usr/sbin/sshd','-t'])
        report['cases']['manual_generator']=manual_generator('manual-base')
        ctl('daemon-reload');ctl('reset-failed','ssh.service','ssh.socket');ctl('start','ssh.socket')
        first=snapshot();report['cases']['socket_only']=first
        ctl('start','dbus.service')
        report['socket_api']=run(['busctl','--system','--no-pager','introspect','org.freedesktop.systemd1','/org/freedesktop/systemd1/unit/ssh_2esocket','org.freedesktop.systemd1.Socket']).stdout
        assert first['socket']['UnitFileState']=='enabled' and first['socket']['SubState']=='listening'
        assert first['service']['ActiveState']=='inactive',first
        assert {x['port'] for x in first['listeners']}=={2222}
        inherited={x['inode'] for x in first['listeners']}
        assert inherited.issubset(set(first['manager_socket_fds'].values()))
        connection=connect(2222)
        active=snapshot();report['cases']['activated']=active
        assert inherited.issubset(set(active['service_socket_fds'].values())),active
        assert inherited=={x['inode'] for x in active['listeners']}
        MAIN.write_text(config(2244))
        report['cases']['persistent_change_without_reload']={'runtime':snapshot(),'effective':run(['/usr/sbin/sshd','-T']).stdout.splitlines()[:12]}
        assert {x['port'] for x in listeners()}=={2222}
        ctl('daemon-reload');loaded=snapshot();report['cases']['reload_without_socket_restart']=loaded
        assert any('2244' in x for x in loaded['socket']['Listen']) and {x['port'] for x in listeners()}=={2222}
        ctl('restart','ssh.socket');changed=snapshot();report['cases']['socket_restart_with_connection']=changed
        assert {x['port'] for x in changed['listeners']}=={2244},changed
        assert not inherited.intersection(x['inode'] for x in changed['listeners'])
        connection.close()
        c=connect(2244);report['cases']['new_socket_inheritance']=snapshot();c.close()
        for family,port in [('inet',2255),('inet6',2266)]:
            ctl('stop','ssh.service','ssh.socket');MAIN.write_text(config(port,family));ctl('daemon-reload');ctl('reset-failed','ssh.service','ssh.socket');ctl('start','ssh.socket')
            case=snapshot();report['cases']['family-'+family]=case
            assert {x['port'] for x in case['listeners']}=={port}
            assert {x['family'] for x in case['listeners']}==({4} if family=='inet' else {6})
        ctl('stop','ssh.service','ssh.socket')
        MAIN.write_text('Include /etc/ssh/sshd_config.d/*.conf\nAddressFamily inet\nListenAddress 127.0.0.1\nUsePAM yes\n')
        (DROP/'10-parent.conf').write_text('Include /etc/ssh/sshd_config.d/nested.inc\n')
        (DROP/'nested.inc').write_text('Port 2277\n')
        report['cases']['nested-Include']=manual_generator('nested')
        assert '2277' in json.dumps(report['cases']['nested-Include'])
        for p in DROP.iterdir():p.unlink()
        # Research-only single-file RO mount to determine generator visibility.
        # Not an alternative production snapshot engine or a full input proof.
        MAIN.write_text(config(2288,'inet'))
        held=os.open(MAIN,os.O_RDWR)
        snap=ROOT/'snapshot';snap.mkdir()
        run(['mount','-t','tmpfs','-o','size=1m,mode=0700','fic-ubuntu-research',str(snap)])
        (snap/'main').write_text(MAIN.read_text())
        run(['mount','-o','remount,ro',str(snap)])
        run(['mount','--bind',str(snap/'main'),str(MAIN)])
        try:
            replacement=config(2299,'inet').encode();os.ftruncate(held,0);os.pwrite(held,replacement,0);os.fsync(held)
            report['cases']['protected-generator']=manual_generator('protected')
            ctl('daemon-reload');report['cases']['protected-daemon-reload']=snapshot()
            assert '2288' in json.dumps(report['cases']['protected-generator'])
            assert any('2288' in x for x in props('ssh.socket')['Listen'])
        finally:
            run(['umount',str(MAIN)]);os.close(held);run(['umount',str(snap)])
        assert '2299' in MAIN.read_text() and any('2288' in x for x in props('ssh.socket')['Listen'])
        report['cases']['persistent-versus-loaded-after-cleanup']=snapshot()
        ctl('start','ssh.socket');assert {x['port'] for x in listeners()}=={2288}
        report['cases']['stale-loaded-listener']=snapshot()
        ctl('stop','ssh.service','ssh.socket')
        report['cases']['enabled-inactive-socket']=snapshot()
        blocker=socket.socket();blocker.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        blocker.bind(('127.0.0.1',2288));blocker.listen(1)
        try:
            failed=ctl('start','ssh.socket',check=False)
            report['cases']['failed-socket']={'start_returncode':failed.returncode,'state':snapshot()}
            assert failed.returncode and props('ssh.socket')['ActiveState']=='failed'
        finally:blocker.close()
        ctl('reset-failed','ssh.service','ssh.socket')
        ctl('stop','ssh.service','ssh.socket');ctl('disable','ssh.socket')
        ctl('start','ssh.service');disabled=snapshot();report['cases']['disabled-socket-manual-service']=disabled
        # RequiredBy installed dependency can pull socket in even when disabled.
        assert disabled['socket']['UnitFileState']=='disabled'
        report['complete']=True;save()
        print(json.dumps({'native_research':'PASS','cases':len(report['cases']),'packages':report['packages']}))
    except Exception as e:
        report['error']=str(e);save();raise
    finally:
        (OUT/'ssh-journal.log').write_text(run(['journalctl','-u','ssh.service','-u','ssh.socket','-n','120','--no-pager'],False).stdout)

if __name__=='__main__':
    import sys
    if sys.argv[1:]==['--self-test']:
        saved=os.environ.pop('FIC_SOCKET_RESEARCH',None)
        try:
            try:guard()
            except AssertionError:pass
            else:raise AssertionError('unmarked research environment accepted')
            assert 'ListenAddress ::1' in config() and 'ListenAddress ::1' not in config(family='inet')
            print('Ubuntu socket research guard PASS')
        finally:
            if saved is not None:os.environ['FIC_SOCKET_RESEARCH']=saved
    elif not sys.argv[1:]:main()
    else:raise SystemExit('unsupported research arguments')
