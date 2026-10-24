#!/usr/bin/env python3
"""Real Ubuntu policy/module gate. Only the guarded disposable native runner."""
import importlib.util
import json
import os
import shutil
import socket
import time
from pathlib import Path

spec=importlib.util.spec_from_file_location('native','/usr/local/bin/fic-openssh-harness.py')
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)

def ctl(*args,check=True): return h.run(['systemctl',*args],check=check)
def listeners():
    result={}
    for file,family in [('tcp',socket.AF_INET),('tcp6',socket.AF_INET6)]:
        for line in Path('/proc/net/'+file).read_text().splitlines()[1:]:
            v=line.split()
            if v[3]!='0A':continue
            raw,port=v[1].split(':');data=bytes.fromhex(raw)
            data=data[::-1] if family==socket.AF_INET else b''.join(data[i:i+4][::-1] for i in range(0,16,4))
            result[(socket.inet_ntop(family,data),int(port,16))]=int(v[9])
    return result

def main():
    h.guard();report={'cases':[],'environment':{'os_release':Path('/etc/os-release').read_text(),'kernel':os.uname().release,'packages':h.run(['dpkg-query','-W','openssh-server','systemd']).stdout}}
    def save(): (h.OUT/'results.json').write_text(json.dumps(report,indent=2))
    def reset(extra='',family='any'):
        ctl('stop','ssh.service','ssh.socket',check=False)
        h.drive('cleanup',{'paths':[]})
        ctl('unset-environment','FIC_OPENSSH_TEST_CHANGE')
        for unit in ('ssh.service','ssh.socket'):
            shutil.rmtree('/etc/systemd/system/'+unit+'.d',ignore_errors=True)
            ctl('unmask',unit,check=False)
        ctl('disable','ssh.service',check=False);ctl('enable','ssh.socket')
        for p in h.DROP.iterdir():
            if p.is_dir() and not p.is_symlink():shutil.rmtree(p)
            else:p.unlink()
        h.MAIN.unlink(missing_ok=True)
        addresses='' if family=='wildcard' else 'ListenAddress 127.0.0.1\nListenAddress ::1\n' if family=='any' else 'ListenAddress 127.0.0.1\n' if family=='inet' else 'ListenAddress ::1\n'
        af='any' if family=='wildcard' else family
        h.MAIN.write_text(f'Include {h.DROP}/*.conf\nPort 2222\nAddressFamily {af}\n'+addresses+f'HostKey {h.KEY}\nPermitRootLogin yes\nPubkeyAuthentication no\nUsePAM no\nMaxAuthTries 6\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n'+extra)
        h.MAIN.chmod(0o644);h.ENV.write_text('SSHD_OPTS=\n');h.ENV.chmod(0o644)
        shutil.rmtree(h.WORK/'module-state',ignore_errors=True)
        ctl('daemon-reload');ctl('reset-failed','ssh.service','ssh.socket',check=False);ctl('start','ssh.socket')
        assert h.state()['ActiveState']=='inactive'
    def case(name,operations,success=True):
        req=h.request();req['operations']=operations
        result=h.drive('module',req);report['cases'].append({'name':name,'result':result});save()
        rows=result['module'];assert len(rows)==len(operations) and all(r['applied']==success for r in rows),(name,result)
        return rows
    try:
        Path('/run/fic').mkdir(exist_ok=True)
        if not h.KEY.exists():h.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(h.KEY)])
        reset()
        selected=[{'policy':p,'value':v} for p,v in [('ssh_root_login','no'),('ssh_pubkey_auth','yes'),('ssh_use_pam','yes'),('ssh_max_auth_tries','3'),('ssh_port','2244')]]
        before=listeners()
        if Path('/run/sshd').exists(): Path('/run/sshd').rmdir()
        assert not Path('/run/sshd').exists(), 'absent stock runtime directory probe'
        rows=case('five-real-policies-inactive-service-receipt',selected*3)
        after=listeners();assert {p for a,p in after}=={2244},after
        assert not set(before.values())&set(after.values())
        assert all(r['main_unchanged'] and r['before_invocation']==r['after_invocation'] for r in rows[-5:]),rows
        assert len(rows[-1]['records'])==5
        effective=dict(line.split(' ',1) for line in h.run(['/usr/sbin/sshd','-T']).stdout.splitlines())
        for key,wanted in {'permitrootlogin':'no','pubkeyauthentication':'yes','usepam':'yes','maxauthtries':'3','port':'2244'}.items():assert effective[key]==wanted
        def fds(pid):
            found=set()
            for p in Path('/proc/'+str(pid)+'/fd').iterdir():
                try:link=os.readlink(p)
                except FileNotFoundError:continue
                if link.startswith('socket:['):found.add(int(link[8:-1]))
            return found
        assert set(after.values())<=fds(1)&fds(rows[-1]['after_pid'])
        report['runtime_proof']={'before':[{'address':a,'port':p,'inode':i} for (a,p),i in before.items()],
                                 'after':[{'address':a,'port':p,'inode':i} for (a,p),i in after.items()],
                                 'manager_fd_inodes':sorted(fds(1)), 'sshd_fd_inodes':sorted(fds(rows[-1]['after_pid'])),
                                 'effective':{key:effective[key] for key in ('permitrootlogin','pubkeyauthentication','usepam','maxauthtries','port')}}
        assert all(r['socket_before']==r['socket_after'] for r in rows[-5:]),rows
        print('Ubuntu initial five policies PASS',flush=True)
        for family in ('inet','inet6','wildcard'):
            reset(family=family);old=listeners()
            case('Port-'+family,[{'policy':'ssh_port','value':'2244'}])
            now=listeners();assert {p for a,p in now}=={2244} and not set(old.values())&set(now.values())
        reset(family='wildcard')
        case('default-port22-no-generated-output',[{'policy':'ssh_port','value':'22'}])
        assert not Path('/run/systemd/generator/ssh.socket.d/addresses.conf').exists()
        assert {p for a,p in listeners()}=={22}
        reset()
        h.MAIN.write_text(h.MAIN.read_text().replace('PermitRootLogin yes' ,'PermitRootLogin no'))
        rows=case('foreign-compliant-no-enrollment',[{'policy':'ssh_root_login','value':'no'}]*2)
        assert all(r['main_unchanged'] and not r['records'] for r in rows),rows
        assert rows[1]['before_invocation']==rows[1]['after_invocation']
        reset(extra='Match User nobody\n    X11Forwarding no\n')
        (h.DROP/'10.conf').write_text('Include /etc/ssh/sshd_config.d/nested/leaf.inc\n')
        (h.DROP/'nested').mkdir();(h.DROP/'nested/leaf.inc').write_text('LogLevel VERBOSE\n')
        case('recursive-Include-unrelated-Match',[{'policy':'ssh_root_login','value':'no'}])
        for name,extra in [('outside-empty','Include /run/fic-openssh-work/nope-*.conf\n'),
                           ('conditional-selected','Match User nobody\n    PermitRootLogin yes\n'),
                           ('conditional-Include','Match User nobody\n    Include /etc/ssh/sshd_config.d/conditional.inc\n')]:
            reset(extra=extra)
            if name=='conditional-Include':(h.DROP/'conditional.inc').write_text('PermitRootLogin yes\n')
            row=case(name,[{'policy':'ssh_root_login','value':'no'}],False)[0]
            assert row['main_unchanged'] and not row['records'],row
        reset();(h.DROP/'foreign.conf').write_text('Port 2277\n')
        row=case('foreign-extra-Port',[{'policy':'ssh_port','value':'2244'}],False)[0];assert row['main_unchanged']
        for fault in ('main-cas','foreign-input','disable','after-save-stop','after-save-disable','after-save-input','after-save-main','durability','unknown-writer','journal-commit'):
            reset()
            rows=case('module-fault-'+fault,[{'policy':'ssh_use_pam','value':'yes','fault':fault}],False)
            if fault.startswith('after-') or fault in ('durability','unknown-writer','journal-commit'):
                assert not rows[0]['main_unchanged'] and (rows[0]['records'] or rows[0]['journal_unusable']),rows
        reset()
        rows=case('unresolved-Prepared',[
            {'policy':'ssh_use_pam','value':'yes','fault':'durability'},
            {'policy':'ssh_root_login','value':'no'}],False)
        assert rows[1]['main_unchanged'] and rows[1]['journal_unchanged'],rows
        for name,mutate in [
            ('inactive-socket',lambda:ctl('stop','ssh.socket')),
            ('disabled-socket',lambda:ctl('disable','ssh.socket')),
            ('masked-socket',lambda:ctl('mask','ssh.socket')),
            ('generator-mask',lambda:Path('/etc/systemd/system-generators/sshd-socket-generator').symlink_to('/dev/null'))]:
            reset();Path('/etc/systemd/system-generators').mkdir(exist_ok=True);mutate()
            row=case(name,[{'policy':'ssh_root_login','value':'no'}],False)[0];assert row['main_unchanged'] and not row['records'],row
            Path('/etc/systemd/system-generators/sshd-socket-generator').unlink(missing_ok=True)
        for unit,body in [('ssh.service','[Service]\nEnvironment=SSHD_OPTS=-p2277\n'),('ssh.socket','[Socket]\nListenStream=2277\n')]:
            reset();drop=Path('/etc/systemd/system/'+unit+'.d');drop.mkdir();(drop/'foreign.conf').write_text(body);ctl('daemon-reload')
            row=case('unsupported-'+unit,[{'policy':'ssh_root_login','value':'no'}],False)[0];assert row['main_unchanged'] and not row['records']
        reset()
        case('rollback-active-refusal',[
            {'policy':'ssh_port','value':'2244'},
        ])
        row=case('rollback-active-ownership-retained',[{'policy':'ssh_port','value':'2244','rollback':True}],False)[0]
        assert row['main_unchanged'] and row['records'],row
        row=case('rollback-offline-ownership-only',[{'policy':'ssh_port','value':'2244','rollback':True,'offline':True}])[0]
        assert not row['main_unchanged'] and 'runtime' in row['release_message'],row
        for fault in ('ro-write','busy','original-write','new-glob','contract-before','contract-after','foreign-socket-restart','socket-disable','generated-drift','final-disable','final-restart'):
            reset();h.MAIN.write_text(h.MAIN.read_text().replace('PermitRootLogin yes','PermitRootLogin no'))
            (h.WORK/'mutation.conf').write_text(h.MAIN.read_text()+'# foreign persistent mutation\n')
            req=h.request();req['timeout_ms']=15000;req['policies']={'ssh_root_login':'no'}
            data=h.drive('adapter-'+fault,req)
            report['cases'].append({'name':'adapter-'+fault,'result':data});save()
            assert data.get('adapter_success')==(fault=='ro-write'),(fault,data)
        reset()
        blocker=socket.socket();blocker.bind(('127.0.0.1',2244));blocker.listen()
        try:
            row=case('foreign-listener-bind-failure',[{'policy':'ssh_port','value':'2244'}],False)[0]
            assert not row['main_unchanged'] and row['records'],row
        finally: blocker.close()
        reset()
        h.MAIN.write_text(h.MAIN.read_text().replace('Port 2222','Port 2233'))
        assert {p for a,p in listeners()}=={2222}
        case('stale-listener-reconciled-from-native-inputs',[{'policy':'ssh_root_login','value':'no'}])
        assert {p for a,p in listeners()}=={2233}
        reset()
        (h.WORK/'outside.conf').write_text('LogLevel VERBOSE\n')
        (h.DROP/'evil.conf').symlink_to(h.WORK/'outside.conf')
        row=case('symlink-manifest-refusal',[{'policy':'ssh_root_login','value':'no'}],False)[0]
        assert row['main_unchanged'] and not row['records']
        for fault in ('pending-ready','pending-timeout','pending-failed'):
            reset();h.MAIN.write_text(h.MAIN.read_text().replace('PermitRootLogin yes','PermitRootLogin no'))
            h.handshake(2222)
            req=h.request();req['timeout_ms']=15000;req['policies']={'ssh_root_login':'no'}
            data=h.drive('adapter-'+fault,req);report['cases'].append({'name':'adapter-'+fault,'result':data});save()
            assert data.get('admission_wait_observed') and data.get('adapter_success')==(fault=='pending-ready'),(fault,data)
        reset()
        ctl('stop','ssh.socket');blocker=socket.socket();blocker.bind(('127.0.0.1',2222));blocker.listen()
        try:
            assert ctl('start','ssh.socket',check=False).returncode!=0
            assert ctl('is-failed','ssh.socket',check=False).stdout.strip()=='failed'
            row=case('failed-socket-before-save',[{'policy':'ssh_root_login','value':'no'}],False)[0]
            assert row['main_unchanged'] and not row['records']
        finally:blocker.close()
        reset();ctl('disable','ssh.socket');ctl('start','ssh.service')
        assert h.state()['ActiveState']=='active'
        row=case('disabled-socket-manually-active-service',[{'policy':'ssh_root_login','value':'no'}],False)[0]
        assert row['main_unchanged'] and not row['records']
        reset()
        for unit,body in [('ssh.service','[Unit]\nDescription=Safe administrator description\n[Service]\nCPUWeight=100\n'),('ssh.socket','[Unit]\nDescription=Safe socket description\n')]:
            directory=Path('/etc/systemd/system/'+unit+'.d');directory.mkdir();(directory/'safe.conf').write_text(body)
        ctl('daemon-reload')
        case('compatible-administrative-service-and-socket-dropins',[{'policy':'ssh_root_login','value':'no'}])
        report['result']='PASS'

    finally:
        save();(h.OUT/'ssh-journal.log').write_text(h.run(['journalctl','-u','ssh.service','-u','ssh.socket','--no-pager','-n','150'],check=False).stdout)
    print(json.dumps({'ubuntu_socket_cases':len(report['cases']),'result':'PASS'}))
if __name__=='__main__': main()
