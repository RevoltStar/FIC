#!/usr/bin/env python3
"""Real SSH release/disable through production backends, disposable PID1 only."""
import importlib.util
import json
import shutil
import sys
import time
from pathlib import Path
spec=importlib.util.spec_from_file_location('h','/usr/local/bin/fic-openssh-harness.py')
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h);h.guard()
platform=sys.argv[1];group=sys.argv[2];assert group in ('all','positive','negative','admission');alt=platform=='alt-p11';ubuntu=platform.startswith('ubuntu-')
if alt:
    h.MAIN=Path('/etc/openssh/sshd_config');h.ENV=Path('/etc/sysconfig/sshd')
    h.DROP=Path('/etc/openssh/sshd_config.local.d');h.KEY=Path('/etc/openssh/ssh_host_ed25519_key')
unit='sshd.service' if alt else 'ssh.service'
ctl=lambda *args,**kw:h.run(['systemctl',*args],**kw)
Path('/run/fic').mkdir(exist_ok=True)
for parent in (h.MAIN.parent,h.ENV.parent):
    h.run(['mount','--bind',str(parent),str(parent)]);h.run(['mount','--make-private',str(parent)])
h.DROP.mkdir(exist_ok=True);h.run(['ssh-keygen','-A'])
fragment=ctl('show',unit,'-p','FragmentPath','--value').stdout.strip();vendor=h.sha(fragment)
intervals=[]
for target in (unit,'ssh.socket') if ubuntu else (unit,):
    path=target.replace('_','_5f').replace('.','_2e').replace('-','_2d')
    v=h.run(['busctl','get-property','org.freedesktop.systemd1','/org/freedesktop/systemd1/unit/'+path,'org.freedesktop.systemd1.Unit','StartLimitIntervalUSec']).stdout.split()
    assert len(v)==2 and v[0]=='t' and v[1].isdigit();intervals.append(int(v[1])/1000000)
assert max(intervals)<=60
report={'platform':platform,'group':group,'cases':[]}
result_name='release-results.json' if group=='all' else 'release-'+group+'-results.json'
def save():(h.OUT/result_name).write_text(json.dumps(report,indent=2))
def reset(root='yes'):
    time.sleep(max(intervals)+.05)
    ctl('stop',unit,'ssh.socket',check=False)
    for p in h.DROP.iterdir():
        if p.is_dir():shutil.rmtree(p)
        else:p.unlink()
    Path('/run/sshd').mkdir(exist_ok=True)
    h.MAIN.write_text(f'Port 22\nListenAddress 127.0.0.1\nHostKey {h.KEY}\nPermitRootLogin {root}\nPubkeyAuthentication no\nUsePAM no\nMaxAuthTries 6\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n')
    h.MAIN.chmod(0o600 if alt else 0o644);h.ENV.write_text('EXTRAOPTIONS=\n' if alt else 'SSHD_OPTS=\n');h.ENV.chmod(0o644)
    shutil.rmtree(h.WORK/'module-state',ignore_errors=True)
    ctl('enable','ssh.socket' if ubuntu else unit);ctl('daemon-reload');ctl('start','ssh.socket' if ubuntu else unit)
    # Socket startup does not clear the deliberately failed service from the
    # preceding refusal case. Explicit fixture administration (after the real
    # start-limit interval) must prove a fresh successful service invocation.
    if ubuntu and ctl('show',unit,'-p','Result','--value').stdout.strip()!='success':
        ctl('start',unit)
        assert ctl('show',unit,'-p','Result','--value').stdout.strip()=='success'
def request(ops):
    targets=[{'path':str(p),'sha256':h.sha(p)} for p in [h.MAIN,h.ENV,*sorted(h.MAIN.parent.glob('ssh_host_*_key*'))] if p.is_file()]
    targets.append({'path':str(h.DROP),'directory':True,'manifest':{str(p.relative_to(h.DROP)):h.sha(p) for p in h.DROP.rglob('*') if p.is_file()}})
    return dict(paths=targets,timeout_ms=15000,operations=ops)
def case(name,ops,expected=None):
    data=h.drive('module',request(ops));rows=data['module']
    report['cases'].append({'name':name,'result':data});save()
    if expected is None:expected=[True]*len(ops)
    assert [r['applied'] for r in rows]==expected,(name,[(r['applied'],r['release_message']) for r in rows],expected)
    assert h.sha(fragment)==vendor
    return rows
def selected():return [dict(policy=k,value=v) for k,v in [('ssh_root_login','no'),('ssh_pubkey_auth','yes'),('ssh_use_pam','yes'),('ssh_max_auth_tries','3'),('ssh_port','2222')]]
def release(k='ssh_root_login',v='no',**kw):return dict(policy=k,value=v,rollback=True,**kw)
def owner(row,k='ssh_root_login'):return next(r for r in row['journal_after']['records'] if r['policy']['policy']==k)
def done(row,k='ssh_root_login',offline=False):
    r=owner(row,k);assert r['status']=='rolled_back',r
    t=r['undo']['transition'];assert t['intent']=='release' and t['target'] is None and t['phase']=='completed'
    assert t['runtime_facts']['persistent']=='Proven' and t['runtime_facts']['offline']==str(offline).lower()
    assert t['runtime_facts']['readiness']==str(not offline).lower()
    assert k+'.status=DISABLE' in row['policy_config']
try:
    if group in ('all','positive'):
        reset();rows=case('active-root-release-others-still-enabled',selected()+[release(stale_after_disable=True)])
        row=rows[-1];done(row);assert 'PermitRootLogin yes' in row['main_after'] and 'PermitRootLogin no' not in row['main_after']
        assert not row['stale_applied'] and row['stale_unchanged'];assert h.handshake(2222).startswith('SSH-2.0-')
        reset();rows=case('last-selection-and-repeat',[dict(policy='ssh_root_login',value='no'),release(),release(keep_policy_config=True)])
        done(rows[1]);assert rows[2]['main_unchanged'] and rows[2]['journal_unchanged'] and rows[2]['before_invocation']==rows[2]['after_invocation']
        reset();ops=selected()+[release(k,v,keep_policy_config=i>0) for i,(k,v) in enumerate([(x['policy'],x['value']) for x in selected()])]
        rows=case('release-all-including-real-port-change',ops)
        for row in rows[5:]:done(row,row['policy'])
        port=rows[-1];assert 'Port 22\n' in port['main_after'] and 'Port 2222' not in port['main_after']
        old={i for a in port['listeners_before']['kernel'].values() for i in a};new={i for a in port['listeners_after']['kernel'].values() for i in a}
        assert old.isdisjoint(new)
        if ubuntu:assert new.issubset(set(port['listeners_after']['pid1_fds'])) and new.issubset(set(port['listeners_after']['main_fds']))
        assert h.handshake(22).startswith('SSH-2.0-')
        reset();row=case('offline-no-start',[dict(policy='ssh_root_login',value='no'),release(offline=True)])[-1]
        done(row,offline=True);assert row['before_pid']==row['after_pid']=='0' and 'ReleasedOffline' in row['release_message']
        reset();row=case('release-current-refreshed-owner',selected()+[dict(policy='ssh_max_auth_tries',value='2'),release('ssh_max_auth_tries','2')])[-1]
        done(row,'ssh_max_auth_tries');assert owner(row,'ssh_max_auth_tries')['undo']['applied_value']=='2'
    if group in ('all','negative'):
        for before in ('legacy-wrapper-syntax','legacy-wrapper-include','legacy-wrapper-policy','fingerprinted-wrapper-edit'):
            reset(root='no');row=case('prepublication-refusal-'+before,selected()+[release('ssh_port','2222',before=before)],[True]*5+[False])[-1]
            assert row['main_unchanged'] and row['before_invocation']==row['after_invocation'] and 'ssh_port.status=ENABLE' in row['policy_config']
        for fault in ('main-cas','after-save-input','after-save-stop','durability','unknown-writer','journal-commit','release-cleanup'):
            reset();rows=case('release-fault-'+fault,[dict(policy='ssh_root_login',value='no'),release(fault=fault),release(keep_policy_config=True)],[True,False,fault=='main-cas'])
            row=rows[1];assert 'ssh_root_login.status=ENABLE' in row['policy_config']
            if fault!='main-cas':
                assert owner(row)['status']=='prepared' and rows[2]['main_unchanged'] and rows[2]['journal_unchanged']
            if fault=='release-cleanup':
                assert owner(row)['undo']['transition']['runtime_facts']['readiness']=='true';h.drive('cleanup',request([]))
        for fault in ('disable-save','registry-rebuild'):
            reset();rows=case('interrupted-disable-resume-'+fault,[dict(policy='ssh_root_login',value='no'),release(fault=fault),release(keep_policy_config=True)],[True,False,True])
            assert owner(rows[1])['undo']['transition']['phase']=='released_awaiting_disable';done(rows[2])
        reset();row=case('disable-journal-ack-indeterminate',[dict(policy='ssh_root_login',value='no'),release(fault='disable-journal-ack')],[True,False])[-1]
        assert row['journal_unusable_at_return'] and 'ssh_root_login.status=DISABLE' in row['policy_config']
        for fault in ('before-save-crash','after-save-crash','runtime-crash'):
            reset();case('crash-setup-'+fault,[dict(policy='ssh_root_login',value='no')]);before=h.MAIN.read_text()
            killed=h.drive('module',request([release(fault=fault)]),allow_crash=True);assert killed['status']=='SIGKILL'
            journal=json.loads((h.WORK/'module-state/journal.json').read_text());r=next(r for r in journal['records'] if r['policy']['policy']=='ssh_root_login')
            assert r['status']=='prepared' and r['undo']['transition']['intent']=='release'
            assert (h.MAIN.read_text()==before)==(fault=='before-save-crash')
            h.drive('cleanup',request([]))
            row=case('crash-restart-gate-'+fault,[release(keep_policy_config=True)],[False])[0]
            assert row['main_unchanged'] and row['journal_unchanged'] and row['before_invocation']==row['after_invocation']
    if group in ('all','admission'):
        reset();case('failed-service-setup',[dict(policy='ssh_root_login',value='no')])
        good=h.MAIN.read_text();ctl('stop',unit);h.MAIN.write_text(good+'FicInvalidDirective yes\n')
        ctl('start',unit,check=False)
        deadline=time.monotonic()+30
        while True:
            state=ctl('show',unit,'-p','ActiveState','-p','SubState','-p','Result').stdout
            if 'ActiveState=failed' in state and 'SubState=failed' in state:break
            assert time.monotonic()<deadline,('failed state not reached',state)
            time.sleep(.1)
        h.MAIN.write_text(good)
        row=case('failed-service-release-refused',[release(keep_policy_config=True)],[False])[0]
        assert row['main_unchanged'] and 'ssh_root_login.status=ENABLE' in row['policy_config']
        reset();case('unsupported-unit-setup',[dict(policy='ssh_root_login',value='no')])
        dropin=Path('/etc/systemd/system')/(unit+'.d');dropin.mkdir(exist_ok=True)
        fixture=dropin/'fic-unsupported-native-test.conf';fixture.write_text('[Service]\nEnvironment=FIC_UNSUPPORTED=1\n')
        ctl('daemon-reload')
        row=case('unsupported-launch-release-refused',[release(keep_policy_config=True)],[False])[0]
        assert row['main_unchanged'] and row['before_invocation']==row['after_invocation']
        fixture.unlink();ctl('daemon-reload')
        reset();row=case('legacy-ID-only-valid-body-release-preserved',[
            dict(policy='ssh_port',value='2222'),release('ssh_port','2222',before='legacy-wrapper-policy')])[-1]
        done(row,'ssh_port');assert 'PermitRootLogin yes' in row['main_after']
        permission=owner(row,'ssh_port')['undo'];assert not permission.get('wrapper_fingerprints') and permission.get('ownership_version',0)==0
    report['status']='PASS';save()
finally:(h.OUT/'release-journal.log').write_text(h.run(['journalctl','-u',unit,'-n','100','--no-pager'],check=False).stdout)
print(json.dumps({'status':report['status'],'platform':platform,'group':group,'cases':len(report['cases'])}))
