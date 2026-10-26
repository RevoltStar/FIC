#!/usr/bin/env python3
"""Native SSH refresh/release lifecycle; guarded disposable systemd only."""
import importlib.util
import json
import shutil
import sys
import time
from pathlib import Path
spec=importlib.util.spec_from_file_location('h','/usr/local/bin/fic-openssh-harness.py')
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
h.guard();platform=sys.argv[1];phase=sys.argv[2];alt=platform=='alt-p11';ubuntu=platform.startswith('ubuntu-')
assert phase=='refresh'
group=sys.argv[3] if len(sys.argv)>3 else 'all'
assert group in ('all','release')
result_name='lifecycle-results.json' if group=='all' else 'lifecycle-release-results.json'
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
report={'platform':platform,'phase':phase,'group':group,'cases':[]}
def save():(h.OUT/result_name).write_text(json.dumps(report,indent=2))
def reset():
    time.sleep(max(intervals)+.05)
    ctl('stop',unit,'ssh.socket',check=False)
    for p in h.DROP.iterdir():
        if p.is_dir():shutil.rmtree(p)
        else:p.unlink()
    Path('/run/sshd').mkdir(exist_ok=True)
    h.MAIN.write_text(f'Port 22\nListenAddress 127.0.0.1\nHostKey {h.KEY}\nPermitRootLogin yes\nPubkeyAuthentication no\nUsePAM no\nMaxAuthTries 6\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n')
    h.MAIN.chmod(0o600 if alt else 0o644);h.ENV.write_text('EXTRAOPTIONS=\n' if alt else 'SSHD_OPTS=\n');h.ENV.chmod(0o644)
    shutil.rmtree(h.WORK/'module-state',ignore_errors=True)
    ctl('enable','ssh.socket' if ubuntu else unit)
    ctl('daemon-reload');ctl('start','ssh.socket' if ubuntu else unit)
def request(operations):
    targets=[{'path':str(p),'sha256':h.sha(p)} for p in [h.MAIN,h.ENV,*sorted(h.MAIN.parent.glob('ssh_host_*_key*'))] if p.is_file()]
    targets.append({'path':str(h.DROP),'directory':True,'manifest':{str(p.relative_to(h.DROP)):h.sha(p) for p in h.DROP.rglob('*') if p.is_file()}})
    return dict(paths=targets,timeout_ms=15000,operations=operations)
def case(name,operations,expected=None):
    data=h.drive('module',request(operations));rows=data['module'];assert len(rows)==len(operations),(name,data)
    if expected is None:expected=[True]*len(rows)
    report['cases'].append({'name':name,'result':data});save()
    assert [r['applied'] for r in rows]==expected,(name,[r['applied'] for r in rows],expected,[r['release_message'] for r in rows if not r['applied']])
    assert h.sha(fragment)==vendor,'vendor unit modified'
    return rows
def selected():
    return [dict(policy=k,value=v) for k,v in [('ssh_root_login','no'),('ssh_pubkey_auth','yes'),('ssh_use_pam','yes'),('ssh_max_auth_tries','3'),('ssh_port','2222')]]
try:
    if group=='all':
        reset();initial=selected()
        changes=[dict(policy=k,value=v) for k,v in [('ssh_max_auth_tries','2'),('ssh_max_auth_tries','3'),('ssh_root_login','prohibit-password'),('ssh_root_login','no'),('ssh_port','2323'),('ssh_port','2222')]]
        rows=case('five-policies-refresh-and-idempotence',initial+initial+changes+initial)
        assert all(r['main_unchanged'] and r['journal_unchanged'] and r['before_invocation']==r['after_invocation'] for r in rows[5:10]+rows[16:]),rows
        baseline=rows[4]['journal_after']['records'];ids={r['policy']['policy']:r['id'] for r in baseline}
        port=next(r['undo'] for r in baseline if r['policy']['policy']=='ssh_port')
        assert port['ownership_version']==1 and port['wrapper_fingerprints']
        for row in rows[10:16]:
            doc=row['journal_after'];owner=next(r for r in doc['records'] if r['policy']['policy']==row['policy'])
            assert doc['schema_version']==3 and owner['id']==ids[row['policy']] and owner['status']=='applied'
            t=owner['undo']['transition'];assert t['phase']=='completed' and t['publication']['durable'] and t['target']['value']==owner['undo']['applied_value']
            assert t['runtime_facts']['persistent']=='Proven' and t['runtime_facts']['readiness']=='true'
            if row['policy']=='ssh_port':
                assert owner['undo']['disabled_mutation_ids']==port['disabled_mutation_ids'] and owner['undo']['wrapper_fingerprints']==port['wrapper_fingerprints']
                old={inode for values in row['listeners_before']['kernel'].values() for inode in values}
                new={inode for values in row['listeners_after']['kernel'].values() for inode in values}
                assert old.isdisjoint(new),'old listening inode survived port refresh'
                if ubuntu:assert new.issubset(set(row['listeners_after']['pid1_fds'])) and new.issubset(set(row['listeners_after']['main_fds']))
        assert h.handshake(2222).startswith('SSH-2.0-')
        reset()
        ops=selected()+[dict(policy='ssh_port',value='2222',before='legacy-journal'),dict(policy='ssh_port',value='2323'),dict(policy='ssh_max_auth_tries',value='2')]
        rows=case('legacy-wrapper-boundary-and-wrapper-free-refresh',ops,[True]*6+[False,True])
        legacy=rows[5];assert legacy['main_unchanged'] and legacy['journal_unchanged'] and legacy['before_invocation']==legacy['after_invocation']
        assert rows[6]['main_unchanged'] and rows[6]['journal_unchanged'] and rows[6]['before_invocation']==rows[6]['after_invocation']
        records=rows[7]['journal_after']['records']
        oldport=next(r['undo'] for r in records if r['policy']['policy']=='ssh_port')
        assert 'wrapper_fingerprints' not in oldport,'legacy wrapper body adopted'
        maximum=next(r['undo'] for r in records if r['policy']['policy']=='ssh_max_auth_tries')
        assert maximum['ownership_version']==1 and maximum['transition']['previous']['ownership_version']==0
        for before in ('owned-drift','malformed-marker','missing-owner'):
            reset()
            row=case('ownership-refusal-'+before,selected()+[
                dict(policy='ssh_max_auth_tries',value='2',before=before)],[True]*5+[False])[-1]
            assert row['main_unchanged'] and row['journal_unchanged'] and row['before_invocation']==row['after_invocation']
        # Real conditional writer / activation admission failures. The second apply
        # is a separate operation and may not adopt an unresolved published target.
        for fault in ('main-cas','after-save-input','after-save-stop','after-save-main','durability','unknown-writer','journal-commit','cleanup'):
            reset()
            ops=selected()+[dict(policy='ssh_max_auth_tries',value='2',fault=fault),dict(policy='ssh_max_auth_tries',value='2')]
            no_effect=fault=='main-cas'
            rows=case('refresh-fault-'+fault,ops,[True]*5+[False,no_effect])
            failed=rows[5];owner=next(r for r in failed['journal_after']['records'] if r['policy']['policy']=='ssh_max_auth_tries')
            assert owner['undo']['applied_value']=='3'
            if no_effect:
                assert owner['status']=='applied' and 'transition' not in owner['undo']
                assert '# foreign CAS edit' in failed['main_after']
            else:
                assert owner['status']=='prepared' and owner['undo']['transition']['previous']['value']=='3' and owner['undo']['transition']['target']['value']=='2'
                assert rows[6]['main_unchanged'] and rows[6]['journal_unchanged'] and rows[6]['before_invocation']==rows[6]['after_invocation']
            if fault=='cleanup':
                assert owner['undo']['transition']['runtime_facts']['status']=='CleanupFailed'
                assert owner['undo']['transition']['runtime_facts']['readiness']=='true'
                h.drive('cleanup',request([])) # explicit fixture administrator, not recovery
        for fault in ('before-save-crash','after-save-crash','runtime-crash'):
            reset();case('crash-setup-'+fault,selected())
            before=h.MAIN.read_text()
            crashed=h.drive('module',request([dict(policy='ssh_max_auth_tries',value='2',fault=fault)]),allow_crash=True)
            assert crashed['status']=='SIGKILL'
            doc=json.loads((h.WORK/'module-state/journal.json').read_text())
            owner=next(r for r in doc['records'] if r['policy']['policy']=='ssh_max_auth_tries')
            assert owner['status']=='prepared' and owner['undo']['applied_value']=='3' and owner['undo']['transition']['target']['value']=='2'
            assert (h.MAIN.read_text()==before)==(fault=='before-save-crash')
            # Fixture-only cleanup of snapshot mounts left by the deliberately killed
            # process. It never edits/reconciles journal ownership.
            h.drive('cleanup',request([]))
            retry=case('crash-restart-gate-'+fault,[dict(policy='ssh_max_auth_tries',value='2')],[False])[0]
            assert retry['journal_unchanged'] and retry['main_unchanged'] and retry['before_invocation']==retry['after_invocation']
    reset()
    released=case('release-current-refreshed-owner',selected()+[
        dict(policy='ssh_max_auth_tries',value='2'),
        dict(policy='ssh_max_auth_tries',value='2',rollback=True,offline=True)])[-1]
    assert 'MaxAuthTries 2' not in released['main_after'] and 'MaxAuthTries 6' in released['main_after']
    owner=next(r for r in released['journal_after']['records'] if r['policy']['policy']=='ssh_max_auth_tries')
    assert owner['status']=='rolled_back' and owner['undo']['applied_value']=='2'
    report['status']='PASS';save()
finally:
    (h.OUT/'lifecycle-journal.log').write_text(h.run(['journalctl','-u',unit,'-n','100','--no-pager'],check=False).stdout)
print(json.dumps(dict(status=report['status'],platform=platform,phase=phase,group=group,cases=len(report['cases']))))
