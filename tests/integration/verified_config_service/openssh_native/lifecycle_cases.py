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
assert group in ('all','release','ownership','multifile','multifile-smoke','multifile-failures')
result_name={'all':'lifecycle-results.json','release':'lifecycle-release-results.json','ownership':'ownership-results.json','multifile':'multifile-results.json','multifile-smoke':'multifile-smoke-results.json','multifile-failures':'multifile-failures-results.json'}[group]
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
    for operation,row in zip(operations,rows):
        if row['applied'] and row['policy']=='ssh_port' and not operation.get('rollback'):
            listeners=row['listeners_after'].get('kernel',{})
            assert listeners and {p.rsplit(':',1)[-1] for p in listeners}=={operation['value']},('actual controlled Port runtime',row)
    return rows
def selected():
    return [dict(policy=k,value=v) for k,v in [('ssh_root_login','no'),('ssh_pubkey_auth','yes'),('ssh_use_pam','yes'),('ssh_max_auth_tries','3'),('ssh_port','2222')]]
def ready_baseline():
    deadline=time.monotonic()+10
    while True:
        try:
            assert h.handshake(22).startswith('SSH-2.0-');break
        except (OSError,AssertionError):
            if time.monotonic()>=deadline:raise
            time.sleep(.05)
def setup_fragment(content='Port 2222\n',literal=False):
    reset();ctl('stop',unit,'ssh.socket',check=False)
    admin=h.DROP/'10-admin.conf';admin.write_text(content);admin.chmod(0o600 if alt else 0o644)
    original='Include '+str(admin if literal else h.DROP/'*.conf')+'\n'+h.MAIN.read_text()
    h.MAIN.write_text(original);ctl('daemon-reload');ctl('start','ssh.socket' if ubuntu else unit)
    ready_baseline()
    return admin,original
op=lambda **kw:dict(policy='ssh_port',value='2022',**kw)
def native_validation_failure():
    admin,original=setup_fragment()
    admin.write_text('Port 2222\nMaxAuthTries invalid\n')
    rows=case('native-validation-fails-after-complete-publication',[op(),dict(policy='ssh_max_auth_tries',value='3')],[False,False])
    transition=rows[0]['journal_after']['records'][0]['undo']['transition']
    assert all(f['publication'] and f['publication']['durable'] for f in transition['files'].values())
    assert rows[0]['before_invocation']==rows[0]['after_invocation'] and rows[1]['journal_unchanged']
def crash_cases():
    for fault in ['before-save-crash','after-save-crash','runtime-crash']:
        admin,original=setup_fragment()
        crashed=h.drive('module',request([op(fault=fault)]),allow_crash=True)
        assert crashed['status']=='SIGKILL'
        doc=json.loads((h.WORK/'module-state/journal.json').read_text());owner=doc['records'][0]
        report['cases'].append({'name':'multi-file-crash-'+fault,'result':crashed,'journal':doc});save()
        assert owner['status']=='prepared' and owner['undo']['transition']['initial'] and owner['undo']['transition']['previous']['value']=='',owner
        assert (h.MAIN.read_text()==original)==(fault=='before-save-crash')
        h.drive('cleanup',request([])) # explicit fixture cleanup, never semantic recovery
        rows=case('multi-file-restart-gate-'+fault,[op(),dict(policy='ssh_max_auth_tries',value='3')],[False,False])
        assert all(r['main_unchanged'] and r['journal_unchanged'] and r['fragments_before']==r['fragments_after'] for r in rows)
try:
    if group=='multifile-failures':
        native_validation_failure();crash_cases()
    if group in ('multifile','multifile-smoke'):
        reset();ctl('stop',unit,'ssh.socket',check=False)
        originals={h.MAIN:'Include '+str(h.DROP)+'/*.conf\n'+h.MAIN.read_text(),
            h.DROP/'10-admin.conf':'# administrator\nPort 2222\nMaxAuthTries 2\n',
            h.DROP/'20-local.conf':'Port +000000002200'}
        for path,content in originals.items():path.write_text(content);path.chmod(0o600 if alt else 0o644)
        ctl('daemon-reload');ctl('start','ssh.socket' if ubuntu else unit);ready_baseline()
        ops=[dict(policy='ssh_port',value=v) for v in ['2022','2022','2323','2323']]
        rows=case('multiple-files-owned-idempotent-refresh-active-release',ops+[dict(policy='ssh_port',value='2323',rollback=True)])
        first=next(r['undo'] for r in rows[0]['journal_after']['records'] if r['policy']['policy']=='ssh_port')
        assert first['included_wrappers']['version']==1 and len(first['included_wrappers']['files'])==2
        assert rows[1]['journal_unchanged'] and rows[1]['main_unchanged'] and rows[1]['fragments_before']==rows[1]['fragments_after']
        assert rows[2]['fragments_before']==rows[2]['fragments_after'],'REFRESH rewrote stable Include files'
        refreshed=next(r['undo'] for r in rows[2]['journal_after']['records'] if r['policy']['policy']=='ssh_port')
        assert refreshed['included_wrappers']==first['included_wrappers'] and refreshed['wrapper_fingerprints']==first['wrapper_fingerprints']
        for path,content in originals.items():assert path.read_text()==content,(path,path.read_text(),content)
        assert all(r['status']=='rolled_back' for r in rows[-1]['journal_after']['records'])
        assert h.handshake(22).startswith('SSH-2.0-') and h.handshake(2222).startswith('SSH-2.0-') and h.handshake(2200).startswith('SSH-2.0-')
        if ubuntu:
            for row in rows:
                kernel={inode for values in row['listeners_after']['kernel'].values() for inode in values}
                assert kernel.issubset(set(row['listeners_after']['pid1_fds'])) and kernel.issubset(set(row['listeners_after']['main_fds']))
    if group=='multifile':
        admin,original=setup_fragment('Port 22\n')
        original=original.replace('Port 22\n','');h.MAIN.write_text(original)
        ctl('daemon-reload');ctl('restart','ssh.socket' if ubuntu else unit)
        rows=case('matching-Include-Port-owned-and-released',[op(),op(),op(rollback=True)])
        assert rows[1]['main_unchanged'] and rows[1]['journal_unchanged'] and rows[1]['fragments_before']==rows[1]['fragments_after']
        assert h.MAIN.read_text()==original and admin.read_text()=='Port 22\n'
        if ubuntu:assert rows[0]['socket_before']==rows[0]['socket_after'] or rows[0]['before_invocation']!=rows[0]['after_invocation']
        admin,original=setup_fragment('Port 2222\nInclude '+str(h.DROP/'nested.inc')+'\nMatch User backup\nPermitRootLogin no\n')
        nested=h.DROP/'nested.inc';nested.write_text('Port 2200\n');nested.chmod(0o600 if alt else 0o644)
        # Restart only the native fixture baseline after adding the nested input.
        ctl('restart','ssh.socket' if ubuntu else unit)
        rows=case('nested-Include-and-child-Match-context',[op(),op(),op(rollback=True)])
        assert admin.read_text().startswith('Port 2222\nInclude ') and nested.read_text()=='Port 2200\n' and h.MAIN.read_text()==original
        for offline in [False,True]:
            admin,original=setup_fragment('Port 2222')
            rows=case(('offline' if offline else 'active')+'-release-preserves-foreign-annotation-and-no-LF',[op(),op(before='fragment-comment',rollback=True,offline=offline)])
            assert admin.read_text()=='Port 2222\n# foreign annotation' and h.MAIN.read_text()==original
            if offline:assert rows[-1]['after_pid']=='0' and 'ReleasedOffline' in rows[-1]['release_message']
            else:assert h.handshake(22).startswith('SSH-2.0-') and h.handshake(2222).startswith('SSH-2.0-')
        admin,original=setup_fragment()
        rows=case('same-value-new-Include-Port-requires-refresh',[op(),op(before='new-port-fragment'),op(),op(rollback=True)])
        owners=[next(r['undo'] for r in row['journal_after']['records'] if r['policy']['policy']=='ssh_port') for row in rows]
        assert len(owners[0]['included_wrappers']['files'])==1 and len(owners[1]['included_wrappers']['files'])==2
        assert not rows[1]['journal_unchanged'] and rows[1]['main_unchanged'] and rows[2]['journal_unchanged']
        assert (h.DROP/'30-new.conf').read_text()=='# new administrator input\nPort 2022\n'
        admin,original=setup_fragment(literal=True)
        rows=case('release-disconnected-recorded-file',[op(),op(before='fragment-disconnect',rollback=True)])
        assert admin.read_text()=='Port 2222\n' and '# administrator removed Include' in h.MAIN.read_text()
        admin,original=setup_fragment()
        rows=case('missing-wrapper-is-not-reconstructed',[op(),op(before='fragment-wrapper-gone',rollback=True)])
        assert admin.read_text()=='# externally removed wrapper\n'
        admin,original=setup_fragment()
        rows=case('included-fingerprint-drift-refuses-apply-and-release',[op(),op(before='fragment-drift'),op(rollback=True)],[True,False,False])
        assert rows[1]['main_unchanged'] and rows[1]['journal_unchanged'] and rows[1]['fragments_before']==rows[1]['fragments_after']
        admin,original=setup_fragment()
        rows=case('refresh-inline-no-effect-retains-previous-owner',[op(),dict(policy='ssh_port',value='2323',fault='first-cas'),dict(policy='ssh_port',value='2323'),dict(policy='ssh_port',value='2323',rollback=True)],[True,False,True,True])
        previous=rows[0]['journal_after']['records'][0]['undo'];retained=rows[1]['journal_after']['records'][0]
        assert retained['status']=='applied' and retained['undo']['applied_value']=='2022' and 'transition' not in retained['undo']
        assert retained['undo']['included_wrappers']==previous['included_wrappers'] and rows[1]['fragments_before']==rows[1]['fragments_after']
        assert '# exact CAS race' in h.MAIN.read_text() and 'Port 22\n' in h.MAIN.read_text() and admin.read_text()=='Port 2222\n'
        admin,original=setup_fragment()
        rows=case('permission-is-bound-to-main-resource',[op(),op(before='wrong-main-resource'),dict(policy='ssh_port',value='2323'),op(rollback=True)],[True,False,False,False])
        assert all(r['main_unchanged'] and r['journal_unchanged'] and r['fragments_before']==r['fragments_after'] for r in rows[1:3])
        for fault in ['main-cas','first-cas','second-cas','fragment-remove','after-save-fragment','fragment-durability','journal-prepare','journal-commit','durability','unknown-writer','after-save-input','cleanup']:
            admin,original=setup_fragment()
            no_effect=fault in ['main-cas','first-cas','fragment-remove']
            retry=op() if no_effect else dict(policy='ssh_max_auth_tries',value='3')
            rows=case('multi-file-failure-'+fault,[op(fault=fault),retry],[False,no_effect])
            if no_effect:
                assert not rows[0]['journal_after']['records'] and rows[1]['applied'],'proven no-effect retry blocked'
            else:
                assert any(r['status']=='prepared' for r in rows[0]['journal_after']['records']),rows[0]
                assert rows[1]['main_unchanged'] and rows[1]['journal_unchanged'] and rows[1]['fragments_before']==rows[1]['fragments_after']
            if fault not in ['cleanup']:assert rows[0]['before_invocation']==rows[0]['after_invocation'],'FIC activated partial graph'
            else:h.drive('cleanup',request([]))
        admin,original=setup_fragment(literal=True)
        h.MAIN.write_text(original+'Include '+str(admin)+'\n')
        rows=case('repeated-logical-Include-one-physical-owner',[op(),op()])
        owner=next(r['undo'] for r in rows[0]['journal_after']['records'] if r['policy']['policy']=='ssh_port')
        assert len(owner['included_wrappers']['files'])==1 and len(owner['included_wrappers']['files'][str(admin)])==1
        assert rows[1]['journal_unchanged'] and rows[1]['fragments_before']==rows[1]['fragments_after']
        admin,original=setup_fragment()
        rows=case('missing-owned-file-refuses-release',[op(),op(before='fragment-file-gone',rollback=True)],[True,False])
        assert not admin.exists() and rows[-1]['main_unchanged']
        assert rows[-1]['journal_after']['records'][0]['status']!='rolled_back'
        native_validation_failure()
        crash_cases()
        for kind in ['outside','glob','cycle','symlink','hardlink','external-hardlink','nested-mount','orphan','match-port','invalid-port']:

            admin,original=setup_fragment()
            if kind=='outside':h.MAIN.write_text(h.MAIN.read_text()+'Include /opt/untrusted/*.conf\n')
            elif kind=='glob':h.MAIN.write_text(h.MAIN.read_text()+'Include '+str(h.DROP/'?.conf')+'\n')
            elif kind=='cycle':admin.write_text('Include '+str(admin)+'\n')
            elif kind in ['symlink','hardlink','external-hardlink']:
                alias=h.MAIN.parent/'fic-source-alias' if kind=='external-hardlink' else h.DROP/'20-alias.conf'
                if kind=='symlink':alias.symlink_to(admin)
                else:
                    import os;os.link(admin,alias)
            elif kind=='nested-mount':h.run(['mount','--bind',str(admin),str(admin)])
            elif kind=='match-port':admin.write_text('Match User backup\nPort 2222\n')
            elif kind=='invalid-port':admin.write_text('Port impossible\n')
            else:admin.write_text('#@FIC_DISABLED_BEGIN policy=ssh_port mutation=orphan@\n#@FIC_DISABLED_LINE@Port 2222\n#@FIC_DISABLED_END policy=ssh_port mutation=orphan@\n')
            rows=case('multi-file-boundary-'+kind,[op(),op()],[False,False])
            assert all(r['main_unchanged'] and r['journal_unchanged'] and r['fragments_before']==r['fragments_after'] and not r['records'] for r in rows)
            if kind=='nested-mount':h.run(['umount',str(admin)])
            if kind=='external-hardlink':(h.MAIN.parent/'fic-source-alias').unlink()
    if group=='ownership':
        reset();ctl('stop',unit,'ssh.socket',check=False)
        original=h.MAIN.read_text().replace('PermitRootLogin yes','PermitRootLogin no').replace('PubkeyAuthentication no','PubkeyAuthentication yes').replace('UsePAM no','UsePAM yes').replace('MaxAuthTries 6','MaxAuthTries 3').replace('Port 22\n','Port 2222\n')
        h.MAIN.write_text(original);ctl('daemon-reload');ctl('start','ssh.socket' if ubuntu else unit)
        initial=selected()
        changes=[dict(policy=p,value=v) for p,v in [('ssh_max_auth_tries','2'),('ssh_max_auth_tries','3'),('ssh_port','2323'),('ssh_port','2222')]]
        releases=[dict(op,rollback=True) for op in initial]
        rows=case('foreign-compliant-owned-idempotent-refresh-release',initial+initial+changes+releases)
        for i,row in enumerate(rows[:5]):
            assert not row['main_unchanged'] and len(row['records'])==i+1,row
            owner=next(r for r in row['journal_after']['records'] if r['policy']['policy']==initial[i]['policy'])
            assert owner['status']=='applied' and owner['undo']['ownership_version']==1
            assert row['main_after'].count('#@FIC_POLICY_BEGIN name='+initial[i]['policy']+'@')==1,row['main_after']
        assert all(r['main_unchanged'] and r['journal_unchanged'] and r['before_invocation']==r['after_invocation'] for r in rows[5:10])
        port=next(r['undo'] for r in rows[4]['journal_after']['records'] if r['policy']['policy']=='ssh_port')
        assert len(port['disabled_mutation_ids'])==1 and len(port['wrapper_fingerprints'])==1
        for row in rows[10:14]:
            if row['policy']=='ssh_port':
                refreshed=next(r['undo'] for r in row['journal_after']['records'] if r['policy']['policy']=='ssh_port')
                assert refreshed['disabled_mutation_ids']==port['disabled_mutation_ids'] and refreshed['wrapper_fingerprints']==port['wrapper_fingerprints']
        assert rows[-1]['main_after']==original and all(r['status']=='rolled_back' for r in rows[-1]['journal_after']['records'])
        assert h.handshake(2222).startswith('SSH-2.0-')
        if ubuntu:
            first=rows[4];assert first['socket_before']==first['socket_after'],'unchanged Port must not regenerate socket'
            for row in rows:
                kernel={inode for values in row['listeners_after']['kernel'].values() for inode in values}
                assert kernel.issubset(set(row['listeners_after']['pid1_fds'])) and kernel.issubset(set(row['listeners_after']['main_fds']))
        # Native OpenSSH defaults also need their own policy blocks.
        reset();ctl('stop',unit,'ssh.socket',check=False)
        original='\n'.join(line for line in h.MAIN.read_text().splitlines() if not line.startswith(('Port ','PermitRootLogin ','PubkeyAuthentication ','UsePAM ','MaxAuthTries ')))+'\n'
        h.MAIN.write_text(original);ctl('daemon-reload');ctl('start','ssh.socket' if ubuntu else unit)
        defaults=[dict(policy=p,value=v) for p,v in [('ssh_root_login','prohibit-password'),('ssh_pubkey_auth','yes'),('ssh_port','22')]]
        rows=case('native-defaults-owned-idempotent-release',defaults+defaults+[dict(op,rollback=True) for op in defaults])
        assert all(not r['main_unchanged'] for r in rows[:3])
        assert all(r['main_unchanged'] and r['journal_unchanged'] and r['before_invocation']==r['after_invocation'] for r in rows[3:6])
        assert rows[-1]['main_after']==original and h.handshake(22).startswith('SSH-2.0-')
        for policy,value in [('ssh_max_auth_tries','6'),('ssh_use_pam','no')]:
            unsupported=case('native-default-outside-policy-range-'+policy,[dict(policy=policy,value=value)],[False])[0]
            assert unsupported['main_unchanged'] and unsupported['journal_unchanged'] and unsupported['before_invocation']==unsupported['after_invocation']
        # Matching Included Port now has creation-bound physical ownership.
        reset();ctl('stop',unit,'ssh.socket',check=False)
        included=h.DROP/'10-matching-port.conf';included.write_text('Port 22\n');included.chmod(0o600 if alt else 0o644)
        original='Include '+str(h.DROP)+'/*.conf\n'+h.MAIN.read_text().replace('Port 22\n','');h.MAIN.write_text(original)
        ctl('daemon-reload');ctl('start','ssh.socket' if ubuntu else unit)
        rows=case('matching-Include-owned-before-verified-activation',[dict(policy='ssh_port',value='22'),dict(policy='ssh_port',value='22'),dict(policy='ssh_port',value='22',rollback=True)])
        assert rows[1]['main_unchanged'] and rows[1]['journal_unchanged'] and rows[1]['fragments_before']==rows[1]['fragments_after']
        assert h.MAIN.read_text()==original and included.read_text()=='Port 22\n' and h.handshake(22).startswith('SSH-2.0-')
        # EOF framing belongs to the current foreign snapshot, not journal
        # history. Exercise both scalar and wrapped EOF Port, active/offline.
        for kind,offline in [('scalar',False),('port',False),('port',True)]:
            reset();ctl('stop',unit,'ssh.socket',check=False)
            original=h.MAIN.read_text().rstrip('\n')
            if kind=='scalar':
                original=original.replace('PermitRootLogin yes','PermitRootLogin no');op=dict(policy='ssh_root_login',value='no')
            else:
                original=original.replace('Port 22\n','')+'\nPort 22';op=dict(policy='ssh_port',value='22')
            h.MAIN.write_text(original);ctl('daemon-reload');ctl('start','ssh.socket' if ubuntu else unit)
            rows=case('no-final-LF-'+kind+('-offline' if offline else '-active'),[op,op,dict(op,rollback=True,offline=offline)])
            assert not rows[0]['main_after'].endswith('\n') and rows[1]['main_unchanged'] and rows[1]['journal_unchanged']
            assert rows[-1]['main_after']==original and all(r['status']=='rolled_back' for r in rows[-1]['journal_after']['records'])
            if offline:assert rows[-1]['before_pid']==rows[-1]['after_pid']=='0' and 'ReleasedOffline' in rows[-1]['release_message']
            else:assert h.handshake(22).startswith('SSH-2.0-')
        reset()
        orphan='#@FIC_SSH_BLOCK_BEGIN version=1@\n#@FIC_SSH_BLOCK_END@\n'+h.MAIN.read_text().replace('UsePAM no','UsePAM yes')
        h.MAIN.write_text(orphan);op=dict(policy='ssh_use_pam',value='yes')
        data=h.drive('module',request([op,op]));rows=data['module']
        report['cases'].append({'name':'empty-orphan-container-refusal','result':data});save()
        assert len(rows)==2 and all(not r['applied'] and r['main_unchanged'] and r['journal_unchanged'] and not r['records'] and r['before_invocation']==r['after_invocation'] for r in rows)
        assert 'Empty FIC managed container' in data['policy_log'] and h.MAIN.read_text()==orphan
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
        for before in ('owned-drift','malformed-marker','missing-owner','missing-block'):
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
    if group not in ('ownership','multifile','multifile-smoke','multifile-failures'):
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
