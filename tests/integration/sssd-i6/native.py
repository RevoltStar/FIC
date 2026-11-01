"""Real installed FIC daemon/CLI integration; disposable systemd container only."""
from common import *
import socket,struct,shutil,sys,re
platform=sys.argv[1]
scenario=sys.argv[2] if len(sys.argv)>2 else 'positive'
CLI='/opt/fic/bin/fic-cli'
JOURNAL=Path('/opt/fic/db/mutation-journal.json')
CONFIG=Path('/opt/fic/config/IDENTITY_ACCESS.conf')
OWN=DROP/'zzzz-fic.conf'
NAMES={p:'sssd_'+p for p in ('offline_credentials_expiration','cache_credentials','account_cache_expiration')}
O,C,A=(NAMES[p] for p in ('offline_credentials_expiration','cache_credentials','account_cache_expiration'))

def command(args,ok=True,timeout=180):
    p=subprocess.run(args,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,
                     env=dict(os.environ,DEBIAN_FRONTEND='noninteractive'))
    r={'command':args,'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr}
    report['commands'].append(r);save()
    assert (p.returncode==0)==ok,r
    return r

def cli(action,policy=None,value=None,ok=True):
    args=[CLI,'policy',action]
    if policy is not None:args+=['IDENTITY_ACCESS',policy]
    if value is not None:args.append(str(value))
    return command(args,ok,240)

def ipc(operation,**fields):
    with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as client:
        client.settimeout(180);client.connect('/run/fic/fic.sock')
        client.send(json.dumps(dict(api_version=1,command=operation,**fields)).encode())
        body=b''
        while True:
            frame=client.recv(1024*1024)
            assert len(frame)>=16,'truncated daemon response'
            magic,total,offset,length=struct.unpack('!4I',frame[:16])
            assert magic==0x00464943 and offset==len(body) and len(frame)==length+16
            assert len(body)+length<=total<=1024*1024
            body+=frame[16:]
            if len(body)==total:break
        response=json.loads(body)
    report['commands'].append({'ipc':operation,'fields':fields,'response':response});save()
    return response

def records(active=False):
    out=[r for r in json.loads(JOURNAL.read_text())['records'] if r['undo']['backend']=='sssd']
    return [r for r in out if r['status'] in ('applied','prepared','rollback_failed')] if active else out

def owner(policy):
    selected=[r for r in records(True) if r['policy']['policy']==policy]
    assert len(selected)==1,selected
    return selected[0]

def observe(name):
    witness=None
    if OWN.exists():
        st=OWN.stat();witness={'present':True,'device':st.st_dev,'inode':st.st_ino,'mode':st.st_mode&0o7777,
                             'owner':st.st_uid,'group':st.st_gid,'sha256':hashlib.sha256(OWN.read_bytes()).hexdigest()}
    experiment(name,{'records':records(),'managed':OWN.read_text() if OWN.exists() else None,'native_witness':witness,
                     'config':CONFIG.read_text(),'service':state()})

def enabled(policy):
    return next((l.split('=',1)[1] for l in CONFIG.read_text().splitlines() if l.startswith(policy+'.status=')),None)

def set_enable(policy,value=None):
    if value is not None:cli('set',policy,value)
    cli('enable',policy)

def apply(policy):
    assert ctl('reset-failed','sssd.service')['exit_code']==0
    cli('apply',policy)
    r=owner(policy);assert r['status']=='applied' and r['undo']['ownership']['current']['assignments']
    return r

def disable(policy):
    response=ipc('disable_policy',module='IDENTITY_ACCESS',policy=policy)
    assert response['ok'] and response['saved'] and response['applied'],response
    assert enabled(policy)=='DISABLE' and not any(r['policy']['policy']==policy for r in records(True))
    return response

def stop_sssd():
    assert ctl('stop','sssd.service')['exit_code']==0
    listing=ctl('list-unit-files','--no-legend','sssd*.socket')
    names=[l.split()[0] for l in listing['stdout'].splitlines() if l.split() and l.split()[0].endswith('.socket')]
    if names:assert ctl('stop',*names)['exit_code']==0
    failed=ctl('list-units','--all','--state=failed','--plain','--no-legend','sssd*.socket')
    names=[l.split()[0] for l in failed['stdout'].splitlines() if l.split() and l.split()[0].endswith('.socket')]
    if names:assert ctl('reset-failed',*names)['exit_code']==0

def prepare():
    assert os.statvfs('/sys').f_flag & os.ST_RDONLY
    assert os.statvfs('/proc/sys').f_flag & os.ST_RDONLY
    command(['systemctl','start','systemd-udevd.service'])
    command(['systemctl','mask','--runtime','--now','getty@tty1.service','console-getty.service'])
    assert ctl('is-enabled','systemd-udev-trigger.service')['stdout'].strip()=='masked'
    text=base(offline=10,account=0)
    text=text.replace('domains = test','domains = test, other')
    text+='\n[domain/other]\nid_provider=ldap\nauth_provider=ldap\nldap_uri=ldap://127.0.0.1:9\nldap_search_base=dc=other,dc=test\ncache_credentials=true\naccount_cache_expiration=0\n'
    if platform=='alt-p11':
        text=text.replace('[sssd]\n','[sssd]\nuser=_sssd\n')
        env=Path('/etc/sysconfig/sssd')
        if not env.exists():
            write(env,'DEBUG_LOGGER=--logger=files\n')
            experiment('explicit-native-environment-fixture',{'path':str(env),'content':env.read_text()})
    if scenario=='remaining-enabled-scope-drift':
        text=text.replace('auth_provider = ldap\n','').replace('auth_provider=ldap\n','')
    configure(text);assert observe_start()['state']['ActiveState']=='active'
    foreign=hashlib.sha256(MAIN.read_bytes()).hexdigest()
    directory=Path('/var/tmp/fic-legacy-packages' if scenario.startswith('legacy-upgrade-') else '/var/tmp/fic-packages')
    if platform=='alt-p11':command(['rpm','-Uvh',*map(str,sorted(directory.glob('*.rpm')))],timeout=600)
    else:command(['dpkg','-i',*map(str,sorted(directory.glob('*.deb')))],timeout=600)
    command(['systemctl','is-active','fic.service','fic-device.service'])
    assert Path('/var/lib/fic-lifecycle/status').read_text()=='INSTALLED\n'
    # Isolate the SSSD gate from optional SSH launch fixtures. A stock
    # platform may enable ssh_use_pam by default; disable it explicitly using
    # the real daemon, never by installing SSH or changing its backend.
    net=ipc('policy_list',module='NET')
    ssh=next(p for p in net['policies'] if p['policy']=='ssh_use_pam')
    if ssh['enabled']:
        result=command([CLI,'policy','disable','NET','ssh_use_pam'])
        experiment('unrelated-ssh-disabled-fixture',result)
    inventory=command(['rpm','-qa'] if platform=='alt-p11' else ['dpkg-query','-W'])
    experiment('inventory',{'platform':platform,'scenario':scenario,'packages':inventory,'pid1':Path('/proc/1/comm').read_text(),
                            'container_mount_namespace':os.stat('/proc/self/ns/mnt').st_ino,'main_sha256':foreign,
                            'os_release':Path('/etc/os-release').read_text(),'kernel':command(['uname','-r'])['stdout'].strip(),
                            'sssd_version':command(['/usr/sbin/sssd','--version'])['stdout'].strip()})
    return foreign

def positive(foreign):
    command([CLI,'policy','list','IDENTITY_ACCESS'])
    response=ipc('policy_list',module='IDENTITY_ACCESS');assert response['ok'],response
    policies={p['policy']:p for p in response['policies'] if p['submodule']=='SSSD'}
    assert set(policies)=={O,C,A},policies
    assert policies[O]['default_value']=='30' and policies[C]['default_value']=='true'
    assert policies[A]['default_value'] is None and not policies[A]['set'] and not policies[A]['value_valid'] and policies[A]['value']==''
    before=CONFIG.read_bytes();cli('enable',A,ok=False);assert CONFIG.read_bytes()==before
    cli('set',O,'30days',ok=False);assert CONFIG.read_bytes()==before
    observe('registration-no-default')
    set_enable(O,10);assert enabled(C)=='DISABLE'
    first=apply(O);mutation=first['id'];inode=OWN.stat().st_ino;bytes_=OWN.read_bytes()
    apply(O);assert owner(O)['id']==mutation and OWN.stat().st_ino==inode and OWN.read_bytes()==bytes_
    observe('same-value')
    cli('set',O,30);apply(O);assert owner(O)['id']==mutation
    observe('refresh-10-to-30')
    set_enable(C);apply(C)
    set_enable(A,60);apply(A)
    for policy,key in ((C,'cache_credentials'),(A,'account_cache_expiration')):
        assignments=owner(policy)['undo']['ownership']['current']['assignments']
        assert {a['section'] for a in assignments}=={'domain/test','domain/other'}
        assert all(a['key']==key for a in assignments)
    command([CLI,'policy','apply','all'],timeout=300)
    observe('three-policies-multidomain')
    disable(C);assert OWN.exists() and len(records(True))==2
    observe('active-release-survivors')
    # Requested A has no owner; B's proven shared file must not be called orphan.
    disable(C);assert OWN.exists() and len(records(True))==2
    observe('no-owner-with-owned-siblings')
    stop_sssd();disable(A)
    released=[r for r in records() if r['policy']['policy']==A][-1]
    proof=released['undo']['ownership']['transition']
    assert proof['release']['offline_verified'] and proof['release']['runtime_receipt'] is None
    assert state()['ActiveState']=='inactive'
    observe('offline-release-survivor')
    reset=ctl('reset-failed','sssd.service')
    assert reset['exit_code']==0 or (platform=='alt-p11' and 'not loaded' in reset['stderr']),reset
    assert observe_start()['state']['ActiveState']=='active'
    disable(O);assert not OWN.exists() and not records(True)
    assert hashlib.sha256(MAIN.read_bytes()).hexdigest()==foreign
    observe('active-last-release')
    set_enable(C);new=apply(C);assert new['id']>mutation
    observe('re-enable-new-owner')
    saved=CONFIG.read_bytes()
    command([CLI,'prepare-uninstall'])
    command([CLI,'policy','rollback','all'],timeout=600)
    assert CONFIG.read_bytes()==saved and enabled(C)=='ENABLE' and not OWN.exists() and not records(True)
    observe('uninstall-release-only')
    if platform=='alt-p11':command(['rpm','-e','fic-cli','fic','fic-dick'],timeout=600)
    else:
        command(['dpkg','--remove','fic-cli','fic','fic-dick'],timeout=600)
        assert JOURNAL.exists() and Path(str(JOURNAL)+'.initialized').exists() and CONFIG.read_bytes()==saved
        command(['dpkg','--purge','fic-cli','fic','fic-dick'],timeout=600)
        assert not JOURNAL.exists() and not CONFIG.exists()
    assert not OWN.exists() and hashlib.sha256(MAIN.read_bytes()).hexdigest()==foreign
    experiment('package-uninstall',{'status':'PASS','foreign_main_sha256':foreign,'managed_absent':not OWN.exists()})

def debugger_disable(symbol,action,operation="disable",symbols="/var/tmp/fic-symbols"):
    pid=int(ctl('show','fic.service','--value','-p','MainPID')['stdout'].strip())
    build_ids=[]
    for path in ('/proc/'+str(pid)+'/exe',symbols):
        output=command(['readelf','-n',path])['stdout']
        match=re.search(r'Build ID: ([0-9a-f]+)',output);assert match,(path,output)
        build_ids.append(match.group(1))
    assert build_ids[0]==build_ids[1],'debugger symbols differ from actual installed executable'
    armed=OUT/'debugger-armed';hit=OUT/'debugger-hit'
    for p in (armed,hit):p.unlink(missing_ok=True)
    instructions=['set pagination off','set confirm off','set breakpoint pending off','file '+symbols,
                  'attach '+str(pid),'break '+symbol,'commands','silent','shell touch '+str(hit)]
    if action=='kill':instructions+=['signal SIGKILL']
    else:
        if action=='cleanup':instructions+=['return (int)-1']
        elif action=='legacy-runtime-failure':instructions+=['return (int)0']
        else:instructions+=['shell python3 /usr/local/bin/debugger-fault.py '+action]
        instructions+=['disable 1','detach','quit']
    instructions+=['end','shell touch '+str(armed),'continue']
    script=OUT/'fault.gdb';script.write_text('\n'.join(instructions)+'\n')
    with (OUT/'gdb.log').open('w') as log:
        debugger=subprocess.Popen(['gdb','-nx','-q','-batch','-x',str(script)],stdout=log,stderr=subprocess.STDOUT)
        until=time.monotonic()+20
        while not armed.exists() and debugger.poll() is None and time.monotonic()<until:time.sleep(.05)
        assert armed.exists(),(OUT/'gdb.log').read_text()
        result=cli(operation,O,ok=False)
        debugger.wait(timeout=30)
    assert hit.exists(),(OUT/'gdb.log').read_text()
    experiment('debugger-seam',{'symbol':symbol,'action':action,'hit':True,'log':(OUT/'gdb.log').read_text(),'cli':result})

def awaiting():
    pending=owner(O);transition=pending['undo']['ownership']['transition']
    assert pending['status']=='prepared' and transition['phase']=='released_awaiting_disable'
    assert transition['version']==3 and transition['release']['runtime_receipt']
    assert transition['a'] and transition['b'] and transition['c'] and transition['p'] and transition['clean']
    assert not OWN.exists()
    return pending

def restart_fic():
    command(['systemctl','stop','fic.service'])
    command(['systemctl','reset-failed','fic.service'])
    command(['systemctl','start','fic.service'],timeout=180)
    assert Path('/run/fic/fic.sock').exists()

def legacy_upgrade(foreign):
    # Real previous executable and package scripts, never an injected I4 owner.
    dropin=Path('/etc/systemd/system/fic.service.d/fixture-no-restart.conf')
    write(dropin,'[Service]\nRestart=no\n',0o644);command(['systemctl','daemon-reload'])
    # The historical scalar writer requires0600/root, whereas D13/U26
    # native precommands prepare0640/native-group. Generate authentic legacy
    # states while stopped; this is the old producer's real offline path,
    # not a fabricated record or an I6 migration.
    offline_legacy=platform in ('debian-13','ubuntu-26.04')
    if offline_legacy:
        stop_sssd();MAIN.chmod(0o600);os.chown(MAIN,0,0)
        experiment('legacy-offline-producer',{'native_metadata_incompatible_with_old_writer':True,'sssd_state':state()})
    set_enable(O,30)
    if scenario=='legacy-upgrade-prepared':
        debugger_disable('fic::rollback::commitMutation','kill','apply','/var/tmp/fic-legacy-symbols')
        command(['systemctl','stop','fic.service'])
    else:
        cli('apply',O)
        if scenario=='legacy-upgrade-rollback-failed':
            debugger_disable('reconcileSssdRuntime','legacy-runtime-failure','disable','/var/tmp/fic-legacy-symbols')
        command(['systemctl','stop','fic.service'])
    previous=owner(O)
    expected={'legacy-upgrade-applied':'applied','legacy-upgrade-prepared':'prepared','legacy-upgrade-rollback-failed':'rollback_failed'}[scenario]
    assert previous['status']==expected and 'ownership' not in previous['undo'],previous
    if offline_legacy:
        # Explicit fixture administration before upgrade; never an automatic
        # start/recovery by new FIC, and never a receipt reconstruction.
        reset=ctl('reset-failed','sssd.service');assert reset['exit_code']==0
        assert observe_start()['state']['ActiveState']=='active'
    image=OWN.read_bytes() if OWN.exists() else None
    generation=state()['InvocationID']
    packages=Path('/var/tmp/fic-packages')
    command(['rpm','-Uvh',*map(str,sorted(packages.glob('*.rpm')))] if platform=='alt-p11' else ['dpkg','-i',*map(str,sorted(packages.glob('*.deb')))],timeout=600)
    command(['systemctl','is-active','fic.service','fic-device.service'])
    assert owner(O)==previous
    cli('apply',O,ok=False);cli('disable',O,ok=False)
    assert owner(O)==previous and (OWN.read_bytes() if OWN.exists() else None)==image
    assert enabled(O)=='ENABLE' and state()['InvocationID']==generation
    assert hashlib.sha256(MAIN.read_bytes()).hexdigest()==foreign
    assert all('ownership' not in r['undo'] for r in records())
    observe(scenario)

def negative(foreign):
    set_enable(O,30)
    if scenario=='stopped-apply':
        stop_sssd();cli('apply',O,ok=False)
        assert not records(True) and not OWN.exists() and state()['ActiveState']=='inactive'
        disable(O);assert state()['ActiveState']=='inactive'
        observe(scenario);return
    if scenario=='journal-invalid':
        doc=json.loads(JOURNAL.read_text());doc['schema_version']=999
        write(JOURNAL,json.dumps(doc));before=JOURNAL.read_bytes()
        cli('apply',O,ok=False)
        assert JOURNAL.read_bytes()==before and not OWN.exists()
        observe(scenario);return
    if scenario=='relation-conflict':
        text=MAIN.read_text().replace('account_cache_expiration = 0','account_cache_expiration = 1',1)
        write(MAIN,text);cli('set',O,0);assert enabled(C)=='DISABLE'
        cli('apply',O,ok=False)
        assert not records(True) and not OWN.exists() and MAIN.read_text()==text
        observe(scenario);return
    apply(O)
    if scenario=='domain-key-drift':
        set_enable(C);apply(C)
        text=OWN.read_text();assert 'cache_credentials = true' in text
        write(OWN,text.replace('cache_credentials = true','cache_credentials = false',1))
        cli('disable',O,ok=False)
        assert len(records(True))==2 and all(r['status']=='applied' for r in records(True))
        assert 'cache_credentials = false' in OWN.read_text()
        observe(scenario);return
    if scenario=='remaining-enabled-scope-drift':
        set_enable(C);apply(C)
        original=owner(C)['undo']['ownership']['current']
        scope=json.loads(original['scope'])
        assert all(domain[7] is True for domain in scope['domains']),scope
        text=MAIN.read_text().replace('[domain/test]','[domain/test]\nauth_provider=ldap')
        write(MAIN,text)
        assert observe_start()['state']['ActiveState']=='active'
        # Exercise the production canonical scope resolver: same-value apply
        # refuses scope drift before mutation, independently of release preflight.
        journal=JOURNAL.read_bytes();image=OWN.read_bytes()
        response=cli('apply',C,ok=False)
        assert 'domain/provider scope changed' in response['stdout'],response
        assert JOURNAL.read_bytes()==journal and OWN.read_bytes()==image
        assert owner(C)['undo']['ownership']['current']['assignments']==original['assignments']
        experiment('scope-drift-proof',{'saved_scope':scope,'canonical_scope_changed':True,
                   'production_apply_refusal':response,'foreign_sha256':hashlib.sha256(MAIN.read_bytes()).hexdigest()})
        identity=OWN.stat();configured=CONFIG.read_bytes();invocation=state()['InvocationID']
        observe('coverage-before-disable')
        response=cli('disable',O,ok=False)
        assert C in response['stdout'] and 'scope mismatch' in response['stdout'],response
        assert enabled(O)=='ENABLE' and enabled(C)=='ENABLE' and CONFIG.read_bytes()==configured
        assert JOURNAL.read_bytes()==journal and all(r['status']=='applied' for r in records(True))
        assert len(records(True))==2 and OWN.read_bytes()==image
        assert (OWN.stat().st_dev,OWN.stat().st_ino)==(identity.st_dev,identity.st_ino)
        assert state()['InvocationID']==invocation and MAIN.read_text()==text
        experiment('scope-drift-foreign-after',hashlib.sha256(MAIN.read_bytes()).hexdigest())
        observe(scenario);return
    if scenario in ('remaining-enabled-unowned','remaining-enabled-unowned-matching-foreign'):
        remaining=C if scenario.endswith('matching-foreign') else A
        set_enable(remaining,None if remaining==C else 60)
        assert not any(r['policy']['policy']==remaining for r in records(True))
        original=owner(O);journal=JOURNAL.read_bytes();image=OWN.read_bytes();identity=OWN.stat()
        configured=CONFIG.read_bytes();invocation=state()['InvocationID']
        observe('coverage-before-disable')
        response=cli('disable',O,ok=False)
        assert remaining in response['stdout'] and 'ownership coverage' in response['stdout'],response
        assert enabled(O)=='ENABLE' and CONFIG.read_bytes()==configured
        assert JOURNAL.read_bytes()==journal and owner(O)==original and original['status']=='applied'
        assert OWN.read_bytes()==image and (OWN.stat().st_dev,OWN.stat().st_ino)==(identity.st_dev,identity.st_ino)
        assert state()['InvocationID']==invocation
        assert not any(r['policy']['policy']==remaining for r in records(True))
        assert all(r['status']=='applied' for r in records(True))
        observe(scenario)
        if remaining==C:
            foreign_before=MAIN.read_bytes()
            command([CLI,'prepare-uninstall']);command([CLI,'policy','rollback','all'],timeout=600)
            assert CONFIG.read_bytes()==configured and not OWN.exists() and not records(True)
            assert MAIN.read_bytes()==foreign_before
            observe('uninstall-unowned-enabled-release-only')
        return
    if scenario=='acknowledgement-unowned-matching-foreign':
        debugger_disable('fic::service::sssd::SssdTransactionCoordinator::acknowledgeDisable','enable-unowned-cache')
        pending=awaiting();assert enabled(O)=='DISABLE' and enabled(C)=='ENABLE'
        assert not any(r['policy']['policy']==C for r in records(True))
        assert ipc('reload_config')['ok']
        journal=JOURNAL.read_bytes();invocation=state()['InvocationID']
        observe('coverage-before-acknowledgement')
        response=ipc('disable_policy',module='IDENTITY_ACCESS',policy=O)
        assert not response['ok'] and response['saved'] and response['applied'] is False,response
        assert C in response['message'] and 'ownership coverage' in response['message'],response
        assert JOURNAL.read_bytes()==journal and owner(O)==pending and not OWN.exists()
        assert state()['InvocationID']==invocation
        observe(scenario);return
    if scenario in ('late-foreign','foreign-relation'):
        late=DROP/'zzzzz-foreign.conf'
        content='[pam]\noffline_credentials_expiration = 30\n' if scenario=='late-foreign' else '[pam]\noffline_credentials_expiration=0\n[domain/test]\naccount_cache_expiration=1\n'
        # A newly administered foreign snippet must satisfy the native
        # launch contract before protected read-only publication. FIC must
        # never chown/chmod foreign inputs to make its release succeed.
        metadata=MAIN.stat();write(late,content,metadata.st_mode&0o7777)
        os.chown(late,metadata.st_uid,metadata.st_gid)
        experiment('prepared-foreign-metadata',{'mode':late.stat().st_mode&0o7777,'owner':late.stat().st_uid,'group':late.stat().st_gid})
        cli('apply',O,ok=False)
        if scenario=='late-foreign':disable(O);assert not OWN.exists()
        else:
            cli('disable',O,ok=False)
            assert not OWN.exists() and enabled(O)=='ENABLE' and owner(O)['status']=='prepared'
        assert late.read_text()==content
        observe(scenario);return
    if scenario=='package-release-refusal':
        write(OWN,'[pam]\noffline_credentials_expiration=99\n')
        saved=CONFIG.read_bytes();pam={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in Path('/etc/pam.d').iterdir() if p.is_file()}
        command([CLI,'prepare-uninstall'])
        command([CLI,'policy','rollback','all'],ok=False,timeout=600)
        command(['rpm','-e','fic-cli','fic'] if platform=='alt-p11' else ['dpkg','--remove','fic'],ok=False,timeout=600)
        assert Path('/opt/fic/bin/fic').exists() and CONFIG.read_bytes()==saved and records(True)
        assert Path('/var/lib/fic-lifecycle/status').read_text()=='UNINSTALLING\n'
        assert {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in Path('/etc/pam.d').iterdir() if p.is_file()}==pam
        observe(scenario);return
    if scenario=='cas-drift':
        debugger_disable('fic::identity::sssd::removeProvenManagedSnippet','cas-drift')
        assert OWN.exists() and '99' in OWN.read_text() and owner(O)['status']=='prepared' and enabled(O)=='ENABLE'
        set_enable(C);cli('apply',C,ok=False);observe(scenario);return
    if scenario=='cleanup-failure':
        debugger_disable('umount2','cleanup')
        assert owner(O)['status']=='prepared' and enabled(O)=='ENABLE'
        transition=owner(O)['undo']['ownership']['transition']
        assert transition['cleanup_errors'] and transition['residuals']
        observe(scenario);return
    if scenario=='wrong-registry-generation':
        debugger_disable('fic::service::sssd::SssdTransactionCoordinator::acknowledgeDisable','configuration-drift')
        awaiting();assert enabled(O)=='ENABLE'
        response=ipc('disable_policy',module='IDENTITY_ACCESS',policy=O)
        assert not response['ok'],response
        assert ipc('reload_config')['ok']
        disable(O);observe(scenario);return
    if scenario=='journal-finalization-failure':
        debugger_disable('fic::rollback::MutationJournal::acknowledgeSssdDisable','readonly-journal')
        pending=awaiting();assert enabled(O)=='DISABLE'
        before=state()['InvocationID'];command(['umount','/opt/fic/db'])
        disable(O);assert state()['InvocationID']==before
        observe(scenario);return
    if scenario in ('crash-before-save','crash-before-ack','runtime-generation-change','receipt-substitution','legacy-v2-awaiting','wrong-physical-witness'):
        symbol='ModuleConfigFileHandler::disablePolicy' if scenario=='crash-before-save' else 'fic::rollback::MutationJournal::acknowledgeSssdDisable'
        debugger_disable(symbol,'kill')
        command(['systemctl','stop','fic.service'])
        pending=awaiting();invocation=state()['InvocationID']
        assert enabled(O)==('ENABLE' if scenario=='crash-before-save' else 'DISABLE')
        if scenario=='runtime-generation-change':
            assert observe_start()['state']['ActiveState']=='active'
            assert state()['InvocationID']!=invocation
        if scenario in ('receipt-substitution','legacy-v2-awaiting'):
            doc=json.loads(JOURNAL.read_text())
            release=next(r for r in doc['records'] if r['id']==pending['id'])['undo']['ownership']
            if scenario=='receipt-substitution':release['transition']['release']['runtime_receipt']['processes'][-1]['start_token']='999999:1'
            else:
                release['version']=2;release['transition']['version']=2
                del release['transition']['release']['runtime_receipt']
            write(JOURNAL,json.dumps(doc))
        if scenario=='wrong-physical-witness':write(OWN,'[pam]\noffline_credentials_expiration=99\n')
        restart_fic()
        before=state()['InvocationID']
        if scenario.startswith('crash-'):
            disable(O);assert state()['InvocationID']==invocation and not OWN.exists()
        else:
            response=ipc('disable_policy',module='IDENTITY_ACCESS',policy=O)
            assert not response['ok'] and response.get('saved') and response.get('applied') is False,response
            assert owner(O)['status']=='prepared' and state()['InvocationID']==before
        observe(scenario);return
    raise AssertionError('unsupported scenario '+scenario)

try:
    foreign=prepare()
    if scenario=='positive':positive(foreign)
    elif scenario.startswith('legacy-upgrade-'):legacy_upgrade(foreign)
    else:negative(foreign)
    experiment('result',{'status':'PASS','platform':platform,'scenario':scenario,'production_daemon':True,'real_packages':True})
except BaseException as error:
    experiment('failure',{'error':repr(error),'scenario':scenario})
    run(['journalctl','-u','fic.service','-u','fic-device.service','-u','systemd-udevd.service','-n','150','--no-pager'])
    if JOURNAL.exists():write(OUT/'failure-journal.json',JOURNAL.read_text())
    raise
