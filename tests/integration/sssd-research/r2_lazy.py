from common import *
import sys
report.update(stage='R2_LAZY',platform=sys.argv[1])
text=base(services='nss')
if sys.argv[1]=='alt-p11' and os.environ.get('FIC_SSSD_ALT_ROOT_FIXTURE')!='1':
 text=text.replace('[sssd]','[sssd]\nuser=_sssd')
 report['fixture']='ALT packaged user=_sssd preserved, real stock responder unit'
configure(text);experiment('monitor-ready-no-pam',observe_start())
native=run(['systemctl','list-unit-files','--no-legend','sssd-pam*.socket'])
units=[line.split()[0] for line in native['stdout'].splitlines() if line.split() and line.split()[0].endswith('.socket')]
experiment('native-pam-units',{'list':native,'sources':ctl('cat','sssd-pam.service',*units),'start':ctl('start',*units) if units else {'absent':True}})
write('/etc/pam.d/sssd-research','auth required pam_sss.so\naccount required pam_sss.so\n',0o644)
request=run(['python3','/usr/local/bin/pam-probe.py','absent-research-user@test'],timeout=15)
experiment('after-pam-request',{'request':request,'monitor':state(),'responder':ctl('show','sssd-pam.service','--all'),'processes':processes(),'journal':run(['journalctl','-u','sssd-pam.service','-u','sssd-pam.socket','-n','70','--no-pager'])})
report['collection_complete']=True;save()
