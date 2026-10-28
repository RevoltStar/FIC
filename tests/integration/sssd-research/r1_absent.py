from common import *
import sys
report.update(stage='R1_ABSENT',platform=sys.argv[1])
assert not Path('/usr/sbin/sssd').exists(), 'requires pre-SSSD base image'
write(MAIN,'[sssd]\n');DROP.mkdir(exist_ok=True)
experiment('absent',{'executable_absent':True,'unit':state(),'engine':generic()})
report['collection_complete']=True;save()
