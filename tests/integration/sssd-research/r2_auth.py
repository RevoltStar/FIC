"""Real local LDAP + native pam_sss; fixture credentials only, TLS on loopback."""
from common import *
import sys,shutil,re
report.update(stage='R2_AUTH',platform=sys.argv[1],scope='one synthetic LDAP password user; not AD/IPA/smartcard/passkey')
fixture=Path('/run/sssd-ldap');fixture.mkdir();(fixture/'db').mkdir()
schema=Path('/etc/ldap/schema') if Path('/etc/ldap/schema').exists() else Path('/etc/openldap/schema')
cert=fixture/'cert.pem';key=fixture/'key.pem'
assert run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','2','-subj','/CN=127.0.0.1','-addext','subjectAltName=IP:127.0.0.1'])['exit_code']==0
conf=''.join(f'include {schema/name}.schema\n' for name in ('core','cosine','inetorgperson','nis'))
modules=list(Path('/usr/lib/ldap').glob('back_mdb.so'))
if modules:conf+=f'moduleload {modules[0]}\n'
conf+=f'pidfile {fixture}/slapd.pid\nargsfile {fixture}/slapd.args\nTLSCertificateFile {cert}\nTLSCertificateKeyFile {key}\nTLSCACertificateFile {cert}\ndatabase mdb\nmaxsize 10485760\nsuffix dc=example,dc=test\nrootdn cn=admin,dc=example,dc=test\nrootpw Research-admin-only\ndirectory {fixture}/db\naccess to attrs=userPassword by self write by anonymous auth by * none\naccess to * by * read\n'
write(fixture/'slapd.conf',conf)
ldaplog=(OUT/'slapd.log').open('w');ldap=subprocess.Popen(['/usr/sbin/slapd','-d','0','-f',str(fixture/'slapd.conf'),'-h','ldap://127.0.0.1:1389'],stdout=ldaplog,stderr=ldaplog)
try:
 deadline=time.monotonic()+10
 while time.monotonic()<deadline and ldap.poll() is None:
  q=run(['ldapsearch','-x','-H','ldap://127.0.0.1:1389','-s','base','-b','','namingContexts'],timeout=2)
  if q['exit_code']==0:break
  time.sleep(.05)
 else:raise RuntimeError('local slapd readiness failed; see slapd.log (fixture failure)')
 ldif='''dn: dc=example,dc=test
objectClass: top
objectClass: domain
dc: example

dn: uid=research,dc=example,dc=test
objectClass: inetOrgPerson
objectClass: posixAccount
cn: Research Fixture
sn: Fixture
uid: research
uidNumber: 160001
gidNumber: 160001
homeDirectory: /nonexistent
loginShell: /bin/sh
userPassword: Research-only-42

dn: cn=research,dc=example,dc=test
objectClass: posixGroup
cn: research
gidNumber: 160001
memberUid: research
'''
 assert run(['ldapadd','-x','-H','ldap://127.0.0.1:1389','-D','cn=admin,dc=example,dc=test','-w','Research-admin-only'],input=ldif)['exit_code']==0
 # Isolated /etc fixture only; no production PAM/NSS topology changed.
 write('/etc/pam.d/sssd-research','auth required pam_sss.so\naccount required pam_sss.so\n',0o644)
 nss=Path('/etc/nsswitch.conf');text=nss.read_text();text=re.sub(r'^(passwd|group):.*$',lambda m:m.group(1)+': files sss',text,flags=re.M);write(nss,text,0o644)
 def config(cache='true',offline=1,cached=0):
  return base(offline=offline,cache=cache).replace('ldap://127.0.0.1:9','ldap://127.0.0.1:1389')+f'ldap_id_use_start_tls=true\nldap_tls_reqcert=demand\nldap_tls_cacert={cert}\nldap_network_timeout=2\nldap_opt_timeout=2\ncached_auth_timeout={cached}\n'
 def auth(wrong=False):return run(['python3','/usr/local/bin/pam-probe.py','research@test',*(['wrong'] if wrong else [])],timeout=20)
 configure(config(cached=3600));experiment('online-start',observe_start())
 experiment('online-identity',run(['getent','passwd','research@test'],timeout=15))
 online=auth();experiment('online-password',online)
 if online['exit_code']!=0:raise RuntimeError('native online PAM did not succeed; no offline claim')
 cache=Path('/var/lib/sss/db/cache_test.ldb')
 def cache_metadata():return run(['ldbsearch','-H',str(cache),'(uidNumber=160001)','dn','lastOnlineAuth','lastLogin','lastCachedPasswordChange'])
 experiment('cache-after-online',cache_metadata())
 def change_password(password):
  ldif=f'dn: uid=research,dc=example,dc=test\nchangetype: modify\nreplace: userPassword\nuserPassword: {password}\n\n'
  return run(['ldapmodify','-x','-H','ldap://127.0.0.1:1389','-D','cn=admin,dc=example,dc=test','-w','Research-admin-only'],input=ldif)
 assert change_password('Different-research-only-43')['exit_code']==0
 rejected=run(['ldapwhoami','-x','-H','ldap://127.0.0.1:1389','-D','uid=research,dc=example,dc=test','-w','Research-only-42'])
 assert rejected['exit_code']!=0
 experiment('cached-auth-while-ldap-online',{'ldap_alive':ldap.poll() is None,'ldap_rejects_old_password':rejected,'old_password_auth':auth(),'cache':cache_metadata()})
 assert change_password('Research-only-42')['exit_code']==0
 ldap.terminate();ldap.wait(timeout=10)
 # USR1 is documented native force-offline signal, no timing assumption.
 ctl('kill','--kill-whom=main','--signal=USR1','sssd.service')
 offline=auth();experiment('offline-password',offline);experiment('cache-after-offline',cache_metadata())
 experiment('offline-wrong-password',auth(wrong=True))
 configure(config(cache='false'));experiment('cache-disabled-restart',observe_start())
 experiment('offline-cache-disabled-existing-db',auth());experiment('cache-retained-after-disable',cache_metadata())
 # Stopped-database fixture makes expiration deterministic without changing clock.
 configure(config());old=int(time.time())-3*86400
 modification=f'dn: name=research@test,cn=users,cn=test,cn=sysdb\nchangetype: modify\nreplace: lastOnlineAuth\nlastOnlineAuth: {old}\n\n'
 changed=run(['ldbmodify','-H',str(cache)],input=modification)
 experiment('synthetic-aged-online-timestamp',changed)
 if changed['exit_code']==0:
  experiment('aged-start',observe_start());ctl('kill','--kill-whom=main','--signal=USR1','sssd.service')
  experiment('aged-expiration-one-day',auth())
  configure(config(offline=0));experiment('unlimited-start',observe_start());ctl('kill','--kill-whom=main','--signal=USR1','sssd.service')
  experiment('aged-expiration-unlimited',auth())
  experiment('cache-after-aged-offline',cache_metadata())
finally:
 ctl('stop','sssd.service')
 if ldap.poll() is None:ldap.terminate();ldap.wait(timeout=10)
 ldaplog.close()
report['collection_complete']=True;save()
print('R2_AUTH collection complete',report['platform'],flush=True)
