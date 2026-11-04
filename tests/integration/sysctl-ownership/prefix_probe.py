import pathlib,subprocess,json,os
assert pathlib.Path('/.dockerenv').exists()
assert [p.name for p in pathlib.Path('/sys/class/net').iterdir()]==['lo']
def run(*args):
 p=subprocess.run(args,text=True,capture_output=True);assert p.returncode==0,(args,p.stdout,p.stderr);return p.stdout
# Only private-network keys below; global kernel tunables remain read-only.
assert os.stat('/proc/self/ns/net').st_ino!=int(os.environ['FIC_HOST_NET'])
binary=next(p for p in ['/usr/lib/systemd/systemd-sysctl','/lib/systemd/systemd-sysctl'] if pathlib.Path(p).exists())
for d in ['/etc/sysctl.d','/run/sysctl.d','/usr/local/lib/sysctl.d','/usr/lib/sysctl.d','/lib/sysctl.d']:
 if pathlib.Path(d).exists():
  for p in pathlib.Path(d).glob('*.conf'):p.unlink()
etc=pathlib.Path('/etc/sysctl.d');etc.mkdir(exist_ok=True)
# Native same-name and cross-directory precedence, including late masks.
etc=pathlib.Path('/etc/sysctl.d');runtime=pathlib.Path('/run/sysctl.d');vendor=pathlib.Path('/usr/lib/sysctl.d')
for d in (etc,runtime,vendor):d.mkdir(exist_ok=True)
key='net.ipv4.ip_forward';leaf=pathlib.Path('/proc/sys/net/ipv4/ip_forward')
for d,value in [(vendor,'0'),(runtime,'1'),(etc,'0')]:
 (d/'20-same.conf').write_text(key+'='+value+'\n')
run(binary,'--prefix=/net/ipv4/ip_forward');assert leaf.read_text().strip()=='0'
(etc/'20-same.conf').unlink();run(binary,'--prefix=/net/ipv4/ip_forward');assert leaf.read_text().strip()=='1'
(etc/'90-later.conf').write_text(key+'=0\n');run(binary,'--prefix=/net/ipv4/ip_forward');assert leaf.read_text().strip()=='0'
(etc/'zzzz-fic.conf').write_text(key+'=1\n');(vendor/'zzzz-fic.conf').write_text(key+'=0\n')
run(binary,'--prefix=/net/ipv4/ip_forward');assert leaf.read_text().strip()=='1'
(runtime/'zzzzz-late.conf').write_text(key+'=0\n');run(binary,'--prefix=/net/ipv4/ip_forward');assert leaf.read_text().strip()=='0'
(etc/'zzzzz-late.conf').symlink_to('/dev/null');run(binary,'--prefix=/net/ipv4/ip_forward');assert leaf.read_text().strip()=='1'
for d in (etc,runtime,vendor):
 for p in d.glob('*.conf'):p.unlink()
a=pathlib.Path('/proc/sys/net/ipv4/ip_forward');b=pathlib.Path('/proc/sys/net/ipv4/ip_forward_use_pmtu')
a.write_text('0');b.write_text('0')
(etc/'10-native.conf').write_text('net.ipv4.ip_forward=1\nnet.ipv4.ip_forward_use_pmtu=1\n')
run(binary,'--prefix=/net/ipv4/ip_forward');assert a.read_text().strip()=='1' and b.read_text().strip()=='0'
(etc/'10-native.conf').unlink();run(binary,'--prefix=/net/ipv4/ip_forward');assert a.read_text().strip()=='1'
# A dot is a literal part of the interface component, not another slash.
run('ip','link','add','fic.test','type','dummy')
key=pathlib.Path('/proc/sys/net/ipv4/conf/fic.test/forwarding');other=pathlib.Path('/proc/sys/net/ipv4/conf/lo/forwarding');key.write_text('0');other.write_text('0')
(etc/'10-native.conf').write_text('net/ipv4/conf/fic.test/forwarding=1\nnet.ipv4.conf.lo.forwarding=1\n')
run(binary,'--prefix=/net/ipv4/conf/fic.test/forwarding');assert key.read_text().strip()=='1' and other.read_text().strip()=='0'
print(json.dumps(dict(binary=binary,version=run(binary,'--version').splitlines()[0],exact_leaf=True,no_foreign_source_keeps_runtime=True,dotted_interface=True,no_unrelated_write=True,same_name_directory_priority=True,global_lexical_priority=True,dev_null_masks=True)))
