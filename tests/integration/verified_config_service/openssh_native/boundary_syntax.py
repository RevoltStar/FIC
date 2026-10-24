"""Real OpenSSH syntax/context evidence; not verified policy apply evidence."""
import os
from pathlib import Path
import subprocess
import tempfile
assert os.environ.get('FIC_SSH_BOUNDARY_NATIVE') == '1'
assert Path('/.dockerenv').exists()
subprocess.run(['ssh-keygen','-A'],check=True,capture_output=True)
Path('/run/sshd').mkdir(exist_ok=True)
r=Path(tempfile.mkdtemp(prefix='fic-ssh-boundary-'))
config=r/'config'
for text,condition,expected in (
 ('PermitRootLogin no\nMatch User backup\n X11Forwarding no\n','user=backup,host=localhost,addr=127.0.0.1','permitrootlogin no'),
 ('PermitRootLogin no\nMatch User root\n PermitRootLogin yes\n','user=root,host=localhost,addr=127.0.0.1','permitrootlogin yes'),
):
 config.write_text(text)
 subprocess.run(['/usr/sbin/sshd','-t','-f',str(config)],check=True,capture_output=True)
 p=subprocess.run(['/usr/sbin/sshd','-T','-f',str(config),'-C',condition],check=True,text=True,capture_output=True)
 assert expected in p.stdout.splitlines()
 keys={line.split(' ',1)[1] for line in p.stdout.splitlines() if line.startswith('hostkey ')}
 assert keys == {'/etc/ssh/ssh_host_rsa_key','/etc/ssh/ssh_host_ecdsa_key','/etc/ssh/ssh_host_ed25519_key'}, keys
print('PASS: real OpenSSH accepts unrelated Match and applies conditional PermitRootLogin override; NOT end-to-end apply')
