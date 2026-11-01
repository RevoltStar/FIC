"""Closed fault actions for gdb in an isolated native container, never FIC code."""
import os,subprocess,sys
from pathlib import Path
assert os.environ.get('FIC_SSSD_RESEARCH')=='1' and Path('/.dockerenv').exists()
assert Path('/proc/1/comm').read_text().strip()=='systemd'
assert os.stat('/proc/self/ns/mnt').st_ino!=int(os.environ['FIC_SSSD_HOST_MNT'])
action=sys.argv[1]
if action=='cas-drift':
    p=Path('/etc/sssd/conf.d/zzzz-fic.conf')
    p.write_text('[pam]\noffline_credentials_expiration = 99\n\n');p.chmod(0o600)
elif action=='readonly-journal':
    subprocess.run(['mount','--bind','/opt/fic/db','/opt/fic/db'],check=True)
    subprocess.run(['mount','-o','remount,bind,ro','/opt/fic/db'],check=True)
elif action=='configuration-drift':
    p=Path('/opt/fic/config/IDENTITY_ACCESS.conf')
    text=p.read_text();old='sssd_offline_credentials_expiration.status=DISABLE'
    assert old in text
    p.write_text(text.replace(old,'sssd_offline_credentials_expiration.status=ENABLE'));p.chmod(0o644)
else:raise AssertionError('unknown closed fixture action '+action)
