#!/usr/bin/env python3
"""Read-only Docker metadata collector. No SSH lifecycle or activation commands.

Usage: collect.py CONTAINER > metadata.json
Only use with an already running audit subject; preparation is deliberately external.
Environment/credential values and private-key contents are never collected.
"""
import json
import subprocess
import sys

container = sys.argv[1]

def read(*args):
    p = subprocess.run(['docker', 'exec', container, *args], capture_output=True,
                       text=True, timeout=20, check=False)
    return {'exit_code': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr}

output = {'container': container}
commands = {
    'os_release': ['cat', '/etc/os-release'],
    'kernel': ['uname', '-r'],
    'systemd_version': ['systemctl', '--version'],
    'openssh_version': ['/usr/sbin/sshd', '-V'],
    'pid1': ['cat', '/proc/1/comm'],
    'unit_files': ['systemctl', '--no-pager', 'list-unit-files', 'ssh*'],
    'sockets': ['systemctl', '--no-pager', 'list-sockets', 'ssh*'],
    'mountinfo': ['cat', '/proc/self/mountinfo'],
    'package': ['sh', '-c', 'if command -v dpkg-query >/dev/null; then '
                "dpkg-query -W -f='${Package} ${Version} ${source:Version}\\n' openssh-server systemd; "
                'apt-cache policy openssh-server; else '
                'rpm -q --qf "%{NAME} %{VERSION}-%{RELEASE} %{SOURCERPM} %{VENDOR}\\n" openssh-server systemd; '
                'rpm -V openssh-server; fi'],
}
for name, args in commands.items():
    output[name] = read(*args)
output['units'] = {}
for unit in ['ssh.service', 'sshd.service', 'ssh.socket', 'sshd.socket']:
    output['units'][unit] = read('systemctl', '--no-pager', 'show', '--all',
        '--property=Id,Names,LoadState,UnitFileState,UnitFilePreset,FragmentPath,DropInPaths,SourcePath,Type,NotifyAccess,ActiveState,SubState,MainPID,InvocationID,TriggeredBy,Triggers,Listen,NeedDaemonReload', '--', unit)
# Metadata only: assignment names only, never their values.
output['input_metadata'] = read('sh', '-c', r'''
for path in /etc/default/ssh /etc/sysconfig/sshd; do
    if test -f "$path"; then
        stat -c '%n mode=%a uid=%u gid=%g' "$path"
        awk '/^[[:space:]]*[A-Za-z_][A-Za-z_0-9]*=/ {s=$0; sub(/=.*/,"",s); print "assignment-name:" s}' "$path"
        sha256sum "$path"
    fi
done
for path in / /etc /etc/ssh /etc/openssh /run /run/fic; do
    if test -d "$path"; then findmnt -T "$path" -n -o TARGET,FSTYPE,PROPAGATION; fi
done
for path in /usr/lib/systemd/system-generators/sshd-socket-generator /lib/systemd/system/ssh.service /usr/lib/systemd/system/sshd.service; do
    if test -f "$path"; then sha256sum "$path"; fi
done
''')
json.dump(output, sys.stdout, indent=2)
print()
