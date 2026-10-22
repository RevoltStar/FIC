"""Opt-in disposable native guard/query proof; no host/system policy apply."""
import os
import subprocess
import sys
import select
import fcntl
from pathlib import Path
if os.environ.get('FIC_MAINTENANCE_NATIVE')!='1' or os.geteuid()!=0:sys.exit(77)
driver,kind=sys.argv[1:]
paths=['/var/lib/rpm/.rpm.lock'] if kind=='rpm' else ['/var/lib/dpkg/lock-frontend','/var/lib/dpkg/lock']
before={p:(Path(p).stat().st_ino,Path(p).read_bytes()) for p in paths}

def held(crash=False):
    holder=subprocess.Popen([driver,'--native-hold',kind],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        assert select.select([holder.stdout],[],[],10)[0], 'holder readiness'
        assert holder.stdout.readline().strip()=='LOCKED',holder.stderr.read()
        for path in paths:
            with open(path,'r+') as lock:
                try:fcntl.lockf(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                except BlockingIOError:pass
                else:raise AssertionError('record lock not retained: '+path)
        query=['rpm','-q','rpm'] if kind=='rpm' else ['dpkg-query','-W','-f=${Status}','dpkg']
        result=subprocess.run(query,capture_output=True,text=True,timeout=5)
        assert result.returncode==0,(query,result.stdout,result.stderr)
        print('READ_ONLY_QUERY_WHILE_LOCKED:',result.stdout.strip(),flush=True)
        if crash:
            holder.kill();holder.wait(timeout=10)
        else:
            holder.stdin.write('Q');holder.stdin.flush()
            assert holder.wait(timeout=10)==0,holder.stderr.read()
    finally:
        if holder.poll() is None:holder.kill()
        holder.communicate(timeout=10)
    for path in paths:
        with open(path,'r+') as lock:fcntl.lockf(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
held();held(True);held()
assert before=={p:(Path(p).stat().st_ino,Path(p).read_bytes()) for p in paths}
print('PASS: real package lock set retained through read-only query; SIGKILL/restart; no file mutation')
