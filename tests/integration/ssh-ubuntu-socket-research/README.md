# Ubuntu socket native research (commit A)

Research fixtures only; not production policy acceptance. Uses real stock
systemd/OpenSSH in disposable privileged containers with no host mounts/network.
The script changes ONLY the container configuration, enablement and runtime;
normal production code must not copy those administrative setup operations.

```sh
bash tests/integration/ssh-ubuntu-socket-research/run-native.sh fic-ssh-audit:ubuntu2404 ubuntu2404
bash tests/integration/ssh-ubuntu-socket-research/run-native.sh fic-ssh-audit:ubuntu2604 ubuntu2604
python3 tests/integration/ssh-ubuntu-socket-research/research.py --self-test
```

Detailed generated evidence: build-ubuntu-socket-research/<row>/. Condensed
committed JSON contains observed versions/states/endpoints/inodes, not private
keys. Single-file RO visibility probe is explicitly a research mount fixture,
not a replacement snapshot/activation engine or full input-closure proof.

The guard rejects unmarked execution before touching files. Root alone is not
sufficient. Transport PASS does not establish production FIC policy safety.
