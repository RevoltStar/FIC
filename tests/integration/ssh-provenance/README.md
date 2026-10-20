# SSH provenance native gate

Run the same `ssh_apply_rollback_tests` executable as root CTest against production
transaction, journal and rollback sources in disposable distro containers. Commands
are injected through the existing fake SSH runner; files, runtime paths and journal
witnesses live in unique `/tmp` fixtures. No host SSH commands, keys or `/etc` writes.
No privileged container, host namespaces or host security mounts are needed.

```sh
CONTAINER_ENGINE=docker bash tests/integration/ssh-provenance/run-native.sh
# Or one profile / an equivalent prepared image:
FIC_SSH_NATIVE_IMAGE=fic-ssh-audit:debian13 \
  bash tests/integration/ssh-provenance/run-native.sh debian13
```

Defaults: `fic-ssh-audit:{debian12,debian13,ubuntu2404,ubuntu2604,alt-p11}`;
images need native C++/CMake, OpenSSL, JSON and the existing core dependencies.
Qt development packages are not needed. Reuses `user_creation` native platform/core
setup and the shared **unchanged** SSH regression source list, not a reduced fake
transaction implementation. `FIC_SSH_TRANSACTION_TESTING` is private to test targets.

Source is mounted read-only, build directory read-write, network disabled. DAC override
capabilities are dropped so filesystem/journal fault tests retain their meaning as root.
The runner prints CTest results and the executable's per-scenario/FAULT outcomes; logs
and per-profile builds are under `build-ssh-provenance/`. The executable runs twice
(CTest and direct reporting), each with new fixtures; this is not twice as many unique
scenarios. This gate proves fixture-based ownership/journal logic on five userspaces,
not real sshd/systemd/PAM behavior or a five-kernel VM matrix.

Related full-project gates (Debian12): `ssh_runtime_tests`, `rollback_executor_tests`,
`mutation_journal_tests`, `atomic_file_writer_remove_tests`. The native script only
builds/runs the complete SSH apply/rollback suite; full CTest remains separate.
