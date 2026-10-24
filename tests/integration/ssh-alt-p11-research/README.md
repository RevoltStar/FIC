# ALT p11 stock OpenSSH research

Run `bash tests/integration/ssh-alt-p11-research/run-native.sh fic-ssh-audit:alt-p11`.
Trusted image must contain native ALT OpenSSH/systemd/Python and boot systemd PID1.
Runtime has private namespaces/cgroups, loopback only, no host mounts/ports.
Python guard checks explicit marker, root, PID1, different caller root/namespace.
`--self-test` only checks refusal without the disposable marker, no mutations.

28 observations are research, not a production policy PASS. Main/env/unit RPM
integrity is recorded before tests. The installed systemd userdb symlink directory
is recorded and left untouched, not mislabeled as an OpenSSH .d default. Optional
administrator `sshd_config.local.d` is explicit test provisioning, not production mkdir.
Full reports export under build-alt-ssh-research/alt-p11; committed evidence excludes
private key bytes. Existing service -A generates native keys only in disposable fixture.
Fixed test restarts use fixture reset-failed to separate start-limit windows; FIC must
not do that. RO experiment is one research bind, not a production snapshot engine.
