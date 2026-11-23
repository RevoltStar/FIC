# Debian 13 Google TOTP native gate

Use the existing [package-lifecycle container setup](../package-lifecycle/README.md)
with a Debian 13 builder. Build the real packages and the probe in that
builder where the production build profile resolves Debian's multiarch
PAM module directories.

```sh
bash /src/tests/integration/package-lifecycle/build-deb.sh debian-13 0.1.2
cmake --build /build --target pam_fic_ssh_stage d13_mfa_probe \
  d13_mfa_ssh_stage_tests pam_control_flow_analyzer_tests -j4
ctest --test-dir /build --output-on-failure \
  -R '^(d13_mfa_.*_tests|pam_control_flow_analyzer_tests|pam_packaging_static_checks|platform_profile_static_checks)$'
```

Prepare the existing systemd runtime fixture for these DEBs. Add
`slapd ldap-utils sssd-ldap libnss-sss libnss-systemd libpam-sss libpam-google-authenticator libpam0g-dev gcc openssh-client openssh-server`
in the runtime image build. Use a fresh image without an existing MFA
slot, LDAP fixture or selected Winbind, homed or SSSD smart-card profiles.
The runner installs the actual FIC DEBs in an isolated PID and mount
namespace with loopback networking and no host mounts. Keep the build
and runtime image preparation separate from the isolated native gate.

```sh
FIC_D13_MFA_PROBE=/path/to/build/tests/d13_mfa_probe \
FIC_D13_MFA_SSH_MODULE=/path/to/build/fic/pam_fic_ssh_stage.so \
  bash tests/integration/package-lifecycle/run-deb.sh \
  DEBIAN13_RUNTIME_IMAGE /path/to/DEBS d13_mfa_native.py
```

Use the evidence directory printed by the runner. `commands.log`
contains verifier verdicts, fixture package versions and SSSD file
metadata. `pam.log` contains actual PAM statuses and prompt counts.
`nsswitch.image` captures the original runtime NSS rules. The gate
retains both modules in `group` and checks the two combined orders
for `passwd` as unsupported, recording the PAM results for the
ordinary fixture accounts separately. Each NSS matrix starts with
fresh faillock counters. `pam-provider.log` contains selected PAM
diagnostics with no fixture credentials.
`common-auth.local` and `common-auth.sssd` preserve the generated
ordering. `result.json` is written after all assertions and credential
cleanup. The runner removes the disposable container. Never invoke
this driver on the host.

The native probe calls `pam_authenticate()` for the real `login`
service and keeps password and OTP responses separate. It checks the
local and LDAP/SSSD success and failure matrix, registration errors,
missing provider, unavailable OTP conversation and faillock behavior.
The test-only module supplies deterministic `PAM_IGNORE`, auth and
system errors, verifies substack boundaries and inspects the
unchanged primary token after a real TOTP check. The production C++
verifier rejects alternate control flows separately. The
[production contract](../../../docs/pam-mfa-d13.md) defines the
scope of these results.

The runner copies the built selector only into the test container.
`ssh-pam.log` contains the actual PAM calls for the dedicated
`fic-sshd-mfa` service, plus SSH prompt counts and remote-command
results. The test-only interposer records PAM calls and injects
evidence publication, removal and setcred failures. Authentication
uses the production selector and real Google Authenticator. The gate
reuses the online TLS/LDAP test fixture for both SSH authentication
chains and the forward-pass conversation. The latter uses a PAM probe
and reports lifecycle success, with no claim of an xrdp client session.
## Verified SSH cutover

Use the same Debian 13 runtime image and real DEBs with the production
PAM modules. Build the `openssh_native_driver` target from
`tests/integration/verified_config_service/openssh_native` with
`FIC_TARGET_PLATFORM=debian-13`. Verified activation needs rootful
Docker in the initial user namespace to prove complete xattr visibility.
The runner creates a disposable systemd container with isolated mounts
and loopback networking.

```sh
FIC_D13_MFA_PROBE=/path/to/d13_mfa_probe \
FIC_D13_MFA_SSH_MODULE=/path/to/pam_fic_ssh_stage.so \
FIC_D13_INCIDENT_PAM_MODULE=/path/to/pam_fic_access.so \
FIC_D13_SSH_CUTOVER_DRIVER=/path/to/openssh_native_driver \
FIC_D13_SSH_CUTOVER_SCOPE=local \
  bash tests/integration/package-lifecycle/run-deb.sh \
  DEBIAN13_RUNTIME_IMAGE /path/to/DEBS d13_mfa_native.py
```

Run again with `FIC_D13_SSH_CUTOVER_SCOPE=sssd` for the LDAP-backed
account. The C++ driver uses the managed block planner, snapshot
validation, CAS and verified activation for the switch and rollback.
The fixture checks both factor combinations, rejection of single
methods, target incident PAM decisions, pinned input drift and a
stopped service. The separate runtime logs include the verified
generation and reference digest without credentials.

Set `FIC_D13_SSH_CUTOVER_PRODUCTION=1` with DEBs built from D13-3C to
exercise the same listener through the production daemon and `fic-cli`.
This gate covers policy registration, independent SSH policies, daemon
restart, ownership drift, guarded uninstall admission and explicit
release. The local account run also waits for a scheduled periodic
apply. The LDAP/SSSD run pins all three stock host-key pairs.

To exercise tally accounting and lockout with the existing owned PAM
slots, omit the cutover driver and set `FIC_D13_SSH_FAILLOCK` to
`preauth-required` or `preauth-requisite`. Those PAM/SSH tests can
also run under rootless Podman.
