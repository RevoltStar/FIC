# Debian 13 empty-password policy gate

Build the real DEBs with `tests/integration/package-lifecycle/build-deb.sh
debian-13 0.1.1` in the Debian 13 builder. Build the
`d13_empty_password_ownership_tests` target in the same build directory.
The ownership executable is opt-in in the native runner because its fixtures
require root-controlled ancestors.

Use the existing Debian package-lifecycle systemd runtime fixture with
`slapd`, `ldap-utils`, `sssd-ldap`, `libnss-sss` and `libpam-sss`
available at boot. The runner copies in the real DEBs and test programs.
The network namespace has loopback only. The LDAP test reuses the
`sssd-research` TLS fixture with online authentication and no cached-password
shortcut.

```bash
FIC_D13_OWNERSHIP_TEST_BINARY=/path/to/build/tests/d13_empty_password_ownership_tests \
    bash tests/integration/package-lifecycle/run-deb.sh \
    DEBIAN13_RUNTIME_IMAGE /path/to/DEBS d13_empty_password_native.py
```

The gate verifies install, daemon registration, PAM results, regeneration,
observation-only, failure on attachment drift, disable and reapply,
faillock composition, same-version reinstall, bulk release and detach.
The ownership fixture covers CAS conflicts, failed durability after rename
in both directions, loss and drift, Prepared recovery and exact-ID release
without a usable provider. The runtime fixture has no host mounts or ports.
