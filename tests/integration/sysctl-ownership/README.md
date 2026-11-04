# SYSCTL ownership native gates

Actual `systemd-sysctl`, isolated systemd PID 1, real journal/CAS/runtime backend.
No source-written foreign-effective parser substitutes for native observations.

Use prepared `fic-package-native:TAG` builders and
`fic-ssh-lifecycle-native:TAG` runtime images:

```bash
bash tests/integration/sysctl-ownership/run-native.sh debian12 debian-12 build-sssd-i1/full
bash tests/integration/sysctl-ownership/run-native.sh debian13 debian-13 build-package-release/debian13
bash tests/integration/sysctl-ownership/run-native.sh ubuntu2404 ubuntu-24.04 build-package-release/ubuntu2404
bash tests/integration/sysctl-ownership/run-native.sh ubuntu2604 ubuntu-26.04 build-package-release/ubuntu2604
bash tests/integration/sysctl-ownership/run-native.sh alt-p11 alt-p11 build-package-release/alt-p11
```

Do not use host security policy apply. Runtime containers have no binds, ports,
host PID/cgroup/network namespaces or network access. Before boot, global
`/proc/sys` and sysfs become read-only; only `/proc/sys/net` in the private network
namespace remains writable. The fixture uses `ip_forward`, `ip_forward_use_pmtu`
and a dummy `fic.test` interface. Each container is discarded.

Two SYSCTL unit suites run per platform with DAC override capabilities dropped so
permission fault tests remain meaningful. `Driver.cpp` exercises the production
backend/journal/verified helper. `prefix_probe.py` directly checks real directory
priority, ordering, masks, exact leaf and literal interface dots. Driver also
rejects masked/custom-argv loader units before journal/artifact mutation.

Real package gate, Debian 12 (actual daemon, CLI, package scripts):

```bash
# Inside prepared Debian 12 builder, /src readonly and /build writable:
bash /src/tests/integration/package-lifecycle/build-deb.sh debian-12 0.0.0-alpha
# Outside:
bash tests/integration/sysctl-ownership/run-package.sh build-sssd-i1/full/lifecycle-packages build-sssd-i1/full
```

Outputs live in `build-sysctl-validation/`: build/CTest logs, inspect receipts,
backend/prefix reports and package transaction events. Tracked `evidence.json`
records source/harness, image and ELF hashes with the results. It is a receipt
for these runs, not a promise of compatibility with later HEADs. Development
failure logs are not counted as passing validation. No raw `.json.gz` blobs.

Limits: selected private-network leaves only; no real host reboot/power loss,
arbitrary kernel knobs, arbitrary privileged adversarial writer, all custom
systemd launch models, or SSSD runtime matrix. Journal/crash uncertainty uses
deterministic fault injection. Package E2E below is Debian 12; native backend
and actual loader checks cover all five listed distributions.

Authoritative contract: [SYSCTL lifecycle](../../../docs/sysctl-lifecycle.md).

Supplemental platform-profile check on ALT p11 fails with
`SDDM configuration path is incorrect`. The same failure was reproduced from
clean task-base `9c6800c5e1ca2bff2bb0723f51b984ffa5bee559` in an isolated source
archive/build. It predates SYSCTL and is not fixed here. The native driver
validates the complete compiled profile on each platform; SYSCTL-specific
profile assertions are also part of the full Debian12 CTest run.
