# Current workspace

## Current base
* Branch main, base ab0f47e (strict DEB dependency analysis). Original lifecycle 752354c, historical native gates 50e0d04. No push.

## Current task
* Attachment68cebd90: fix silent PAM password-domain skip, prove real infrastructure detach retry, then final minimal DEB runtime gates on Debian12/13 and Ubuntu24/26. Accepted lifecycle architecture remains unchanged. Two commits A/B requested.

## Accepted architecture / invariants
* AGENTS17/docs/package-lifecycle.md: four durable states, daemon-only policy release, infrastructure-only helper, shared daemon.lock, ownership/CAS/journal contract unchanged. No M1/runtime/finalizer/automatic restart/cancel/orphan adoption.
* Domain applicability is explicit Supported/NotApplicable/Error. Only resolved native ALT passwdqc/static + pwhistory/TCB excludes C2; capability/scope/topology errors fail PAM_PASSWORD in JSON.
* Native experiments only in disposable private PID1/cgroup/mount/network Docker containers, no host binds/ports/network, per-mount readonly sysfs. Podman absent. Build containers may bind repository readonly and their own caches.

## Completed
* A source fix + new package_release_support_tests; all old false causes inspected (native ALT vs missing capability, unavailable/empty scope, unsupported/mixed topology), plus one-success-masks-other-error case.
* 9 affected CTest PASS on Ubuntu24 and Debian12; new regression rejects original supports code with bool→enum adaptation (real behavioral RED), current code GREEN. Affected production targets and actual DEBs built.
* New detach_retry_native.py through real APT/prerm PASS: stop-time filesystem obstruction before detach, then partial common-auth detach before account failure. Physical proof rejects even updater exit0; main payload/referenced module retained, UNINSTALLING persists, config unchanged, active records released. Restricted systemd restart interval1 suppresses startup/periodic apply; repeated rollback and ordinary remove/purge succeed. No production retry fix/manual PAM reattachment needed.
* Manual recovery procedure, validation docs, compact native evidence committed with A. Raw evidence path is in evidence/followup-detach-retry-ubuntu2404.json. Raw build logs: build-package-followup/.

## Changed areas
* daemon PackageReleaseResources/PackageReleaseSupport/UninstallRollback; support test/CTest; native detach runner/driver; lifecycle docs/evidence.
* B-only uncommitted harness files: Dockerfile.runtime-deb and minimal_runtime_native.py (do not include them in A).

## Remaining
* B: final minimal runtime gates on all four DEB distributions; actual Depends/helper/all packaged ELF/dpkg audit/readiness/remove/purge, evidence and documentation. No matrix PASS yet.
* Ubuntu24 and Debian12 current-tree packages: build-recovery-policy/ubuntu2404/followup-packages and build-env-full-debian12/followup-packages. Build images fic-deb-depends-build:ubuntu2404 and fic-followup-build:debian12; Debian13 image build in progress. Other caches build-recovery-policy/{debian13,ubuntu2604} survive.
* Runtime images must start from distro base, never build image; only boot/harness prerequisites preinstalled. Dockerfile.runtime-deb prefetches dependency closure without running FIC, actual APT install must run under PID1 with network none. No --no-download for local archives (APT blocks local file copying too).
* Earlier readiness-timeout cause remains unproved; injected sync delay showed sensitivity. Do not optimize/relax30s readiness in this task. No real-user PAM/physical devices/graphical/SSH continuity claims.
* Auto permission review once timed out on Debian13 image build; allowed single retry started. Earlier quota failure executed nothing. Do not bypass approval.
