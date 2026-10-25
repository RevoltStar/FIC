# Package lifecycle validation — 2026-10-25

Production implementation: `752354c`; prerequisite platform enumeration fix:
`6676a79`. Contract: [package-lifecycle.md](package-lifecycle.md).
Reproduction instructions and isolation requirements:
[native gates](../tests/integration/package-lifecycle/README.md).

## Actual packages

These are production FIC executables and production package scriptlets, with local
test versions `0.1.0` → `0.1.1`. No dummy package/ownership engine substitutes for
FIC. Docker replaces Podman by explicit user authorization. Each runtime has its
own systemd PID1, mount/PID/cgroup/network context, no host binds/ports/network,
and verified per-mount read-only sysfs. No host policy apply or physical device
mutation was performed.

| Native runtime | Actual package-manager gate | Result |
| --- | --- | --- |
| Debian 12 | apt/dpkg install, upgrade, configuring fault/retry, remove, purge, reinstall; optional prelogin installed/deactivated | PASS |
| Debian 13 | Same core DEB lifecycle, including `dpkg --configure -a` | PASS |
| Ubuntu 24.04 | Same core DEB lifecycle | PASS |
| Ubuntu 26.04 | Same core DEB lifecycle | PASS |
| ALT p11 | RPM install, upgrade, partial release/retry, erase, retained-state/helper reinstall, emergency erase | PASS |

RPM has no native purge/configure-a action; those entries are not simulated.
The minimal ALT image's foreign sudoers fixture needs an explicit administrator
mode repair before FIC install, recorded in the commands. FIC never adopts or
repairs that foreign metadata.

Committed [evidence](../tests/integration/package-lifecycle/evidence) includes exact
commands, versions, exit codes, IPC reports, PAM/config/journal/witness hashes,
image identity/isolation and archive digests. Long stdout is excerpted with its
complete SHA-256; original unabridged commands.json remains in the uniquely named
ignored build evidence directory recorded in each file. Failed directories do
not have PASS results and were not reused as successful evidence.

### Follow-up: DEB runtime dependencies

The original runtime images also contained build/devel libraries, so the matrix
above did not prove completeness of `Depends`. A subsequent minimal-image check
found missing Qt Core in the main DEB: failed `dpkg-shlibdeps` analysis had silently
fallen back to `libc6, libstdc++6`.

The detector now uses a temporary Debian source-package context, preserves errors
and rejects failed/empty analysis. The shared path covers main/CLI/device/helper/
session/prelogin ELF inputs. Regression tests cover relative paths with spaces,
multiple inputs, native errors, empty output and package-builder failure
propagation, including helper-only failures; the test fails against the previous
detector. Five related CTest pass; affected executables and three actual DEBs were
rebuilt on Ubuntu 24.04.

Corrected `fic`, `fic-dick` and `fic-cli` DEBs were installed via APT in a separate
Ubuntu 24.04 systemd PID1 container without Qt Core, CMake, g++ or Qt devel packages
preinstalled. Dependency downloads were prepared beforehand; runtime networking
was disabled. APT installed Qt Core from declared dependencies, all four shipped
executables passed `ldd` without missing libraries, packages reached
`install ok installed`, both daemons were active, CLI/status and device readiness
passed. This follow-up is Ubuntu 24.04 evidence, not a repeat of the five-distro
matrix. Raw build/test/native logs are in `/tmp/fic-readiness-diag/build-fixed-debs.log`
and `/tmp/fic-deb-depends-native/` on the validation machine.

## Proven scenarios and limits

### Follow-up: password-domain classification and detach retry

`PackageReleaseResources::supports(PamPassword)` formerly returned false for
both the legitimate native ALT topology and unresolved capabilities/scopes;
it could also hide one failed resolution behind the other successful one.
The explicit Supported/NotApplicable/Error result now prevents that omission:
only the resolved native ALT pair excludes C2; resolution/topology errors
produce a FAILED PAM_PASSWORD JSON result and fail the PAM resource group.

Nine affected CTest passed on Ubuntu24 and Debian12, including the new support
regression, uninstall lifecycle/order and both provider/password release suites.
The new regression was linked against the original supports implementation
(only bool→enum return adaptation): it failed with support misclassified; the
current implementation passed. This is behavioral RED/GREEN, not a compile-only
failure due to the changed return type.

The real Ubuntu24 detach-retry gate passed two actual prerm failures injected
after successful policy rollback and daemon stop: a directory at
`/var/lib/pam/auth.new`, then at `account.new`. The latter left common-auth
physically detached while common-account and the incident gate remained.
Native pam-auth-update can exit0 despite failed writes; independent physical
proof correctly refused removal. The main package stayed installed, referenced
libraries stayed present, UNINSTALLING/config/journal provenance remained.
After explicit removal of each obstruction, a real systemd restricted restart
with interval1 and repeated rollback passed without reapplying released policy
resources or altering desired config. Normal APT remove and dpkg purge then
passed. No production retry change or manual PAM reattachment was needed.
See [committed evidence](../tests/integration/package-lifecycle/evidence/followup-detach-retry-ubuntu2404.json)
and the [manual retry procedure](package-lifecycle.md#manual-retry-after-infrastructure-detach-failure).

All five actual package gates enable/apply shared login.defs and Sudo policies,
then release them without changing desired ENABLE/values. Debian/Ubuntu also use
active C2 quality/history, lockout and provider ownership. ALT uses native
faillock/pwhistory and passwdqc provider ownership; quality activation remains its
existing StaticVerifyOnly contract. Compatible upgrades retain active mutation
IDs and exact desired configuration. The current C2 read-only package preflight
accepts an active-owned slot with a neutral sibling.

A genuine foreign SSSD staging conflict causes a partial rollback while unrelated
login.defs ownership releases. Foreign bytes/config remain; after explicit fixture
repair, retry completes. Reverse Required planning, shared-resource targets,
NotEnrolled/unsupported handling, journal/CAS/recovery and the other backend
algorithms are also covered by the existing full unit/fault-injection suites.
This does not claim native physical mutation of every backend class: graphical
DE/DM, live SSH sessions and physical devices are outside these container gates.
Existing ALT/Ubuntu SSH release restrictions were preserved; SSH is stopped by
the test administrator before package runs.

DEB gates verify failed config/journal configure without byte repair, explicit
administrator restoration, real `dpkg --configure -a`, concurrent apply/prepare,
STANDARD/IGNORE_ERROR/SKIP, live-writer refusal despite all-SKIP, unsafe override
metadata, a genuine failed ExecStop with best-effort stop, broken main ELF and
journal, foreign PAM-reference refusal and successful retry. ALT verifies erase
refusal and retry with actual PAM physical references and broken ELF/journal.
SKIP never runs an offline policy rollback or reads the poisoned journal.

Successful remove preserves configuration and journal/witness; main and helper
can be reinstalled from this supported retained state. DEB late purge works after
the main ELF is gone, deletes retained configuration/journal/witness and keeps
the restrictive REMOVED marker. An additional real-dpkg gate holds daemon.lock
during late postrm: purge fails, FIC data/external PAM remain, and retry succeeds.
dpkg itself deletes its own neutral PAM conffiles before postrm; their deletion
is distinguished from FIC data loss.

The actual restricted-daemon gate checks malformed config/journal, default-deny
mutating IPC, periodic suppression, SIGKILL/restart, then a PID1/container restart
with fresh tmpfs `/run` and persistent UNINSTALLING. This proves the requested
restart-equivalent admission boundary, not a physical host reboot. Separate real
ELF gates prove singleton rejection before side effects (default/custom socket),
crashed lock-holder recovery, and read-only virgin/corrupt preflights.

## Build and regression checks

* Full Debian 12 project configure/build: PASS, including GUI/session/prelogin
  and all test targets. Production affected targets/packages also build natively
  on the other four distributions.
* Full CTest excluding the permission-fault journal test: 204 selected, 199 PASS,
  4 opt-in native SKIP, one stale platform static assertion failed after the RPM
  pre-script split. That assertion was corrected; six affected static/contract
  tests reran PASS. There is no remaining failed test from that run.
* MutationJournal permission fault-injection test: PASS separately as UID1000;
  root would invalidate its chmod-denial fixture. Across the full selection and
  corrected rerun, 201 distinct tests passed and four were skipped by normal CTest.
* Two skipped gates (singleton and maintenance preflight) were then run explicitly
  in disposable containers: PASS. The generic verified-service native gate was
  not run for this package task; actual five-distro package gates independently
  exercise PAM attach/release/detach rather than claiming the skipped isolated
  PAM component gate ran.
* New native Python drivers compile; runner/build scripts pass bash syntax checks;
  `git diff --check` passes.

Raw validation log hashes/excerpts are in `evidence/validation.json`.

## Findings and remaining boundaries

The native runs found and fixed: missing SSH executable enumeration preventing
Ubuntu/ALT staging; strict treatment of a genuinely failed-but-empty missing unit;
fresh dependency-only missing state; incorrect legacy C2 pair validation; systemd
unit cache reload before postinstall inspection; and the ALT dependency bootstrap
mistaking preserved post-remove configuration for an unsupported legacy upgrade.

During parallel full compilation plus several long native runs, device readiness
occasionally exceeded the existing 30-second bound and configure failed. The
exact cause was not proved; final repeat gates passed with the same product
timeouts. These failed attempts are not PASS evidence. Readiness remains bounded:
heavy-load startup can fail package configuration and require a safe retry; this
work does not promise unbounded liveness or silently waive readiness.

Real-user PAM authentication, graphical boot, physical devices and a physical VM
reboot remain untested here. Arbitrary old development scriptlets are unsupported:
there is no migration, adoption or guarantee that new scripts prevent an old
scriptlet from running. No separate runtime/finalizer/retry protocol was restored.
