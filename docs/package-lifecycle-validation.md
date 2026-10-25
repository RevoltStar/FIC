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

The initial single-Ubuntu proof below was extended by the final four-platform
follow-up described after it. Historical build-image gates remain distinct.

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

### Historical minimal DEB runtime matrix (c7b598c, dependency decision superseded)

Production PAM classification is `621910c`; historical commit `c7b598c`
added unnecessary non-ELF uninstall dependencies `sudo`, `procps` and
`openssh-server` to fic Depends. Native binaries were rebuilt on each matching
distro; final archives were repackaged with that exact production builder.
Archive/ELF/builder digests, exact versioned Depends, separate build/runtime image
IDs and commands are committed in the evidence files below.

| Runtime | Install / configured / readiness | All packaged ELF | Remove / purge / dpkg audit |
| --- | --- | --- | --- |
| Debian 12 | PASS | 5/5, no unresolved libraries | PASS |
| Debian 13 | PASS | 5/5, no unresolved libraries | PASS |
| Ubuntu 24.04 | PASS | 5/5, no unresolved libraries | PASS |
| Ubuntu 26.04 | PASS | 5/5, no unresolved libraries | PASS |

The five ELF files are fic, fic-cli, fic-dick, fic-package-infrastructure and
pam_fic_access.so. Main/remove also leaves the dependency helper available;
its ldd and physical prove-remove pass before final purge. Packages reach
install ok installed and dpkg audit is empty; no half-configured result is
counted as PASS. The final detach-retry gate was repeated successfully with
these final archives in minimal Ubuntu24, without build/devel dependencies.

Direct library dependencies are libc6/libgcc-s1/libstdc++6; fic also requires
GLib2, Qt6 Core, OpenSSL3 and libsystemd0; fic-dick (including the infrastructure
helper's combined analysis) requires SQLite3 and OpenSSL3. Debian12 uses
libglib2.0-0/libqt6core6/libssl3; the other three use the t64 package names.
Qt minimum versions are 6.4.0, 6.8.2, 6.4.0 and 6.10.2 respectively. The PAM
runtime/modules dependencies supply the PAM library closure. Tool/data
dependencies include udev/systemd/util-linux for fic-dick, and libnotify-bin,
util-linux, nftables, libpam-runtime/libpam-modules/libpam-pwquality plus
sudo/procps/openssh-server for fic. CLI requires its native C++ runtime and exact
fic version. Full per-platform version constraints and every ldd line are in
`evidence/followup-runtime-{debian12,debian13,ubuntu2404,ubuntu2604}.json`.

Two genuine findings preceded these PASS runs:

* Harness: installing udev only after boot and readonly sysfs caused native
  ConditionPathIsReadWrite to skip udevd. FIC correctly rejected reload and
  readiness. The separate runtime fixture now boots native udev with readonly
  /sys and /proc/sys, coldplug masked and test-only udev condition overrides.
  No product unit/check/timeout was weakened; hardware enforcement is not tested.
* Packaging: without the three tool/data providers, ordinary removal failed on
  missing sudoers, sshd_config and Debian12's dangling 99-sysctl.conf symlink.
  That workaround incorrectly required optional managed software and is superseded
  by physical no-ownership inspection; see the optional-resource matrix below.
  OpenSSH package installation/activation follows distro package behavior; the
  gate explicitly stops SSH before release. A regression against the previous
  package builder fails on the missing sudo dependency; the fixed builder passes.

Initial failures and native diagnostics are retained in
`evidence/followup-runtime-initial-findings.json`; they are not PASS evidence.
Reproduction uses prepare-runtime-deb.sh and minimal_runtime_native.py as
described in the native README. Runtime images start from clean distro bases,
preinstall only systemd/udev/dbus/Python/CA boot and harness prerequisites, and
prefetch actual Depends without installing FIC or Qt. Actual APT install uses
that cache with runtime networking disabled. All listed build/devel packages
and Qt Core are asserted absent before installation.

Nine affected CTest passed on each of the four build platforms; after the final
provider fix, five related tests per platform passed again, alongside native
gates, Python compilation, shell syntax/static checks and git diff --check.
This is targeted validation, not a new full project CTest run. Log hashes/image
identities are in `evidence/followup-validation.json`.

### Optional programs: replacement for c7b598c dependency workaround

FIC no longer depends on sudo, openssh-server or procps. Audit found no core
procps command calls: SysctlRuntime uses descriptor-based `/proc/sys` I/O, and
all four DEB profiles use systemd-sysctl. ELF dependency discovery remains
strict. The historical matrix above describes the old archives, not current
requirements; its dependency workaround was an incorrect product decision.

| Minimal native runtime | Install without all three optional programs / five ELF | Ordinary remove from INSTALLED / purge | Physical / pending / active ownership refusal |
| --- | --- | --- | --- |
| Debian 12 | PASS | PASS | PASS |
| Debian 13 | PASS | PASS | PASS |
| Ubuntu 24.04 | PASS | PASS | PASS |
| Ubuntu 26.04 | PASS | PASS | PASS |

Each platform has two separate real APT runs: ordinary remove directly from
INSTALLED, and an explicit rollback-all proof/negative gate. The latter first
requires every SSH/SUDO/SYSCTL row to report NOTHING_TO_RELEASE. Unknown SSH
markers, detached sudo fragments and empty sysctl staging must refuse without
adoption. Unsafe parent permissions, hardlinked sudo state and a symlinked
sysctl artifact must also refuse. Test-only artifacts are then removed by the
test administrator; clean remove/purge succeeds with unchanged desired values.

A fresh APT reinstall then seeds three valid records through production
MutationJournal APIs under daemon.lock: SSH Prepared, SUDO Prepared, SYSCTL
Applied with a deliberately drifted managed assignment. This tests unresolved
transactions/active ownership, not successful native optional-provider apply.
Rollback-all refuses in each backend, preserves active IDs/undo payloads and
physical/configured state, and actual APT removal fails with UNINSTALLING and
main payload retained. The runner destroys the container with ownership still
active; it does not rewrite the journal to manufacture a clean removal.

Versioned Depends, archive/ELF hashes, isolation, command output digests,
per-backend reports and retained typed records are in
`evidence/optional-providers-{debian12,debian13,ubuntu2404,ubuntu2604}.json` under
`tests/integration/package-lifecycle/`. Native fixtures assert absence of both
optional package installations and sudo/visudo/sshd/sysctl executables.
Ubuntu bases initially contained procps; the test image now explicitly removes
preinstalled optional providers before dependency preparation. The original
procps assertion failure was fixture contamination, not a product failure.

Affected executables and rollback_executor_tests build on each matching
platform; five focused CTest pass on each. Ubuntu24 additionally builds/tests
all four other direct test consumers of RollbackExecutor. Unit coverage keeps
existing strict active rollback/CAS, unhealthy journal and SSH Prepared gates,
and adds missing parents/providers, foreign config without visudo, unknown
markers, detached fragments, staging and dangling parent aliases. Shell/Python
syntax, dependency regression and git diff --check pass. This is not a full
project build/CTest or new ALT native run. Runtime `/sys` and `/proc/sys` are
read-only; no live SSH session, real-user PAM or physical enforcement claim.
Absence inspection is bounded and fail-closed, within existing cooperative
FIC locking; it does not claim atomic isolation from arbitrary privileged
external filesystem writers. No MutationJournal schema/recovery, apply, active
release algorithm or package-lifecycle architecture was changed.

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
