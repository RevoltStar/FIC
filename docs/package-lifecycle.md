# Package lifecycle

This contract replaces the unfinished M1 runtime/finalizer design. Real FIC
DEB/RPM acceptance and its limits are recorded in
[package-lifecycle-validation.md](package-lifecycle-validation.md).

## State and admission

`/var/lib/fic-lifecycle/status` is a root:root, mode0600 single-link regular
file in a root:root mode0700 physical directory. Accepted contents are exactly
`INSTALLING`, `INSTALLED`, `UNINSTALLING`, or `REMOVED`, followed by one newline.
Missing, malformed, aliased or untrusted state never authorizes daemon startup.
Installation must explicitly establish startup permission after infrastructure
proofs. It is not a proof that the package manager has already exited.

The daemon holds the existing daemon.lock for its lifetime, independently of
its IPC socket. In UNINSTALLING it starts in restricted mode, including with
broken policy configuration: no startup apply, incident containment/reconcile,
periodic apply or session reconciliation. Read-only IPC does not enter the
ordinary incident preflight/post-reconciliation path.

`fic-cli prepare-uninstall` requires a root IPC peer. Requests are executed
synchronously by the daemon event loop. Before reporting success it acquires
the existing command-hash mutation lock, publishes UNINSTALLING durably, stops
auxiliary writer units, proves their stopped unit/cgroup state, and performs
a bounded process census. A failed drain leaves UNINSTALLING active; retry is
allowed. Trust-sync rechecks Installed while holding the same hash-store lock.
New device writers refuse admission outside Installed. Database initialization
is restricted to Installing. No uninstall cancellation exists.

Mutating IPC in this mode returns `error_code=UNINSTALL_IN_PROGRESS`, logs and
security-audits the refusal without sending a notification per request. Unknown
commands are denied by default. Rollback all and prepare require root.

The census does not fence arbitrary privileged execution. The contract covers
cooperating current binaries and detected manual copies; it does not claim
kernel-level exclusion of an independently launched old or modified binary.

## Release and package integration

The running daemon is the only ownership release engine. Package scripts use
an infrastructure-only helper, shipped with the existing fic-dick dependency,
after daemon prepare/rollback. The helper takes daemon.lock, repeats actual
systemd unit/cgroup/process proofs, detaches permanent hooks and proves no PAM
references remain before recording Removed. It never loads a policy journal.
Cross-distribution package-manager results are in the validation report.
Existing SSH, ownership/CAS, non-reverting policy and
MutationJournal contracts remain.

## Registered rollback classes

Bulk rollback enumerates the production registry, then verifies every active
journal owner is known. A registered policy is considered even when its saved
status is DISABLE. Unknown active owners fail the global preflight; no resource
independence is invented for them. Existing Prepared/RollbackFailed semantics
and schema are unchanged.

| Registered class | Uninstall treatment |
| --- | --- |
| SYSCTL | Existing scalar/file rollback and resource hints |
| DAC/SudoEdit | Existing shared sudo rollback, uninstall target excludes every policy; no config DISABLE writes |
| NET/SshEdit | Existing journal reverse delta and platform release restrictions; active ALT/Ubuntu SSH must first be stopped by the administrator |
| FIREWALL/HostFiltering managed policies | Existing nft ownership rollback; with no journal entry, strictly prove absence of the reserved object and validate ownership document |
| FIREWALL exclusive control | Unsupported; never invent an undo; unexpected active ownership blocks removal |
| FIREWALL incident exceptions | NotEnrolled; incident/package hooks handled separately |
| OSS/Grub | Existing three enrolled variable rollback contracts |
| IDENTITY_ACCESS/SSSD | Existing managed snippet rollback; physically absent trusted parents/snippet without a record prove nothing to release, staging artifacts remain a conflict |
| IDENTITY_ACCESS/KERBEROS | Existing scalar rollback |
| IDENTITY_ACCESS/PAM and internal PAM_CONTAINER | Joint platform topology/provider/password release before per-policy resolution; independent physical final proof |
| IDENTITY_ACCESS/USER_CREATION | Existing journal-backed defaults rollback |
| IDENTITY_ACCESS/PASSWORD_AGING | Five scalar login.defs policies release; two account operations intentionally non-reverting |
| OSS/DesktopEnvironment | Joint domain release plus physical proof before retiring scope checkpoint; non-reverting policy identities retain their contract |
| OSS/DisplayManager | Joint domain release and physical proof before retiring checkpoint; no DM restart |
| DAC/Mode_and_Owner; OSS/Fstab (11); Device Control; other explicit NotEnrolled controls | No historical OS state restoration; unexpected active non-scope ownership is an error |

A complete reverse Required-dependency plan is checked before release. Shared
PAM/DE/DM owners form resource groups. A failed dependent blocks its prerequisite,
while unrelated groups continue. Reports include per-policy status, mutation IDs,
resource outcomes, retained active records and native provider/password details.
A failure does not disable any configured policy or discard its provenance.

Administrative IPC uses the existing API version and framing. The new root-only
requests are `{"command":"prepare_uninstall","api_version":1}` and
`{"command":"rollback_all","api_version":1}`. `status` includes
`lifecycle_state`; a successful prepare returns UNINSTALLING. Bulk rollback
returns `ok`, `message`, `results` and `summary`. Global unprovable provenance
uses `error_code=ROLLBACK_STATE_UNPROVEN`; individual failures retain a detailed
report and are distinct from that global refusal. Existing GUI/CLI mutations
receive the daemon's explicit uninstall error instead of an implicit save/apply.


## Uninstall override and data retention

`/etc/fic-uninstall-overload` is trusted bounded data, never sourced shell. Root
ownership, physical trusted parent, regular single-link file and no writable
metadata are required. Missing file uses these defaults:

```text
ROLLBACK_TYPE=STANDARD
FIC_REQUIRED_UNINSTALL_STATUS=TRUE
FIC_REQUIRED_STOP=TRUE
```

`ROLLBACK_TYPE` also accepts `IGNORE_ERROR` (attempt rollback; tolerate individual
reported release failures) or `SKIP` (do not request or inspect policy rollback).
A globally unavailable journal/registry/rollback response still requires explicit
SKIP. Prepare/stop each accept FALSE (attempt and warn) or SKIP (do not request).
Malformed, duplicate, unknown, oversized or unsafe input is an error. Emergency
warnings go to stderr and the available system log. Actual absence of writers and
PAM references is mandatory in every mode. Overrides cannot turn foreign policy
artifacts into FIC-owned state, erase active references or adopt an orphan.

DEB remove retains desired configuration and journal/witness together. Late purge
uses the successful Removed proof under the same daemon.lock, without invoking a
removed ELF; it deletes configuration/database/journal/witness even after emergency
removal. The small restrictive Removed marker survives. A trusted fresh install
can replace it with Installing and later Installed after full proofs. RPM erase
retains persistent state; RPM has no native dpkg-style purge action.

Fresh install and compatible new-to-new upgrade perform configuration, journal,
PAM/incident and device DB proofs, explicitly publish Installed, then start normal
services after releasing daemon.lock. Upgrade performs no ownership rollback.
Abort hooks never cancel Uninstalling or unconditionally restart/apply. Individual
policy apply errors may be reported by the running daemon without claiming that
persistent/infrastructure validation failed. Broken persistent state is fatal.

## Replacement of unfinished M1

| Old component | Current disposition |
| --- | --- |
| daemon.lock, durable atomic writes, writer census, domain CAS/release | Retained; used by daemon and closed infrastructure operations |
| lifecycle admission and phase model | Replaced by four-state explicit admission |
| runtime ABI/package prerequisite, runtime retention, manifest engine | Removed |
| package-session/coordinator and offline policy release commands | Removed; only running-daemon ownership release remains |
| deferred finalizer, transaction locks, retry/recovery protocol | Removed; explicit install completion replaces delivery/retry |
| legacy compatibility scripts/migration | Not supported; no false early-scriptlet refusal guarantee |

Historical research documents are marked superseded. They are not an additional
production lifecycle or evidence that the current native matrix passed.
