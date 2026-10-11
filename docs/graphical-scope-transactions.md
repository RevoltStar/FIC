# Transactional graphical scope and ownership-safe release

DE and DM use independent checkpoints in the same MutationJournal.

## Authority and state

Configured scope is intent in OSS.conf. The scope policy's setter saves data;
its apply validates ENABLE and a typed nonempty list, without journal access,
native commands, session enumeration or physical reconciliation. Empty intent
is savable but enabled apply returns UNCONFIGURED.

After a successful administrative scope save and registry reload, the daemon
runs a separate internal apply of the corresponding graphical submodule through
the existing serialized planner. It reports `saved` and `applied` separately;
failed apply preserves the new intent. There is no external CLI or self IPC.
Direct apply of only the scope performs validation only, including daemon
pre-processing. Startup, periodic, reload and manual dependent apply use the
same physical coordinators. Required dependencies and reverse-disable guards
remain; compliance is an independent observer of current inventory.

MutationJournal retains independent `scope/de` and `scope/dm` global checkpoints
and physical provenance. Prepared/failed/partial retain the previous committed
checkpoint; checkpoints grant no physical ownership. A committed checkpoint
means system resources were reconciled and verified, **not** that all present
or future user sessions converged. SessionOnly failure does not invalidate it.

`screenlock_timeout`, `disable_kde_lock_screen_media_controls` and DE compliance
require the DE declaration. `disable_autologin` and DM compliance require the
DM declaration. Neither declaration requires an already committed checkpoint.

## New-session incident reporting

The serialized session_ready worker retains logind/peer/context validation and
one current-inventory snapshot. A targeted PolicyExecutionPlanner executor
reconciles only the new session and evaluates enabled inventory compliance from
that snapshot. Dependencies still use their ordinary apply; disabled/missing/
failed Required dependencies block the dependent with its own failure origin
and violation_severity. No whole-module/all-session apply is substituted.

SessionOnlyFailed, applicable Unsupported and applicable MandatoryGlobal global
proof failures become Failed policy results. Converged and NotApplicable results
are Applied for incident reporting; MandatoryGlobalRuntimeWarning remains an
Applied result with WARN diagnostics, never an incident on its own. An unrelated
global failure does not invalidate successful SessionOnly reconciliation.
For each owner the targeted executor aggregates all owned global requirements
from the already computed report with the session outcome, including globals
for a different DE. Own applicable MandatoryGlobal declarations also prevent
false success when Stage A stops before collecting complete contributions.
A missing proof is diagnosed as an unverified own obligation, with checkpoint
context; a foreign failure alone cannot create ownership. Actual coordinator
phases (global_preflight/ensure/release/verify) survive in the report. Independent
session SUCCESS is retained explicitly alongside global FAILED; the adapter
neither retries global reconciliation nor rolls back session settings or journal
provenance.

Release-only failures are separate from desired requirements. Before backend
operations the coordinator snapshots active scalar records from the healthy,
schema-validated MutationJournal, routing by the scalar's canonical desktop and
setting. Only recorded scalar owners are used; artifact/checkpoint primary policy
references and old scope membership never establish policy ownership. Failures
retain owner, mutation ID, resource, desktop, actual phase and backend cause;
each physical record is counted once per owner. Completed releases do not leave
false obligations. This report is diagnostic and grants no rollback authority.

Enabled owners aggregate release, desired and targeted session outcomes into one
result with their own severity. Disabled or unproven owners retain the global
failure diagnosis without activating an arbitrary policy or the scope policy.
A snapshot survives backend changes to Prepared/release progress and journal
health failures. Persisted release progress intentionally has empty owners: if a
later invocation has no surviving owner evidence, it remains unproven rather
than guessing from the primary policy; physical recovery is unchanged.

ScopeTransition exposes typed failure phases including checkpoint_state,
checkpoint_prepare and checkpoint_commit. A commit persistence failure after
successful physical verification keeps the global transition failed but retains
verified desired settings and completed releases; it does not invent a backend
failure. Native callback failures retain their actual phase even if saving the
failed checkpoint also fails. No error-message substring classification is used.

One aggregate PolicyIncidentReporter call feeds the existing IncidentController,
severity max, audit, notification deduplication and active response. Diagnostics
retain policy, session ID, UID, DE, phase and cause. Failed work can be retried by
the existing periodic/event paths. Historical apply results are not rewritten.
Without a validated target context, ordinary SessionAware execution is skipped;
only authoritative current-inventory compliance can produce a violation. An
invalid IPC packet is not proof of a policy failure.

## Transition

DesktopGlobalConfigReconciler is the authorized scope recovery entrypoint. It
reads enabled typed configured intent, validates the complete desired state and
collects owner sets for every physical key. It does not recursively execute the
scope policy. It preflights **all** target and release backends before protected
writes, persists Prepared, ensures retained/added requirements, releases obsolete
ownership, verifies native/resource state and durability, then commits.

All administrative/apply/session events run synchronously through the daemon.
Cached module entries must still match a captured current config snapshot at
collection. Every config snapshot is checked again before commit; an external
change leaves the transition partial and requires registry reload/retry. The
data setter does not start this sequence; the administrative handler subsequently executes the relevant submodule as a distinct apply stage.

Failures retain intent and provenance. Preflight failures preserve physical
state and the previous committed checkpoint. Physical/native/fsync/commit
failures leave diagnostic failed/partial state. A poisoned journal authorizes
nothing until witness-aware durable recovery succeeds. Retry proves independent
before/after physical projections; it never reconstructs a completed release.

## Physical records

`desktop / restore_desktop_scalar` binds the trusted desktop/setting route to
its mutation ID, exact original scalar line (or absence), current/previous
applied line, sorted owner refs, had_applied and ensure/release phase. Paths and
whole foreign-file backups are absent. GNOME also records the exact original
lock line and native cache before/target SHA-256 digests. Immutable originals,
monotonic prior ownership, valid canonical values, owner/resource identities and
phase/status parity are checked by the journal.

Owner sets are independent of the record's primary policy. Removing the primary
owner cannot close a shared resource that another owner still needs. Generic
per-record DE undo is refused; RollbackExecutor uses the joint owner release
route over all active records. Empty ordinary ensure is a no-op; complete staged
requirements and proven ownership are required to authorize release.

### GNOME

Known resources are profile/user, db/fic.d/99-fic.conf,
db/fic.d/locks/99-fic and db/fic below the trusted dconf root. Exact key/lock
inverse deltas preserve foreign bytes, CRLF, locks and user overrides. Source
names, identities, metadata, contents and profile priority are checked around
publication; no foreign profile entry is silently moved.

`desktop / own_desktop_artifact` separately proves creation of fixed-route
files, empty groups, profile entry, native cache and dconf/db/profile/fic.d/locks
directories. It carries kind, ensure/release phase, had_applied and directory
device/inode; it stores no arbitrary path or foreign snapshot. Artifact ID
markers bind physical objects to the journal. A cache created by FIC has a
native identity source `00-fic-ownership` with `[fic/ownership] cache-id='<id>'`;
preexisting caches never acquire creation ownership.

Creation is Prepared before publication. Directories are staged privately with
ID/inode proof, then exclusively published using renameat2 NOREPLACE. Interrupted
stages are recovered or released only through matching trusted route, marker and
inode; foreign staged children are preserved/refused. Marker scratch files are
not public configuration. New public dirs/files use 0755/0644 even with a
restrictive daemon umask. Shared file changes use AtomicFileWriter snapshot CAS.

Native dconf compilation renders the complete current/target sources.
`dconf update` runs in an isolated directory containing only the copied fic.d;
its bytes must agree with independent native compile. Only the verified fic
cache is CAS-published. Other databases are never regenerated. Native getters
prove required values and non-writability. A foreign lock can remain after our
lock is released; release does not require overriding foreign policy.

Cleanup deletes empty created files/groups/dirs/cache/profile only with valid
creation proof. Foreign content is preserved, and transferred containers or
profile entry are explicitly Detached rather than deleted. Release Prepared,
physical absence/projection checks and durability precede journal resolution.
Missing Applied markers, changed owned scalars, unknown cache state, wrong IDs,
symlinks, unsafe metadata and orphan artifacts fail closed.

### FLY and session-only limits

FLY persistent release uses an exact inverse of the one
`themerc/Variables/ScreenSaverDelay` parameter in the installed master file.
Other lines/groups/newline state remain intact. The marker binds ID+resource;
snapshot CAS/FIC locking and exact applied/original proofs protect update,
release and crash retry. A missing FLY master is not fabricated.

Inactive FLY preflight checks only trusted path/file safety and absence of orphan
FIC markers, without requiring [Variables] or ScreenSaverDelay syntax:

| Requirements / active ownership | File | Outcome |
| --- | --- | --- |
| Neither | Absent, safely proved | SUCCESS, no mutation |
| Neither | Foreign layout, no FIC marker | SUCCESS, bytes unchanged |
| Neither | FIC marker present | FAIL / orphan ownership |
| Either present | Any | Existing strict scalar/marker/CAS/recovery/release proof |

Missing parents are accepted only after proving each existing trusted ancestor;
symlinks and unsafe metadata remain failures. Active ownership is never discarded
because scope no longer requires FLY. The full preflight of every global backend
still precedes any protected mutation.

FLY ensure and release operate on the installed system theme master and verify
that exact persistent source. `persistent_configuration=VERIFIED` is reported
separately from `runtime_effect=NOT_VERIFIED`, independently of ordinary log
filtering. A session-scoped `fly-wmfunc FLYWM_UPDATE_VAL ScreenSaverDelay N*60`
is a convergence helper; failure is a MandatoryGlobal runtime warning, not a
false proof or reversal of persistent enforcement. User theme files are untouched.

KDE/XFCE are SessionOnly. They enumerate all applicable current sessions,
perform native setters/readback and return FAIL if any applicable session fails;
no applicable sessions means SUCCESS for a valid configured policy. New
`session_ready` events apply enabled relevant policies; periodic apply repairs
drift. KDE retains unique D-Bus owner/PID/UID, procfs environment and same-UID
topology checks, native kwriteconfig5/6+kreadconfig5/6, unconditional configure
reload and final readback. XFCE retains typed inspection and typed property repair.
They create no MutationJournal records or user ownership markers and perform no
rollback. Excluding KDE/XFCE stops future enforcement; prior user values remain.

KConfig Kiosk/immutable keys and XFCE system XML/locking are forbidden as FIC
security boundaries: the user controls their configuration source graph, including
XDG_CONFIG_DIRS. Native conditional inverse/CAS is therefore not required for
these deliberately non-reverting writes. LXQt remains recognized by inventory
and compliance but screenlock_timeout explicitly reports Unsupported; there is
no no-op locker backend.

## Enrollment and package removal

| Policy/backend | Current contract |
| --- | --- |
| Scope and compliance | NotEnrolled; logical checkpoints do not mutate OS settings |
| screenlock_timeout | Supported joint rollback for GNOME/FLY; KDE/XFCE physical routes are intentionally NotEnrolled |
| disable_kde_lock_screen_media_controls | NotEnrolled; disabling leaves current user settings unchanged |
| Unknown DE policies/actions/routes | Unsupported/fail-closed |

Owner release invalidates the successful scope checkpoint before physical
change. A successful registry/configuration reconciliation must reverify and
recommit it; failed config save cannot leave consumers authorized by stale
protection. Root-only `fic --maintenance desktop-prerm-prepare preflight|release`
uses the same backends over genuinely empty target requirements, independent
of current scope, active DE or policy status. Debian/RPM removal gates preflight
before service stop, then release after writers stop and before PAM gate detach.
Failures refuse removal. Unknown ownership is not erased.

## CAS boundary and validation

Root resources use existing snapshot CAS plus FIC locking. This is not atomic
conditional rename/unlink against an unrelated writer ignoring the lock: a
residual race remains between final proof and rename/unlink/rmdir. The accepted
boundary applies to shared system resources, not KDE/XFCE user writes. Private
staging is not a source of policy/legacy adoption permission.

Tests distinguish coordinator mocks, temporary filesystem/journal/fsync faults,
generated package scripts, and actual native dconf/GSettings. The explicitly
container-only gnome_journal_native_probe requires root, /.dockerenv and
FIC_NATIVE_GNOME_PROBE=container-only; it is not ordinary host CTest. It covers
existing/created containers, all missing parents, shared owners, foreign edits,
foreign lock/database preservation, restart and cleanup. Native GNOME Shell,
FLY runtime and live KDE/XFCE sessions are NOT VERIFIED. The current checked
image/package matrix and exact test results belong in HANDOFF; native package
inspection is not live-session or package-manager erase proof.

## Display manager scope

`controlled_display_managers` accepts SDDM, GDM and LIGHTDM. Configured intent
is saved by the setter; the administrative handler separately applies the DM
submodule. Scope apply validates only; disable_autologin invokes reconciliation.
Empty intent is UNCONFIGURED on apply. `disable_autologin` and the observational
`absence_of_uncontrolled_display_managers` have Required scope dependencies.
The coordinator validates current configuration versions and complete installed,
selected and running inventory before it prepares `scope/dm`. It preflights all
targets and releases, enforces installed controlled managers, releases obsolete
owners, verifies actual Applied records and resolved releases, and rechecks
inventory and intent before committing. Unknown selected/running managers fail
compliance; inactive installed managers outside scope do not. Unsupported custom
configuration routes fail closed. Direct policy apply cannot bypass the
coordinator or authorize a hypothetical staged mutation.

Physical DM provenance contains a manager, fixed route, exact marker identity,
LightDM seat set, inserted separator, creation ownership and pinned creation
device/inode, prior Applied authority and ensure/release phase. It contains no
arbitrary path or snapshot of administrator configuration. One exact FIC block
at the primary file's end clears SDDM User, disables GDM AutomaticLoginEnable
and TimedLoginEnable, or clears LightDM autologin-user and disables
autologin-guest for every applicable seat. Session names and administrator
bytes are preserved. A FIC-owned block is always created for each installed
controlled DM even if foreign administrator settings already disable autologin.
There is no no-op enrollment optimization. Orphan markers and changed owned blocks refuse mutation.
Release removes only the proven block; a created empty file is unlinked only
when its original creation inode still matches. A replacement is detached and
preserved. Prepared precedes publication; fsync and native inspection precede
Applied. Recovery finishes an interrupted release before fresh enrollment.

SDDM verification follows the installed 0.19–0.21 native ConfigReader tokenizer
and loading order, with package version proof. GDM uses native GKeyFile and
checks the platform's higher-priority runtime configuration. LightDM uses
native `--show-config`, including wildcard/specific seats and source routes.
No display manager is started or restarted by reconciliation. SUCCESS confirms
**native persistent configuration**. It explicitly reports
`live_runtime=NOT_VERIFIED`, since a running manager may cache old settings.
This boundary is included in administrative apply output, independently of
ordinary log filtering; it does not claim live-session enforcement.

Compiled paths are distribution-specific. ALT SDDM uses
`/etc/X11/sddm/sddm.conf` and `/usr/share/sddm/conf.d`; Debian/Ubuntu use
`/etc/sddm.conf` and `/usr/lib/sddm/sddm.conf.d`. Debian/Ubuntu GDM runtime input
is `/run/gdm3/custom.conf`; ALT uses `/var/run/gdm/custom.conf`. For that
read-only runtime input, a root-owned `/var/run` directory or its standard
root-owned alias to the protected `/run` directory is re-proved before use and
closure. Other aliases fail closed. Mutation targets still reject symlinks.
Inputs and directory membership are re-proved after native inspection, so
inspection-time changes cannot authorize stale protection.

Scope/compliance are NotEnrolled; disable_autologin has joint Supported rollback.
Unknown DM policies and generic individual DM undo actions are Unsupported.
`fic --maintenance dm-prerm-prepare preflight|release` releases proven owners
independently of current scope or manager selection. Package removal preflights
before stopping writers and releases before PAM detach; failure blocks removal.
The root CAS/FIC-lock residual race described above also applies to DM files.
