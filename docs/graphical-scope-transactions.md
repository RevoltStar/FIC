# Transactional graphical scope and ownership-safe release

DE and DM use independent checkpoints in the same MutationJournal.

## Authority and state

Configured scope is intent in OSS.conf. `set_value` for the scope only saves
that intent and reloads the registry. It neither mutates OS resources nor
commits a scope transition. Empty scope is savable, but enabled apply returns
UNCONFIGURED.

MutationJournal holds both logical checkpoints and independent physical
provenance. `scope/de` belongs only to
`OSS/DesktopEnvironment/controlled_desktop_environments`. Its sorted canonical
committed_scope/target_scope and phase pending/failed/partial/committed are
validated on write, status change and reload. Applied plus phase committed
is the only authorization for ordinary dependent apply. Prepared/failed/partial
retain the last committed checkpoint; they do not assert that its protection
remains effective. Checkpoints grant no physical ownership.

`screenlock_timeout`, `disable_kde_lock_screen_media_controls` and
`absence_of_uncontrolled_desktop_environments` have Required scope dependencies.
The existing planner/reverse graph blocks missing/disabled/failed dependencies
and refuses scope disable while a consumer is enabled. Direct session and
compliance entrypoints also require a matching committed checkpoint. Compliance
is observational: an excluded running DE can violate it after a successful
release; it does not reverse administrative intent or terminate sessions.

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
change leaves the transition partial and requires registry reload/retry. Scope
set_value never starts this sequence.

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

The current FLY backend cannot prove effective runtime enforcement. Production
scope transitions with a nonempty FLY policy requirement fail before physical
writes. Its journaled persistent inverse remains usable for independent release;
no FLYWM_UPDATE_VAL call writes untracked session state.

KDE/XFCE setters also fail closed before any native writer. Existing KDE
owner/PID/UID/procfs/environment/topology checks and typed XFCE reads remain.
Session-only requirements cannot yield a successful scope checkpoint while
conditional mutation/equivalent exclusion is unavailable, including when an
agent is absent. There are no newly created untracked session changes to undo.
Unproven legacy user/system changes are never adopted or restored.

The inspected [kwriteconfig source](https://github.com/KDE/kconfig/blob/master/src/kreadconfig/kwriteconfig.cpp)
and [Xfconf D-Bus contract](https://github.com/xfce-mirror/xfconf/blob/master/common/xfconf-dbus.xml.in)
provide separate writes without expected-value/version operands. This describes
the current backend limitation, not an assertion that every future native
mechanism is impossible.

## Enrollment and package removal

| Policy/backend | Current contract |
| --- | --- |
| Scope and compliance | NotEnrolled; logical checkpoints do not mutate OS settings |
| screenlock_timeout | Supported joint rollback for permitted journaled root mutations; unavailable session/FLY enforcement explicitly refuses apply |
| disable_kde_lock_screen_media_controls | Unsupported rollback; its native session setter is unavailable |
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
is saved without physical reconciliation. Empty intent is UNCONFIGURED on
apply. `disable_autologin` and the observational
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
bytes are preserved. Orphan markers and changed owned blocks refuse mutation.
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
