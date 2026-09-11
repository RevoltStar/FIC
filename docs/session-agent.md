# FIC session agent

`fic-session-agent` is a per-graphical-session process, not a per-user
service. It is started by XDG Autostart inside every graphical user session
and exposes session metadata to the root `fic` daemon through:

```text
/run/user/<uid>/fic/session-<session-id>.sock
```

The agent does not receive policy values and does not apply policies. It only
returns the desktop name, session type, X11 display, and Wayland display of its
own session. Only a root peer is allowed to query the socket. The daemon is the
authoritative source of the session candidate list and never delegates
session selection to an agent.

After its context socket is listening, the agent sends the minimal untrusted
hint `{"event":"session_ready","session_id":"..."}` to the separate
daemon-owned `/run/fic/fic-session-events.sock`. It never sends a PID, desktop,
display, policy name, or policy value on this endpoint. If the daemon is still
starting, notification retries run in a background thread while the context
socket remains available. A positive ACK means only that reconciliation was
scheduled. The daemon derives the peer UID from `SO_PEERCRED`, validates the
claimed session through logind, and then queries the existing context socket;
the agent is not a privileged identity or a source of policy decisions.

The agent prefers `XDG_SESSION_ID`, but validates the referenced logind session:
it must belong to the agent UID and have `Class=user`. Remote sessions are
accepted. The logind type is normally `x11`, `wayland`, or `mir`; a directly
identified `Type=tty` session is accepted only when the agent reports a
consistent graphical context and a non-empty desktop identity. For a normal
`startx`, raw `XDG_SESSION_TYPE=tty` (or an empty value) is valid when `DISPLAY`
is present; the effective type becomes `x11`. A matching `WAYLAND_DISPLAY`
makes the effective type `wayland` and wins over `DISPLAY` when both exist.
Explicit raw `x11` and `wayland` values still require their matching display.
The agent publishes this canonical effective type to the daemon from the same
environment snapshot that passed identity validation. This covers a
session-bound `startx` without accepting an arbitrary TTY as graphical.
`Active=yes` is intentionally not required.

If `XDG_SESSION_ID` is absent or rejected, the agent calls
`sd_pid_get_session(0)` and applies the same validation to the login session of
its own process. If the process belongs to any logind session, that result is
authoritative: a non-user, foreign-UID, non-graphical TTY, or otherwise
unsuitable process session causes a fail-closed exit and cannot be replaced
with a different session of the same user.

Processes started as shared `systemd --user` services may not belong to any
specific `session-*.scope`; systemd documents that `sd_pid_get_session()` then
returns `-ENODATA`. Only for this distinct not-associated result, the agent
enumerates the current UID's sessions with `sd_uid_get_sessions(uid, 0, ...)`,
applies the UID/class/native-graphical-type predicate, and accepts the result
only when exactly one graphical candidate remains. TTY sessions are never
selected by this UID-only fallback, even if the agent environment looks
graphical. It does not use active state, seat, display, age, ordering, or
another winner heuristic. Zero or multiple candidates remain fail-closed.

This third fallback handles a systemd-managed XDG Autostart when one graphical
session is unambiguous, while preserving isolation for SSH processes and for
UIDs with simultaneous graphical sessions. The XDG Autostart entry must remain
per-session and must not be converted into a deliberately shared per-user
service; desktop environments with multiple GUI sessions and no session-bound
identity handoff cannot be resolved by this fallback.

`controlled_desktop_environments` is the exact administrative scope for all
desktop-dependent policies. Its default empty list means `UNCONFIGURED`; it is
not inferred from packages, session descriptors, or distribution identity.
An ordinary policy ignores both a reliably classified desktop outside this
scope and an unclassifiable graphical session; neither affects that ordinary
policy's apply result. A controlled desktop without a required policy backend
is `Unsupported` and fails. Detection of desktops outside the scope and
unclassifiable graphical sessions belongs exclusively to the fixed
`absence_of_uncontrolled_desktop_environments` policy. It checks the complete
current inventory, fails closed for either case, and observes compliance only;
it does not terminate sessions.

For policies that require graphical-session access, the daemon:

1. Builds one shared inventory of current foreground/background and remote
   native graphical sessions, which logind exposes independently of the agent.
   A `Type=tty` startx session is
   included only when its exact session-id endpoint is an owned Unix socket;
   the complete socket owner, peer and response identity checks still happen
   during the query. Closing or dead sessions are excluded. Therefore FIC does
   not claim discovery of an arbitrary startx session without its bound agent.
2. Waits up to 10 seconds for a matching agent socket when XDG Autostart is
   still starting, retrying only a missing socket or a transient refused
   connection.
3. Verifies the socket type and owner on every attempt, then verifies the
   connected peer UID. An unsafe socket fails immediately without retries.
4. Runs fixed utilities itself after switching to the session user's UID and
   supplementary groups.
5. Reads the resulting setting back and treats an agent still unavailable
   after the bounded readiness wait, command failure, timeout, unsupported
   desktop, or incorrect value as a policy failure.

Consequently, a native graphical logind session is discovered without an
agent, but policy apply fails after the readiness timeout if its agent never
appears. A graphical desktop inside `Type=tty` is discovered only through its
exact session-bound agent endpoint. A plain TTY without that endpoint is not a
candidate.

`OSS/screenlock_timeout` implements current-session convergence for GNOME, Unity, and
Budgie through `gsettings`, KDE Plasma through `kreadconfig`/`kwriteconfig`,
XFCE through `xfconf-query`, and FLY through `fly-wmfunc`. KDE and XFCE are
`SessionOnly`. Controlled GNOME and FLY are `MandatoryGlobal`: their system
backends prove the machine-wide state before current-session convergence. FLY
authority is `/usr/share/fly-wm/theme.master/themerc`; the session backend does
not read or write `~/.fly/theme/current.themerc`. KDE does not publish global
requirements while its KConfig source graph remains controlled by the session
user.
The same backend-driven ensure -> verification sequence runs both during normal
policy apply and targeted `session_ready` reconciliation, before the current
session is converged. Successful authoritative global enforcement
makes an optional current-session convergence failure a warning; a
`SessionOnly` failure remains fatal for that operation. Unsupported controlled
desktops and failures before global verification remain errors.

FIC-owned global desktop configuration has a separate active-requirement
lifecycle. Physical identity is `(backend, setting)`, not the owning policy.
Each setting has one required value and a transient set of enabled policy
owners. Policies requesting the same value share one requirement. Owners are
used for merge, validation, and diagnostics; backends do not persist or verify
them as system configuration.

Stage A builds and validates the complete desired state for all registered
backends: capability/contributor consistency, backend existence, typed
backend desktop identity, contribution
owner matching the producing policy, explicit desktop association, and nonempty
physical keys. Every registered backend is bound to exactly one canonical
`DesktopEnvironmentKind`; a backend without one, a duplicate backend for the
same desktop, and a contribution whose desktop differs from the bound backend
desktop are all rejected. Every applicable `MandatoryGlobal` `(policy, desktop)` must have
at least one contribution, while a contribution for `SessionOnly` is rejected.
Different
values for the same physical key are conflicts, including contributions from
one policy. Any Stage A failure prevents all backend mutation; policy order
never selects a winner. Identical setting names in different backends are
independent.

After Stage A succeeds, each `DesktopSystemBackend` with active requirements is
reconciled independently: ensure the supplied setting values and verify their
effective protected system state. Checking only that a FIC-owned fragment has
the requested text is insufficient when higher-precedence configuration can
override it. Failures are accumulated with backend and operation diagnostics; a
failed backend does not block another backend's enforcement, and any failure
makes the overall result unsuccessful. There is no transaction spanning
backends.

Reconciliation returns a structured report with Stage A validity, independent
per-backend attempted/verified results, and per-policy/per-desktop results
derived only from the backends required by that policy. Shared same-value
settings make every owner depend on the same backend result. A failure in an
unrelated desktop backend therefore changes the overall report to failed but
does not contaminate another policy's verified result.

`ENABLE` means FIC checks and enforces the active requirement. `DISABLE` means
FIC stops checking and enforcing it. A missing setting in the active requirement
set is not a deletion command: the backend is not called with an empty full-state
replacement, and existing system configuration remains untouched. This also
preserves unrelated FIC/backend state and foreign administrator configuration.
Rollback, provenance, baseline restoration, uninstall cleanup, and purge
semantics are outside this contract.

The daemon registers `GnomeSystemBackend` as backend `"gnome"`, typed as
`DesktopEnvironmentKind::Gnome`. It owns a separate dconf database:
`/etc/dconf/db/fic`, source keyfile `/etc/dconf/db/fic.d/99-fic.conf`, and lock
file `/etc/dconf/db/fic.d/locks/99-fic`. The `.conf` basename is accepted by
the supported dconf compiler. The backend adds
`system-db:fic` as the first system database in `/etc/dconf/profile/user`, while
preserving administrator comments, blank lines, foreign database entries, and
their relative order. The profile parser accepts the documented dconf source
types `user-db:`, `service-db:`, `system-db:`, and `file-db:` (`file-db` is a
read-only source), including leading/trailing whitespace and inline `#`
comments; foreign lines are kept byte-for-byte. A profile whose first source is
not writable, an unknown source type, and duplicate `system-db:fic` entries all
fail closed before any mutation.

For controlled GNOME, `screenlock_timeout=N` contributes and locks exactly
`/org/gnome/desktop/session/idle-delay=uint32 N*60`,
`/org/gnome/desktop/screensaver/lock-enabled=true`,
`/org/gnome/desktop/screensaver/lock-delay=uint32 0`, and
`/org/gnome/desktop/lockdown/disable-lock-screen=false`. The lockdown key is
mandatory for a provable screen lock: `disable-lock-screen=true` prevents GNOME
Shell from locking the screen at all, so the other three keys alone cannot
verify the policy. Existing valid settings
and locks in the FIC-owned fragments are merged and retained. After atomic
source updates the backend runs verified `dconf update`, then uses a clean,
explicit `DCONF_PROFILE=/etc/dconf/profile/user` context for `gsettings get`
and `gsettings writable`; every value must match and every key must report
non-writable. This includes `gsettings get org.gnome.desktop.lockdown
disable-lock-screen == false` and a non-writable lockdown key. Correct source
files with stale effective state trigger one
recompilation attempt and another verification. `dconf` and `gsettings` are
optional platform executables and are resolved only for active GNOME global
requirements.

The daemon unit runs with `UMask=0027`, which must not leak into public GNOME
dconf state. FIC-created dconf directories (`dconf`, `dconf/profile`,
`dconf/db`, `dconf/db/fic.d`, `dconf/db/fic.d/locks`) receive an explicit
fd-based `fchmod 0755` after their secure creation, so they stay traversable by
ordinary desktop users regardless of the daemon umask; managed files are
written `0644`/root-owned. `dconf update` runs with an isolated child umask
`0022` (a `ProcessOptions::childUmask` capability in the shared process
executor; the parent process umask is never modified). Existing foreign
directories are validated, never re-permissioned: every directory component
from the trusted root through the profile and compiled-database parents must
remain trusted-owned, free of group/world write bits, and other-executable
(`0751` suffices; `0750` fails closed with
`GNOME dconf directory is not traversable by ordinary users`). Verification —
in both `ensureManagedSettings` and the independent `verifyManagedSettings`
pass — additionally requires the profile and the compiled database
`/etc/dconf/db/fic` to be regular, trusted-owned, not group/world writable, and
world-readable (`0644` is the expected compiled mode; `0640`/`0600` fail with
`compiled GNOME FIC dconf database is not readable by ordinary users`). Root
`gsettings` success alone never counts as verified when the compiled state is
unreadable to ordinary users.

A directory is considered FIC-created only when its `mkdirat` call succeeds.
If creation races with another process and returns `EEXIST`, the raced-in
directory is opened with `openat(..., O_NOFOLLOW)`, validated as existing
foreign state, and never passed to the FIC-created-directory `fchmod` path.

The daemon also registers `KdeSystemBackend` as backend `"kde"`, typed as
`DesktopEnvironmentKind::Kde`. The backend remains groundwork for a future
authoritative KDE design and can manage `/etc/xdg/kscreenlockerrc` with per-key
Kiosk immutability:

```ini
[Daemon]
Autolock[$i]=true
Timeout[$i]=N
Lock[$i]=true
LockGrace[$i]=0
RequirePassword[$i]=true
```

`Lock=true` is required because timeout and password settings alone do not
prove that locking is enabled. The backend replaces conflicting active forms
of these five keys while retaining comments, blank lines, unrelated groups,
unrelated keys, and stale settings with no active requirement. It never uses
whole-group or whole-file immutability.

Both KDE system files, `/etc/xdg/kscreenlockerrc` and
`/etc/xdg/kdeglobals`, and their full ancestor chain use the same fd-based
`openat`/`O_NOFOLLOW`, trusted-owner, safe-write-bit, traversal, atomic-write,
and `fsync` contract as the GNOME system state. Existing foreign ancestors are
never chmod'ed (`0750` fails closed; `0751` is sufficient), FIC-created
directories receive explicit `0755`, and both files must be world-readable
regular trusted-owned files. Both files are prevalidated before either is
changed. Effective verification resolves the optional separately packaged
`fic-kconfig-verifier` only for active KDE requirements. This helper is linked
to the platform's real KF5/KF6 ConfigCore and runs once with
`KConfig::FullConfig`, a clean temporary `HOME` and `XDG_CONFIG_HOME`, the
complete platform `XDG_CONFIG_DIRS` hierarchy, and `LC_ALL=C`/`LANG=C`. It
installs conflicting user and `kdedefaults/kdeglobals` values for all five
keys and requires every effective value to remain immutable. Textual `[$i]`
presence without this proof is insufficient. `DISABLE` remains
no-cleanup/no-rollback. The headless `fic` package does not depend on KDE; the
verifier is supplied by the optional `fic-kconfig-verifier` package.

For controlled FLY, `screenlock_timeout=N` contributes exactly one
`FlySystemBackend` requirement in `[Variables]`: `ScreenSaverDelay=N*60`.
`ScreenSaver` and `ScreenSaverDBUS` are administrator-owned locker selection
state and are preserved without verification. The backend securely traverses every component below
the trusted root with `openat`/`O_NOFOLLOW`, rejects unsafe ownership or
group/world-writable state, preserves unrelated master content, and atomically
replaces the ordinary-user-readable `themerc`. It may create a missing file
inside an existing trusted `theme.master` directory, but never creates that
directory. Verification reads only the master file. One session-scoped
`fly-wmfunc FLYWM_UPDATE_VAL ScreenSaverDelay N*60` call is an immediate convergence helper and does
not provide persistent authority.

This verifier models the standard distribution environment; it cannot prove
the environment used by the running screen locker. In Plasma 5, `ksmserver`
owns `KSldApp` on X11 and `kwin_wayland` owns it on Wayland. In Plasma 6,
`kwin` owns it. Plasma 5 and Plasma 6 source
`$XDG_CONFIG_HOME/plasma-workspace/env/*.sh` before completing session startup,
with user scripts taking precedence, and propagate the resulting environment
to session processes and user-systemd/DBus activation. KConfig in both KF5 and
KF6 uses `XDG_CONFIG_HOME` and `XDG_CONFIG_DIRS` through `QStandardPaths`; it
also honors `KDE_SKIP_KDERC`, which can suppress `/etc/kde5rc`. User systemd
environment and unit overrides provide additional user-controlled startup
paths. No standard root-owned mechanism was found that fixes these inputs for
the actual locker process across both supported Plasma generations while
preventing ordinary-user overrides. Therefore the production
`screenlock_timeout` policy publishes no KDE global contribution and does not
invoke `KdeSystemBackend` for a KDE-only scope.

The platform KDE hierarchy records the standard distribution environment:
Debian 12/13 use `/etc/xdg` followed by
`/usr/share/desktop-base/kf5-settings`; Ubuntu/Kubuntu 24.04 and 26.04 use
`/etc/xdg/xdg-plasma`, `/etc/xdg`, and
`/usr/share/kubuntu-default-settings/kf5-settings`; ALT p11 uses `/etc/xdg`.
This metadata improves verifier correctness for the normal distro startup but
is not a security boundary against a user-modified session environment.

KDE current-session convergence reads the five values, writes them only when
needed, always calls `org.kde.screensaver.configure`, and only then performs
the final file readback. A configure failure fails the `SessionOnly`
reconciliation. KScreenLocker exposes no runtime-effective timeout read API,
so successful reload plus file readback is the best available convergence
contract; the readback alone does not prove the value cached by the running
locker.

GNOME and FLY are `MandatoryGlobal`; KDE and XFCE are `SessionOnly`; LXQt
remains unsupported.
`DesktopSystemBackend` remains the only global enforcement mechanism: policies
describe requirements and have no parallel value, protection, or verification
hooks.

`OSS/disable_kde_lock_screen_media_controls` is applicable only to controlled
KDE sessions. A successfully identified non-KDE desktop is `NotApplicable`.
Unclassified inventory entries are ignored by ordinary scoped policies but
fail the dedicated full-inventory compliance policy.

After installing or upgrading the package, existing graphical sessions must
be restarted or the agent must be launched manually before session-dependent
policy apply commands can succeed.

Startup/explicit/periodic apply continues to enumerate existing sessions and
reconciles declarative FIC-owned global desktop state after rebuilding the
registry. Config mutations do the same immediately after a successful rebuild.
A later `session_ready` performs a full-inventory compliance check, runs the
same registry-wide `DesktopGlobalConfigReconciler`, then invokes only targeted
enabled `SessionAwarePolicy` session convergence; it does not re-run all OSS
policies. Each policy receives `resultFor(policy, session.desktop)`. Only a
missing or failed relevant result prevents runtime convergence for future
`MandatoryGlobal` policies; `SessionOnly` policies remain independent. Once the
relevant global result is verified, session preparation and runtime failures are
warnings and cannot retroactively invalidate persistent global enforcement.
Runtime reconciliation diagnostics do not rewrite the historical result of an
earlier apply operation.

dconf profile selection happens at login. A newly installed `system-db:fic`
is authoritative for fresh sessions, while an already running GNOME session
may not observe the new profile or lock until relogin. FIC does not restart the
shell or terminate the session; the existing GNOME session handler performs
best-effort convergence for that current session and now enforces all four
screen-lock values, including
`org.gnome.desktop.lockdown disable-lock-screen=false`. This limitation does not
weaken verification of the persistent profile for new sessions.

For normal apply the daemon installs the same report as explicit per-pass
context on every session-aware policy. Multi-DE policies evaluate each desktop
separately: verified desktops may still receive best-effort runtime convergence,
while missing coverage or a failed relevant backend makes the policy result
fail. `apply_policy` and `apply_module` use policy/module-scoped report success,
so an unrelated backend failure does not reject a successful targeted request;
full apply and startup retain overall failure if any backend failed.

The session-event listener is mandatory startup infrastructure. `fic.service`
remains `Type=notify`, `NotifyAccess=main`, and `TimeoutStartSec=600s`;
`READY=1` is sent only after startup apply and successful listen on both the
administrative and session-event sockets. A session-event listen failure exits
before readiness.

`fic-session-agent --version` and `fic-session-agent --build-info` report the
compiled product version and build provenance without requiring a graphical
session environment.
