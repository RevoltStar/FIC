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

`OSS/screenlock_timeout` currently implements this flow for GNOME, Unity, and
Budgie through `gsettings`, KDE Plasma through `kreadconfig`/`kwriteconfig`,
XFCE through `xfconf-query`, and FLY through `fly-wmfunc` plus the user's
`~/.fly/theme/current.themerc`. Other desktop environments fail explicitly until
a dedicated daemon-side backend is implemented. These existing backends are
classified `SessionOnly`: none is claimed as `MandatoryGlobal`, because no
implemented system lock/kiosk mechanism currently proves precedence over user
configuration. A future `MandatoryGlobal` backend must separately apply the
global value, apply protection/immutability, and verify persistent effective
state. The same value -> protection -> verification sequence runs both during
normal policy apply and targeted `session_ready` reconciliation, before the
current session is converged. Successful authoritative global enforcement
makes an optional current-session convergence failure a warning; a
`SessionOnly` failure remains fatal for that operation. Unsupported controlled
desktops and failures before global verification remain errors.

FIC-owned global desktop configuration has a separate declarative lifecycle.
Enabled policies contribute desired entries grouped by a registered
`DesktopSystemBackend`; the reconciler replaces and then verifies only the
backend's FIC-managed namespace. A backend must preserve administrator-owned
configuration outside that namespace. Disabled or removed policies therefore
disappear from desired state and their stale FIC-owned entries are removed on
the next successful config rebuild, including after daemon restart. Matching
state is not rewritten. No GNOME, KDE, XFCE, or FLY system backend is
registered yet, so the production policies below remain session-only.

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
A later `session_ready` performs only targeted enabled `SessionAwarePolicy`
reconciliation plus a full-inventory compliance check; it does not re-run all
OSS policies. For a future `MandatoryGlobal` policy, that targeted operation
does re-ensure and verify the policy's own global state before converging the
new session. Runtime reconciliation diagnostics do not rewrite the historical
result of an earlier apply operation.

The session-event listener is mandatory startup infrastructure. `fic.service`
remains `Type=notify`, `NotifyAccess=main`, and `TimeoutStartSec=600s`;
`READY=1` is sent only after startup apply and successful listen on both the
administrative and session-event sockets. A session-event listen failure exits
before readiness.

`fic-session-agent --version` and `fic-session-agent --build-info` report the
compiled product version and build provenance without requiring a graphical
session environment.
