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
authoritative source of the local graphical session list and never delegates
session selection to an agent.

The agent prefers `XDG_SESSION_ID`, but validates the referenced logind session:
it must belong to the agent UID, have `Class=user`, be local (`Remote=no`), and
have type `x11`, `wayland`, or `mir`. `Active=yes` is intentionally not
required, matching the daemon contract for multiple local graphical sessions.

If `XDG_SESSION_ID` is absent or rejected, the agent calls
`sd_pid_get_session(0)` and applies the same validation to the login session of
its own process. If the process belongs to any logind session, that result is
authoritative: a remote, TTY, non-user, foreign-UID, or otherwise unsuitable
process session causes a fail-closed exit and cannot be replaced with a
graphical session of the same user.

Processes started as shared `systemd --user` services may not belong to any
specific `session-*.scope`; systemd documents that `sd_pid_get_session()` then
returns `-ENODATA`. Only for this distinct not-associated result, the agent
enumerates the current UID's sessions with `sd_uid_get_sessions(uid, 0, ...)`,
applies the same UID/class/remote/type predicate, and accepts the result only
when exactly one local graphical candidate remains. It does not use active
state, seat, display, age, ordering, or another winner heuristic. Zero or
multiple candidates remain fail-closed.

This third fallback handles a systemd-managed XDG Autostart when one graphical
session is unambiguous, while preserving isolation for SSH processes and for
UIDs with simultaneous graphical sessions. The XDG Autostart entry must remain
per-session and must not be converted into a deliberately shared per-user
service; desktop environments with multiple GUI sessions and no session-bound
identity handoff cannot be resolved by this fallback.

For policies that require graphical-session access, the daemon:

1. Lists local graphical user sessions through `loginctl`.
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

`OSS/screenlock_timeout` currently implements this flow for GNOME, Unity, and
Budgie through `gsettings`, KDE Plasma through `kreadconfig`/`kwriteconfig`,
XFCE through `xfconf-query`, and FLY through `fly-wmfunc` plus the user's
`~/.fly/theme/current.themerc`. Other desktop environments fail explicitly until
a dedicated daemon-side backend is implemented.

After installing or upgrading the package, existing graphical sessions must
be restarted or the agent must be launched manually before session-dependent
policy apply commands can succeed.

`fic-session-agent --version` and `fic-session-agent --build-info` report the
compiled product version and build provenance without requiring a graphical
session environment.
