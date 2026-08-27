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
its own process. It never enumerates a user's sessions and never selects a
primary, display, active, or first session. This remains correct when a UID has
multiple simultaneous graphical sessions.

Processes started as shared `systemd --user` services may not belong to any
specific `session-*.scope`; systemd documents that `sd_pid_get_session()` then
returns no session. When the launcher also did not preserve a valid
`XDG_SESSION_ID`, exact per-session identity is unavailable and the agent exits
fail-closed. The XDG Autostart entry must therefore remain per-session; it must
not be converted into a shared per-user service without an explicit,
session-bound identity handoff.

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
