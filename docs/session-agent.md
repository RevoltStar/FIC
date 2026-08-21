# FIC session agent

`fic-session-agent` is started by XDG Autostart inside every graphical user
session. It exposes session metadata to the root `fic` daemon through:

```text
/run/user/<uid>/fic/session-<session-id>.sock
```

The agent does not receive policy values and does not apply policies. It only
returns the desktop name, session type, X11 display, and Wayland display of its
own session. Only a root peer is allowed to query the socket.

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
