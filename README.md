FIC 2.0 - daemon-centered Free Integrity Control prototype

Components:
- fic: daemon, owns policy application and /opt/fic/config mutations through /run/fic/fic.sock
- fic-session-agent: per-graphical-session context provider; it does not apply policies
- fic-cli: terminal client; sends set/enable/disable/apply commands to fic
- fic-gui: graphical client; sends config mutation commands to fic
- fic-dick: device database collector

Access model:
- Access to the daemon API is intentionally controlled by Unix socket permissions.
- Members of the `fic` OS group are treated as full FIC administrators and currently have full access to all daemon API commands, including configuration changes, policy application, device database changes, lock/unlock actions, hash recalculation, and daemon shutdown.
- Ordinary users must not be added to the `fic` group.
