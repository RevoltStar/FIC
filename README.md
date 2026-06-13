FIC 2.0 - daemon-centered Free Integrity Control prototype

Components:
- fic: daemon, owns policy application and /opt/fic/config mutations through /run/fic/fic.sock
- fic-session-agent: per-graphical-session context provider; it does not apply policies
- fic-cli: terminal client; sends set/enable/disable/apply commands to fic
- fic-gui: graphical client; sends config mutation commands to fic
- fic-dick: device database collector
