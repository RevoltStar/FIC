#!/usr/bin/env python3
from pathlib import Path
import sys


root = Path(sys.argv[1])
agent_cmake = (root / "fic-session-agent/CMakeLists.txt").read_text()
provider = (
    root / "fic-session-agent/src/SystemdLogindSessionProvider.cpp"
).read_text()
resolver = (root / "fic-session-agent/src/SessionIdentityResolver.cpp").read_text()
main_source = (root / "fic-session-agent/src/main.cpp").read_text()
desktop = (root / "fic-session-agent/fic-session-agent.desktop.in").read_text()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


require("pkg_check_modules(LIBSYSTEMD REQUIRED IMPORTED_TARGET libsystemd)" in agent_cmake,
        "fic-session-agent does not resolve libsystemd through pkg-config")
require("PkgConfig::LIBSYSTEMD" in agent_cmake,
        "fic-session-agent is not linked to the imported libsystemd target")
require("sd_pid_get_session(0" in provider,
        "agent fallback does not resolve the current process session")
require("result == -ENODATA" in provider,
        "agent provider does not distinguish an unbound process from hard errors")
require("sd_uid_get_sessions(uid, 0" in provider,
        "agent does not enumerate all online UID sessions after ENODATA")

for forbidden in (
    "sd_uid_get_display",
    "show-user",
    "list-sessions",
):
    require(forbidden not in provider and forbidden not in resolver,
            f"session identity resolver contains forbidden UID heuristic: {forbidden}")

require("Exec=@FIC_PRIVATE_BINDIR@/fic-session-agent" in desktop,
        "session agent is no longer launched directly by per-session XDG Autostart")
require('"session-" + sessionId + ".sock"' in main_source,
        "session agent socket is no longer keyed by the resolved session id")
require("info.remote ||" not in resolver,
        "session agent still rejects every remote logind session")
require("allowGraphicalContextForTty" in resolver and
        "graphical_context(agentContext)" in resolver,
        "session agent does not validate the session-bound startx context")
require("candidate, false, agentContext" in resolver,
        "UID-only fallback can ambiguously select a TTY session")

for dockerfile, dependency in (
    ("packaging/deb/Dockerfile", "libsystemd-dev"),
    ("packaging/deb/Dockerfile.debian13", "libsystemd-dev"),
    ("packaging/deb/Dockerfile.ubuntu2404", "libsystemd-dev"),
    ("packaging/deb/Dockerfile.ubuntu2604", "libsystemd-dev"),
    ("packaging/rpm/Dockerfile", "libsystemd-devel"),
):
    require(dependency in (root / dockerfile).read_text(),
            f"{dockerfile} does not install {dependency}")
