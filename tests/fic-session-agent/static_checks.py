#!/usr/bin/env python3
from pathlib import Path
import sys


root = Path(sys.argv[1])
install_layout = (root / "cmake/FicInstallLayout.cmake").read_text()
agent_cmake = (root / "fic-session-agent/CMakeLists.txt").read_text()
provider = (
    root / "fic-session-agent/src/SystemdLogindSessionProvider.cpp"
).read_text()
resolver = (root / "fic-session-agent/src/SessionIdentityResolver.cpp").read_text()
main_source = (root / "fic-session-agent/src/main.cpp").read_text()
desktop = (root / "fic-session-agent/fic-session-agent.desktop.in").read_text()
deb_builder = (root / "packaging/deb/build-fic-debian12-deb.sh").read_text()
rpm_builder = (root / "packaging/rpm/build-fic-alt-p11-rpm.sh").read_text()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


require("pkg_check_modules(SESSION_AGENT_LIBSYSTEMD REQUIRED IMPORTED_TARGET libsystemd)" in agent_cmake,
        "fic-session-agent does not resolve libsystemd through pkg-config")
require("PkgConfig::SESSION_AGENT_LIBSYSTEMD" in agent_cmake,
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

require('set(FIC_SESSION_AGENT_BINDIR "/usr/libexec/fic" CACHE PATH' in install_layout,
        "session agent public executable directory is not canonicalized in the install layout")
require('RUNTIME DESTINATION "${FIC_SESSION_AGENT_BINDIR}"' in agent_cmake,
        "session agent is not installed in its public executable directory")
require('RUNTIME DESTINATION "${FIC_PRIVATE_BINDIR}"' not in agent_cmake,
        "session agent must not be installed in the private executable directory")
require("WORLD_READ WORLD_EXECUTE" in agent_cmake,
        "session agent CMake install mode is not executable by ordinary users")
require("Exec=@FIC_SESSION_AGENT_BINDIR@/fic-session-agent" in desktop,
        "session agent XDG Autostart does not use the canonical public path")
require("/opt/fic/bin/fic-session-agent" not in desktop,
        "session agent XDG Autostart points into the private tree")

for builder_name, builder in (
    ("DEB", deb_builder),
    ("RPM", rpm_builder),
):
    require("/opt/fic/bin/fic-session-agent" not in builder,
            f"{builder_name} packaging leaves the session agent in the private tree")
    require('chmod 0755 "$package_root/usr/libexec/fic"' in builder and
            'chmod 0755 "$package_root/usr/libexec/fic/fic-session-agent"' in builder,
            f"{builder_name} packaging does not enforce public session-agent modes")
    require('chmod 0750 "$package_root/opt/fic/bin/fic-cli"' in builder,
            f"{builder_name} packaging does not preserve the private fic-cli mode")
    require('chmod 0755 "$package_root/opt/fic/bin/fic-cli"' not in builder,
            f"{builder_name} packaging makes fic-cli executable by ordinary users")
    require("find /opt/fic -type d -exec chmod 2750" in builder,
            f"{builder_name} packaging no longer keeps /opt/fic private")
    for forbidden_private_mode in (
        "chmod 0755 /opt/fic",
        "chmod 0755 \"$package_root/opt/fic\"",
        "find /opt/fic -type d -exec chmod 0755",
        "find \"$package_root/opt/fic\" -type d -exec chmod 0755",
    ):
        require(forbidden_private_mode not in builder,
                f"{builder_name} packaging makes /opt/fic world-traversable")

require("--root-owner-group" in deb_builder,
        "DEB packaging does not normalize package ownership to root:root")
require("%defattr(-,root,root,-)" in rpm_builder,
        "RPM packaging does not normalize package ownership to root:root")
require('"session-" + sessionId + ".sock"' in main_source,
        "session agent socket is no longer keyed by the resolved session id")
require("info.remote ||" not in resolver,
        "session agent still rejects every remote logind session")
require("allowGraphicalContextForTty" in resolver and
        "graphical_context(agentContext)" in resolver,
        "session agent does not validate the session-bound startx context")
require("candidate, false, agentContext" in resolver,
        "UID-only fallback can ambiguously select a TTY session")
require("effectiveGraphicalSessionType" in resolver and
        'context.sessionType != "tty"' in resolver and
        "context.desktop.empty()" in resolver,
        "session agent does not canonicalize session-bound startx context")
serve_client = main_source[main_source.index("void serve_client"):]
serve_client = serve_client[:serve_client.index("} // namespace")]
require("const fic::session_agent::AgentSessionContext& context" in serve_client and
        'environment_value("XDG_SESSION_TYPE")' not in serve_client and
        '{"session_type", context.sessionType}' in serve_client,
        "session agent IPC response is not serialized from the validated context")
require("agentContext.sessionType = *effectiveType" in main_source and
        "serve_client(clientFd, sessionId, agentContext)" in main_source,
        "session agent does not publish the canonical graphical session type")

for dockerfile, dependency in (
    ("packaging/deb/Dockerfile", "libsystemd-dev"),
    ("packaging/deb/Dockerfile.debian13", "libsystemd-dev"),
    ("packaging/deb/Dockerfile.ubuntu2404", "libsystemd-dev"),
    ("packaging/deb/Dockerfile.ubuntu2604", "libsystemd-dev"),
    ("packaging/rpm/Dockerfile", "libsystemd-devel"),
):
    require(dependency in (root / dockerfile).read_text(),
            f"{dockerfile} does not install {dependency}")
