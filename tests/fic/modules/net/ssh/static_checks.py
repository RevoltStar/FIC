#!/usr/bin/env python3
from pathlib import Path
import sys


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def parse_properties(path):
    properties = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        require(separator, f"{path}: malformed property: {raw_line}")
        properties[key] = value
    return properties


def main():
    if len(sys.argv) != 2:
        print("usage: static_checks.py <repo-root>", file=sys.stderr)
        return 2

    root = Path(sys.argv[1])
    registry = (root / "fic/src/daemon/main_function.cpp").read_text(encoding="utf-8")
    registration = registry.find("std::make_unique<NET_ssh_pubkey_auth>(")
    require(registration >= 0, "ssh_pubkey_auth must be registered in initPolicyRegistry")
    require(
        "platform.ssh, executables"
        in registry[registration : registration + 180],
        "ssh_pubkey_auth must receive the selected SSH profile and executable resolver",
    )

    config = parse_properties(root / "fic/src/resources/config/NET.conf")
    require(
        config.get("ssh_pubkey_auth.status") == "DISABLE",
        "ssh_pubkey_auth must be shipped disabled by default",
    )
    require(
        config.get("ssh_pubkey_auth.value") == "yes",
        "ssh_pubkey_auth must enforce PubkeyAuthentication yes",
    )

    for language in ("ru", "en"):
        localization = (root / f"fic/src/resources/lang/{language}.lang").read_text(
            encoding="utf-8"
        )
        prefix = "[module:NET][policy:ssh_pubkey_auth]"
        require(
            "\n" + prefix + "=" in "\n" + localization,
            f"{language}.lang lacks ssh_pubkey_auth title",
        )
        require(
            "\n" + prefix + "[description]=" in "\n" + localization,
            f"{language}.lang lacks ssh_pubkey_auth description",
        )

    registration = registry.find("std::make_unique<NET_ssh_use_pam>(")
    require(registration >= 0, "ssh_use_pam must be registered")
    require("platform.ssh, executables" in registry[registration:registration + 180],
            "ssh_use_pam must use the selected SSH profile")
    require(config.get("ssh_use_pam.status") == "ENABLE",
            "ssh_use_pam must be enabled by default")
    require(config.get("ssh_use_pam.value") == "yes",
            "ssh_use_pam must have fixed yes value")
    policy = (root / "fic/src/modules/net/ssh/policies/NET_ssh_use_pam.cpp").read_text()
    require('FixedPolicyTypeValue>("yes")' in policy,
            "ssh_use_pam must be fixed to yes")
    semantics = (root / "fic/src/modules/net/ssh/SshManagedBlock.cpp").read_text()
    require('{"ssh_use_pam", SshDirectiveSemantics::ScalarFirstWins, "UsePAM"}' in semantics,
            "UsePAM first-value semantics must be explicit")
    rollback = (root / "fic/src/rollback/RollbackExecutor.cpp").read_text()
    require('policyName == "ssh_use_pam"' in rollback,
            "ssh_use_pam must be rollback-enrolled")
    for language in ("ru", "en"):
        localization = (root / f"fic/src/resources/lang/{language}.lang").read_text()
        prefix = "[module:NET][policy:ssh_use_pam]"
        require("\n" + prefix + "=" in "\n" + localization,
                f"{language}.lang lacks ssh_use_pam title")
        require("\n" + prefix + "[description]=" in "\n" + localization,
                f"{language}.lang lacks ssh_use_pam description")
    startup = (root / "fic/src/main.cpp").read_text()
    helper_start = startup.find("AccessReadinessResult recomputeAccessReadiness(")
    helper_end = startup.find("bool mayChangeSshPamBridge(", helper_start)
    require(0 <= helper_start < helper_end,
            "access readiness must use one recomputation helper")
    helper = startup[helper_start:helper_end]
    pam = helper.find("PamIncidentAccessGateVerifier::prove(")
    bridge = helper.find("reconciler.evaluateReadiness(")
    ready = helper.find("DaemonReadinessState::Ready")
    require(0 <= pam < bridge < ready,
            "READY recomputation must prove PAM before SSH runtime reconciliation")
    apply = startup.find("run_daemon_apply_all_pass(", startup.find("int main("))
    startup_recompute = startup.find("recomputeAccessReadiness(", apply)
    notify = startup.find('"READY=1', startup_recompute)
    require(0 <= apply < startup_recompute < notify,
            "startup must apply, recompute both proofs, then announce READY")
    require("if (mayChangeSshPamBridge(requestText))" in startup and
            startup.count("recomputeAccessReadiness(") >= 4,
            "startup, admin mutation and periodic apply must recompute both proofs")

    return 0


if __name__ == "__main__":
    sys.exit(main())
