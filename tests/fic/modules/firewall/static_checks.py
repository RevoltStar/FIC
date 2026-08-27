#!/usr/bin/env python3
from pathlib import Path
import sys


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def require_log_level(source, message, level):
    start = source.find(message)
    require(start >= 0, f"missing firewall log message: {message}")
    end = source.find(");", start)
    require(end >= 0, f"unterminated firewall log statement: {message}")
    statement = source[start:end]
    require(
        f"logLevel::{level}" in statement,
        f"firewall log message has the wrong level: {message}",
    )


def main():
    if len(sys.argv) != 2:
        return 2
    root = Path(sys.argv[1])
    config = (root / "fic/src/resources/config/FIREWALL.conf").read_text()
    for policy in (
        "block_rdp", "block_ftp", "custom_rules", "exclusive_firewall_control"
    ):
        require(f"{policy}.status=DISABLE" in config, f"missing {policy} status")
    require("block_rdp.value" not in config, "block_rdp must be status-only")
    require("block_ftp.value" not in config, "block_ftp must be status-only")
    require(
        "exclusive_firewall_control.value" not in config,
        "exclusive control must be status-only",
    )
    require("custom_rules.value=[]" in config, "custom_rules default is missing")

    registry = (root / "fic/src/daemon/main_function.cpp").read_text()
    for policy_class in (
        "BlockRdpPolicy", "BlockFtpPolicy", "CustomRulesPolicy",
        "ExclusiveFirewallControlPolicy",
    ):
        require(policy_class in registry, f"{policy_class} is not registered")

    daemon = (root / "fic/src/main.cpp").read_text()
    require(
        "reconcileFirewall" in daemon
        and "run_daemon_apply_all_pass" in daemon
        and 'applyAllPoliciesExceptModule(\n        policyRegistry, "FIREWALL")' in daemon,
        "daemon startup/periodic pass does not reconcile FIREWALL",
    )
    process_options = (
        root / "fic-common/fic-core/include/fic/core/process/ProcessExecutor.h"
    ).read_text()
    require(
        "standardInput" in process_options,
        "ProcessExecutor does not expose bounded standard input",
    )
    backend = (
        root / "fic/src/modules/firewall/FirewallBackend.cpp"
    ).read_text()
    require(
        '{"-c", "-f", "-"}' in backend and '{"-f", "-"}' in backend,
        "nft scripts must be checked and then applied through stdin",
    )
    require("flush ruleset" not in backend, "FIREWALL must not flush the ruleset")
    for message in (
        "Managed firewall rule set is missing:",
        "Refreshing managed firewall rule set:",
        "Refreshing managed firewall table:",
        "Managed firewall table is missing:",
    ):
        require_log_level(backend, message, "DEBUG")
    require_log_level(
        backend, "Removing stale managed firewall table:", "INFO"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
