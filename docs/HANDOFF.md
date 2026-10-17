# Current working state

## Current base
* `main`, audit base `7e91772c0790f958cea6fc4aab23c9b878b053c7`, initially clean. One audit commit requested; no push.

## Current task
* Research-only stock OpenSSH compatibility audit of VerifiedConfigServiceActivator, completed. No production/policy/SSH/unit/config changes.

## Accepted architecture / invariants
* Activator remains standalone: active notify/main, same namespace/root, pinned launch contract, pre-existing non-shared publication parents/workspace, identity-safe cleanup. No integration or relaxed gates.
* Separate runtime/source/inference/NOT_TESTED. Docker userspaces share WSL2 kernel; no claim of real VM compatibility or successful activation from a read-only probe.

## Completed / changed areas
* `docs/verified-config-native-compatibility-audit.md`: matrix, exact preflight, stock units/envfiles/sockets, Includes/propagation, exact package-source READY analysis, alternatives/roadmap.
* Adjacent sanitized evidence JSON: per-condition results and package/runtime metadata for all five platforms.
* `tests/integration/verified_config_service/audit/`: autonomous read-only probe reusing FIC helpers, Docker metadata collector, reproduction instructions. No activation/mount/restart commands.
* All stock configurations rejected: EnvironmentFile on all; Debian12 `/lib` symlink in FragmentPath; Ubuntu socket trigger/inactive service; ALT simple/none/inactive. ALT unused systemd userdb symlink is a candidate-tree rejection, not active main-config input.

## Validation
* Native probe configure/build/run PASS on Debian12/13, Ubuntu24.04/26.04, ALT p11 in disposable Docker with systemd PID1; 82/88/88/88/82 individual checks, including expected UNSUPPORTED/NOT_TESTED.
* Exact distro source packages studied, sources/hashes referenced in report. Stock SSH only observed after initial boot, no start/stop/restart/reload/daemon-reload/mount operations during audit.
* Python syntax and JSON status/metadata consistency checks PASS; git diff --check PASS.
* Full FIC build/CTest/privileged activator gate not rerun: production untouched; audit does not execute activation.

## Remaining / limits
* No unfinished audit implementation. Future work recommended: EnvironmentFile proof, private-boundary deployment on shared-root VM, bounded SSH adapter; socket coordinator/ALT readiness separate.
* Kernel for all rows: 6.6.87.2-microsoft-standard-WSL2. VM/physical distro kernels, actual FIC trust/daemon, activator restart/cleanup, Ubuntu READY execution, network/PAM login, package upgrades/private-boundary lifecycle and Astra1.8 NOT_TESTED.
* ALT VM 172.17.1.107 unavailable (No route to host). No inference about its current state.
* Audit disposable containers/images and exact sources remain local research artifacts; they are not installed on a production host or committed. Do not run old native activation gate as a stock SSH read-only probe.
