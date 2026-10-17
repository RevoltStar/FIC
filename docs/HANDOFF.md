# Current working state

## Current base
* `main`, research base `d0c7e2d642a15c6f7a126f8ec06f83df024ff71a`, initially clean. One research commit requested, no push.

## Current task
* Architecture research + native EnvironmentFile PoC; no production integration or relaxed activator gates.

## Architecture / conclusions
* Existing activator still rejects EnvironmentFiles. Policies, SSH, transactions/ownership/journal, units/packaging unchanged.
* Exact systemd252/255/257/258/259 sources and native FIFO barrier show PID1 reads envfiles in manager namespace before fork/spawn; newer executor receives serialized parsed values. Each condition/pre/main spawn rereads.
* Recommend B (internal loaded launch-input coverage contract) using existing A (RO tmpfs/bind engine). Keep ActivationRequest; v1 require existing literal regular file targets with reference SHA, refuse optional-absence/glob/symlink. This is research recommendation, not implemented production support.
* Optional absent ≠ universally equivalent empty object. Parent RO directory can protect absence but broad /etc/default or /etc/sysconfig lifecycle needs a separate design; no persistent placeholder.
* Claims manager bytes / child env+argv / actual config read / cleanup after trusted READY are distinct. Existing privileged-adversary/observer/contract ABA residuals remain.

## Completed / changed areas
* `tests/integration/verified_config_service/environment_file_research/`: autonomous Docker runner, CMake, C++ fixture and README; reuses real FIC mount/hash/copy/observer/typed reader/AtomicFileWriter.
* `docs/verified-config-environment-file-research.md` and sanitized evidence JSON: exact source map/hashes, A/B/C comparison, 33 native cases, next production specification/regression plan.
* Native tests only own `/run/fic-env-research` and `fic-env-research.service`; no stock SSH lifecycle commands. Temporary mounts/daemon-reload only inside new disposable containers, removed by runner trap.
* Negative source rename confirms production identity gate must reject, despite laboratory frozen bytes. Overmount ABA restores endpoint SHA+ID but child got foreign env; sticky observer rejects. Cleanup EBUSY is false, not Success.

## Validation
* Native configure/build/runner on Debian12/13, Ubuntu24.04/26.04, ALT p11: 33 PASS / 0 FAIL each. Final exact source logs `build-environment-file-research/*-verified.log`; evidence is committed JSON.
* Bash syntax, matching case-set/evidence checks, source metadata SHA, git diff --check PASS.
* Full project build/CTest not rerun: production unchanged. Research publisher is NOT full activate/recovery/locking/CAS implementation.

## Remaining / limits
* All five Docker userspaces share kernel 6.6.87.2-microsoft-standard-WSL2. No VM/physical distro-kernel/reboot/package-upgrade validation; /dev/kvm absent.
* No production activate or SSH -f/-o parser test (fixture is explicitly synthetic), no optional-absence production lifecycle, C unit ownership/rollback, Ubuntu sockets or ALT notify implementation.
* Source archives/build artifacts are ignored local research data. Stock SSH images remain cached; runner destroys only its disposable containers.
* Next step needs a production task: narrow EnvironmentFile contract support + real activator regression matrix, preserving existing trust/namespace/private-parent/cleanup gates. No automatic integration with policies.
