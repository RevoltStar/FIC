# Current workspace

## Current base / task
* Branch `main`; base `50a60c3d6a7717a11ad0f4c21cbf373ec43b0ce9`.
* Bounded verified cleanup retry complete. One requested commit:
  `fix(service): retry transient EBUSY during verified cleanup`. No push.

## Accepted architecture / invariants
* Production changes only `VerifiedConfigServiceActivator.cpp`, inside cleanup
  plus `<thread>`. Direct shared publication and existing proofs remain.
* One independent steady-clock5s cleanup grace, even after activation timeout;
  not5s per mount. Initial reverse pass for all, then reverse rounds only for
  syscall EBUSY. Sleeps20/40/60/80/100ms capped by remaining time.
* Before every ordinary umount2(...,0), original namespace/object/mount/source/type
  checks run again and target FD closes. No adoption, force/lazy or recovery.
* Transient EBUSY is not a final error. Persistent EBUSY yields one error per
  target with errno/deadline/attempt count/elapsed; mixed errors retain reverse
  order. Primary status/diagnostic retained; unfinished cleanup fails closed.
* `cleaned` prevents RAII from starting another budget. Journal, ownership/CAS,
  success predicate, service ordering and logging implementation unchanged.

## Completed / changed areas
* Local cleanup round algorithm; no new public settings/contracts/types.
* Existing generic native target includes `CleanupRetryCases.h`: actual child FD
  holders with barriers, multiple/transient/persistent, expired activation grace,
  between-pass replacement, non-EBUSY and no-delay cases.
* Existing SSH driver/gate adds transient faults for apply/snapshot/release and
  asserts successful commit/release without ERROR; permanent faults retain Prepared.
* Contract and current validation: `docs/verified-config-service-activator.md`,
  `docs/verified-config-cleanup-validation.md` (T1–T9 details and exact observations).

## Validation
* `cmake --build build-startup-classification --target fic verified_config_service_tests ssh_verified_activation_tests -j2` PASS.
* Targeted CTest generic/SSH unit2/2 PASS. Initial sandbox-only address enumeration
  failed; final read-only netlink-enabled run PASS.
* Docker Debian12/systemd generic native **220 PASS /0 SKIP**. Final real-FD
  transient7 calls/406ms; multiple5+7 calls/410ms; persistent52 calls/~5002ms;
  expired activation timeout with transient/persistent grace verified.
* Focused Docker SSH cleanup gate **7/7 PASS**; its SSH unit1/1 PASS.
  Existing release-plan native gate **9/9 PASS** (and unit1/1).
* Runtime containers: privileged but private PID/mount/cgroup, network none,
  no host binds/ports/socket; /sys and /proc/sys RO. Final generic mountinfo:
  zero fic-vcsa mounts; actor/service stopped and own container removed.
* Python syntax, diff review and git diff --check PASS.
* Evidence: `build-cleanup-retry-native/evidence/` native log/summary/inspect;
  `build-cleanup-native/evidence/` SSH7-case/release-plan JSON; execution logs
  `/tmp/fic-cleanup-retry/`. Initial SSH fixture assumed one release cleanup;
  corrected per-cleanup fault reset/counting; final tests PASS without proof changes.

## Remaining / limits
* No unfinished implementation. No remote VM/real KESL accessed for this patch.
  Owner will test rebuilt FIC with KESL separately; no guarantee arbitrary refs
  release within5s, no automatic old Prepared recovery.
* No full cross-distro/package/project CTest matrix. Existing privileged
  identity-check→umount race and local-only shared cleanup boundary remain.
