# SSSD native compatibility — R1

Research snapshot: 2026-10-28, FIC base `d1b00069aa9982fea3d7a34ea11eeaabe1c3604b`.
Docker explicitly authorized instead of Podman. Five real distribution userlands,
stock SSSD packages and systemd PID 1 share the Docker/WSL Linux kernel. This is
neither bare-metal certification nor a production SSSD adapter.

Approval was verified in the task conversation during the follow-up audit:
user reply to `call_e6b52697b66e4bde805cf319106068f6`, question 0,
“Да, использовать Docker”. It authorized the Docker substitution for R1/R2.
No Podman experiment is recorded. Docker success does not establish equivalent
Podman behavior; mount propagation, enforcing LSM and kernel differences need
separate deployment/native acceptance gates before claiming support there.

Authoritative observations/commands: [evidence](sssd-native-research-evidence.json).
Versioned distribution-source hashes and numbered excerpts:
[`source-r1.json`](../tests/integration/sssd-research/source-r1.json).
Reproduction: [runner](../tests/integration/sssd-research/README.md).

## Native matrix

| Profile | SSSD package version | Stock launch | Existing public engine with complete request |
|---|---|---|---|
| Debian 12 | 2.8.2-4+deb12u1 | notify/main, root, PIDFile=/run/sssd.pid | UNSUPPORTED: nonempty PIDFile |
| Debian 13 | 2.10.1-2 | notify/main, root; privileged ignored chown/chmod precommands | PASS for bounded snapshot + notify proof on prepared fixture |
| Ubuntu 24.04 | 2.9.4-1.1ubuntu6.8 | notify/main, root, PIDFile=/run/sssd.pid | UNSUPPORTED: nonempty PIDFile |
| Ubuntu 26.04 | 2.12.0-1ubuntu5.5 | notify/main, User/Group=sssd; privileged ignored chown/chmod precommands | PASS for bounded snapshot + notify proof on prepared fixture |
| ALT p11 | 2.9.8-alt3 | notify/main, unit root, PIDFile=/var/run/sssd.pid; packaged config has user=_sssd | UNSUPPORTED: nonempty PIDFile |

PASS here means engine `Success`, readiness=true, no cleanup errors/residuals;
it does **not** establish complete SSSD C (Semantics) or P (Persistent). A means
Inputs and B means Activation; service admission is a separate prerequisite.
See the [canonical proof table](sssd-verified-activation-design.md).
Each experiment installs all providers/tools for research; it does not propose
adding any of these packages as FIC dependencies. Define installed operationally:
trusted monitor executable, native loaded unit, needed provider/responder
executables/libraries and tools exist at the expected package versions. A
metapackage name or `is-enabled` alone proves none of this.

Precision note from the captured properties: all five parent units have empty
TriggeredBy; the concrete rejecting field on the older three is PIDFile.
systemd normalizes ALT’s /var/run/sssd.pid to /run/sssd.pid in its properties.

## Stock launch contract

All five: ExecStart `/usr/sbin/sssd -i ${DEBUG_LOGGER}`, Environment
`DEBUG_LOGGER=--logger=files`, optional EnvironmentFile (DEB `/etc/default/sssd`,
ALT `/etc/sysconfig/sssd`), Restart=on-abnormal, start-limit interval 50s/burst 5.
Conditions permit main config OR nonempty conf.d. Complete `systemctl cat`,
`show --all`, package file lists and native socket/service enablement are in the
evidence; fields omitted from this summary must not be assumed absent.

Debian 13 precommands recursively adjust /etc/sssd ownership/group readability,
plus DB/GPO/log ownership. Ubuntu 26.04 uses root:sssd and group traversal, also
chowns DB/GPO/log files to sssd. Commands have privilege/ignore-failure prefixes;
their failure on RO inputs can be ignored while initialization continues. ALT
ships /etc/sssd root:_sssd 0750, conf.d 0750 and main root:root 0600; its monitor
may additionally change identity according to config. The root-only LDAP test
fixture is a controlled replacement of the packaged example, never evidence of
the packaged `_sssd` configuration's full authentication behavior.

No replacement service was substituted for stock launch tests. Supplemental
FIFO ExecStartPre under /run is explicitly a **controlled launch fixture**, used
only to hold `activating/start-pre` deterministically. Other overrides/custom
RootImage, namespaces, provider commands, credentials, socket topologies or unit
changes require a separately admitted exact contract. Current generic engine
supports same mount namespace as manager/MainPID, not arbitrary sandboxing.

## Configuration input graph

Monitor reads `/etc/sssd/sssd.conf`, then eligible non-hidden `*.conf` files from
compile-time `/etc/sssd/conf.d`. Native tests on all five loaded 33 from
10-first=11 → zzzz-fic=22 → zzzzz-local=33; duplicate keys in one snippet loaded
the last value 34. Hidden `.hidden.conf` and `.conf.bak` did not override 30.
Preserve the **whole directory manifest**, not only FIC's file. Native SSSD merges
later snippets as observed above; the future FIC support boundary is stricter:
any loaded foreign snippet later than zzzz-fic.conf blocks apply/REFRESH regardless
of its contents, including agreeing or unrelated settings. Its presence alone
does not block releasing proven FIC ownership.

Missing main + complete snippet loaded 44 on every profile. Source establishes
an in-memory `[sssd]` parse seed, not a vendor configuration search. Newer sources
explicitly reject both main and snippets absent; condition checks are another
independent gate. ALT also packages `/usr/lib64/sssd/conf/sssd.conf` and example
templates; inventory/spec/source inspection does not find that template read by
the standard monitor path. It is package/control input, not an implicit extra
monitor priority layer. Stock /etc content is package-owned and may change on
upgrade: its absence/exact bytes must be witnessed, not guessed from examples.

**`-c` trap, native on all five:** foreground monitor `-c /run/sssd-alt/sssd.conf`
still loaded global conf.d value 52. `sssctl config-check -c` defaults snippets to
the main file's sibling conf.d (fixture value 53). Always supply `-s` matching
the actual monitor snippet directory; a successful check of different inputs is
not an activation proof. Alternate launch is not admitted by the proposed v1.

Symlink/hardlink snippets were accepted in these fixtures. This is not permission
for FIC to follow them: engine's no-symlink, link-count, safe-path and nested-mount
rules remain stricter. Older profiles skipped insecure/foreign snippets while
remaining active with old/default value; newer units can repair foreign ownership
before the monitor reads it. World-readable snippets fail newer monitor startup.
Thus config-check, stock precommands and monitor are distinct observations.
ACL/xattr fixtures capture getfacl/getfattr and monitor outcomes; no SELinux/AppArmor
enforcing-label equivalence has been proved in this Docker environment.

## Reading, readiness and reload

Exact installed sources (monitor.c `load_configuration`/`confdb_read_ini`,
`mark_service_as_started`, `notify_startup`) show INI→ConfigDB before child startup.
READY=1 follows provider registration and configured service registration/count.
Socket-activated responders are treated separately. This is not a directory
server reachability, backend health forever, cached password or successful PAM
authentication proof. Native fixture LDAP points to closed loopback port 9 and
stock service still becomes active with NSS/PAM processes.

After file mutation 30→37, same InvocationID/ConfigDB retained 30. `reload` is not
implemented by stock unit; SIGHUP rotates logs and clears selected NSS/autofs
caches, not INI reload. Full restart loads 37. LDB source values prove ConfigDB
load, not every consumer's in-memory value. R2 investigates consumers separately.

## RO snapshots, boundaries and races

Manual RO bind fixture (not a copied engine snapshot) covered main + all conf.d,
under private /etc/sssd bind boundary. Prepared metadata stock restart passed all
five. Ubuntu 26.04 unprepared root:0600 failed: ignored precommands cannot repair
RO permissions for non-root SSSD. Production must validate sufficient, trusted
native metadata **before** snapshot; do not alter policy ownership automatically.
Debian 13/Ubuntu 26.04 public engine also completed real copied-RO activation with
main, conf.d and explicit existing EnvironmentFile covered. Optional absent
EnvironmentFile remains unsupported; do not create one merely to claim success.

An ordinary shared `/` needs preprovisioned private parent mount boundaries for
/etc/sssd **and each EnvironmentFile parent**; no global propagation change or
per-file permanent bind (would break AtomicFileWriter rename). Boundaries are a
deployment task, never created by production activator. These containers have
convenient private mount trees. No new shared-peer or enforcing-LSM experiment was
performed here; previous generic proofs are not SSSD-specific certification.

Deterministic existing-engine checkpoints on Debian 13/Ubuntu 26.04:

* Same-content inode replacement before bind: InterferenceDetected.
* EnvironmentFile mutation before bind: ChecksumMismatch.
* New late snippet after snapshot copy: engine Success with the original pinned
  directory, but late persistent file is visible after cleanup.
* Write through preopened original config FD during publication succeeds; engine
  Success still protects the copied input used by restart. Persistent source
  differs afterwards. **A generic Success is insufficient for policy Success.**
* Direct write/create through published RO path fails EROFS; activation succeeds.
* FIFO pre-start barrier: native config-check passes, late snippet then changes
  the value actually loaded after release to 71. Activating service is rejected
  by existing engine; check-then-restart without snapshot is unsafe.
* Monitor SIGSTOP after READY preserves old ConfigDB while main inode/snippet
  change. On supported profiles an attempted restart exceeded the outer 20s
  harness limit; process was killed and disposable container discarded.
  Result INCONCLUSIVE for cleanup/deadline guarantee, not a readiness PASS.

Malformed config restart fails on all five; stopped and absent service admission
are recorded separately. Concurrent directory enumeration, live unit mutation,
exact READY-boundary responder failures and peer mount propagation remain
NOT_TESTED here. Engine checkpoint results do not substitute for those cases.
No functional authentication claim is made in R1.

These retained NOT_TESTED/INCONCLUSIVE cases are mandatory future acceptance
gates in the [I1–I6 gate catalogue](sssd-cross-policy-validation-design.md#mandatory-native-acceptance-gates).
Collection completeness and the saved-evidence CTest do not mean native runtime
validation was rerun. That requires the separate opt-in container runner.

## Existing FIC discrepancies (read-only audit)

`SssdRuntime::attach()` can return no activeUnit for unchanged or inactive state;
verification then proves only persistent bytes. The current policy can therefore
report applied without proving active consumption, contrary to the target
contract. Current rollback rejects a later conflicting snippet before deleting
its owned key; target ownership release must not be blocked by a foreign override.
Current Prepared recovery can promote source+restart observations. Do not carry
these behaviors into uncertain verified activation recovery without new receipts.
These findings are documented, **not fixed** by R1/R2.

## I1 implementation validation (separate from historical R1/R2)

The new [I1 API](sssd-verified-activation-design.md#implemented-i1-read-only-api)
observes stock launch contracts and complete inputs read-only. New results live
in [I1 evidence](../tests/integration/sssd-i1/evidence.json); old R1/R2 JSON/source
exports are unchanged. Normal saved-evidence CTest is not native execution.

All five stock profiles can be classified/captured by I1, including older
PIDFile profiles. This does not change their generic-engine Unsupported result.
Debian13 privileged precommands and Ubuntu26 nonroot identity/precommands require
I3's protected metadata/consumer proofs. Ubuntu26 stock chown/chmod resolve to
reviewed uutils paths; ALT uses configuration user=_sssd and an installed empty
sssd.service.d directory. No automatic package/permission repair occurs in I1.

Two native environment findings are bounded explicitly: missing ALT LDB backend
modules prevented fixture startup until the full native provider package closure
was installed; ALT config-check reports ignored hidden/suffix files as exit-1
merge warnings despite zero validator issues. Neither is an I1 runtime policy
success/failure claim. The runner separately asserts monitor startup, ConfigDB,
merge order, exact warnings and I1 results. The native unloaded-drop-in failure
on Debian12 was fixed by checking the native unit lookup negative set rather
than relying only on loaded properties. See the reproducible runner for details.

| I1 native userspace | Installed SSSD | Read-only launch/closure | Launch/source races and late snippets | Remaining activation work |
|---|---|---|---|---|
| Debian 12 | 2.8.2-4+deb12u1 | PASS | PASS | stock PIDFile unsupported by generic engine; I3 |
| Debian 13 | 2.10.1-2+b1 | PASS | PASS | privileged precommands/metadata and full SSSD proofs; I3 |
| Ubuntu 24.04 | 2.9.4-1.1ubuntu6.8 | PASS | PASS | stock PIDFile unsupported by generic engine; I3 |
| Ubuntu 26.04 | 2.12.0-1ubuntu5.5 | PASS | PASS | nonroot identity, precommands/metadata/consumers; I3 |
| ALT p11 | 2.9.8-alt3 | PASS | PASS | stock PIDFile, _sssd responder identity and full proofs; I3 |

These are new I1 native runs on a shared WSL kernel, not activation or deployment
certification. Exact systemd/package versions, commands and status-specific
observations are retained in the linked new evidence.

### I1 follow-up: ALT identity and admission races

The closed ALT p11 consumer profile requires an explicit effective `[sssd]
user=_sssd`, including configurations without an explicit `services` key.
Missing user, root, and unknown names are Unsupported. Ordered snippets may
supply the value; only their final effective assignment is checked. Debian and
Ubuntu retain their existing optional-user rules.

This restriction follows the reviewed patched 2.9.8-alt3 source: monitor.c
830–855 defaults a missing user to root, accepts root or SSSD_USER, and uses
that identity for its monitor bus (1662–1666). The stock config selects _sssd;
the native socket-activated PAM service has User=_sssd. The new evidence retains
numbered source excerpts/hashes tied to unchanged R1 provenance. ALT also ships
a control facility for privileged operation; that alternative topology is
**Unsupported by the current closed I1 profile**, not declared invalid for ALT
in general. I1 does not modify it or try to repair identities.

New disposable native runs confirm the mismatch: missing/root user leaves the
monitor active but native lazy PAM exits with status 3. Effective _sssd from
ordered snippets admits capture and starts the stock lazy responder. Unknown
user prevents monitor startup. A failed nonexistent-user PAM request does not
prove authentication success. Persistent-input negatives are also tested while
the old monitor/ConfigDB remain active, with/without explicit services.

All five profiles pass genuine nested-mount gates: empty root:root tmpfs mode
0700, independently verified different mount ID, then exactly `nested mount in
controlled tree`. The earlier special-permission-bit rejection did **not** prove
mount detection. Generic readTree and its check order are unchanged.

All five also pass deterministic first-admission gates: control, vendor-unit
comment mutation preserving ExecStart properties, EnvironmentFile byte/inode
changes, creation of an absent optional environment, and an unloaded drop-in.
The operation-local checkpoint follows initial launch/env/UnitPath observations
and precedes their final proof; no capture/revalidate pair or timing sleeps
substitutes for the first-admission experiment. Older systemd can reject the
drop-in directly via UnitPath while newer versions report changed launch state;
exact allowed diagnostics are asserted. These are read-only optimistic I1
observations, not linearizable protection or completed A/B/C/P. I2/I3 remain
unimplemented; historical R1/R2 evidence has not been rewritten.
