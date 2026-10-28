# SSSD native compatibility — R1

Research snapshot: 2026-10-28, FIC base `d1b00069aa9982fea3d7a34ea11eeaabe1c3604b`.
Docker explicitly authorized instead of Podman. Five real distribution userlands,
stock SSSD packages and systemd PID 1 share the Docker/WSL Linux kernel. This is
neither bare-metal certification nor a production SSSD adapter.

Authoritative observations/commands: [evidence](sssd-native-research-evidence.json).
Versioned distribution-source hashes and numbered excerpts:
[`source-r1.json`](../tests/integration/sssd-research/source-r1.json).
Reproduction: [runner](../tests/integration/sssd-research/README.md).

## Native matrix

| Profile | SSSD package version | Stock launch | Existing public engine with complete request |
|---|---|---|---|
| Debian 12 | 2.8.2-4+deb12u1 | notify/main, root, PIDFile=/run/sssd.pid | UNSUPPORTED: PIDFile/trigger admission |
| Debian 13 | 2.10.1-2 | notify/main, root; privileged ignored chown/chmod precommands | PASS for bounded snapshot + notify proof on prepared fixture |
| Ubuntu 24.04 | 2.9.4-1.1ubuntu6.8 | notify/main, root, PIDFile=/run/sssd.pid | UNSUPPORTED: PIDFile/trigger admission |
| Ubuntu 26.04 | 2.12.0-1ubuntu5.5 | notify/main, User/Group=sssd; privileged ignored chown/chmod precommands | PASS for bounded snapshot + notify proof on prepared fixture |
| ALT p11 | 2.9.8-alt3 | notify/main, unit root, PIDFile=/var/run/sssd.pid; packaged config has user=_sssd | UNSUPPORTED: PIDFile/trigger admission |

PASS here means engine `Success`, readiness=true, no cleanup errors/residuals;
it does **not** mean the future policy's runtime/effective/P proof is complete.
Each experiment installs all providers/tools for research; it does not propose
adding any of these packages as FIC dependencies. Define installed operationally:
trusted monitor executable, native loaded unit, needed provider/responder
executables/libraries and tools exist at the expected package versions. A
metapackage name or `is-enabled` alone proves none of this.

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
Preserve the **whole directory manifest**, not only FIC's file. Conflicting later
snippets prevent proving the requested effective value, not releasing ownership.

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

## Existing FIC discrepancies (read-only audit)

`SssdRuntime::attach()` can return no activeUnit for unchanged or inactive state;
verification then proves only persistent bytes. The current policy can therefore
report applied without proving active consumption, contrary to the target
contract. Current rollback rejects a later conflicting snippet before deleting
its owned key; target ownership release must not be blocked by a foreign override.
Current Prepared recovery can promote source+restart observations. Do not carry
these behaviors into uncertain verified activation recovery without new receipts.
These findings are documented, **not fixed** by R1/R2.
