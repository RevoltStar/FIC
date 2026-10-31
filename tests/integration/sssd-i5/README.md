# SSSD I5 native release gate

This standalone backend gate uses the disposable Docker/systemd/SSSD images from
I3/I4. It never installs FIC packages or connects production policy objects.
Normal CTest validates retained evidence and unit contracts only; it does not
start privileged containers. Docker substitutes for Podman with user approval.

From the repository root, after preparing the existing I3 images:

```sh
bash tests/integration/sssd-i5/run-native.sh fic-sssd-i3:debian12 debian-12
bash tests/integration/sssd-i5/run-native.sh fic-sssd-i3:debian13 debian-13
bash tests/integration/sssd-i5/run-native.sh fic-sssd-i3:ubuntu2404 ubuntu-24.04
bash tests/integration/sssd-i5/run-native.sh fic-sssd-i3:ubuntu2604 ubuntu-26.04
bash tests/integration/sssd-i5/run-native.sh fic-sssd-i3:alt-p11 alt-p11
python3 tests/integration/sssd-i5/collect-evidence.py
python3 tests/integration/sssd-i5/check-evidence.py
```

Keep sources frozen for all five final runs. The runner records source hashes
before building and checks them again after execution. Collection requires all
five completion records, exact current source maps, probe binaries and raw report
hashes. A failed or source-stale run cannot become retained PASS. Reports are
lossless gzip with deterministic gzip timestamps; the index binds compressed and
raw hashes. Historical R1/R2/I1/I2/I3/I4 reports and indexes are not rewritten.
The older retained gates now verify their accepted historical commits rather
than misrepresenting old runtime observations as execution of changed I5 code.

Each fixture has real systemd PID 1, private PID/cgroup/network namespaces, no
network or host runtime binds and tmpfs /run and /tmp. Compilation has /src RO and
/build RW. Native source trees, packages and command hashes are the previously
reviewed I3 versions; no package download occurs during the gate. An explicit
private /etc boundary is a test deployment precondition, not a production
activator mutation. ALT's absent EnvironmentFile is supplied by the fixture,
with native _sssd identity preserved. Unrelated console gettys are quiesced to
avoid known fixture mount interference. Only active-fixture start-limit counters
are reset. Offline-positive fixture preparation additionally stops native responder
socket units and clears their failed state, because eager native responders can
leave the alternative socket activation units failed. Production neither stops
nor resets them and refuses an unproven socket topology. Missing environment
files are never fabricated by production.

The real coordinator performs I4 acquisition then I5 release. Reports separate
released/surviving assignments, native physical witnesses, typed journal states,
A/B/C/P, cleanup, active/offline mode, staging and terminal disposition. Independent
ldbsearch verifies the resulting ConfigDB (including a released override exposing
a different foreign value). It does not perform production authentication.

Coverage includes one/two/three owners, releasing first/middle/largest sequence,
complete multi-domain release, surviving Apply/REFRESH, last-file removal,
offline release, pending disable, foreign late matching/conflicting/unrelated
inputs, inactive/unknown foreign settings, revealed invalid relations, drift,
legacy/unknown/corrupt provenance, CAS/durability, consumer/ConfigDB/P/cleanup and
journal failures. Offline race tests include start and start-then-stop; monotonic
service epochs must prevent an obsolete stopped claim. DisableRelease must stay
ReleasedAwaitingDisable: I5 has no production acknowledgement, config reader or
assertion that all administratively ENABLE policies were checked.

Real `_exit(74)` seams exercise Prepared, MutationArmed, partial/staged writes,
publication, activation dispatch, A/B/C, P, terminal journal publication,
rename-away, staged unlink, directory fsync, offline verification and awaiting
disable. Every crash is followed by a new process and witness-aware journal,
inspection, physical/staging observations and sibling/no-effect gates. Only
unarmed exact no-effect Prepared resolves. A terminal document published just
before a failed/terminated journal fsync may become durable on a new trusted
reload; this is not guessing completion from config bytes. Process termination
checks do not emulate storage power failure.

Fixture teardown explicitly removes fault-injected residual mounts *after*
recording their refusal/inspection. Production inspection never cleans or adopts
these. The test executable reuses I4's write interposer for a real partial staged
write; it is not linked into production. Root tests for seven proof-bound-removal
seams and foreign restoration are also in `sssd_proven_removal_tests`.

The five Docker/WSL profiles do not certify bare metal, enforcing LSM, Podman,
AD/IPA/trusted domains, future packages or a real FIC daemon/package lifecycle.
The existing cooperative root-writer CAS/removal race remains documented in
`docs/sssd-verified-activation-design.md`. I6 must integrate real registry/disable
acknowledgement and eliminate the competing legacy mutating path.


An exploratory Ubuntu 26.04 run had an I4 acquisition prerequisite refuse with
`mount namespace event before commit` after A/B/C/P, retaining unresolved journal
and reporting no success. Its complete raw report/source/probe hashes are saved
in `diagnostics/ubuntu2604-unattributed-mount-event.*`. No unit/kernel event trace
was retained, so the cause is UNKNOWN; this is neither classified as an
infrastructure defect nor asserted to be a FIC defect. The source tree changed
during that exploratory run; it is not a source-current completed matrix. The
retained guard also checks this negative observation. Final five-platform reports
remain separate; no production watch, timeout or retry guarantee was weakened.
