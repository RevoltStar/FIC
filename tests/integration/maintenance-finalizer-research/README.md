# Finalizer delivery research — not production lifecycle code

Fixtures install **dummy packages** and systemd test units. Never execute on a host.
Use disposable Docker images/private namespaces. No host `/etc`, `/run`, cgroup or
Docker-socket mounts. Source can be mounted read-only at `/src`.
All Python fixtures require `FIC_FINALIZER_RESEARCH=1`.

* `dpkg_sequence.py`: `docker run --rm --network none -e FIC_FINALIZER_RESEARCH=1 -v "$PWD:/src:ro" fic-ssh-audit:debian12 python3 /src/tests/integration/maintenance-finalizer-research/dpkg_sequence.py` (also debian13/ubuntu2404/ubuntu2604).
* `path_delivery.py`: private privileged systemd container, `--cgroupns=private --tmpfs /run --tmpfs /tmp -e container=docker`. PID1 `/lib/systemd/systemd` on DEB, `/usr/lib/systemd/systemd` on ALT. Wait for manager boot with a bounded timeout. `docker cp` fixture to `/usr/local/bin`, then `docker exec -e FIC_FINALIZER_RESEARCH=1 ... python3 /usr/local/bin/probe.py`. Fixtures use `/var/lib/m1-delivery` because boot tmpfiles can remove fresh `/tmp` files. Each run needs a fresh container.
* `oneshot_probe.cpp` + `retry_delivery.py`: compile fixed C++ fixture to `/usr/local/bin/m1-oneshot` inside the above systemd container after path probe. Run retry fixture with explicit opt-in. This demonstrates one bounded timer attempt, not a complete persistent retry-budget implementation. Restart the same container to check `/var/lib/m1-delivery/boot-attempt`. This is a userspace boot, not kernel/power-loss validation.
* `rpm_sequence.py`: ALT container needs `rpm-build`, Python3 and `runuser`; create non-root `m1builder`. ALT disallows root rpmbuild. Run as root with explicit opt-in; only rpmbuild subprocess runs as builder. Fresh container/virgin dummy package required. Native fixture packages are called `fic-m1-status-probe`, never `fic`.

`evidence/` contains actual captured outputs with line-ending/trailing-whitespace normalization only; it is not a byte-forensic capture. Default images lacked ALT rpmbuild/Python;
those were installed inside a temporary research container. The original `%posttrans`
fixture failed to parse on that ALT builder; supported `/usr/lib/rpm/*.filetrigger`
was tested separately. The production FIC backend, units, packaging and security
state are not changed by these research fixtures. Existing M1 working changes are
separate and unfinished. See `docs/maintenance-finalizer-delivery-research.md`.

`dpkg_sequence.py` additionally exercises actual interest-noawait triggers,
dpkg `--post-invoke` and apt `DPkg::Post-Invoke`, testing POSIX record-lock
contention during those phases. Final logs are `evidence/dpkg-hooks-*.log`.
`crash_delivery.py` after the path probe checks bounded on-failure restart with
FIFO barriers. `pidfd_probe.cpp` is a standalone bounded kernel primitive probe;
it does not implement package-owner verification or a production finalizer.
Research scripts are ignored by global `*.py` and evidence by global `*.log`:
include these explicitly with `git add -f` if committing this research later.

## Superseding retry lifecycle

`retry_protocol_probe.cpp` + `retry_lifecycle.py` supersede the original one-timer
`retry_delivery.py` experiment. In each fresh private systemd container:

```sh
g++ -std=c++17 -Wall -Wextra -Werror /research/retry_protocol_probe.cpp -o /usr/local/bin/m1-retry-probe
FIC_FINALIZER_RESEARCH=1 python3 /research/retry_lifecycle.py
```

Mount this fixture directory read-only at `/research`. The protocol fixture uses
scaled 250 ms admission / 300 ms recurring timer / 700 ms service timeout. Native
matrix outputs: `evidence/retry-lifecycle-{debian12,debian13,ubuntu2404,ubuntu2604,alt-p11}.log`.
Eight temporary attempts, cooldown under hook storm, structural block over multiple
timer intervals, crash and timeout recovery, reexec and unit removal are checked.
The test harness bounds observation by monotonic deadlines; short polling in
`wait()` observes systemd result transitions, not production retry delivery.
No actual FIC fence/journal/PAM/manifest/daemon is used. Removal of fixture units
is not an actual FIC package purge/reinstall validation. See the authoritative
`docs/maintenance-finalizer-retry-lifecycle.md` for safety/liveness and remaining gates.

## Runtime prerequisite/lifetime research (dummy packages)

* `pre_payload_probe.py deb|rpm`: initial pre-script has no helper; upgrade sees
  only old helper. ALT needs rpm-build and non-root `m1builder` as above.
* `runtime_order_deb.py`: real apt/dpkg fresh, incompatible exact Pre-Depends,
  upgrade/downgrade, configure failure/configure-a, aborted remove, joint purge.
  Native RED: main postrm purge runs after runtime payload has disappeared.
* `runtime_order_rpm.py`: actual ALT Requires(pre), ABI preun/postun, exact installed
  dependency, upgrade/downgrade/failed erase and own runtime postun RED.
* Both order scripts accept `--retention-gate` only as a **research fixture mode**:
  simulate retaining runtime until a modeled proof in a later transaction. The
  harness marker is not a production authorization or verified FIC proof.

Each script run requires a fresh disposable package database/fixture directory;
`runtime_order_rpm.py --retention-gate` uses a distinct directory after an ungated
run that removed its packages. Use `FIC_FINALIZER_RESEARCH=1`. No host installation.
Evidence is `pre-payload-*.log`, `runtime-order-*.log`, `runtime-retention-*.log`.
See `docs/maintenance-runtime-package-design.md` for proposed ownership/version/
lifetime contract and the pending user-visible two-transaction removal decision.
