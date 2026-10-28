# SSSD R1 / R2 native research

Research only. No policy apply, FIC installation, host security/mount changes or
production adapter. Run from repository root. Docker substitutes for Podman by
explicit user approval. Runtime containers have real systemd PID 1, privileged
mount/ptrace capability, network none/loopback only, private PID/cgroup/mount
namespaces, no host binds or ports. The build container alone reads source and
writes its build cache. Never run Python fixtures directly on a host; root,
Docker, PID1, namespace and loopback guards reject that route.

Measured image bases were the existing `fic-ssh-lifecycle-native` images. SSSD
and tools were installed from native repos by Containerfile. For a fresh machine
use Containerfile.base (equivalent compiler/systemd prerequisites, without SSH):

```sh
docker build -f tests/integration/sssd-research/Containerfile.base \
  --build-arg BASE_IMAGE=debian:12 -t fic-sssd-base:debian12 .
docker build -f tests/integration/sssd-research/Containerfile \
  --build-arg BASE_IMAGE=fic-sssd-base:debian12 -t fic-sssd-research:debian12 .
bash tests/integration/sssd-research/run-native.sh fic-sssd-research:debian12 debian-12 R1
bash tests/integration/sssd-research/run-native.sh fic-sssd-research:debian12 debian-12 R1_MORE
bash tests/integration/sssd-research/run-native.sh fic-sssd-base:debian12 debian-12 R1_ABSENT
```

Other pairs: debian:13 / debian-13; ubuntu:24.04 / ubuntu-24.04;
ubuntu:26.04 / ubuntu-26.04; ALT p11 official userland / alt-p11. ALT images need
enabled p11 repos; the measured setup used HTTPS distrib-coffee p11 mirror (same
branch, not another distro). Base-rebuild recipe is provided for reproducibility;
measured evidence identifies actual image IDs and package versions. Repository
updates may change versions: rerun source collection and do not reuse old claims.

Full transcripts/traces and container inspect are exported to ignored
`build-sssd-research/<platform>/<stage>/`; container is destroyed even on failure.
Positive synchronization uses systemd job completion, observed ConfigDB values,
SIGSTOP state or FIFO/checkpoint barriers. Short polling sleeps only await a
specific bounded predicate. They do not establish PASS by elapsed time. Outer
20s probe timeout is recorded as INCONCLUSIVE, not a cleanup or readiness proof.

Source collection runs **only inside disposable build container** with network:

```sh
docker run --rm -e FIC_SSSD_RESEARCH=1 \
  -v "$PWD/tests/integration/sssd-research/fetch-source.sh:/fetch.sh:ro" \
  -v "$PWD/build-sssd-research/debian-12:/build:rw" \
  fic-sssd-research:debian12 bash /fetch.sh
python3 tests/integration/sssd-research/source-audit.py
python3 tests/integration/sssd-research/collect-evidence.py
python3 tests/integration/sssd-research/check-evidence.py
```

Repeat fetch for all profiles. DEB exact source version from installed
sssd-common, distro patches applied by apt-get source. ALT exact SRPM, spec
%prep patch, archive hashes recorded. No source build is substituted for native
packaged executables. The source-audit export is a navigation aid, not proof
that every excerpt was executed.

`EngineProbe.cpp` calls the actual public generic engine; optional hooks are
the existing test-only checkpoints, compiled out of production. Manual RO binds
are clearly identified and are not another snapshot engine. Supplemental unit
drop-in is a FIFO launch fixture, never reported as stock unit behavior.

CI `sssd_research_evidence_checks` checks syntax, isolation metadata and key
counterexamples in committed evidence; it is not a fresh privileged native run.
The four precise coverage levels and NOT_TESTED/INCONCLUSIVE gaps are in docs.
