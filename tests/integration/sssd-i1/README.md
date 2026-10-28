# SSSD I1 native gates

Production sources: `fic/src/service/sssd/`. This harness exercises read-only
capture/revalidation, **not** verified activation, a runtime receipt, or policies.
Fixtures alone write/restart/mount inside disposable containers. Normal CTest
never invokes Docker or privileged gates. Existing R1/R2 evidence is untouched.

Build stock-package images (Docker substitution explicitly authorized):

```sh
DOCKER_CONFIG=/tmp/fic-package-docker-config docker build \
  --build-arg BASE_IMAGE=debian:12 -t fic-sssd-i1:debian12 \
  -f tests/integration/sssd-i1/Containerfile .
tests/integration/sssd-i1/run-native.sh fic-sssd-i1:debian12 debian-12
```

Repeat with Debian 13, Ubuntu 24.04, Ubuntu 26.04, ALT p11 and their actual
compile-time platform IDs. For this run the three available Debian/Ubuntu base
images were `fic-ssh-lifecycle-native:{debian12,debian13,ubuntu2404}`; other bases
were `ubuntu:26.04` and `alt:p11`. All install stock distribution packages.
ALT uses the signed native repository through the accessible French mirror;
ftp.altlinux.org and mirror.yandex.ru timed out/refused in this Docker network.
No TLS/signature verification bypass. Its full provider/LDB closure includes
`samba-dc-libs`; missing this package produced an LDB backend error, not an I1 bug.
`libcap-devel` supplies ALT's missing pkg-config development dependency.

The runner builds with read-only source/build-directory mounts in an unprivileged
builder, then **copies** the executable/scripts into a separate privileged
systemd PID-1 container with no host binds, no host networking, no published
ports and only loopback. It verifies these properties and a different mount
namespace, collects results on exit, and removes the container. Its isolated
LDAP URI is `127.0.0.1:9`, no external directory or production credentials.

Raw commands/results and container inspection are retained in ignored
`build-sssd-i1/<platform>/native`. `collect-evidence.py` exports the separate
reviewable `evidence.json`, measured `launch-fixtures.json`, raw-result hashes,
versions, image IDs and source hashes. `check-evidence.py` validates this saved
snapshot and syntax only; its PASS is **not another native execution**.

Gates cover:

* `launch-phase-change`: vendor file mutation, new unloaded drop-in, changed
  optional environment input. Debian 12 showed that NeedDaemonReload alone can
  miss an unloaded drop-in; production now observes the native UnitPath negative
  set too. Empty stock ALT drop-in directories are captured, never trusted as
  authority for later files. Unknown vendor bytes are rejected even if ExecStart
  remains the same (reviewed per-platform unit digests).
* `conf-d-capture-race`: six deterministic checkpoints after the first complete
  read and before the confirming read: create/delete/replace inode/change
  bytes/change mode/change bytes then restore. Hooks compile only into this
  driver, not FIC. Observable drift must fail; no arbitrary privileged ABA claim.
* `late-foreign-snippet`: matching/conflicting/unrelated loaded later files all
  preserve read-only evidence of the FIC-named file and mark apply conflict.
  The filename is **never** ownership evidence. Earlier and nonloaded/hidden
  files have separate observations; symlink/hardlink/owner/mode/dir/mount fail.
* Stock launch, main absent + complete snippets, both absent, optional env
  absent vs present, unknown environment variable, group-mode boundaries,
  ordered duplicate projection compared with native merge listing, monitor log
  and actual ConfigDB. Native starts/restarts are fixture actions only.
* Explicit `sssctl config-check -c/-s` and missing sibling `conf.d` for custom
  `-c`. ALT reports skipped hidden/suffix files as two merge messages and exit 1;
  the harness recognizes exactly that warning set and checks the native order
  and ConfigDB separately. It does not turn arbitrary exit 1 into success.

Kernel/mount/LSM conclusions remain Docker/WSL bounded. AD/IPA/authentication,
I2 semantics/domain support and I3 activation/readiness/P/cleanup remain outside
I1. Prior research gaps keep their historical statuses.
