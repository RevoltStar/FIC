# SSSD I4 native transactions and crash recovery

This gate tests the standalone production transaction coordinator, schema-3
version-1 SSSD ownership payload and existing I1/I2/I3 adapter. It does not
register policies, implement release/disable, or claim I5/I6/daemon/package E2E.

Reuse the disposable, stock systemd/SSSD images prepared for I3:

```sh
tests/integration/sssd-i4/run-native.sh fic-sssd-i3:debian12 debian-12
tests/integration/sssd-i4/run-native.sh fic-sssd-i3:debian13 debian-13
tests/integration/sssd-i4/run-native.sh fic-sssd-i3:ubuntu2404 ubuntu-24.04
tests/integration/sssd-i4/run-native.sh fic-sssd-i3:ubuntu2604 ubuntu-26.04
tests/integration/sssd-i4/run-native.sh fic-sssd-i3:alt-p11 alt-p11
python3 tests/integration/sssd-i4/collect-evidence.py
python3 tests/integration/sssd-i4/check-evidence.py
```

Each run builds from source read-only with a separate writable build directory,
then copies the probe/fixture into a new privileged container with real systemd
PID 1, private cgroup/PID/mount namespaces, loopback-only networking and no host
runtime binds/ports. Container inspection and guard assertions are retained.
Only temporary fixture state is changed. Source maps are captured before build
and compared after the complete run; a changed source or incomplete run cannot
be collected. Each completion binds the actual probe binary and raw report.
Historical R1/R2/I1/I2/I3 evidence is not modified.

`Driver.cpp` calls the real coordinator/journal/adapter. It seeds tool trust only
inside this test fixture. Production never installs tools or seeds trust.
`StagedWriteCrash.cpp` is linked only into this test executable: it intercepts
the real staging-file write, writes half its bytes and terminates the process.
The production writer is unchanged; this is not an alternative backend. Other
termination checkpoints use `_exit(74)` without C++ unwinding. Every crash is
inspected by a separate new process with a freshly loaded witness-aware journal.

`native.py` validates exact installed bytes, independently observed file identity/
metadata/hash versus journal publication, complete required/confirmed target keys,
I3 consumer evidence, current/previous/target ownership and sibling gates. Its
explicit fixture teardown removes test leftovers only after their classification;
production inspection never unmounts/adopts them. Prepared no-effect resolution
is exercised with both previous ownership and fresh absence. Every armed or
ambiguous crash remains unresolved; target bytes do not authorize Applied.

Positive/negative coverage includes foreign matching/differing first Apply,
same-value, both REFRESH directions, sibling keys, two LDAP domains, foreign/
default relation values and cache=false, unsupported providers/dynamic scope,
selected-but-disabled roots, scope/provider drift, missing/drifted/unrecorded
keys, same-bytes replacement inode, orphan/missing/corrupt journal, unknown schema,
legacy scalar records and legacy removal stages, unsafe metadata, late snippets,
absent main, readonly metadata template, missing conf.d/environment and stopped
service. A structurally healthy but incomplete sibling owner is explicitly
refused. CAS drift, uncertain publication durability, hidden source-FD mutation,
persistent drift, post-I3 owned-file timestamp drift, restart ambiguity, cleanup
failure and both finalization failure outcomes retain accurate provenance.

The 17 crash boundaries include before/after Prepared, armed-before-write,
partial/full staging, after rename before parent fsync, publication facts,
durable publication, activation permission, actual restart dispatch, completed
A/B/C, before/after cleanup, completed P, runtime facts, before finalization and
journal rename before its durability proof. The last case can load an already
Completed document only after the NEW journal object proves its durability; it
never promotes a Prepared record by matching config bytes.

Raw JSON reports are retained losslessly as `reports/<platform>.json.gz`, with
both compressed/raw hashes and actual observation counts in `evidence.json`.
For example, `gzip -dc reports/debian-12.json.gz` displays the complete raw report.
Ordinary CTest executes only unit tests and retained-evidence validation; it
never launches Docker or repeats native authentication/provider experiments.

## Boundaries

* Root-owned CAS uses the existing cooperative locking and optimistic
  check/rename model; arbitrary privileged writers can still race it.
* Coordinator serialization covers its entrypoints, not legacy SSSD mutators or
  arbitrary processes. Caller must hold normal daemon admission; I6 must replace
  legacy paths before policy integration. Active legacy ownership is refused
  without migration or historical-proof fabrication.
* Positive fixtures provision PRIVATE publication boundaries and native metadata.
  ALT supplies an explicit EnvironmentFile. Absent external environment, unknown
  native revisions/tools, lazy-only PAM, unsupported topology/provider and
  unproven LSM configurations remain refused. No host deployment provisioning is
  performed.
* Repeated fixture restarts reset stock SSSD start-limit counters only when the
  service is active; ALT may unload a stopped unit. Production never resets
  counters. Rapid real calls can fail closed at the native service start limit.
* C is the accepted bounded source-causal proof, not a functional authentication,
  future LDAP availability, in-memory read or periodic cleanup guarantee. No
  cache/credential deletion is performed.
* Docker/WSL evidence is not bare-metal, enforcing-LSM, AD/IPA/trust or Podman
  certification. I5 verified release and I6 real policy/client/package integration
  remain future work.

Authoritative API/ownership/recovery contract:
[SSSD design](../../../docs/sssd-verified-activation-design.md#i4-transaction-coordinator-backend-no-policy-integration).
