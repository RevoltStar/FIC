# SSSD verified activation — I1/I2/I3 and future transaction design

Native facts and bounded coverage: [R1](sssd-native-compatibility.md).
Reuse `VerifiedConfigServiceActivator` and its existing snapshot/publication/
launch/cleanup engine. Do not create another activation engine or pretend an
SSH activation profile is an SSSD profile.

## I3 adapter contract (no policy or ownership authority)

`service/sssd/SssdVerifiedActivationAdapter` activates the **observed** I1 graph,
canonical I2 scope and explicit typed section/key expectations. Forged scope,
hypothetical preview, empty/duplicate targets, provider/scope/relation conflicts
or values different from the captured graph are refused before publication.
The adapter neither writes configuration/journal nor returns policy SUCCESS;
`PolicyCoverage::NotEvaluated` remains explicit. I4/I5/I6 are not implemented here.

A single bounded attempt (maximum five minutes) uses the existing generic
engine and internal proof callbacks. The process-local operation mutex prevents
concurrent adapter calls; it does not serialize arbitrary privileged writers.
Existing generic mount/observer/cleanup guarantees and residual races apply.
There is no admission or runtime receipt cache and no service supervisor.

### Closed support and native prerequisites

Only already-active/stable `sssd.service`, notify/main, exact I1 stock unit
fingerprint, researched package revision and native executable identities are
supported. The existing verified executor/hash store must already trust
systemctl, `/usr/sbin/sssd`, the platform package-query executable and
`/usr/bin/ldbsearch` (plus `/usr/bin/dbus-send` for modern backend protocol);
the adapter never provisions tools or trust hashes.
Package revisions are closed to the five I3 native observations; an unreviewed
revision is UnsupportedConfiguration even with the same upstream version.

The SSSD-only PIDFile exception is `/run/sssd.pid` for Debian12/Ubuntu24/ALT;
Debian13/Ubuntu26 retain empty systemd PIDFile. Contents must identify the
confirmed monitor through a no-symlink root-owned regular single-link descriptor.
It is checked before publication and against the new monitor, never used alone
as process identity. Generic and SSH profiles retain their previous restrictions.
Snapshot validation has no SSSD activation authority.

Native ignored privileged precommands remain unchanged. Debian13 group-readable
root metadata and Ubuntu26 root:sssd group-readable/searchable metadata must
already permit RO initialization; the adapter never repairs foreign metadata.
The published snapshot preserves bytes, owner/group/mode and mtime; native
chown/chmod attempts against RO data can fail without establishing their effect.
ALT requires the existing I1 `[sssd] user=_sssd` contract and real child UID/GID.

The complete `/etc/sssd` parent is one controlled tree, including exact empty
subdirectories. The narrow explicit-directory manifest is accepted only by the
closed SSSD engine profile. This protects absent main/conf.d slots. An absent
optional EnvironmentFile **outside** that tree remains Unsupported before mount;
no placeholder file or global `/etc` snapshot is created. Consequently stock ALT
with absent `/etc/sysconfig/sssd` is not a positive supported environment. Its
positive native fixture has explicit administrator-supplied native launch
configuration; the stock absence refusal is retained separately in evidence.

Required PAM semantics currently support a monitor-spawned configured PAM
responder (`services=pam`), not lazy-only responders. Backend-only expectations
can omit PAM. Missing consumers return NotProven/Unsupported, never partial SUCCESS.

### Source-causal C: exact chain and limits

Versioned distribution sources, hashes and anchors are retained in
[I3 source review](../tests/integration/sssd-i3/source-review.json), tied to the
original R1 archive/patch provenance. These sources describe initialization;
they are not runtime evidence on their own.

1. A protects the complete expected graph and launch sources. The new monitor
   InvocationID differs from the admitted one; main/child executable objects,
   parent/start tokens, credentials, root, mount namespace and service cgroup
   are observed through procfs/pidfds and rechecked. Native code and provider
   module fingerprints remain pinned; LDAP modules must actually be mapped.
2. Monitor `confdb_setup` precedes spawning children. Each selected backend and
   required responder must hold a descriptor **and shared mapping** to the
   observed ConfigDB object. `/proc/PID/map_files` resolves object identity
   correctly even when OverlayFS `maps` reports the backing device number.
   The native root/service-controlled ConfigDB ancestry is checked without
   following symlinks; native service-group writable directories are allowed
   only for the specific nonroot identity, never world-writable directories.
   ConfigDB and central-bus ancestors are opened without symlinks; access/default
   ACLs are refused instead of silently trusting extra named principals.
3. The stable bounded ConfigDB generation (identity, metadata and SHA-256) must
   project to the protected I2 scope, selected values and relation dependencies.
   `ldbsearch` searches a private size-sealed memory copy; it never receives the
   live database pathname. TDB's write-capable open/recovery is therefore confined
   to that copy, whose mutation is itself refused. The live generation is checked
   before and after. No cache, credential or ConfigDB mutation is performed by FIC.
4. In SSSD2.8/2.9 the backend's monitor connection is constructed after successful
   `dp_init_recv`/target initialization. UNIX socket diagnostics prove a
   bidirectional peer relation between descriptors of the exact new child and
   monitor; a matching command line or socket filename is insufficient.
5. In SSSD2.10/2.12 the connection is created earlier, so it is insufficient.
   The adapter connects to the central bus and verifies SO_PEERCRED against the
   exact new monitor. Read-only GetNameOwner/GetConnectionUnixProcessID bind the
   selected backend's unique bus owner to its pinned PID. IsOnline is called on
   that **unique owner**, and the PID is checked again. The native interface is
   installed by `dp_init_interface` only after successful modules/targets/options
   initialization. Either boolean reply proves that initialized consuming path;
   it does not assert LDAP is online. No RegisterService, responder-name
   impersonation, RequestName or authentication is performed. A responder's
   birth order/monitor READY is deliberately not used as a registration proof.
6. PAM `sss_process_init` reads domain options before its event loop. A bounded
   unauthenticated GET_VERSION request must return native protocol version and
   SCM_CREDENTIALS from that exact responder PID/UID/GID. This establishes the
   functioning initialized consumer, not a password check.

| Selected parameter | Consumer/read moment | Proven scope; excluded claims |
|---|---|---|
| offline_credentials_expiration | LDAP `sdap_get_options` at initialization; PAM `sysdb_cache_auth` at request time | LDAP relation dependency validated; future PAM path reads expected ConfigDB value. No actual auth path is claimed. |
| cache_credentials | backend/PAM `confdb_get_domain_internal` during domain initialization | Domain flag available to the known future PAM/cache path. No assertion that credentials were stored or a login succeeded. |
| cached_auth_timeout | domain initialization; PAM cached-auth request path | Configured seconds and I2 clamp are reported separately. No cached-auth request is implied by protocol availability. |
| account_cache_expiration | LDAP options/cleanup setup at initialization | Expected option available to cleanup code. No assertion that periodic cleanup has executed. |

C is bounded causal evidence, not direct memory inspection. It does not prove
LDAP availability, future process survival, arbitrary provider semantics,
AD/IPA trusts, actual authentication or cache cleanup. It requires the complete
chain; READY, a new PID, a ConfigDB match or a source-code path alone is insufficient.
No runtime instrumentation, authentication or SSSD hooks are used in production.

### Publication versus completed A

The published callback validates the bounded RO snapshot, exact bytes/metadata/
manifest, negative slots, I1/I2 graph and required launch/code inputs. This is a
local prerequisite (`publishedValidated`), **not** completed Input Proof A.

A becomes Proven only in the ready callback after publication validation **and**
a complete successful `proveRuntime`: new monitor generation, ConfigDB binding,
initialized selected backends/required responders and the existing bounded
source-causal chain. `activationAttempted` records dispatch entry only and cannot
promote A. Pre-restart unit/mount interference, timeout after publication, and
attempted restart without full consumer proof leave A NotProven, even if some B
facts were established. No additional runtime proof subsystem is introduced.

A records historical protected-input consumption. Subsequent persistent drift or
cleanup failure does not erase that fact, but forbids overall SUCCESS. A later
runtime-generation change can invalidate current B/C while historical A remains
Proven; P keeps its independent existing meaning.

### P and result algebra

After ordinary ownership-checked cleanup, P reopens original resources and
compares complete identities/manifests/bytes/metadata, negative slots, environment,
unit lookup and launch/native code sources. Dynamic old MainPID/InvocationID/Job
are removed only from the **configuration** comparison; P separately confirms
the newly proven runtime generation when one exists. It never requires the old
monitor to survive the intended restart.

Admission, A/B/C/P, generic primary/status, cleanup errors, residual mounts and
possible runtime effects are separate fields. Restart dispatch is recorded
conservatively even if systemctl times out. Cancellation does not undo runtime
changes. Refusal, failed activation, unknown runtime effect, activated-but-P-not-
proven and failed cleanup cannot satisfy `success()`. Cleanup failure never
promotes an otherwise successful activation and prevents P. Failed primary
activation remains visible even when P can independently be established.

Native fault/functional reports and current-source integrity checks are in the
[I3 runner](../tests/integration/sssd-i3/README.md). Historical R1/R2/I1/I2 evidence
is unchanged: its guards compare against the exact accepted historical commits;
current I1/I2 behavior is regression-tested separately. Full Git history is
required for these guards (CI fetch-depth=0); they do not relabel historical
PASS as evidence for modified sources.

## Admission, transaction and proof obligations

Terminology follows [SSH activation/REFRESH/release](ssh-verified-activation-adapter.md)
and the existing adapter's `inputs`, `activation`, `semantics`, `persistent`
results. The stable identifiers below are checked against
[`research-contract.json`](../tests/integration/sssd-research/research-contract.json);
they do not redefine the engine or constitute native evidence.

**Service admission is a separate read-only prerequisite, not A.** It verifies
supported installed SSSD/executables, trusted manager/unit/EnvironmentFile inputs,
the native launch contract, stable active runtime and supported topology, plus
safe preprovisioned publication parents. Absent, stopped, activating or unproven
SSSD fails apply before persistent mutation. FIC does not install, enable or
start it to make admission pass. Unsupported alternate -c, arbitrary consumer
commands, sandbox/namespace topology and unsafe absent inputs remain rejected.

The following transaction steps are future I4/I5 obligations, not I3 behavior.
Under resource serialization, capture ownership and the complete candidate
INI graph/metadata/manifest, project effective values and validate relations/scope.
These preflight checks are not final A/B/C proofs of a running instance. Persist
transaction preparation before the one conditional mutation, using existing
CAS/metadata/durability and journal mechanisms. Never infer historical ownership
from current foreign bytes. The future implementation must then establish:

<!-- sssd-proof-contract -->
| Proof | Meaning | Required evidence |
|---|---|---|
| A | Inputs | Activation used the protected, expected configuration inputs: complete same-generation main/conf.d closure, exact manifests/metadata and pinned trusted launch inputs/executables. |
| B | Activation | Protected service activation and required runtime/readiness postconditions are proven on the admitted unit, with process/InvocationID and required consumer identities bound to that activation. |
| C | Semantics | Selected effective parameters match their targets for the proven provider/domain scope and consuming generation; matching config-check -c/-s and source-derived projection alone are not a functional-authentication guarantee. |
| P | Persistent | After successful cleanup, required persistent state is proven by reopening original resources and comparing identities, exact manifests, bytes/metadata and the still-required launch contract. |
<!-- /sssd-proof-contract -->

The same engine publishes RO copies for A and performs protected activation for
B. READY=1 is an initialization event; it does not independently prove SSSD C,
required lazy responder health or offline authentication. A hidden-source late
snippet/write must prevent policy Success through P even if protected activation
succeeded. Unknown launch changes at any phase prevent final Success.

Generic public `activate()` can prove its bounded snapshot/notify activation
contract. **Generic engine Success ≠ SSSD policy Success:** it does not supply
the whole SSSD-specific C or post-cleanup P. Failed cleanup/residual mounts also
prevent Success even when `primaryStatus` records a successful activation.
Reuse existing narrow same-engine proof callbacks/expected launch contracts as
SSH does; no second engine or global admission relaxation.

For a new mutation, journal finalization follows the complete required A/B/C/P proofs and final
installed-resource/runtime rechecks, not just `ActivationResult::success()`.
Journal finalization failure remains an explicit policy failure with accurate
saved/runtime/provenance outcomes. Unknown runtime effects retain unresolved
provenance; no blind restoration of historical bytes.

## Platform adaptation

Debian 13 and Ubuntu 26.04: existing generic notify activation works when native
metadata and complete existing inputs are safe. Need a closed SSSD semantic
adapter/receipt and Prepared lifecycle, not a new mount engine. Precommands must
be pinned and their ignored failures understood; verify metadata postconditions.

Debian 12, Ubuntu 24.04, ALT: explicit SSSD notify profile would need narrowly
validated stock PIDFile/activation triggers and responder identities. Do not
remove generic PIDFile/TriggeredBy rejection globally. ALT config-level user and
group transitions require pinned final child identity beyond unit User alone.
All profiles: lazy responders, IFP/PAC/NSS/PAM sockets and provider dependencies
need a closed per-profile graph. Nondefault units/custom sandbox remain refused.

Configuration closure consists of main and complete conf.d, explicit launch
EnvironmentFile, unit fragments/drop-ins and manager environment, executables
and config-selected commands. Certificate/keytab/krb5/DNS/NSS/LDAP external inputs
are additional functional-auth inputs, **not proven** by the INI snapshot. Limit
v1 proof to loading the requested parameters into known consumers; reject custom
consumer commands. Do not claim full auth correctness from this bounded closure.

## Ownership and crash boundaries

One FIC-owned `/etc/sssd/conf.d/zzzz-fic.conf`; per-policy keys only. Preserve
foreign main/snippets and sibling policy keys. A compliant foreign value still
requires creating the policy's own section/key ownership; it grants no ownership
of the foreign setting/file. An existing unproven zzzz-fic.conf is not adopted
because its name or contents match. Any SSSD-loaded foreign snippet ordered
after zzzz-fic.conf blocks apply/REFRESH, even if it agrees with the target or
contains unrelated keys. This conservative support boundary is independent of
the native parser's merge semantics; the snippet alone does not block release.
Future domain keys must have explicit section/key ownership. Use existing
CAS/file metadata/durability and MutationJournal, a shared SSSD resource lock,
exact previous/target witnesses and
explicit unresolved Prepared gate. No uncertain automatic semantic recovery.

Same-value apply still needs full A/B/C/P obligations; a genuinely current runtime
receipt may re-prove the relevant prior activation/semantics without another
restart. Recheck admission, boot/process/executable/launch, complete input graph,
selected values and scope, and persistent state; stale/unproven receipts or
unchanged files alone cannot authorize Success. Native statements that a changed
INI needs restart describe SSSD reload behavior, not a requirement to restart
again when a current receipt already proves consumption.
REFRESH is one ownership-preserving transition with no intermediate foreign
configuration. Active rollback requires verified activation of the remaining image;
stopped rollback may release persistent ownership without starting SSSD. A late
foreign override or remaining foreign relation conflict is diagnostic, not a
reason to retain a proven owned key. Missing owned file/key is not adoption or
automatic recreation. Failed cleanup, ambiguous restart or failed P must not
be promoted to applied/fully released.

No production code, journal schema or policy dependencies changed in R1.
R2 must refine consumer/domain/relation semantics before implementation.

## Implemented I1 read-only API

`service/sssd/SssdServiceAdmission` provides `admit(deadline)` and
`revalidate(launchReference, deadline)`. `SssdVerifiedInputClosure` provides
`capture(deadline)` and `revalidate(inputReference, deadline)`. Failures carry
existing typed `detail::Failure/ActivationStatus`; a returned reference is an
observation, never an activation result or authority to mutate. There are no
production callers in policies yet. Existing SSSD apply/runtime/rollback stay
unchanged. I1 itself implements none of I2–I6; the separate I2 API below now projects expected semantics.

Admission uses the same private root-PID1 typed D-Bus reader, with a narrow
read-only SSSD entrypoint adding state, sandbox, InvocationID and Manager.UnitPath.
No new activation profile or permission is added to the generic engine. Exact
per-distribution commands/flags, native environment path, user/group, PIDFile,
reviewed vendor-unit **content digest**, no unknown loaded overrides, and trusted
unit-source fingerprints are required. Changing even unprojected vendor-unit
bytes needs a new reviewed profile; an unchanged ExecStart alone is insufficient.

The full native lookup negative set is rechecked for pending unit/type drop-ins
and shadowing units too: NeedDaemonReload/DropInPaths alone missed an unloaded
override in the Debian 12 native gate. An existing drop-in directory is allowed
only when root-controlled and proven empty by the generic tree reader. MainPID
executable, invocation, process start token, process/root/mount namespace,
root-controlled executable byte/identity fingerprints and the compile-time host
profile are checked. Native /bin aliases are bounded: usr-merge, stock sh→dash/
bash and Ubuntu 26.04's exact chown/chmod uutils aliases. Configuration user and
declared responder executables are observed without claiming consumer readiness.

The closure reuses `openAbsolute`, `Fd`, `identity`, `readTree`,
`fingerprintUnitSource`, `ContentDigest` and the existing `ActivationRequest` data
model. It reads a bounded complete `/etc/sssd` tree (including all conf.d entries),
then reconfirms it through fresh descriptor traversal, comparing bytes, mount/
inode identities, size, mode, owner/group, nlink, mtime and ctime. A second launch
proof and final graph reread close the interval spent checking consumers.
Source bytes and full attributes remain available to I2 and ownership release;
no enrollment is inferred for zzzz-fic.conf. Every later eligible foreign snippet
marks `applyConflict()` independent of content; it does not destroy the reference.

Existing main, complete conf.d and environment become `inputs.paths`. Absent
main/conf.d/optional environment are explicit negative dependencies with pinned
parent observations, never fabricated files. `engineNeedsNegativeDependencySupport`
and `activationLimit` expose remaining I3 work; `genericActivationSupported` is
always false in I1. Generic activation still rejects stock PIDFile profiles.
No snapshot, mount, service job, persistent write, journal access or fallback to
SssdRuntime occurs in production I1.

Supported INI projection is deliberately narrow: ASCII section/key assignments,
whole-line comments, repeated sections/keys and last-wins ordered merge. Values
are uninterpreted text with source provenance. Unknown syntax, continuation,
quoting, inline comments, invalid control/encoding and empty values are Unsupported,
not guessed effective semantics. Provider/default/domain/relation interpretation
belongs to I2. File aliases/hardlinks, unsafe ownership/modes, xattrs/ACL/labels,
nested conf.d directories/mounts and unknown launch executable/env indirection fail
closed. Group-readable config is admitted only by the newer Debian13/Ubuntu26
profiles; native metadata preparation for activation remains I3's responsibility.

The reused reader requires root/CAP_SYS_ADMIN with xattr visibility in the
initial user namespace, even though I1 does not mount anything. Manager environment
is limited to the reviewed native PATH forms and C/C.UTF-8/POSIX locale assignments;
other values are Unsupported rather than an unproven collation/launch context.

Capture is optimistic, operation-scoped and deadline/budget bounded. It detects
observed changes, including same-bytes inode replacement and ordinary byte
restoration with changed ctime. It cannot atomically freeze arbitrary privileged
writers or exclude privileged ABA. References must be revalidated by I3 at its
own proof boundaries. I1 proves neither completed A nor B/C/P, current ConfigDB
correspondence, runtime policy success, ownership or journal finalization.

Native commands, five-platform evidence and limits:
[`sssd-i1/README.md`](../tests/integration/sssd-i1/README.md).


I1 follow-up tightens the ALT consumer identity boundary: explicit effective
`user=_sssd` is mandatory even without services; privileged ALT alternatives
remain outside this closed profile. Missing-user defaults are not inferred to
match the stock socket responder. Native identity/source evidence and its
limits are recorded in [compatibility](sssd-native-compatibility.md#i1-follow-up-alt-identity-and-admission-races).

Operation-local first-admission checkpoints exist only with
`FIC_SSSD_I1_TESTING`; production contains no callback API or hook state. They
exercise vendor bytes, optional environment content/object/absence, and pending
UnitPath overrides between initial observations and final confirmation. The
unchanged production sequence rejects every injected change; the control admits.
The corrected mode-0700 nested-mount fixture verifies the mount-boundary reason,
without changing the generic reader. These tests do not provide atomic file/unit
locking, responder generation proof, or I3 runtime/cleanup authority. The full
`/etc/sssd` scan and existing generic PIDFile limitations remain unchanged.


## Implemented I2 semantics-only API

`SssdDomainScope::{domainScope,inputFingerprint,sameScopeReference}` creates and
compares immutable exact I1-bound domain references. This includes structural
comparison of the computed domain facts and their bound input, not just stored
fingerprints; preview decisions use a fresh canonical I1-derived scope and
reject forged or hypothetical observed references. `SssdEffectiveConfiguration::
effectiveConfiguration` computes typed Days/Seconds/bools with source/default/
foreign/unknown/owned provenance. `previewConfiguration` logically merges proposed
own-key Apply/Refresh/ReleasePreview operations. `SssdRelationValidator::
validateRelations` provides provider-aware per-root diagnostics and aggregate
expected semantic consistency. [Scope contract](sssd-domain-scope-design.md#implemented-i2-scope-reference),
[value contract](sssd-policy-semantics.md#implemented-i2-expected-semantic-projection)
and [preview contract](sssd-cross-policy-validation-design.md#implemented-i2-computation-and-hypothetical-operations)
are authoritative for their respective types and boundaries.

I2 is pure computation: no files, commands, service jobs, ConfigDB/cache writes,
mounts, journal, policy registration or integration into current SssdRuntime.
No I1/generic/SSH validation is relaxed. SemanticProjection Validated means the
supported LDAP configuration is expected to satisfy the reviewed relation; it
is not completed C, completed A/B/C/P, policy Success or a runtime receipt.
Preview also reports PolicyCoverage::NotEvaluated: I4/I6 must separately prove
the complete required key set against canonical domain scope before policy
SUCCESS. Structural scope consistency does not establish that policy coverage.

I3 must bind these exact inputs/scope/expected values to verified runtime
activation and the monitor/backend/late responder generation/readiness, then
establish persistent proof, protected negative dependencies, safe publication/
cleanup, metadata/precommand handling and platform PIDFile constraints. I4 must
provide trusted ownership context and transaction/CAS/journal integration; I5
must implement physical ownership release with separate runtime outcomes; I6
must integrate policy metadata/dependencies/clients and real package-policy E2E.
None of I3–I6 is started by I2. AD/IPA realm/trust, other mechanisms and deployment
LSM/kernel guarantees remain outside the current native Docker/WSL proof.
