# Proposed SSSD verified activation — research design, not implementation

Native facts and bounded coverage: [R1](sssd-native-compatibility.md).
Reuse `VerifiedConfigServiceActivator` and its existing snapshot/publication/
launch/cleanup engine. Do not create another activation engine or pretend an
SSH activation profile is an SSSD profile.

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

Next, under resource serialization, capture ownership and the complete candidate
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
unchanged. I2–I6 are not implemented by this API.

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
