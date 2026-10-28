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
