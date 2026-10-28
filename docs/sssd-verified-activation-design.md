# Proposed SSSD verified activation — research design, not implementation

Native facts and bounded coverage: [R1](sssd-native-compatibility.md).
Reuse `VerifiedConfigServiceActivator` and its existing snapshot/publication/
launch/cleanup engine. Do not create another activation engine or pretend an
SSH activation profile is an SSSD profile.

## Proof obligations

* **A:** trusted native installed package/executable graph, manager identity,
  active stable notify monitor, exact unit/environment/namespace contract and
  already provisioned safe mount parents. Absent/inactive/activating/unproven
  fails apply before persistent mutation; no install/enable/start repair.
* **B:** complete same-generation INI closure, parser/metadata admissibility,
  full conf.d manifest, requested effective settings and relations. Include
  existing literal EnvironmentFile targets, manager environment, unit sources,
  native monitor/backend/responder executable identities. Reject alternate -c,
  unbounded commands/inputs and unsafe absent paths until explicitly designed.
* **C:** same engine publishes RO copies; validate using matching `sssctl -c/-s`
  and source-derived projection inside published closure; restart exact native
  unit, pin new InvocationID/MainPID and READY. Confirm required consumers and
  domain initialization; `READY=1` is a necessary initialization event, not an
  offline authentication or all-provider health oracle.
* **P:** after successful cleanup, re-open persistent input graph, compare exact
  roots/inodes, manifest, bytes/metadata and launch identity to intended result.
  A hidden-source late snippet/write must prevent policy Success even when C
  succeeded. Preserve unknown outcome/provenance; never auto-adopt.

These are future requirements. Generic public `activate()` supplies bounded
publication + notify/cleanup; the native tests demonstrate it cannot supply P
or SSSD semantic consumer proof alone. Reuse narrow internal same-engine proof
callbacks/expected launch contract pattern already established for SSH, rather
than broadening the public API speculatively in research.

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
foreign main/snippets and sibling policy keys. Future domain keys must have
explicit section/key ownership. Use existing CAS/file metadata/durability and
MutationJournal, a shared SSSD resource lock, exact previous/target witnesses and
explicit unresolved Prepared gate. No uncertain automatic semantic recovery.

Same-value apply still needs A/B/C/P or a demonstrably valid runtime receipt;
unchanged bytes alone are insufficient. REFRESH must be one ownership-preserving
transaction. Active rollback requires verified activation of the remaining image;
stopped rollback may release persistent ownership without starting SSSD. A late
foreign override or remaining foreign relation conflict is diagnostic, not a
reason to retain a proven owned key. Missing owned file/key is not adoption or
automatic recreation. Failed cleanup, ambiguous restart or failed P must not
be promoted to applied/fully released.

No production code, journal schema or policy dependencies changed in R1.
R2 must refine consumer/domain/relation semantics before implementation.
