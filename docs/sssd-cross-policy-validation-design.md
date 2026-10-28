# Proposed SSSD relation validator and implementation sequence

Research only; no validator/policy/journal implementation in R2.
[Semantics](sssd-policy-semantics.md), [domain model](sssd-domain-scope-design.md),
[activation proofs](sssd-verified-activation-design.md).

## Confirmed relation

Let `O` be effective global offline days and `A[d]` effective account days for
each covered domain, after all snippets/defaults, including foreign inputs.
After separate nonnegative numeric validation:

`valid(d) = A[d] == 0 || (O > 0 && A[d] >= O)`.

| O | A | Relation | Native LDAP all five | Native proxy all five |
|---|---|---|---|---|
| 0 | 0 | valid | active | active |
| 0 | 1 | conflict | EINVAL backend / failed unit | active |
| 1 | 0 | valid | active | active |
| 1 | 1 | valid (equality accepted) | active | active |
| 2 | 1 | conflict | EINVAL backend / failed unit | active |
| 1 | 2 | valid | active | active |

All six combinations pass native config-check. Conflict still fails LDAP when
cache_credentials=false. The source diagnostic says “larger” but the code uses
`>` to reject O>A; equality is valid. Monitor can ingest ConfigDB while backend
later rejects options. Do not collapse config-check/monitor/backend/PAM results.

This is proven LDAP behavior. AD/IPA use separate option-loading paths without
the same relation check in the inspected source; no real directory runtime
proof exists. Proxy accepts these configurations and does not implement the
same cleanup contract. A future FIC validator should independently enforce the
safe relation for providers whose account cleanup it promises to manage, even
if their native constructor fails to check it. First release should reject
unsupported provider scope rather than claim universal cleanup semantics.

## Validator inputs and output

Run a pure semantic projection before persistent mutation under existing shared
resource serialization. Inputs: exact ordered INI closure and launch profile,
scope receipt, proposed replacement of own keys, native per-version defaults,
ownership map and operation kind. Output: typed per-domain effective values,
their provenance (own/foreign/default), relation results and explicit unknowns.
It neither mutates foreign data nor repairs it. Native config-check is an
additional check of the **same** `-c/-s` graph, not this validator's replacement.

* Apply/REFRESH O: evaluate every selected supported domain's A against proposed
  effective O, not just FIC-enabled account policies.
* Apply/REFRESH A: evaluate against effective global O even if O policy is
  disabled/foreign/default. Multi-domain success requires every covered domain.
* cache_credentials true: evaluate the same image; never suppress LDAP relation
  checks merely because caching was previously false. No automatic account/O
  alignment. No Required dependency; Recommended only remains unchanged.
* Disabled policy contributes its foreign/native effective value, never its
  retained FIC config value. Missing native option has native default 0.
* Late overrides that prevent requested apply value are a conflict before CAS;
  untrusted/ambiguous input, unknown provider/scope/default or unsafe numeric
  parsing is failure, not “assume compliant”. Recheck exact graph after cleanup.
* Disabling/rollback is **ownership release**, not a relation repair operation.
  Remove only proven own keys even if the revealed foreign configuration is
  conflicting. Report persistent release and runtime reconciliation separately;
  do not restore foreign history, retain own keys as a fix, or claim full runtime
  success if restart/projection fails. The future release transaction must be
  able to represent released-but-runtime-failed honestly, including inactive
  persistent-only release. This requires explicit receipt/state design first.

No credential DB cleanup is authorized by any of these operations. An invariant
over login ages is not permission to delete cached identities/passwords.

## Recommended implementation commits I1–I6 (not started)

| Stage | Existing components / new narrow work | Journal changes | Required native gates | Open risk |
|---|---|---|---|---|
| I1 native closure | Reuse SssdConfiguration + existing safe file/launch utilities; closed SSSD input/launch profile and complete INI projection, matching config-check -c/-s | None | five versions, omitted main, duplicates, aliases/links, private parents, native metadata/env/precommands | Version drift and unknown provider commands |
| I2 scope + relations | Pure projector/validator and immutable domain receipt from merged closure; preserve Recommended | Design typed section/key scope payload; no mutations yet | multi-domain/inactive/foreign/default/relation matrix, negative/boundary values; source vs actual AD/IPA lab distinction | Dynamic trust scope still refused |
| I3 verified adapter | Same generic engine + narrow existing internal proof callbacks/expected launch; SSSD consumer/readiness receipt and platform-specific PIDFile/trigger identities | Receipt type only until lifecycle integrates it | active/stopped/activating; main/backend/PAM generations, RO metadata, optional env, unit/env races, lazy responders, cleanup and timeout barriers | Generic C != consumer/P; no arbitrary notify/profile relaxation |
| I4 transactional apply/REFRESH | Existing CAS/AtomicFileWriter, shared SSSD resource lock and MutationJournal; one shared file with per-policy section/key ownership | Versioned backend transition payload: previous/target image+scope, CAS/durability, publication/runtime/P outcomes, unresolved Prepared; exact historical compatibility decision required, no auto-adoption | same-value active proof, one-step REFRESH, siblings, conflicts, every crash boundary, hidden source FD/late snippet, stale objects | Existing auto-Prepared recovery must not imply uncertain success |
| I5 verified release | Reuse SssdRollback/uninstall/disable orchestration; active verified remaining image vs no-start inactive release | Explicit ownership-release/runtime outcomes and disable acknowledgement; preserve proven provenance on partial failure | later foreign override, inactive service, missing owned artifact, relation conflict after release, failed P/restart/cleanup, disable retries | Persistent release may succeed while runtime reconciliation fails |
| I6 policies + end-to-end | Register future fixed-true cache and account policies through existing registry/config/localization/UI/CLI; rework current offline policy using above contracts | No extra global schema beyond reviewed backend payload; confirm journal/witness pairing | real packages and daemon IPC, apply/same-value/REFRESH/disable/uninstall, local LDAP online/offline all five; AD/IPA real lab before claiming their support | FIC range/default for new account policy still a product decision; LSM/bare-metal/trust gates remain |

Every stage needs unit/contract/negative tests as well as listed native gates.
Do not connect an incomplete adapter as a fallback, start SSSD to make apply pass,
or replace unknown C/P outcomes with `is-active`. Current R1/R2 research does not
claim I1–I6 are implemented or production-ready.
