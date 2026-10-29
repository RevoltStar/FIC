# Proposed SSSD domain scope

R2 design and evidence boundaries; implemented I2 API is specified below. [Evidence/semantics](sssd-policy-semantics.md).

## Domain sets must remain separate

* Configured sections: explicit `[domain/name]` in the merged native INI graph.
* Enabled/selected roots: `[sssd] domains` plus versioned per-domain enabled
  handling. Never equate “has a section” with “has a running backend”.
* Runtime roots/consumers: validated monitor/backend/responder generation.
* Discovered/trusted subdomains: dynamically materialized domains, not necessarily
  explicit INI sections or present when apply starts.

Native all five: an extra inactive section with conflicting values appears in
ConfigDB but has no corresponding active backend; sole domain enabled=false gives
“No domain is enabled”. Two selected LDAP/proxy domains start, while invalid
selected LDAP relation fails the mixed fixture. `sssctl domain-list` is an
observation, not an exhaustive stable future-discovery witness.

Versioned `sysdb_subdomains.c/new_subdomain` explicitly copies parent
cache_credentials, first-factor length and cached_auth_timeout; newer versions
also read selected subdomain configuration afterward. This is SOURCE_CONFIRMED
inheritance, not a functional guarantee for every AD/IPA trust/provider lifecycle.
Provider option arrays and dynamic discovery are separate from that domain bool.
Do not write fabricated `[domain/foo/bar]` sections or assume their creation
controls an undiscovered trust. No AD/IPA discovery runtime exists in this lab.

## Recommended first implementation boundary

Use an immutable scope receipt derived from the **merged full input graph** and
bound to the same launch/config generation. Record exact root names, selected
and enabled states, id/auth providers and relevant consumer identities. Never
let a later apply silently change scope under an existing receipt.

Initial domain policy support should cover explicit selected static roots in a
closed provider/consumer allowlist that has real tests (LDAP password initially;
proxy cache flag only after its own functional gate). Write own values in each
proven `[domain/name]` within the one FIC-owned drop-in. Do not change domains,
enabled or foreign sections. Every selected root must be either proven covered
or explicitly rejected: no partial global “all domains true” success.

Inactive roots are reported and not called runtime-covered. To avoid unnoticed
future enablement, scope change requires fresh validation/REFRESH; a stored
receipt does not authorize newly enabled domains. An empty selected scope is not
proof of meaningful password cache enforcement. Reject malformed names/duplicate
case identities and unsupported inherited/dynamic configuration before mutation.

For AD/IPA a later implementation may support a parent+inheritance receipt only
after versioned source and real trust tests show all relevant children consume
the expected bool/options, including newly discovered domains and overrides.
Until then dynamic/trusted coverage is **UNSUPPORTED**, not silently excluded
from a policy claiming whole-service coverage. Explicitly configured AD roots
alone are insufficient proof of their dynamic children.

## Support acceptance criteria

`sssd_cache_credentials` may report policy Success only if every domain in its
declared scope is covered by the full [A/B/C/P contract](sssd-verified-activation-design.md),
after separate service admission. C=Semantics binds selected effective values
to supported consumers/scope; B=Activation/readiness alone is insufficient.
The declared scope is not silently narrowed to the subset that happened to pass.

Configured roots and dynamically discovered/trusted subdomains are separate
categories. Changing a parent's cache flag is not proof that all current or
future children comply. Unknown provider, unsupported topology or unproven
scope means unsupported/failure for the policy requiring it, not global Success.
Never manufacture sections for undiscovered trusted domains. A changed root,
enablement, provider or discovered-domain set requires rechecking the old runtime
receipt before it can authorize another apply without restart.

These are present evidence boundaries, not permanent bans on AD/IPA or other
providers. Future implementations must either pass the concrete provider/scope
native gates (including trust changes and claimed authentication mechanisms) or
explicitly refuse that configuration. R2's proxy acceptance of option combinations
does not prove LDAP cleanup semantics or proxy functional auth support.

## Ownership and rollback

Existing journal resources identify section/option. Future one-to-many domain
ownership must retain each exact section/key and whole-file CAS witness, sibling
policy ownership, scope receipt and transition provenance. Do not capture every
foreign setting as owned just because it was part of the merged proof.

Even a matching foreign value requires the policy's own section/key in the
FIC-owned file; never adopt the matching foreign file/value itself. Any loaded
foreign snippet ordered later than zzzz-fic.conf blocks apply/REFRESH regardless
of content. That admission/support restriction does not prevent releasing a
proven own key merely because the late file exists.

Reevaluation of scope is mandatory on REFRESH or changed launch/input graph;
unresolved Prepared blocks new work. Do not construct historical scope from
current foreign bytes. Missing owned domain/key is drift, not permission to
recreate/adopt it. Rollback deletes only proven own keys from the originally
owned set, even if that root is inactive or a later foreign snippet overrides
it; no historical foreign restore. Remaining foreign conflicts are reported
separately from ownership release and runtime readiness. Stopped SSSD does not
require start to release a proven persistent setting.


## Implemented I2 scope reference

SssdDomainScope accepts the existing SssdInputReference; it never reads files,
queries D-Bus, enumerates runtime domains or creates a second scanner.
DomainScopeReference owns shared immutable DomainScopeData, including a deep
immutable I1 copy, formatVersion=1, platform, exact graph/launch/projection
fingerprints and diagnostic domain records. It is ephemeral expected semantic
data, not a persistent/runtime receipt or authority to mutate.

Configured sections, explicitly selected ordered roots, effective enabled roots,
expected backend names and unselected sections remain separate vectors. Per-root
records include id/auth providers, enabled explicit/default state, provider
classification, possible dynamic/trust scope and future required monitor/backend/
PAM/NSS consumer identifiers. Expected backends are not claimed running.

Reviewed native enabled semantics start with domains, remove enabled=false and
add unlisted enabled=true roots. Missing enabled retains membership in domains.
The closed positive profile requires explicit static LDAP password roots:
auto-enabled unlisted roots are reported but UnsupportedConfiguration. All-disabled
or no explicit roots is unsupported, never empty-scope success. Duplicate names,
empty list entries, missing/case-mismatched sections and ambiguous case identities
are invalid. Explicit selection order is preserved; unsupported auto-added roots
are reported canonically, without claiming their native initialization order. The parser supports a bounded ASCII name subset; nested domain
sections and subdomain/inheritance configuration cannot prove trusted coverage.
Extra inactive sections remain visible without being called runtime consumers.

ldap/ldap (including the versioned auth default to id) is the only positive
provider pair. Proxy has native startup evidence but unsupported password/cleanup
scope. AD/IPA expose possible dynamic/trusted children, with no real realm/trust
functional proof; unknown pairs are unsupported. No failing root is dropped to
produce partial global success. Future I3 must prove the actual consumers and
discovery contract before extending support.

DomainScopeReference remains a public immutable data container, not an authority
token. A caller can copy its data and retain old fingerprints while changing
computed facts; those fingerprints alone do not authenticate the facts.
sameScopeReference therefore compares the full structure: format/generation,
platform, configured/selected/enabled/unselected roots, expectedBackends, every
domain's providers/classification/flags/consumers/issues, global issues and the
recomputed binding of its stored I1 input, in addition to the fingerprints.

previewConfiguration recomputes the canonical scope from its input, requires
full structural equivalence and rejects hypothetical references as observed.
All admissibility decisions then use only that canonical scope, never the
caller's domain map or selected/enabled flags. A forged ghost root, enabled flag,
provider classification, removed issue or altered expectedBackends returns
NotProven with no candidate configuration. This is structural validation, not a
new signed-token or cryptographic protocol.

Canonical input hashing includes ordered contents, all source and
absence identities/metadata, launch/process/executable references and consumer
mapping. Identical final root/value lists do not excuse changed snippets, object
identity, metadata, provider, enabled flag or launch generation. Records retain
the facts behind the hash for diagnosis. Hypothetical references additionally
carry a distinct proposed-source-graph fingerprint and hypothetical=true, so
a shadowed key removal cannot masquerade as an observed unchanged graph. There is no mutable cache or privileged
ABA guarantee; future I3 must revalidate I1 at its proof boundaries.

[Unit/native tests and retained source evidence](../tests/integration/sssd-i2/README.md)
cover these boundaries on all five platforms. I3–I6 remain unimplemented.
