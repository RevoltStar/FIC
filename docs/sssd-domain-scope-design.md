# Proposed SSSD domain scope

Research design only. [Evidence/semantics](sssd-policy-semantics.md).

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
