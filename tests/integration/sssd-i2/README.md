# SSSD I2 native gates

This harness compares pure I2 expected semantic projections with stock SSSD
config-check, real monitor/backend startup and ConfigDB. It does not certify
consumer-generation bindings, authentication, completed C/A/B/C/P or a runtime
receipt. Writes and service operations occur only in disposable native fixtures.
Normal CTest validates retained evidence and never launches Docker.

Reuse the stock five I1 images:

```sh
DOCKER_CONFIG=/tmp/fic-package-docker-config \
 tests/integration/sssd-i2/run-native.sh fic-sssd-i1:debian12 debian-12
```

Repeat for `fic-sssd-i1:debian13 debian-13`,
`fic-sssd-i1:ubuntu2404 ubuntu-24.04`,
`fic-sssd-i1:ubuntu2604 ubuntu-26.04`,
`fic-sssd-i1:alt-p11 alt-p11`. Image construction and repository provenance are
in ../sssd-i1/README.md and Containerfile. Runtime containers use systemd PID1,
private namespaces, no host binds or published ports, network none/loopback.
Only isolated LDAP 127.0.0.1:9 and nonexistent test identities are configured.
Source is RO-mounted into an unprivileged builder; binaries/scripts are copied
into separate disposable runtime containers, which are removed on exit.

`provider-scope-coverage` exercises one/two LDAP roots, default auth mapping,
inactive foreign sections, explicit enabled false/true and auto-added roots,
LDAP+proxy, unknown provider, AD/IPA, dynamic/trust flags. AD/IPA are evaluated
against a new persistent graph while the previous known LDAP monitor runs;
their functional realm/trust runtime is NOT_TESTED, not a fabricated PASS.

`effective-relation` compares all six R2 pairs for LDAP and proxy on every
platform, plus false cache, one conflicting member of a two-LDAP scope, omitted
native values and native case-insensitive true/false vs invalid yes. Config-check
acceptance is retained separately from backend initialization failure. Proxy
native acceptance never becomes a supported LDAP cleanup/relation proof.
ALT fixture preserves explicit user=_sssd under the accepted I1 profile.

`scope-receipt-change` obtains a real I1 reference and I2 scope, then changes
persistent domains/provider/enabled/value in a deterministic fixture operation
and captures again. Exact references must differ even if target policy value or
root count is unchanged. Unit tests additionally exercise source-only/inode/
metadata/order changes, provenance and hypothetical Apply/REFRESH/release.

Raw commands, configurations, status/exit codes, computed results, ConfigDB and
filtered backend diagnostics live in ignored `build-sssd-i2/<platform>/native`.
After successful runs:

```sh
python3 tests/integration/sssd-i2/source-review.py
python3 tests/integration/sssd-i2/collect-evidence.py
python3 tests/integration/sssd-i2/check-evidence.py
```

Source review uses cached versioned R1/R2 patched trees, cross-checks unchanged
R2 hashes, and retains numbered bool/default/enabled/provider/relation excerpts.
The collector exports actual reports, image IDs, raw hashes and current source
hashes, command exit codes/output hashes (full outputs in raw reports), and fingerprints historical R1/R2/I1 artifacts without rewriting them.
Retained-evidence PASS means consistency of saved observations, not a new run.

Docker/WSL shared-kernel evidence does not certify bare metal, Podman, enforcing
LSM, real AD/IPA, trust discovery or account-cleanup timing. I3 activation,
consumer readiness/identity, generation/P/negative-publication/cleanup and I4–I6
policy/transaction/journal/release/package integration remain separate work.
