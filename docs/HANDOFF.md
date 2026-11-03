# Current workspace

## Current base
* Branch main; task base `e7acd8b847c95a5e31446df7ad49314fe817105e`.

## Current task
* Attachment a18db528: multi-file SSH Port ownership throughout the existing trusted Include graph. Three requested commits: foundation, apply/REFRESH, release/lifecycle. No push.

## Accepted architecture
* One journal operation under existing SSH mutex, complete per-file plan before CAS; separate conditional replacements with durable checkpoints. No physical multi-file atomicity, blind compensation or Prepared semantic recovery.
* Existing platform boundaries/launch/listener proofs remain. No suppression of ListenAddress, no Port normalization. Scalar policy semantics unchanged.
* Versioned SSH payload extension only; global journal schema remains 3. Historical single-file/fingerprinted and ID-only contracts retained without inferred historical fingerprints.

## Completed foundation
* Trusted read-only Port source capture reuses adapter capture/closure; same limits and profile boundary. Logical visits retained; unique physical source positions mapped; ambiguous aliases refuse. Recorded disconnected paths require current trusted coverage.
* Per-path creation fingerprints and v3 typed file plans/receipts extend existing SSH projection/transition. Attempt checkpoint precedes CAS; receipt/durability independent per file; common runtime phase cannot advance after partial publication. Pending gate remains shared by all SSH writers. No production apply switched yet.
* Journal round-trip/restart/partial-publication/malformed authority tests and recursive/repeated Include/Match source-map tests added.

## Validation
* Debian12 builder: mutation_journal_tests and ssh_verified_activation_tests built; CTest2/2 PASS (final rerun1.48s). Log build-ssh-owned-validation/multifile-foundation-ctest.log. Production sources mounted read-only; no host security changes.

## Remaining
* Foundation complete; continue with authorized per-file generation comparison; specialized Port plan/publication and apply/REFRESH; verified active/offline release, acknowledgement and final physical inspection across all known paths.
* Native five-platform gates and actual Debian12 package/CLI/SSH lifecycle; full build/CTest; docs/evidence. Existing SSSD source-bound evidence guard is known stale and must not be weakened or relabeled.
