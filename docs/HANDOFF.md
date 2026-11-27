# DM inventory property batching

## Current base

Branch main; base 3fb17c7d7afe39e4ac6b0856dd983f3fa62b970b.

## Current task

Completed bounded systemctl show batching; local commit only, no push.

## Accepted architecture / invariants

Sequential batches of at most 32 over the unchanged validated unit union.
Exact Id/Names matching and per-request coverage, independent of response order.
Identical canonical repeats accepted; missing/conflicting/ambiguous/truncated
replies fail closed without fallback. Native empty/repeated ExecStart retains
old empty/last-command classification. Existing ProcessExecutor limits remain.
No changes to inventory modes, PackageQuery consumers, executable trust,
default selection/logind, SDDM proof, ownership/journal or transaction rechecks.
No atomic snapshot claim.

## Completed / changed areas

Production DisplayManagerInventory parser/query loop and existing DM suite.
Native two-production-driver comparison in tests/integration/dm-inventory,
including complete requested-name property coverage and retained plain JSON.
Architecture/validation/native README updated.

## Validation

Target builds display_manager_transaction_tests, policy_save_dependency_tests,
policy_execution_planner_tests passed. Root DM suite passed in disposable Docker;
five planner/save/package/architecture/UI CTests passed.
Logs /tmp/fic-dm-opt/batch-tests-final.log, batch-contract-tests.log,
batch-final-build.log. Shell syntax, Python compile and git diff --check passed.
Native final results and limitations: docs/graphical-scope-validation.md and
tests/integration/dm-inventory/batch-evidence/. The runner uses systemd PID1,
real ProcessExecutor and the inventory Run seam; not the executable-trust
constructor. Existing deterministic tests retain trust/full-mode coverage.

## Native results

All five native property/classification comparisons passed (Debian12/13,
Ubuntu24/26, ALT p11); three repetitions each. Show calls 110–157 → 4–5.
No control probe exceeded 250 ms. Final logs: /tmp/fic-dm-opt/*-batch-complete.log.
Implementation complete; one local completion commit, no push.

## Remaining / limits

No unfinished implementation or known task blockers.
No full project build/CTest, real DM/login enforcement, host state changes or
cold-HDD tests. Historical research evidence remains separate from this matrix.
