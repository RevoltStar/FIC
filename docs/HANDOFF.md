# Current workspace

## Current base / task
* main; base `69cdb12df31e26562c63655edb92d9b810a02565`.
* Attachment 1fd56dc8: PAM I6 source-manifest follow-up; one commit `test(pam): bind I6 evidence to native runtime inputs`, no push. Stop after completion.

## Accepted architecture / invariants
* Test-only: no production PAM/registry/Required/C2/ALT topology/MutationJournal/rollback/package payload changes. R1–I5 algorithms/evidence untouched.
* I6 runner/checker share `i6-source-manifest.py`: deterministic tracked path + NUL + SHA256(content). Legacy source roots/extensions plus `.in` templates, native PAM payloads, config/lang resources, runtime recipe and actual packaging static-test inputs. Docs/generated evidence excluded; image/package/binary receipts remain separate.
* L1/L2/L3 evidence does not establish daemon/CLI/systemd L4. All native account/PAM/shadow/TCB changes only disposable Docker; no host mutation.
* Existing supplemental results retain original source/binary/package receipts; not relabelled as current reruns. Their production/payload/gate subjects are unchanged.

## Completed / changed areas
* Shared I6-only manifest helper; historical receipt branch in run-i1.sh unchanged.
* Isolated-checkout regressions exercise real checker: relevant input mutation invalidates hash/evidence; docs/generated evidence do not. Original checkout/resources never modified by negative tests.
* Research §14 documents exact input scope and evidence boundary.

## Validation
* Repeated `FIC_PAM_GATE_STAGE=i6 bash tests/integration/pam-dependencies/run-i1.sh TAG PLATFORM BUILD_DIR` + `run-functional.sh TAG BUILD_DIR` on Debian12/13, Ubuntu24.04/26.04, ALT p11: fic/affected targets build PASS, 25/25 relevant CTest each, registry/Required audit and native functional reports PASS (246 main consumer operations).
* All5 before==after source: `ddffb22f1c6739303a70d4597e5fd3f67495e3c4b2a1b4f06b3ec5c154bddd2c`; 1226 tracked inputs. Observed 35 packaging static-test reads all included. Old source evidence rejected before rerun.
* `python3 tests/integration/pam-dependencies/check-i6-evidence.py build-pam-i6` PASS current-source L1/L2/L3, no active final journal ownership.
* `python3 tests/integration/pam-dependencies/test-i6-source-manifest.py build-pam-i6` PASS stable hash +14 mutation cases (12 invalidate hash/checker, 2 docs/evidence remain valid); resources restored in isolated checkout.
* Binary/consumer/image/package receipts match the previous accepted run all5; no supplemental subject changes. Original supplementary receipts/results preserved separately in compact evidence. Main native runs actually repeated; no source hash substitution.
* Bash syntax, Python compilation and git diff --check PASS. Compact evidence updated; historical R1–I5 unchanged.

## Remaining / limits
* No mandatory follow-up work remains. This changeset is the single completion commit requested above; no push or further I6 changes.
* No production/source payload changes, no new PAM scenarios, full-project CTest or daemon/CLI/systemd L4. Existing I6 limits (root not locked, reset rather than timeout expiry, domain/GUI infrastructure absent, legacy NotEnrolled/ABA/CAS boundaries) unchanged.
* Raw current evidence: ignored build-pam-i6; supplemental source receipts retain their original algorithm and are not claims of new complete-manifest runs. Accepted compiled/runtime subjects and tracked payload bytes unchanged from base; historical evidence not upgraded retroactively.
