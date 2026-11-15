# Current workspace

## Current base / task
* Branch `main`; I2 base `332be35f254a7daa17887239ef7bddae78cef7d5`.
* I2 direct shared publication for trusted SSH paths is complete. Requested commit: `fix(service): support bounded shared publication for verified SSH activation`; no push.

## Accepted architecture / invariants
* Internal `PublicationPropagationPolicy`: `RequireNonShared` default; SSH explicitly selects `AllowKnownShared` in captureReference, activation and release snapshot validation. Public/generic and SSSD remain strict. No public/env permission switch.
* Unknown optional metadata always refused. Effective parent statx mount ID, target/source/type/object/RO/manifest/EROFS, launch/runtime and A/C/P/listener proofs preserved. `Operation::cleanup` unchanged from base; no ownership/journal/lifecycle changes.
* Success cleanup is LOCAL to FIC/PID1/target namespace. T2/T3 nested downstream mounts can retain propagated RO copies after local Success. No private boundaries, global scanner, forced/lazy cleanup or adoption.

## Completed / changed areas
* Five production files in `fic/src/service/`: MountSupport h/cpp, ActivationProof.h, ServiceActivator.cpp, ssh/SshVerifiedActivationAdapter.cpp.
* Generic T1–T4/shared-root native tests and default/unknown-metadata units; SSH `shared` native scenario; SSSD I3 `shared-boundary` scenario included in source manifest.
* Contract docs and historical audit distinction updated. Authoritative results/versions/receipts: `docs/ssh-shared-publication-validation.md`.

## Validation
* Generic Ubuntu26 native: **208 PASS, 0 SKIP**, including prior private/non-shared slave/negative tests, T1–T4, root/run shared.
* Shared production SSH lifecycle: **PASS on Debian12/13, Ubuntu24/26, ALT p11**, 8 groups per platform (apply/repeats/cold receipt/RO/active release/REFRESH/drift/cleanup failure/offline validation).
* Existing SSH private/service/socket gates: **PASS**, Debian12/13 30 cases each; Ubuntu24/26 52 each; ALT 65 groups.
* SSSD Ubuntu26 private A/B/C/P/EROFS and shared/shared-slave refusal without restart: **PASS**; source/completion receipt verified. Not a full new SSSD native matrix.
* Full real-PAM/Qt Debian12 configure/build **PASS** (`build-i2-full`, no stubs). Targeted and all service/SSSD CTests **PASS**; harness self-test, shell/Python syntax, diff check **PASS**.
* Full CTest root: **219 PASS / 4 SKIP / 6 FAIL**. Five pre-existing failures reproduced from clean base: path layout, platform profile, incident lifecycle and DE architecture static checks; identity hierarchy (separately built/run). Mutation journal permission-fault test fails under root, PASS nonroot.
* Additional full UID1000 run without passwd identity: **204 PASS / 13 SKIP / 12 FAIL**; additional root/account-sensitive failures (incl. mode/owner segfault and incident group abort) do not occur in root run. See validation doc; no unrelated fixes or green-suite claim.

## Remaining / limits
* No unfinished I2 implementation. VM smoke **NOT_RUN**: snapshot/clone + console not confirmed; no real VM/host SSH/mount/security changes. Containers share Docker/WSL kernel; no global cleanup/authentication guarantee.
* First Ubuntu26 shared run had one fail-closed `descriptor identity unavailable`; later full reruns PASS without production changes. Cause not established. Saved failure `/tmp/fic-i2/ubuntu2604-initial-failure.json`.
* Raw reports/build logs `/tmp/fic-i2/`; SSSD receipt `build-sssd-i3/ubuntu-26.04/native/`. Build artifacts are not committed.
* Baseline CTest failures and nonroot suite prerequisites remain outside I2. Do not start a follow-up without a new task.
