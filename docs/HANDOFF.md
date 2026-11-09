# Current workspace

## Current base / task
* main; I1 base `27f974394afab1439e7eac847baab67bbaadd2db`.
* Attachment49f212a7 SSH Manager.Environment fix complete. This changeset is the one requested commit `fix(ssh): validate supported manager environment semantically`; no push. Stop after commit.

## Accepted architecture / invariants
* Only production edit: SshVerifiedActivationAdapter.cpp, pure finite-key classifier. Locale names bounded128 ASCII bytes; four exact PATHs; XDG list≤512 bytes/4 unique system dirs, single trailing slash, no user/traversal/empty dirs. Snap desktop export confirmed from installed Ubuntu26 snapd profile. Directory existence/recursive ownership are not new inputs.
* Default-deny loader/crypto/SSHD_OPTS/LANGUAGE/unknown keys; no values in diagnostics. Original full ManagerEnvironment remains in exact launch comparison (no normalization/filtering). Generic activator/DBus/process/runtime/ownership/REFRESH/rollback/journal/PAM/package contracts unchanged. Trusted OS/residual privileged ABA boundary retained.
* Native mutations ONLY guarded disposable systemd Docker, no runtime host binds/ports/network. SSH-only research VM used read-only for snapd package/profile inspection during I1; no restart, config or manager environment mutations there.

## Completed / changed areas
* SSH classifier + integrated unit positive/negative/type/bounds/diagnostic/no-normalization matrix.
* Existing native Driver hooks test21 environment races across before-admission-proof/publication/post-restart stages; new environment scenario has3 positives +unknown-key pre-save refusal.
* Real current-build CMake-installed daemon/fic-cli fixture (not DEB install): R1 and reported-XDG environments apply/owned journal/process/kernel listeners/-t/-T/repeat/RuntimeVerified disable/exact restore PASS.
* Native test-only fixes: explicit systemd PID1; usr-merge-safe staging; package-equivalent root0644 PAM payloads; Debian ss diagnostic image recipe; stale Port refusal checks now assert existing multi-file wrappers; Debian fsync fault assertion separates unusable-at-return from existing subsequent durable tryGet recovery with exact prior record retained. No journal/recovery production edit.
* Docs: adapter grammar + validation, native README, compact docs/ssh-manager-environment-validation.json. Raw evidence ignored build-ssh-i1/PROFILE/evidence; /tmp/ssh-i1-* logs.

## Validation
* Five native suites all exit0: Debian12/13 each30 generic +59 adapter +24 module groups; Ubuntu24.04/26.04 each52; ALT p11 65. Unit ssh_verified_activation_tests PASS each.
* Existing multi-file-smoke all5 exit0: apply/repeat/REFRESH/repeat/RuntimeVerified active release; exact Include files/fingerprints preserved and restored. Environment25 groups PASS; production daemon/CLI2 cases PASS.
* Ubuntu26 full project build PASS (build-pam-i1/ubuntu2604/i1-full-build.log).
* Corrected full CTest (Git safe.directory, drop DAC_OVERRIDE/DAC_READ_SEARCH):220 PASS,2 FAIL,4 opt-in native SKIP /226 (build-pam-i1/ubuntu2604/Testing/i1-full-ctest-corrected.log).
* Remaining FAILs: incident_state_lifecycle_static_checks, same assertion reproduced on clean base archive (old RPM attrs string check); identity_policy_hierarchy_tests, unchanged PAM-only target expecting obsolete Recommended activation dependency. Changed SSH adapter not linked into that target. Do not fix unrelated PAM/packaging automatically.
* SSSD I3/I4/I5 retained evidence checks PASS; SSSD I6 historical tests PASS; no SSSD native reexecution. PAM I6 current-source checker FAIL stale: accepted ddffb22f..., already-base manifest e3acc8db... differs. No replacement hashes or weakened gates.
* Python/Bash syntax, JSON/receipt checks and git diff --check PASS. Only production adapter differs; prohibited components unchanged.

## Remaining / limits
* No unfinished I1 functional work. One requested completion commit, no push or automatic further work.
* Full CTest is NOT all green:2 unrelated failures +4 opt-in skips explicitly retained. Full native package-manager lifecycle and authentication/session security not claimed. Historical evidence not relabelled as current native execution. Shared Docker/WSL kernel.
* Early exploratory failures (missing ss/image CMD/staging metadata/stale native assertions/one runner edited while active) were followed by successful final reruns; final source code/scripts frozen for accepted runs. Existing source-bound PAM receipts remain stale and require a separately authorized rerun if current PAM matrix is needed.
