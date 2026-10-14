# Current working state

## Current base
* Branch `main`; USER_CREATION task base `dc1b746dd40d30108b0ffb7d4a917610accd0cf4` (completed SUDO C).
* Completion commit is HEAD after final validation; resolve exact SHA with `git log -1`. No push.

## Current task
* USER_CREATION mandatory ownership apply/rollback for seven policies; native Podman five-platform acceptance. Implementation and all mandatory gates complete. User-authorized completion commit; no push.

## Accepted architecture / invariants
* Every enabled supported USER_CREATION policy owns a journal-proven sub-block even on compliant foreign defaults. Only proven effective owned repeat is zero-write; refresh A→B is one CAS replacement.
* Shared IdentityLoginDefs backend retained. Typed ownership in central policy specs: USER_CREATION OwnWhileEnabled; PASSWORD_AGING ObserveCompliantForeign (old fresh no-op preserved).
* Rollback releases current exact ownership, preserves current foreign bytes/peer owners, removes final container; never restores foreign history. Prepared recovery, orphan/drift refusal, symlink/CAS/durability protections unchanged.
* GROUP and USERGROUPS_ENAB independent, no dependencies/automatic coupling. GROUP is an existing local name, not numeric GID; SUCCESS describes configured native default, not unconditional actual account group.
* D12/U24 supplementary adduser ADD_EXTRA_GROUPS/EXTRA_GROUPS; empty owns only flag0. D13/U26 useradd GROUPS; empty always GROUPS=. ALT supplementary Unsupported.
* All actual account/group/native /etc experiments ONLY disposable Podman, source read-only, build-cache writable, no host security mounts/apply.

## Completed / changed areas
* Removed USER_CREATION fresh foreign no-op; two shared policies opt into mandatory ownership. RU/EN descriptions explain GROUP/private-group interaction.
* Existing foreign-compliance tests retained/converted; per-route ownership lifecycle matrix includes current foreign changes, peers, drift/orphan/CAS, Prepared recovery, external/repeated release. PASSWORD_AGING regression retained.
* tests/integration/user_creation: actual production driver, OS compatibility check, native gate, focused build, reproducible runner and distro adduser runtime preparation.
* docs/rollback.md, architecture-diagrams.md and user-creation-native-validation.md describe lasting contract/native evidence.

## Validation
* Final user_creation_tests + identity_login_defs_tests PASS as part of full CTest, including all additional ownership cases.
* Native five-platform matrix PASS with actual vendor shadow/adduser, all4 GROUP×USERGROUPS combinations, real HOME/SKEL/SHELL/create-home/accounts/memberships, CLI overrides. Final frontend distinctions PASS; counts D12/U24=118 each, D13/U26=120 each, ALT=100; total576,0 FAIL0 SKIP. /tmp/podman-fic-UC-final.log.
* Per-policy real process cuts Prepared before/after:68 crashes across five rows. ALT supplementary explicit Unsupported refusal,6 supported policies.
* Full configure/build PASS; final non-root CTest181/181 PASS (15 static checks included), /tmp/fic-UC-configure.log and /tmp/fic-UC-final-{build,ctest}.log. Root-only2/2 PASS in Debian12 Podman with DAC_OVERRIDE/DAC_READ_SEARCH dropped (build-sudo-native/debian12/root-tests-UC-{build,ctest}.log).
* Bash syntax and packaging language staging inspected; no packaging contract change.

## Remaining / known limits
* No required unfinished work. Final diff reviewed, bash syntax and git diff --check PASS. Task committed after validation; no push.
* Existing conditional CAS is not kernel-atomic against arbitrary writers. Process cuts are not physical power-loss tests.
* No universal account-creation interception, no existing-account mutation, no ALT supplementary provider, no arbitrary frontends/-r/LDAP guarantee. See native report for scope and commands.
