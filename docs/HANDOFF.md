# Current workspace

## Current base / task
* Branch main; base `7fa70b279d2bfcfc0d3b88df37802205a8a42b36`.
* Removed forced Yandex mirror selection from ALT p11 CI in one thematic commit
  (HEAD). No push or Actions dispatch; user will run CI separately.
* User boundary remains: static checks only, NO configure/build/CTest,
  development checks, container runs/builds or integration tests.

## Accepted contract / completed
* ALT p11 container CI now retains the repositories configured by its image.
  Removed both disabling alt.list and enabling yandex.list. apt-get update/install
  and the dependency list are unchanged. Packaging Dockerfiles are unchanged.
* Existing CI matrices remain: native ubuntu-24.04/ubuntu-26.04 with matching
  profiles; debian:12/debian:13/registry.altlinux.org/p11/alt:latest containers
  with debian-12/debian-13/alt-p11 profiles on ubuntu-24.04 host.
* Both matrices fail-fast:false. Five full non-root variants plus the unchanged
  Ubuntu24.04 compiler-warnings and sanitizers jobs = seven variants.
* Container dependency installation/workspace preparation uses root, while
  configure and existing run-development-checks.sh full use fic-ci via runuser,
  guarded by UID!=0. Existing CTest filters and provenance checkout retained.

## Changed areas
* .github/workflows/ci.yml; this required handoff snapshot.

## Validation (static only, actually executed)
* Python/PyYAML parsed workflow and compared it to base: only the ALT repository
  rewrite commands/comment removed; all other job fields, dependencies and
  matrix entries unchanged. No apt sources rewriting remains in ALT CI. PASS.
* Final diff review and git diff --check PASS.
* NO builds, tests, containers or GitHub Actions run by user requirement.

## Remaining / limits
* Runtime behavior awaits user-triggered CI; image defaults are not overridden.
* Five build-and-test (<platform>) check contexts replaced old build-and-test;
  branch protection requiring the old name may need manual adjustment.
