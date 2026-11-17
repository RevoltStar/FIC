# Current workspace

## Current base / task
* Branch main; base `ca0e8b6a820ef80fc4de959af80734f1d74a84d0`.
* Five-distribution GitHub Actions CI configuration prepared in one thematic
  commit (HEAD). No push, no Actions dispatch. User will push/run CI separately.
* Explicit user boundary: NO configure/build/CTest/development checks, container
  builds/runs, integration tests or equivalent runtime validation in this task.

## Accepted contract / completed
* Native build-and-test matrix: ubuntu-24.04 and ubuntu-26.04 runners, matching
  FIC_TARGET_PLATFORM. Container matrix on ubuntu-24.04 host: debian:12 ->debian-12,
  debian:13 ->debian-13, registry.altlinux.org/p11/alt:latest ->alt-p11.
* Both matrices fail-fast:false, distinct build-and-test (<platform>) check names,
  no continue-on-error. Five full non-root variants plus unchanged Ubuntu24.04
  compiler-warnings and sanitizers jobs = seven total.
* Containers use jobs.container and explicit bash shell. Install native distro
  dependencies as root BEFORE checkout to ensure git/full provenance history;
  checkout@v6 fetch-depth:0, persist-credentials:false. Prepare fic-ci user/group
  and workspace ownership, then runuser -u fic-ci executes configure and existing
  scripts/run-development-checks.sh full. Inner UID!=0 guard, same cwd/build-ci
  paths for CMakeCache and git rev-parse. No alternate CTest filtering system.
* Native configure also guards UID!=0. Existing full script owns non-root CTest
  exclusion; sanitizer retains -L '^unit$' -LE '^root$' and all flags/options.
* Debian dependencies follow Debian Dockerfiles plus bash/CA/passwd/util-linux.
  ALT uses RPM Dockerfile's p11 mirror setup and package list, plus CI tools:
  git-core, bash, CA, file, passwd, shadow-utils, util-linux. No host build tools,
  libraries, Docker socket mounts, privileged flags, extra capabilities or services.
* Workflow triggers, contents:read, concurrency and warning/sanitizer job contents
  preserved. No production, tests, profiles, packaging or lifecycle modifications.

## Changed areas
* .github/workflows/ci.yml. No helper scripts added.
* This required AGENTS.md handoff snapshot.

## Validation (static only, actually executed)
* Read current CI/development script/profiles/CTest labels/all five packaging
  Dockerfiles and relevant CI/Dockerfile history before edits.
* YAML parsed with Python/PyYAML (on key handled as YAML1.2). Asserted five exact
  profile mappings against FicTargetPlatform.cmake, seven expanded variants,
  fail-fast:false, distinct names, checkout settings, non-root wrapper/cwd,
  unchanged compiler-warnings/sanitizers and workflow controls; PASS.
* Statically compared every distro Dockerfile dependency list to CI; PASS.
  Queried installed p11 RPM metadata read-only: runuser=util-linux,
  useradd=shadow-utils, git executable=git-core. Explicit CI packages reflect this.
* Read official Ubuntu26.04 package metadata HTML for all21 native dependency
  names, parallel bounded requests only; all FOUND, no packages/images downloaded.
* GitHub docs confirm ubuntu-26.04 runner, matrix.include, fail-fast, jobs.container
  and explicit shell requirement. Official Debian/ALT docs confirm image names.
* Final diff review and git diff --check PASS. NO builds or tests run by request.

## Remaining / limits
* Runtime success of all five jobs is NOT proved. User will push and supply actual
  Actions results; do not start local or remote jobs for this preparation task.
* Old `build-and-test` check context becomes five `build-and-test (<platform>)`
  contexts. Branch protection requiring old name may need manual rules updates;
  no repository settings changed, no aggregator job introduced.
* Official references: https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax
  https://docs.github.com/en/actions/reference/runners/github-hosted-runners
  https://hub.docker.com/_/debian
  https://docs.altlinux.org/ru-RU/platform/11.0/html-single/alt-platform/index.html
  https://packages.ubuntu.com/resolute/
