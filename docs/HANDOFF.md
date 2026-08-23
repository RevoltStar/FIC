# FIC: передача контекста

## Current base

- Дата: 2026-08-23.
- Ветка: `main`.
- Базовый commit задачи: `9d56ff9`.

## Current task

- Debian/Ubuntu package integration для по умолчанию выключенных
  `pam-auth-update` profiles FIC без изменения PAM policy architecture.

## Accepted architecture / invariants

- PAM policies по-прежнему только inspect/prove/configure provider options/
  verify; они не устанавливают packages, не вызывают `pam-auth-update` и не
  меняют topology.
- Debian/Ubuntu package владеет declarations в `/usr/share/pam-configs/`, а
  администратор явно активирует их. Источник истины после активации —
  `PamConfiguration` -> `PamControlFlowAnalyzer` -> `PamCapabilityVerifier`.
- ALT p11 не получает Debian profiles, dependency или maintainer-script calls;
  будущая интеграция должна отдельно использовать штатный ALT mechanism.

## Completed

- В DEB `fic` добавлены физические profiles `fic-faillock-notify` (1025),
  `fic-faillock` (0) и `fic-pwhistory` (1023), все `Default: no` и без policy
  values.
- Добавлены прямые dependencies `libpam-runtime`, `libpam-modules`.
- `postinst configure` вызывает `pam-auth-update --package`; `prerm remove`
  снимает все три profiles до удаления payload. `--enable` и `--force` не
  используются, upgrade не сбрасывает выбор администратора.
- Добавлен отдельный packaging contract test и verifier fixture ожидаемого
  generated PAM stack; обновлены architecture и DEB/RPM package docs.

## Changed areas

- `packaging/deb/`, включая новые `pam-configs/fic-*`;
- PAM/packaging tests и `tests/CMakeLists.txt`;
- `docs/architecture-diagrams.md`, DEB/RPM packaging README.

## Validation

- `cmake -S . -B build-check -DFIC_TARGET_PLATFORM=ubuntu-24.04` — успешно.
- `cmake --build build-check -j2` — полный build успешно.
- Целевые PAM/policy/package/platform tests — 4/4 успешно.
- Нативная сборка Ubuntu 24.04 всех пяти DEB с version
  `0.0.0-pam-integration` — успешно; artifact `fic` проверен через `dpkg-deb`:
  profiles являются regular files 0644, dependencies и maintainer scripts
  соответствуют контракту, conffiles и запрещённых flags нет.
- Полный CTest: 37 passed, 4 sandbox-dependent skipped, новый test включён;
  один известный несвязанный failure `ipc_protocol_validation_tests` на
  assertion для status request.
- `bash -n` для DEB/RPM builders и `git diff --check` — успешно до финального
  обновления HANDOFF.

## Remaining

- Реальный `pam-auth-update` и активация PAM profiles не запускались: ordering
  проверен безопасным fixture и semantic verifier, но нужна staging runtime
  проверка на поддерживаемых Debian/Ubuntu profiles.
- ALT RPM в этой среде не собирался; отсутствие Debian integration проверено
  статически. ALT-specific `pam-config` / `pam-config-control` integration
  остаётся отдельной будущей задачей.
- Несвязанный `ipc_protocol_validation_tests` в scope задачи не исправлялся.
