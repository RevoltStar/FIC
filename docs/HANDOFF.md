# FIC: передача контекста

## Current base

- Ветка: `main`.
- Родитель текущей незакоммиченной правки: `d19fb2e`.

## Current task

- DAC-проверка provider-managed final symlink targets (`/etc/resolv.conf`):
  для каждого разрешённого target валидируется отдельный target-specific
  contract (owner/group/mode) вместо ожиданий исходного `FileAccessRule`;
  provider targets — validate-only (без chmod/chown).

## Accepted architecture / invariants

- `ProviderManagedFileTarget` в `PlatformProfile.h` несёт полный DAC contract:
  `path` + `provider` + `owner` + `group` + `permissions` (maximum-mode
  semantics, как у `FileAccessRule`).
- Контракты по платформам: `/run/systemd/resolve/{stub-,}resolv.conf` →
  `systemd-resolve:systemd-resolve 0644`; `/usr/lib/systemd/resolv.conf`,
  `/run/NetworkManager/resolv.conf`, `/run/resolvconf/resolv.conf` →
  `root:root 0644`. ALT p11 — только `/run/NetworkManager/resolv.conf`.
- `PlatformCompatibility::validatePlatformProfile` fail-closed валидирует
  metadata provider targets: absolute normalized path, непустые owner/group,
  permissions (не 0, без битов вне 07777), duplicate targets, валидный
  provider.
- `ModeAndOwner`: static path (regular file по policy path) — rule stats +
  remediation; provider target — target-specific `FileStats` expectation через
  `applyOpenedRule(..., validateOnly=true)`, target обязан быть regular file
  (проверка через `fstat` закреплённого дескриптора, `FileStats::file_type()` /
  `is_regular_file()`), при mismatch — FAIL без мутации.
- validate-only != trusted: полная валидация + report, но FIC не remediate
  provider targets (lifecycle принадлежит provider).
- Сохранены security invariants: descriptor/openat2 resolution, inode/topology
  verification, symlink 0777 не нарушение, no realpath()+stat().

## Completed

- Контракты зафиксированы во всех 5 профилях (Debian 12/13, Ubuntu
  24.04/26.04, ALT p11) на основе upstream-источников (systemd unit
  `User=systemd-resolve`, umask 022/fchmod 0644; NetworkManager/resolvconf —
  root:root 0644).
- Fail-closed валидация metadata в `PlatformCompatibility.cpp`.
- Target-specific validate-only логика в `ModeAndOwner.cpp` с
  expected/actual diagnostics и пояснением «FIC did not modify».
- `FileStats`: `file_type()` / `is_regular_file()` из `fstat` дескриптора.
- Тесты: `ModeAndOwnerTests.cpp` — provider-тесты под новые контракты +
  regression (иной owner/group → SUCCESS; wrong group → FAIL без мутации;
  stricter mode → SUCCESS; не-regular target → FAIL; remediation alias
  сохраняет remediation). `PlatformProfileTests.cpp` — полная проверка
  контрактов по всем профилям + negative-тесты валидации (empty owner/group,
  permissions 0 и вне 07777, duplicate, relative и non-normalized path).
- Обновлён authoritative раздел `/etc/resolv.conf` в
  `docs/architecture-diagrams.md`.

## Changed areas

- `fic/src/platform/PlatformProfile.h`, `PlatformCompatibility.cpp`,
  `fic/src/platform/profiles/*`.
- `fic/src/modules/dac/mode_and_owner/ModeAndOwner.cpp`.
- `fic-common/fic-core/include/fic/core/fs/FileStats.h`,
  `fic-common/fic-core/src/fs/FileStats.cpp`.
- `tests/fic/modules/dac/ModeAndOwnerTests.cpp`,
  `tests/fic/platform/PlatformProfileTests.cpp`.
- `docs/architecture-diagrams.md`.

## Validation

- Full build (`/tmp/fic-dev-build`, real source dir): success — все targets,
  включая `fic`, `fic-gui`, `fic-session-agent`, `fic-dick` и все тесты.
- Full CTest: 73/73 passed.
- `python3 tests/fic/platform/static_checks.py .` и
  `python3 tests/common/static_checks.py .`: exit 0.
- `git diff --check`: clean.
- Build-обход: на хосте нет libsystemd-devel — pkg-config переопределён через
  `PKG_CONFIG_PATH=/tmp/fic-dev-tree/pkgconfig` со stub `libsystemd.so`
  (символы sd-login/sd-daemon/sd-journal возвращают -ENOSYS/-ENXIO) и stub
  headers c `extern "C"`. Всё в `/tmp/fic-dev-tree/*` — вне git.

## Remaining

- Не проверялось: сборка с реальным libsystemd (нет в host-окружении; реальный
  build выполняется в distro containers), запуск на реальных дистро-средах,
  dpkg/rpm-lookup контрактов в runtime (сознательно не делается — контракты
  compile-time).
- Ключевой regression-тест проверен на старой реализации (временное отключение
  новой логики): тест падает, подтверждая, что он ловит регрессию.
- Коммит не создавать без отдельного явного запроса пользователя.

