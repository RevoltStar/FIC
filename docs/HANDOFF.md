# FIC: передача контекста

## Current base

- Ветка: `main`.
- Родитель текущей правки: `90abe22`.

## Current task

- Сделать `/etc/resolv.conf` provider-aware без борьбы с generated files.

## Accepted architecture / invariants

- Static resolver file остаётся remediate-capable.
- Provider-managed final symlink target проверяется по exact profile allowlist,
  owner/group и maximum mode, но FIC не выполняет для него `fchown`/`fchmod`.
- Descriptor pinning и повторная проверка inode policy symlink сохранены.

## Completed

- Debian 12/13: systemd-resolved, NetworkManager и resolvconf targets.
- Ubuntu 24.04/26.04: systemd-resolved и NetworkManager targets.
- ALT p11: NetworkManager target; openresolv остаётся static topology.
- NetworkManager `no-stub-resolv.conf` и произвольные targets отклоняются.

## Changed areas

- Platform DAC provider metadata во всех пяти profiles и validation.
- `FileStats` сообщает закреплённый policy target; `ModeAndOwner` разделяет
  remediate и provider validate-only handling.
- Mode/profile tests и архитектурная документация.

## Validation

- `mode_and_owner_tests` и `platform_profile_tests` — passed для всех пяти
  target profiles в ALT builder container.
- Target `fic` built successfully для ALT p11 profile.
- Покрыты static/resolved stub/resolved non-stub/NetworkManager/resolvconf,
  arbitrary target, validate-only owner/mode и symlink replacement pinning.
- Реальные package experiments выполнены на Debian 12/13, Ubuntu 24.04/26.04
  и ALT p11; target matrix подтверждена package binaries/manpages/tmpfiles.

## Remaining

- Host CMake не имеет `libsystemd`; validation выполнена в контейнере.
- После этого коммита остаются задачи 5-6 из пользовательского списка.
