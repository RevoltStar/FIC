# FIC: передача контекста

## Current base

- Дата: 2026-08-21.
- Ветка: `main`.
- Базовый commit задачи: `8c89200` (`Разделение операций в gui на "Сохранить" и "Сохранить и Применить"`).

## Current task

- Исправление ошибок применения DAC/GRUB-политик на ALT Workstation K 11.4.

## Accepted architecture / invariants

- Штатные package-owned symlink ALT разрешаются только через точные
  `allowedFinalSymlinkTargets`; общий fail-closed запрет symlink не ослабляется.
- GRUB-политики редактируют канонический regular defaults file платформы, чтобы
  сохранить существующую atomic write и `rejectSymlink` модель.

## Completed

- ALT p11 GRUB defaults path изменён с symlink `/etc/default/grub` на
  `/etc/sysconfig/grub2`.
- Для DAC объявлены точные связи `/etc/sysctl.conf` →
  `/etc/sysctl.d/99-sysctl.conf` и `/etc/grub.cfg` → `/boot/grub/grub.cfg`.
- Platform contract/static tests и профильная документация обновлены.

## Changed areas

- `fic/src/platform/profiles/AltP11Profile.cpp`;
- `tests/platform/PlatformProfileTests.cpp`, `tests/platform/static_checks.py`;
- `fic/README.md`, `docs/architecture-diagrams.md`.

## Validation

- `python3 tests/platform/static_checks.py .` — успешно.
- `git diff --check` — успешно.
- Сборка и compiled tests не запускались по прямому запросу пользователя.

## Remaining

- После сборки нового ALT p11 пакета требуется staging-проверка применения
  `blocking_user_access_to_system_files`, `grub_timeout` и
  `grub_disable_recovery` на штатной package layout.
