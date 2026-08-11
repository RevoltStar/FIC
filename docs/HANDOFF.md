# FIC: передача контекста

Этот файл хранит актуальный снимок незавершенной работы. Обязательные правила и
границы компонентов находятся в `AGENTS.md`.

## Текущий снимок

- Обновлено: 2026-08-11.
- Ветка: `main`.
- Базовый commit: `0024bf9` (`Исправляем класс (и наследников) Mode_And_Owner`).
- Текущая задача: второй security/reliability pass для
  `ModeAndOwner`/`FileStats`/`ExclusivePidLock`.
- Реализация и локальные проверки завершены; изменения рабочей копии не
  зафиксированы commit.

## Сделано

- `ModeAndOwner::apply()` после успешного `fchown` перечитывает inode и только
  затем решает, нужен ли `fchmod`; сброшенные Linux биты SUID/SGID
  восстанавливаются в том же apply.
- `FileAccessRule` получил default-empty `allowedFinalSymlinkTargets`.
  Валидация требует для целей абсолютный, непустой, лексически нормализованный
  путь без дубликатов.
- Обычный путь сохраняет безопасную descriptor-модель и запрещает final
  symlink. Для явно разрешённого final symlink:
  - parent открывается от `/` через `openat2` без symlink-компонентов;
  - сам link закрепляется `O_PATH|O_NOFOLLOW` и читается через
    `readlinkat(fd, "")`;
  - относительная цель разрешается от parent и лексически нормализуется;
  - точное совпадение с allowlist открывается от `/` с
    `RESOLVE_IN_ROOT|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS`;
  - `fstat`/`fchown`/`fchmod`/verification выполняются на одном target inode.
- Если build headers не содержат `linux/openat2.h`, используется локальное UAPI
  объявление; если syscall отсутствует в runtime kernel, symlink exception
  отклоняется fail closed с `ENOSYS`. Небезопасного path-based fallback нет.
- Debian 12/13 и Ubuntu 24.04/26.04 разрешают для `/etc/resolv.conf` только
  `/run/systemd/resolve/stub-resolv.conf` и
  `/run/systemd/resolve/resolv.conf`. ALT p11 и все protected commands не имеют
  symlink exceptions. `custom_mode_and_owner` syntax не изменён и остаётся
  fail closed.
- Restriction info показывает allowlisted targets только у правил, где они
  действительно заданы.
- `FileStats::fromBorrowedDescriptor()` создаёт `F_DUPFD_CLOEXEC` duplicate с
  явной семантикой владения. `ExclusivePidLock` открывает lock-файл с
  `O_CLOEXEC|O_NOFOLLOW`; коррекция owner/group/mode, `flock`, PID I/O,
  `ftruncate` и `fsync` теперь относятся к одному inode.
- Добавлены тесты абсолютных/относительных/неожиданных symlink targets,
  нормализации `..`, запрета intermediate symlink, missing semantics, custom
  fail-closed, profile metadata/display/validation и one-inode PID lock.
- Архитектурная документация описывает flags, fail-closed fallback и остаточную
  namespace race.

## Изменённые файлы

- `fic-common/fic-core/include/fic/core/{FileStats,ExclusivePidLock}.h`;
- `fic-common/fic-core/src/FileStats.cpp`;
- `fic/src/modules/dac/submodules/ModeAndOwner.{h,cpp}` и три реализации в
  `modeandowner/`;
- `fic/src/platform/{PlatformProfile.h,PlatformCompatibility.cpp}`;
- профили Debian 12/13 и Ubuntu 24.04/26.04;
- `tests/dac/ModeAndOwnerTests.cpp`;
- `tests/paths/ExclusivePidLockTests.cpp`;
- `tests/platform/{PlatformProfileTests.cpp,static_checks.py}`;
- `tests/CMakeLists.txt`;
- `docs/architecture-diagrams.md` и этот файл.

## Выполненные проверки

- `cmake -S . -B build-check -DFIC_TARGET_PLATFORM=debian-12` — успешно.
- Полная сборка `cmake --build build-check -j2` — успешно.
- `ctest --test-dir build-check --output-on-failure -E release_contract_tests`
  — 30/30 успешно; три host-dependent теста корректно skipped.
- `platform_profile_tests` отдельно собран и успешно выполнен для
  `debian-13`, `ubuntu-24.04`, `ubuntu-26.04` и `alt-p11`; Debian 12 входит в
  основной CTest.
- `git diff --check` — успешно до финального обновления HANDOFF.
- Реальное применение политики к системным файлам и package builds не
  выполнялись.

## Ограничения и решения

- Conditional regression test смены owner/group и восстановления `04755`
  присутствует, но в текущем sandbox реальный chown на другой отображённый
  UID/GID недоступен (`EINVAL`), поэтому privileged ветка корректно пропущена.
- Link inode и его имя повторно сверяются по `st_dev/st_ino` перед возвратом
  target descriptor. Привилегированный конкурент может переименовать policy
  symlink после этой проверки. Это способно временно рассинхронизировать имя и
  применённое правило, но не перенаправляет операции на неожиданный inode:
  изменения остаются на уже открытой точной allowlisted цели.
- `release_contract_tests` не запускался в общем CTest из-за известного
  несвязанного рассинхрона package artifacts, зафиксированного в предыдущем
  снимке.
