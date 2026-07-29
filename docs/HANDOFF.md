# FIC 2.0: передача контекста

Этот файл хранит актуальный снимок незавершенной работы. Обязательные правила и
границы компонентов находятся в `AGENTS.md`.

## Текущий снимок

- Обновлено: 2026-07-29.
- Ветка: `main`.
- Базовый commit: `5bedbc6`.
- Текущая задача: исправление ALT p11 package-transaction trigger после ошибки
  сборки `Macro %transfiletriggerin not found`.
- Исправление завершено и проверено, изменения пока не зафиксированы commit.

## Сделано

- В `PlatformProfile` добавлена секция `packageManager`: Debian 12 и Ubuntu
  24.04 используют `dpkg-query`, ALT p11 — `rpm`. Bootstrap query executable
  проверяется как root-owned regular executable с безопасными правами, но не
  включается в управляемый hash-реестр, чтобы не создавать циклическое доверие.
- Реестр `executables` расширен идентификаторами `Lscpu`, `Dmidecode` и
  `Udevadm`. Теперь trust sync покрывает также команды `fic-dick`, для которых
  ранее требовалось ручное заполнение hash; `Udevadm` подготовлен в том же
  профильном наборе для последующего перевода shell helper на resolver.
- Добавлена root-only offline-команда:

  ```text
  /opt/fic/bin/fic --trust-sync-platform
  ```

  Это не IPC-команда и она недоступна обычному daemon runtime.
- `PackageTrustSync` выбирает доступные executable через общий resolver,
  подтверждает точного владельца-пакет и сверяет содержимое файла:
  - для `dpkg` — с `md5sums` из control metadata;
  - для RPM — с `FILEDIGESTS`, поддерживая MD5/SHA-1/SHA-256/SHA-512.
- На merged-/usr системах alias из package metadata допускается только при
  совпадении device/inode с выбранным профильным путем.
- Если профильная утилита не установлена, она пропускается; если хотя бы один
  существующий кандидат имеет небезопасные метаданные, не принадлежит пакету
  или отличается от package checksum, операция завершается fail-closed без
  изменения hash-файла.
- В `CommandHashStore` добавлен `saveHashes()`: SHA-256 рассчитываются до
  загрузки/записи, все значения сохраняются одним атомарным `ConfigFileHandler`
  write с сохранением посторонних/ручных записей. Записи сериализованы общим
  PID/flock lock-файлом, поэтому IPC `hash calc` и package sync не теряют
  параллельные изменения.
- Debian/Ubuntu `fic` package:
  - выполняет первичный sync до включения systemd services;
  - устанавливает `interest-noawait` file triggers для `/usr/bin`,
    `/usr/sbin`, `/bin`, `/sbin`.
- ALT p11 `fic` package:
  - выполняет первичный sync до включения services;
  - устанавливает ALT-native `/usr/lib/rpm/fic-trust-sync.filetrigger`,
    реагирующий на изменения в тех же каталогах. Стандартная spec-секция
    `%transfiletriggerin` намеренно не используется: ALT RPM 4.13.0.1 не
    экспортирует этот macro, а выполняет executable `*.filetrigger` через
    собственный post-transaction dispatcher.
- Обычная проверка по `VerifiedProcessExecutor` не изменилась и никогда не
  принимает mismatch автоматически. `fic-cli hash calc` оставлен как явная
  административная break-glass операция.
- Обновлены unit/static tests, основные README, packaging README и
  `docs/architecture-diagrams.md`. Языковые policy-файлы не менялись:
  trust-sync запускается неинтерактивными package hooks и пишет техническую
  диагностику в stdout/stderr, а не пользовательские policy-сообщения.

## Локальные проверки

- Полная сборка всех целей для ALT p11 успешна:

  ```bash
  cmake -S . -B build-check -DFIC_TARGET_PLATFORM=alt-p11
  cmake --build build-check -j2
  ```

- `ctest --test-dir build-check --output-on-failure`: 13 тестов, 11 passed,
  `admin_socket_tests` и root-only `command_hash_batch_tests` штатно skipped
  (`SKIP_RETURN_CODE=77`) в непривилегированной среде.
- Для Debian 12 собраны `fic` и `platform_profile_tests`; обе
  `platform_profile_static_checks`/`platform_profile_tests` прошли.
- Для Ubuntu 24.04 также собраны `fic` и `platform_profile_tests`; обе
  профильные проверки прошли.
- `bash -n` успешен для Debian, Ubuntu и ALT packaging scripts.
- Локальный ALT RPM 4.13 query format проверен read-only: `FILEDIGESTS` для
  `/usr/bin/lscpu` и `/usr/bin/systemctl` возвращает ожидаемые 32-hex digests.
- Выполнена отдельная минимальная ALT `rpmbuild -bb` smoke-сборка пакета с
  `/usr/lib/rpm/fic-trust-sync.filetrigger`: сборка успешна, RPM автоматически
  добавил требование `rpmlib(PosttransFiletriggers)`.
- Новый helper проверен с подходящим и неподходящим списком файлов на stdin;
  `bash -n`, `platform_profile_static_checks` и `git diff --check` успешны.

Полные product package builds, установка/обновление пакетов,
`fic --trust-sync-platform` и policy apply не запускались. Выполнялась только
изолированная smoke-сборка тестового RPM без его установки.

## Что осталось

- Полный ALT package builder после исправления не перезапускался. Следует
  повторить команду, которая ранее завершалась на `%transfiletriggerin`, затем
  в disposable ALT p11 VM установить пакет, проверить первичное заполнение
  `commandhash.txt`, обновить `systemd`/`openssh` и убедиться, что native
  filetrigger обновляет только пакетно подтвержденные файлы.
- `fic-dick` пока использует свои hardcoded пути `lscpu`/`dmidecode`, а shell
  helper самостоятельно выбирает `udevadm`; trust sync уже заполняет hashes для
  их первых профильных путей. Если сами потребители должны использовать общий
  resolver, `fic-platform` нужно вынести из внутреннего `fic/src` в
  `fic-common`; internal headers демона нельзя подключать напрямую из
  `fic-dick`.
