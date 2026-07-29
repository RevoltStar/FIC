# FIC 2.0: передача контекста

Этот файл хранит актуальный снимок незавершенной работы. Обязательные правила и
границы компонентов находятся в `AGENTS.md`.

## Текущий снимок

- Обновлено: 2026-07-29.
- Ветка: `main`.
- Базовый commit: `0d40820`.
- Текущая задача: отдельный compile-time профиль и пакетирование для Debian 13.
- Реализация завершена и локально проверена, изменения пока не зафиксированы
  commit.

## Сделано

- Добавлен `fic/src/platform/profiles/Debian13Profile.cpp`:
  - профиль имеет идентификатор `debian-13`;
  - runtime compatibility требует `ID=debian` и `VERSION_ID=13`;
  - используется пакетная база `dpkg`;
  - SSH, sudo, display-manager и DAC paths заданы отдельно от Debian 12;
  - для завершенного в Debian 13 merged-/usr перехода `df` задан каноническим
    путем `/usr/bin/df`.
- `debian-13` зарегистрирован в `cmake/FicTargetPlatform.cmake` как отдельное
  допустимое значение `FIC_TARGET_PLATFORM`.
- Общий Debian-family builder принимает `debian-13` и создает пакеты с тегом
  `debian13`.
- Добавлены отдельные entry points:
  - `packaging/deb/build-fic-debian13-deb.sh`;
  - `packaging/deb/build-fic-debian13-deb-docker.sh`;
  - `packaging/deb/Dockerfile.debian13` на базе `debian:13`.
- Статические и C++ profile tests расширены проверками регистрации,
  пакетирования, точного `VERSION_ID`, SSH/GDM и merged-/usr путей Debian 13.
- Обновлены `README.md`, `fic/README.md`, `packaging/deb/README.md` и
  `AGENTS.md`.
- Архитектурные границы и формат IPC не менялись; изменения
  `docs/architecture-diagrams.md` не требуются.

## Локальные проверки

- Полная конфигурация и сборка всех целей успешны:

  ```bash
  cmake -S . -B build-check-debian13 -DFIC_TARGET_PLATFORM=debian-13
  cmake --build build-check-debian13 -j2
  ```

- `ctest --test-dir build-check-debian13 --output-on-failure`: 13 тестов,
  11 passed; root-only `admin_socket_tests` и `command_hash_batch_tests`
  штатно skipped (`SKIP_RETURN_CODE=77`).
- `build-check-debian13/fic/fic --version` выводит:

  ```text
  fic 2.0 target-platform=debian-13
  ```

- `tests/platform/static_checks.py`, `bash -n` для общего и новых Debian 13
  builders, а также `git diff --check` прошли.

Полная Docker-сборка `.deb`, установка пакетов, package trust sync и реальные
policy apply не запускались.

## Что осталось

- Собрать комплект командой
  `./packaging/deb/build-fic-debian13-deb-docker.sh 0.1.0`.
- Установить полученные пакеты в disposable Debian 13 VM и проверить:
  - успешный `postinst` и первичный `fic --trust-sync-platform`;
  - запуск `fic.service`, `fic-device.service` и session agent;
  - package transaction trigger после обновления `systemd` или `openssh`;
  - SSH/GDM/DAC policies на фактически установленном наборе пакетов.
- Read-only проверка ранее использовавшейся VM `172.17.1.105` не выполнена:
  в текущем `known_hosts` нет закрепленного ED25519 host key. Проверка
  `StrictHostKeyChecking` намеренно не ослаблялась.
