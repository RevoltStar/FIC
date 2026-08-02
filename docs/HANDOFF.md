# FIC 2.0: передача контекста

Этот файл хранит актуальный снимок незавершенной работы. Обязательные правила и
границы компонентов находятся в `AGENTS.md`.

## Текущий снимок

- Обновлено: 2026-08-02.
- Ветка: `main`.
- Базовый commit: `c6f7ee6`.
- Текущая задача: удалить неподдерживаемую на всех четырех целевых платформах
  SYSCTL-политику `kernel.exec-shield`.
- Изменения рабочей копии не зафиксированы commit.

## Сделано

- Политика `kernel_exec_shield_enable` удалена из `init_policyMap()` и общего
  заголовка регистрации политик.
- Удалены класс `SYSCTL_buffer_overflow_protection`, его заголовок и исходник;
  мертвая capability-заглушка не оставлялась.
- Удалены default config-поля политики из `SYSCTL.conf` и название/описание из
  обеих локализаций.
- Добавлена статическая регрессия, запрещающая возвращать `kernel.exec-shield`,
  старый policy ID или имя удаленного класса в runtime-дерево `fic`.
- Число зарегистрированных в конфигурациях политик уменьшилось с 68 до 67.

## Измененные файлы

- `fic/src/core/main_function.{h,cpp}`;
- удалены
  `fic/src/modules/sysctl/submodules/globalkernelprotection/SYSCTL_buffer_overflow_protection.{h,cpp}`;
- `fic/src/scripts/config/SYSCTL.conf`;
- `fic/src/scripts/lang/{ru,en}.lang`;
- `tests/platform/static_checks.py`.

## Выполненные проверки

- `python3 tests/platform/static_checks.py .`: успешно.
- Поиск старого sysctl, policy ID и имени класса: в runtime-коде и данных
  совпадений нет; строки остались только в запрещающей регрессии.
- Проверка инвентаря default config: 67 policy status entries.
- `git diff --check`: успешно.
- Release-сборка цели `fic` с профилем `alt-p11`: успешно.
- `platform_profile_static_checks` и `sysctl_configuration_tests`: 2 теста,
  ошибок нет.
- Реальные sysctl, `/opt/fic`, службы и политики хоста не изменялись.

## Что осталось

- Пункт production readiness о квалификации остальных 67 политик не закрыт:
  нужны runtime applicability contract и живая VM-матрица Debian 12/13,
  Ubuntu 24.04 и ALT p11.
- Для upgrade-контракта из предыдущей задачи остается package-manager проверка
  на disposable VM: install, upgrade/resume, manual rollback и remove.

## Риски и решения

- Существующий pre-release `SYSCTL.conf`, сохраненный package manager как
  conffile, может оставить две неиспользуемые строки старой политики. Демон их
  не регистрирует и не применяет. Миграция или compatibility alias намеренно не
  добавлены: стабильных релизов нет, а текущие правила требуют чистого удаления.
- Компиляция платформенного профиля не является квалификацией поведения на этой
  ОС. Живое применение `kernel.exec-shield` не запускалось, поскольку пользователь
  уже подтвердил отсутствие параметра на всех четырех целевых ядрах.
