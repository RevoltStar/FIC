# FIC 2.0: передача контекста

Этот файл хранит актуальный снимок незавершенной работы. Обязательные правила и
границы компонентов находятся в `AGENTS.md`.

## Текущий снимок

- Обновлено: 2026-07-29.
- Ветка: `main`.
- Базовый commit: `833da90`.
- Текущая задача: единый distribution-specific реестр исполняемых файлов,
  используемых политиками демона.
- Реализация завершена, проверена и зафиксирована текущим коммитом.

## Сделано

- В `PlatformProfile` добавлен типизированный `executables`-реестр. Он содержит
  `PlatformExecutableSpec` с логическим `ExecutableId`, упорядоченными
  кандидатами и признаком обязательности.
- Поддерживаемые идентификаторы: `Sshd`, `Systemctl`, `Loginctl`, `Visudo`.
  Кандидаты объявляются ровно один раз в профилях Debian 12, Ubuntu 24.04 и
  ALT p11; из секций `ssh`, `sudo` и удалённой `systemTools` копии списков
  удалены.
- Добавлен общий `PlatformExecutableResolver`. Он:
  - выбирает первый пригодный профильный кандидат;
  - требует абсолютный нормализованный путь, обычный исполняемый файл без
    конечного symlink;
  - в production требует владельца root и запрещает запись group/others;
  - кэширует выбор, но повторно проверяет кэшированный путь при каждом
    обращении и при его инвалидировании снова перебирает кандидатов;
  - возвращает подробную fail-closed диагностику по каждому отвергнутому пути.
- Проверка профиля требует ровно по одной корректной записи для каждого
  поддерживаемого `ExecutableId`, отклоняет неизвестные/повторяющиеся ID,
  пустые, относительные, ненормализованные и повторяющиеся пути.
- Все daemon-потребители профильных команд переведены на resolver:
  - SSH runtime получает `Sshd` и `Systemctl`;
  - sudo получает `Visudo`;
  - блокировка и перечисление графических сессий получают `Loginctl`;
  - display-manager policies получают `Systemctl`.
- `init_policyMap()` и IPC reload сохраняют один resolver на весь срок жизни
  daemon и передают его политикам по ссылке.
- Для Debian канонические `/usr/bin/systemctl` и `/usr/bin/loginctl` поставлены
  первыми, а `/bin/...` оставлены fallback-кандидатами. Это исключает
  расхождение между выбранным путем и ключом hash-хранилища на usrmerge-системе.
- Существующая модель hash-проверки сохранена: привилегированные вызовы
  `sshd`, `systemctl`, `loginctl lock-sessions` и `visudo` по-прежнему идут
  через `VerifiedProcessExecutor`. Resolver не принимает новый hash
  автоматически во время runtime.
- Обновлены unit/static tests, `README.md`, `fic/README.md` и архитектурная
  диаграмма.

## Локальные проверки

Успешно выполнена полная сборка ALT p11:

```bash
cmake -S . -B /tmp/fic-executables-build \
  -DFIC_TARGET_PLATFORM=alt-p11 -DBUILD_TESTING=ON
cmake --build /tmp/fic-executables-build -j2
ctest --test-dir /tmp/fic-executables-build --output-on-failure
```

Собраны все цели. Из 12 CTest-проверок 11 прошли, `admin_socket_tests` штатно
пропущен с `SKIP_RETURN_CODE=77`; ошибок нет.

Для Debian 12 и Ubuntu 24.04 отдельно полностью собран daemon и выполнен
`platform_profile_tests`:

```text
debian-12: passed
ubuntu-24.04: passed
alt-p11: passed
```

Также успешно выполнен `git diff --check`. Реальные package builds и runtime
policy apply не запускались.

## Что осталось

- Централизация путей намеренно не решает автоматическое доверенное первичное
  заполнение `/opt/fic/db/commandhash.txt`. Следующий отдельный этап —
  package-transaction trust sync: package hooks/triggers должны перечислять
  тот же `executables`-реестр, доверять только пакетно подтверждённым файлам и
  никогда не принимать runtime mismatch автоматически.
- `lscpu` и `dmidecode` в `fic-dick`, а также shell helper
  `fic-udevadm-trigger` не относятся к daemon policy registry и пока не
  переведены. Если реестр должен стать общим для нескольких executables,
  `fic-platform` следует вынести из внутреннего `fic/src` в отдельную общую
  библиотеку; нельзя подключать internal headers демона напрямую из
  `fic-dick`.
