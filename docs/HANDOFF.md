# FIC: передача контекста

Этот файл хранит актуальный снимок незавершенной работы. Обязательные правила и
границы компонентов находятся в `AGENTS.md`.

## Текущий снимок

- Обновлено: 2026-08-11.
- Ветка: `main`.
- Базовый commit: `83596e6` (`Исправляем архитектуру хранения и пакетирования конфигурации`).
- Текущая задача: исправление `ModeAndOwner::apply()` и `FileStats`.
- Реализация и локальные проверки завершены; изменения рабочей копии не
  зафиксированы commit.

## Сделано

- `FileStats` читает полный permission mode по маске `07777`, включая SUID,
  SGID и sticky bit.
- Path-based `stat/chown/chmod/stat` заменён на один RAII descriptor:
  `open(O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK)`, `fstat`, `fchown`, `fchmod` и
  контрольный `fstat` выполняются для одного открытого объекта.
- Конечные symlink запрещены и дают `ELOOP`; target symlink не изменяется.
  Только `ENOENT` считается отсутствием, остальные open/fstat errors являются
  failure.
- `FileStatsOperationResult` сохраняет operation/path, `std::error_code`,
  системное описание и errno. NSS lookup использует reentrant API и различает
  отсутствующий owner/group от системной lookup error.
- Добавлен явный `MissingFilePolicy`: системные profile policies используют
  `Ignore`, `custom_mode_and_owner` использует `Fail`.
- Удалены fallback неизвестной группы в `root` и мутация `expected`.
  Отсутствующие expected owner и group обрабатываются симметрично как failure.
- Итог `ModeAndOwner::apply()` определяется отдельными флагами ownership,
  permissions и verification, а не количеством diagnostic strings. Все
  причины логируются; частично успешные изменения не откатываются, итоговый
  public result остаётся `bool`.
- `ExclusivePidLock`, единственный другой consumer изменённых методов
  `FileStats`, переведён на новый result и логирует системную причину.
- Архитектурная документация дополнена fd/symlink/missing semantics.

## Изменённые файлы

- `fic-common/fic-core/include/fic/core/FileStats.h`;
- `fic-common/fic-core/src/FileStats.cpp`;
- `fic-common/fic-core/include/fic/core/ExclusivePidLock.h`;
- `fic/src/modules/dac/submodules/ModeAndOwner.{h,cpp}`;
- три policy implementation в
  `fic/src/modules/dac/submodules/modeandowner/`;
- `tests/dac/ModeAndOwnerTests.cpp`, `tests/CMakeLists.txt`;
- `docs/architecture-diagrams.md`.

## Тестовое покрытие

`mode_and_owner_tests` проверяет:

- actual `04755` против expected `0755` и expected `04755`;
- SGID/sticky comparison (`03775`);
- remediation `0755 -> 04755` и `04755 -> 0755` с post-verification;
- Ignore для missing profile system file/command и Fail для missing custom path;
- symlink rejection, сохранение `ELOOP`, неизменность link target;
- unknown group/owner без fallback и неизменность `expected`;
- partial success без rollback и сохранение нескольких diagnostics одной
  категории;
- `fchown` failure и логирование syscall cause (на non-root test runner).

## Выполненные проверки

- `cmake -S . -B build-check -DFIC_TARGET_PLATFORM=debian-12` — успешно.
- Полная сборка `cmake --build build-check -j2` — успешно.
- `ctest --test-dir build-check --output-on-failure -E release_contract_tests`
  — 29/29 успешно; три host-dependent теста корректно skipped.
- Релевантные `mode_and_owner_tests`, platform profile/static и file handler
  tests — успешно.
- `git diff --check` — успешно.

## Что осталось / ограничения

- Реальное применение DAC к системным файлам не запускалось: тесты используют
  только temporary files; conditional negative `fchown` test не выполняет
  привилегированную мутацию.
- Descriptor гарантирует, что проверка, изменение и verification относятся к
  одному inode и исключает подмену конечного path на symlink между шагами. Он
  не закрепляет имя каталога: другой привилегированный процесс всё ещё может
  переименовать path после `open`; закрытие этой namespace race потребовало бы
  отдельного parent-directory/openat2 дизайна и не входит в минимальную правку.
- `release_contract_tests` исключён из полного CTest из-за известного
  несвязанного рассинхрона числа package artifacts.
