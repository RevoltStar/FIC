# FIC: передача контекста

## Current base

- Ветка `main`, HEAD `41be075`.
- Рабочее дерево содержит незакоммиченный GRUB follow-up (см. Current task).

## Current task

- **GRUB follow-up к коммиту `d518cb0`** (owned drop-in / shared file
  refactor), незакоммичено. Две правки поверх текущего HEAD:
  1. **Validate-only base defaults для Debian/Ubuntu**: новое поле
     `GrubPlatformConfig::baseDefaultsPath` (Debian 12/13, Ubuntu 24.04/26.04:
     `/etc/default/grub`; ALT — пусто, запрещено `validateGrubConfig`).
     `validateBaseGrubDefaults()` (GrubConfiguration.cpp) проверяет
     `/etc/default/grub` ПЕРЕД любой мутацией managed drop-in и перед
     rebuild, включая idempotent apply: missing → OK; иначе regular
     не-symlink файл, size limit, без group/world write, root owner при
     `enforceOwnership`, безопасная цепочка родителей (group/world write
     запрещены; world-writable допустим только со sticky-битом — иначе
     тесты под /tmp не работают). Unsafe → fail closed, managed файл не
     меняется, rebuild не запускается.
  2. **Concurrent-drift guard в компенсации**: `GrubManagedConfig` хранит
     `installed_` — точный post-write state из
     `AtomicWriteResult::installedTargetState`. `restoreOriginal(error,
     concurrentDrift)` разрешена ТОЛЬКО при
     `AtomicFileWriter::targetStateMatches(path, installed_)`; иначе
     concurrent-drift conflict: внешнее состояние сохраняется, original не
     восстанавливается, файл не удаляется, компенсирующий rebuild не
     запускается (drift-диагностика в `result.diagnostics`).
     Регрессия из `d518cb0` (restore использовал текущее состояние файла как
     expected → затирание внешней записи) устранена.

## Accepted architecture / invariants

- GRUB topology из `d518cb0` сохранена: Debian/Ubuntu — owned
  `/etc/default/grub.d/zzzz-fic.cfg`; ALT — shared `/etc/sysconfig/grub2`.
- Компенсация GRUB — только для «apply изменил source → rebuild failed →
  вернуть apply в исходное состояние». НЕ путать с пользовательским rollback
  GRUB policy (journal/reconciler/DISABLE-cleanup — отдельные будущие задачи).
- Сравнение состояний файлов — через `AtomicFileWriter::targetStateMatches`
  / `AtomicTargetState` (identity+content+mode+owner+group), никаких
  параллельных механизмов.
- Остальные GRUB-гарантии `d518cb0` не тронуты: strict managed format, FIC
  marker, allowed-key whitelist, CR/LF/NUL rejection, safe quoting, later
  `*.cfg` fail-closed, idempotent apply с rebuild, atomic write, global GRUB
  mutex, verified executable, empty env, `DISABLE` без cleanup.

## Completed

- Platform: `GrubPlatformConfig::baseDefaultsPath`; `validateGrubConfig`
  требует его для OwnedDefaultsDropIn и запрещает для SharedDefaultsFile;
  профили Debian12/13, Ubuntu2404/2604 задают `/etc/default/grub`.
- GRUB module: `validateBaseGrubDefaults` + вызов в начале
  `ensureManagedGrubDropInValue`; `GrubManagedConfigurationOptions::
  baseDefaultsPath`; `Grub.cpp` прокидывает path из профиля.
- `GrubManagedConfig`: `installedState()`/`installed_` (snapshot из
  `saveConfig`), новая сигнатура `restoreOriginal(error, concurrentDrift)`.
- Тесты: `GrubPolicyTests` +2 функции (`testBaseDefaultsValidation` — 6
  сценариев base defaults; `testManagedConcurrentDriftCompensation` —
  existing+created drift, conflict ⇒ ровно 1 rebuild call, drift-диагностика);
  `PlatformProfileTests` — baseDefaultsPath контракт (positive+3 negative);
  `static_checks.py` — Debian-профили обязаны объявлять baseDefaultsPath,
  ALT — запрещено.
- `fic/README.md`: раздел «Работа с GRUB» дополнен base-defaults валидацией
  и concurrent-drift семантикой компенсации.

## Changed areas

- `fic/src/platform/` (PlatformProfile.h, PlatformCompatibility.cpp,
  profiles/Debian12|Debian13|Ubuntu2404|Ubuntu2604Profile.cpp)
- `fic/src/modules/oss/grub/` (GrubConfiguration.*, GrubManagedConfig.*,
  Grub.cpp)
- `tests/fic/modules/oss/grub/GrubPolicyTests.cpp`,
  `tests/fic/platform/PlatformProfileTests.cpp`,
  `tests/fic/platform/static_checks.py`
- `fic/README.md`, `docs/HANDOFF.md`

## Validation

- `grub_policy_tests`: PASS (build-tests, build-warnings, build-sanitizers
  ASan+UBSan с detect_leaks — все PASS).
- `platform_profile_tests`: exit 0. `static_checks.py .`: exit 0.
- Full build `build-tests` (-DFIC_TARGET_PLATFORM=ubuntu-24.04): exit 0,
  без warnings.
- Full CTest: **100% passed, 0 failed out of 96** (1 pre-existing skip
  `command_hash_batch_tests`).
- CI compiler-warnings профиль (`-Wall -Wextra -Wpedantic`, target
  `grub_policy_tests`): exit 0; новых предупреждений от изменений нет
  (4 добавленных -Wmissing-field-initializers устранены полными
  инициализаторами агрегатов; 86 pre-existing warnings в
  Ubuntu2404Profile.cpp + 2 в тестах не тронуты).
- `git diff --check`: clean.
- Sanitizers: точечный (configure по CI-флагам + target grub_policy_tests +
  запуск); полного sanitizer build всего дерева не выполнялось.

## Remaining

- Коммит GRUB follow-up.
- Sanitizer-профиля в проекте нет — не запускались.
- Accepted limitations (не баги): TOCTOU между targetStateMatches и
  компенсирующей записью закрывается `expectedTargetState=installed_`
  в самой записи; cross-process CAS для managed GRUB updates отсутствует.
