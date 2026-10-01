# FIC: передача контекста

## Current base

- Ветка `main`; HEAD = `71f695cc9fab58ec3b5496b8b81830616269b3a9`
  ("Follow-up к последнему коммиту №2"). Поверх HEAD —
  **незакоммиченный final cleanup к Шагу 7F** (2 правки + регрессии).
  Коммит НЕ делать без явного запроса.

## Current task

**Final cleanup (Step 7F) — реализация и валидация завершены,
не закоммичено.** Base before this follow-up:
`71f695cc9fab58ec3b5496b8b81830616269b3a9` (чистое дерево).

- **(1) Orphan empty canonical FIC provider block — fail closed.**
  `PamProviderPackageRelease.cpp::preflightPhysicalState`: после strict
  parse, если `parse.view.present && parse.view.entries.empty()` →
  preflight FAIL с диагностикой "orphan empty FIC PAM provider block";
  никакой deletion/healing; config+journal byte-identical. Существующее
  rejection блоков с present-but-uncovered entries не тронуто (новый
  check покрывает только случай, когда entry-loop вообще не выполняется).
  **Важно (отклонение от исходной постановки):** состояние
  `parse.ok==true && present && entries.empty()` в текущем коде
  НЕДОСТИЖИМО — строгая грамматика Step 7A (commit `aa3f8b66`,
  `PamProviderManagedBlock.cpp`, "пустой FIC PAM provider block") уже
  fail-closed отвергает блок без entry на уровне parse. Новый check
  оставлен как defense-in-depth на случай будущего ослабления грамматики;
  регрессия `testEmptyOrphanProviderBlockRejectedAtPreflight` закрепляет
  контракт end-to-end (Stage A FAIL + Stage B FAIL + byte-identical) и
  на base `71f695c` проходит (мутация нового check её не ломает —
  негативный контроль для этого сценария невозможен технически).
- **(2) Route-aware `pamProviderManagedPrimaryPath(s)`.** Новый общий
  предикат `capabilityHasManagedProviderRoute(descriptor, capability)`
  (anonymous namespace `PamProviderRollback.cpp`): ≥1 binding с
  `pamProviderManagedEntryPlacement(...).has_value()`. Используется
  ОДИН раз обоими потребителями managed-domain модели:
  `pamProviderManagedPrimaryPath` (enumeration primary paths) и
  `pamProviderContainerRollbackRouteForPayload` (container proof).
  Никаких distro switch. Матрица: ALT passwdqc
  (`/etc/passwdqc.conf`) и ALT pwhistory
  (`/etc/security/fic-pwhistory.conf`, AltTcbManaged) — исключены;
  D12 pwhistory (ModuleArguments) — исключён; D12/D13/U24/U26
  faillock+pwquality и D13/U24/U26 pwhistory
  (ProviderConfigFile+PamAuthUpdate) — включены.

## Accepted architecture / invariants

- Все прежние инварианты Шага 7F (ownership proof, Stage A/B
  согласованность, exact orphan identity, record-specific
  classification, `activePamFlagSuppressionAuthority`, final
  re-enumeration, Detached=no second lifecycle, zero-wrapper flag
  release, Prepared authority, conditional-delete hardening, Stage-A
  binding whitelist, crash-after-delete recovery) — без изменений.
- Managed-provider domain = ЕДИНЫЙ общий предикат
  `capabilityHasManagedProviderRoute` для enumeration и container
  proof; второй whitelist/distro switch не вводить.
- Package preflight сканирует ТОЛЬКО route-managed primaries; файлы
  unmanaged ProviderConfigFile-возможностей (passwdqc.conf) — не
  provider domain, в scan не входят (даже с FIC_PAM_-подобным
  содержимым).

## Completed

- Оба пункта выше + регрессии:
  - `PamProviderRollbackTests` (+3): route-aware ALT-профиль (ровно 1
    primary, конкретные пути passwdqc.conf/fic-pwhistory.conf
    отсутствуют), D13-like (все 3 present) / D12-like (pwhistory
    ModuleArguments отсутствует), container proof на unmanaged
    capability (passwdqc + ALT pwhistory) → Conflict, положительный
    контроль на managed faillock.
  - `PamProviderPackageReleaseTests` (+2): empty orphan block (Stage A
    FAIL, diagnostic, Stage B FAIL, config+journal byte-identical),
    ALT-shaped package release (managed faillock primary чист, temp
    `/etc/passwdqc.conf` с FIC_PAM_-подобным контентом не участвует в
    scan, release проходит, файл byte-identical).
- Негативный контроль: откат `pamProviderManagedPrimaryPath` к
  ProviderConfigFile-only eligibility →
  `testManagedPrimaryPathsRouteAwareAltProfile` FAIL на "exactly one
  managed provider primary"; после восстановления — PASS.

## Changed areas

- `fic/src/modules/identity_access/pam/PamProviderRollback.{h,cpp}`,
  `fic/src/modules/identity_access/pam/PamProviderPackageRelease.cpp`.
- `tests/fic/modules/identity_access/pam/{PamProviderRollbackTests,
  PamProviderPackageReleaseTests}.cpp` (регистрация в main() каждого
  файла; CTest-цели существовали, `tests/CMakeLists.txt` не менялся).


## Validation (фактически выполнено)

- Полный build `build-check` (ubuntu-24.04) — 0 errors.
- Полный CTest — **115/115 PASS** (1 skip: `command_hash_batch_tests`,
  окружение).
- `python3 tests/integration/packaging/PamPackagingChecks.py $PWD` —
  PASS.
- `git diff --check` — чисто.
- **Real-distro gates: 5/5 PASS** — `pam_provider_rollback_gate.sh` на
  debian-12, debian-13, ubuntu-24.04, ubuntu-26.04 и
  `pam_provider_rollback_gate_alt.sh` на altlinux-p11 (важно именно для
  ALT: изменённая enumeration domain). Логи: `/tmp/gate7f-*.log`.

## Remaining

1. Коммит НЕ делать без явного запроса.
2. Прошлое Remaining (prerm mutation-checks через
   `pam_prerm_release_gate.sh`) не закрыто и осталось вне scope: apt
   зеркала sandbox нестабильны; пререквизит — пересборка prebuilt debs
   из `dist/` (built 21.09, до всех изменений 7F). Запускать с
   `-e http_proxy= -e https_proxy=` (prerm-скрипт не сбрасывает
   хостовый loopback proxy).
3. Не трогали (вне scope): C2 topology, PamOptionFile semantics,
   Step 6 option reconciliation, codec, activation, D12 coordinator,
   MutationJournal schema.

## Следующему агенту

- `capabilityHasManagedProviderRoute` — internal helper в anonymous
  namespace `PamProviderRollback.cpp`; публичного API для него нет и не
  нужно (проверяется через `pamProviderManagedPrimaryPaths` и
  `pamProviderContainerRollbackRouteForPayload`).
- Все callers `pamProviderManagedPrimaryPath(s)` — только
  `PamProviderPackageRelease.cpp` (`knownProviderPrimaries`) и
  внутренний plural-хелпер; поведение managed-путей не изменилось,
  изменился только состав исключаемых unmanaged путей.
- Если будущая задача ослабит строгую грамматику Step 7A (разрешит
  пустые блоки), preflight empty-block check станет первичной линией
  защиты — не удалять вместе с ней без отдельного решения.
- Прежние знания о gate-инфраструктуре (podman `--network=slirp4netns`,
  `-e http_proxy= -e https_proxy=`, логи в `/tmp/gate-*.log`) остаются
  в силе.
