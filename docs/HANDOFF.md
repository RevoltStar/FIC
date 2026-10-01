# FIC: передача контекста

## Current base

- Ветка `main`; HEAD = `aacd164` («Follow-up к последнему коммиту №3»).
  Поверх HEAD — **незакоммиченный Шаг 7F** (PAM provider rollback:
  runtime rollback/package release + real-distro gates, см. Current
  task). Коммит НЕ делать без явного запроса.

## Current task

**Шаг 7F — PAM provider managed rollback + package release, выполнен,
не закоммичен.** Реализован runtime rollback управляемой PAM
конфигурации провайдера и package release при удалении пакета, плюс
real-distro валидация на реальных образах.

Ключевые решения (принятые, не пересматривать без задачи):

- **Ownership proof.** Физическое состояние рендерится ПОСЛЕ
  `prepareMutation` (physical == journal mutation id — часть ownership
  proof). Rollback выполняет payload только если ТЕКУЩАЯ platform
  profile подтверждает identity journal-записи (provider, config path,
  managed key, placement contract) через ТУЖЕ typed-routing SSOT, что и
  apply (`pamProviderManagedEntryPlacement`,
  `pamProviderRollbackRouteForFeature`). Predicat —
  `configurationMode == ProviderConfigFile` (НЕ
  `configTopology.has_value()`: в production-профилях топология
  провайдера — `provider.defaultConfigTopology`, nullopt в capability —
  норма; этот баг был найден real-distro gate на D12).
- **Flag-release фиксация:** foreign-состояние содержит активную строку
  managed key; apply-transition
  (`setPamProviderManagedFlagTransition`, `createSuppressionIds`, НЕ
  `keepSuppressionIds`) сам оборачивает её.
- **Package release (DEB prerm / RPM preun):** orphan wrapper preflight
  → fail-closed; flag=false release; FIC-created container удаляется
  условно (provenance-bound), pre-existing primary сохраняется; журнал
  перезагружается.
- **Managed-provider lock** fail-closed и требует существования
  runtimeDir (unit harness обязан создавать `paths.runtimeDir`).
- Gate driver (`tests/integration/pam-c2/pam_provider_rollback_driver.cpp`)
  намеренно исключён из default build/CTest (мутирует реальное
  PAM-состояние); резолвит маршруты только через SSOT
  (`PamProviderCatalog`), ничего не хардкодит.

## Completed

- Runtime rollback executor + package release + conditional delete of
  FIC-created container (production code: `PamProviderManagedLock.*`,
  `PamProviderPackageRelease.*`, `PamProviderRollback.*`,
  `RollbackExecutor.*`, `PamProviderManaged{Block,EntryExecutor,FlagExecutor}.*`,
  `AtomicFileWriter` (fsync-контракт), `fic/src/main.cpp` wiring).
- Unit/contract тесты: `PamProviderPackageReleaseTests.cpp` (+6
  тестов), `RollbackExecutorTests.cpp`, `IdentityPolicyHierarchyTests.cpp`
  (runtimeDir фикс), `tests/CMakeLists.txt` (driver target,
  EXCLUDE_FROM_ALL).
- Packaging wiring: DEB (`build-fic-debian12-deb.sh` prerm) + RPM
  (`build-fic-alt-p11-rpm.sh`); `PamPackagingChecks.py` расширен — PASS.
- Real-distro gates (production driver против реального /etc/security,
  компилированный production platform profile, реальный MutationJournal):
  - `pam_provider_rollback_gate.sh` (D12/D13/U24/U26, G1–G7):
    faillock scalar apply/disable byte-exact, flag=false wrap/unwrap,
    displaced block, pwquality (conditional по route), pwhistory typed
    routing (refused на ModuleArguments-платформах), preflight
    read-only + release foreign-only, retry idempotence.
  - `pam_provider_rollback_gate_alt.sh` (ALT p11 rpm-вариант, A1–A6):
    без apt; pwquality/pwhistory сценарии пропускаются ПО ROUTE
    (passwdqc/tcb-топология ALT), не по имени дистрибутива.
  - **Все пять gates PASS: debian-12, debian-13, ubuntu-24.04,
    ubuntu-26.04, altlinux-11.**
  - Sandboxing-заметки: podman (не docker); detached `podman logs`
    пустые — вывод в mounted `/out`; host glibc новее контейнерных —
    бинарники с хоста несовместимы, driver собирается ВНУТРИ контейнера;
    proxy из env недоступен из контейнера — `unset http_proxy …` перед
    apt (уже в gate-скрипте).

## Changed areas

- `fic/src/modules/identity_access/pam/` (rollback/package release/lock),
  `fic/src/rollback/`, `fic-common/fic-core/.../AtomicFileWriter.*`,
  `fic/src/main.cpp`.
- `packaging/{deb,rpm}/build-fic-*.sh`,
  `tests/integration/packaging/PamPackagingChecks.py`.
- `tests/fic/...` (unit), `tests/CMakeLists.txt`,
  `tests/integration/pam-c2/` (driver + 2 gate-скрипта),
  `docs/rollback.md`.

## Validation (фактически выполнено)

- Полный build `build-check` (ubuntu-24.04) — 0 errors.
- Полный CTest — **114/114 PASS** (1 skip: `command_hash_batch_tests`,
  окружение), включая прогон после финального фикса
  `PamProviderRollback.cpp`.
- `python3 tests/integration/packaging/PamPackagingChecks.py $PWD` —
  PASS.
- Real-distro gates — все PASS (см. Completed).
- `git diff --check` — чисто.

## Remaining

1. Финальный отчёт №124 (36 пунктов) — составляется отдельно; матрицы:
   unit vs distro gates, conditional delete, lock domain, package
   wiring DEB+RPM.
2. Прод-apply на absent primary отказывает (FailClosed); создание
   primary требует platform-level proof contract.
3. PAM argv override на production daemon harness end-to-end не
   прогонялся (покрыт preflight/policy-level regression).
4. Не трогали: C2 topology, PamOptionFile semantics, Step 6 option
   reconciliation, codec, activation, D12 coordinator/slot writer.
5. Не коммитить без явного запроса.
