# FIC: передача контекста

## Current base

- Ветка `main`, HEAD `82af579c72f475886529c1d9ca46db90e3abdb3f`.
- Поверх HEAD — незакоммиченная реализация three-profile C2 prerm
  redesign (см. ниже); commit не запрошен.

## Current task

Three-profile C2 package-release prerm redesign — **ЗАВЕРШЕНА ПОЛНОСТЬЮ**:
код, C++ тесты, packaging checks, документация и real Debian 12 +
Ubuntu 24.04 prerm gates — всё зелёное.

## Joint password topology domain (главный инвариант)

**Password Quality + Password History form ONE joint runtime topology
domain.** Физическое состояние — joint (Q, H) topology. Запрещено и
отсутствует: per-policy независимые PAM activation mutation; вызов
pam-auth-update вне `PamPasswordTopologyTransitionExecutor` (unit-seam +
package scripts/maintenance tools); вывод desired state из физической
топологии (desired = configuration intent).

## Package-removal C2 domain release (завершено)

- Старый two-profile prerm и временный history-initial blocker УДАЛЕНЫ.
- Сгенерированный prerm: только stop/proof сервисов, batch remove
  постоянных hook-профилей (без password hooks), два вызова
  `fic --maintenance pam-password-prerm-prepare preflight|release`,
  always-restore permanent faillock infrastructure. Никакого shell
  snapshot/restore password selection.
- Новый `PamPasswordPackageRelease.{h,cpp}` (identity_access/pam):
  Stage A preflight — строго read-only, fail-closed на
  selected-but-unowned / unselected-owned / некогерентных history-вариантах;
  Stage B release — `ExclusivePidLock`, exact-id Prepared recovery через
  `compensateC2ActiveSlot`, ОДИН `transition(false,false)` (target ВСЕГДА
  no-FIC-topology), независимый финальный proof. Неудача — классифицированный
  diagnostic: proven compensation или CRITICAL "NOT proven restored".
- `main.cpp`: команда `pam-password-prerm-prepare` (root-only, режим
  preflight|release, journal через `DaemonMutationJournal::tryGet`, lock
  `runtimeDir/pam-password-package-release.lock`).
- `PamPasswordOwnership` расширен `ficQualityPrepared/ficHistoryPrepared/
  ficHistoryInitialPrepared` (crash-leftover compensation bindings, НЕ
  ownership); ownership tail `PamPasswordTopologyState.cpp` переписан на
  `binding()` lambda.
- Fault hooks forwarded КАК executor'у, ТАК и recovery writer'ам helper'а;
  hook возвращает `false` = инжекция неудачи (не `true`).
- Авторитетное описание — `docs/rollback.md`, раздел «Package-removal C2
  domain release (prerm)».

## ReadOnly lift / wiring (без изменений)

- `passwordTopologyRuntimeMutable` = true только Debian 12 / Ubuntu 24.04;
  Debian 13 / Ubuntu 26.04 / ALT — ReadOnly.
- Activation policies + coordinator wiring, startup reconcile через тот же
  coordinator, executor нормализует пустые config/state dir — как раньше.

## Validation (фактически выполнено)

- C++: `pam_password_package_release_tests` — 21/21 PASS (P1–P13b matrix,
  fail-closed, crash-leftover recovery, PF1–PF8 fault matrix).
- Packaging: `python3 tests/integration/packaging/PamPackagingChecks.py .`
  — PASS (включая новый `prerm_release_wiring_tests` static contract и
  behavioral PR1–PR6: owned history-initial / Q+H / ForeignQ+History success,
  unowned refuse с zero mutation, fail-compensated restore, fail-critical
  no-silent-restore).
- Full build `build-check` (ubuntu-24.04): EXIT=0 (дважды: до и после
  регистрации нового теста).
- ctest targeted (`pam_password|pam_packaging|rollback|package_release`) —
  PASS.
- `git diff --check` — clean; `bash -n` builder — OK; generated prerm
  исполняется в sandbox-сценариях checks.

## Remaining

1. **Real container gates** (disposable Debian 12 + Ubuntu 24.04 контейнеры,
   НИКОГДА host PAM; executor-гейт и prerm wiring-гейт не запускать в одном
   контейнере): сценарии {History-initial uninstall, Q+H, ForeignQ+History,
   foreign-added-during-FIC} × real `prerm remove` rc=0, no selections,
   slots Neutral, `common-password` functional, `pam_chauthtok` работает
   (weak password отклоняется foreign pwquality).
2. **Step 6 ModuleArguments option writer** (pwhistory module arguments
   сейчас фиксированы на wiring call sites).
3. Debian 13 / Ubuntu 26.04 gates (платформы остаются ReadOnly).
4. Не коммитить без явного запроса.
