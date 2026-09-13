# FIC: передача контекста

## Current base

- Ветка `main`, базовый commit `310a33d` (HEAD); рабочее дерево содержит
  незакоммиченную реализацию стратегии pam_faillock (см. ниже).

## Current task

- Трансформация `enable_authentication_lockout` из fixed-ENABLE политики в
  трёх-стратегическую pam_faillock интеграцию (`preauth_requisite`,
  `preauth_required`, `authsucc`) end-to-end. Ядро реализовано; остаются
  runtime-валидация и дополнительные тесты (см. Remaining).

## Accepted architecture / invariants

- `PamFaillockStrategy` живёт в `fic::platform` (`PlatformProfile.h`).
- `PamCapabilityConfig` получил `supportedFaillockStrategies`,
  `defaultFaillockStrategy` (по умолчанию `preauth_required`) и
  `strategyActivations` (рецепты pam-auth-update на стратегию). Все пять
  профилей объявляют все три стратегии.
- `PamTopologyStatus` получил `activeStrategy`; `PamTopologyManager` получил
  `canEnableStrategy`/`enableStrategy` (базовая реализация fail-closed).
  Стратегия-переход атомарен: inspect → snapshot → candidate → apply →
  re-read → verify → commit; rollback через существующие механизмы.
- `enable_authentication_lockout.value`: `preauth_required` |
  `preauth_requisite` | `authsucc` (default `preauth_required`). НЕТ миграции
  `ENABLE`: старое значение в пользовательском конфиге станет invalid →
  fail-closed. Только lockout — стратегическая политика; history/quality
  остались `ENABLE` (fallback в `PamCapabilityActivationPolicy`).
- `PamControlFlowAnalyzer`: новые violation kinds
  `RecoverableFailureAccounting` (authsucc-топология: authfail учёл сбой, но
  стек завершился успешно) и `PrematureSuccessAccounting` (authsucc учёл
  успех на пути, завершившемся отказом); evidence-флаг `authsuccDenied`;
  общий детектор `detectPamFaillockStrategy(authStack, error)` — fail-closed
  при неоднозначности (requisite/required preauth, authsucc, комбинированные
  формы отклоняются).
- Debian/Ubuntu: монолитный `fic-faillock` заменён композиционными
  pam-configs профилями: `fic-faillock-authfail` (Priority 1),
  `fic-faillock-preauth-required` (1025, required preauth + account),
  `fic-faillock-authsucc` (Priority 0, control
  `[success=ok default=bad]`, БЕЗ account-фазы; upstream `sufficient`
  сознательно не копируется). `fic-faillock-notify` (1025) остался для
  preauth_requisite. Рецепты в профилях:
  requisite={notify,authfail}, required={preauth-required,authfail},
  authsucc={authsucc,authfail}. Переход = `pam-auth-update --disable` всех
  нецелевых fic-faillock профилей → `--enable` целевых, с rollback.
- ALT: `AltPamFaillockTopologyManager` поддерживает все 3 стратегии. Layout:
  preauth-блок с `requisite|required` правилом + authfail + account;
  authsucc — якорный блок (original pam_tcb hex + jump
  `[success=1 default=bad] pam_tcb...`) + authfail + authsucc-правило
  `[success=ok default=bad] pam_faillock.so authsucc`, БЕЗ account-блока.
  Стратегия определяется по маркерам блоков (не через общий детектор).
- GUI/CLI изменений не требуют: комбо-бокс строится из editor spec
  (`PossibleListPolicyTypeValue`), первое значение = default.

## Completed

- Platform contract, профили, менеджеры (pam-auth-update + ALT), политика
  (`PamCapabilityActivationPolicy`), analyzer (2 violation kinds + детектор),
  compositional pam-configs, packaging builders (prerm/install списки),
  `IDENTITY_ACCESS.conf.in` default, ru/en.lang, README (fic, deb packaging),
  обновлены затронутые тесты и static checks.

## Changed areas

- `fic/src/platform/PlatformProfile.h`, `fic/src/platform/PamFaillockStrategy.cpp` (новый),
  `fic/src/platform/profiles/*`
- `fic/src/modules/identity_access/pam/` (менеджеры, analyzer, policy,
  `PamTopologyManager.cpp` новый, factory)
- `packaging/deb/pam-configs/*`, `packaging/deb/build-fic-debian12-deb.sh`
  (debian13/ubuntu делегируют ему), `packaging/deb/README.md`
- `fic/src/resources/config/IDENTITY_ACCESS.conf.in`, `ru.lang`, `en.lang`
- `tests/integration/packaging/PamPackagingChecks.py`,
  `tests/fic/platform/static_checks.py`,
  `tests/fic/modules/identity_access/pam/{AltPamFaillockTopologyManager,PamCapabilityActivationPolicy}Tests.cpp`
- `fic/README.md`

## Validation

- `cmake --build build-check --target fic`: PASSED (configure только через
  `cmake -S fic -B build-check -DFIC_TARGET_PLATFORM=ubuntu-24.04`, т.к.
  root-configure падает на отсутствии gio-2.0 для fic-session-agent).
- `python3 tests/integration/packaging/PamPackagingChecks.py .`: PASSED.
- `python3 tests/fic/platform/static_checks.py .`: PASSED.
- Синтаксическая проверка изменённых тестов (g++ -fsyntax-only): PASSED.
- `git diff --check`: PASSED.

## Remaining

- Полный CTest не выполнялся: root CMake configure требует gio-2.0 dev
  (WSL), плюс runtime PAM-тесты требуют реальные Debian 12/13, Ubuntu
  24.04/26.04 и ALT окружения (контейнеры или documented deferral).
- Новые unit-тесты на стратегии ещё не написаны: 6 pairwise переходов + 3
  идемпотентности для обоих менеджеров, authsucc-инварианты analyzer
  (Recoverable/Premature cases), отсутствие стратегии в рецепте платформы.
- Проверить сгенерированный pam-auth-update common-auth на реальной
  Debian/Ubuntu системе: порядок fic-faillock-authfail (P1) vs authsucc (P0)
  и отсутствие прыжка мимо authsucc.
- Коммит не создавать без отдельного запроса пользователя.
