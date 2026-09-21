# FIC: передача контекста

## Current base

- Ветка `main`, base для follow-up:
  `626cee143920efdf590238053888cab27acc3e01`.
- Follow-up исправляет safety gaps первого managed-slot коммита.

## Current task

- Follow-up к managed-slot commit `626cee143920efdf590238053888cab27acc3e01`:
  закрыть crash compensation/recovery, upgrade legacy-domain и оставшиеся
  profile-selection causal-ownership gaps.
- Исправлена совместимая с nlohmann-json 3.11.2/3.11.3 сериализация optional
  PAM strategy provenance: string при наличии значения, JSON `null` иначе.
- Исправлен top-level layout Debian builder и regressions follow-up; legacy
  PasswordQuality/PasswordHistory на Debian/Ubuntu больше не экспонируют
  activation policies и классифицируются как `ReadOnly`.

## Accepted architecture / invariants

- `Prepared` journal record и имя `fic-*` сами по себе не доказывают physical
  ownership и не дают права destructive rollback.
- Четыре permanent hook profile являются package infrastructure; policy меняет
  только strict `/etc/pam.d/fic-faillock-*` slots с exact mutation id.
- Rollback нейтрализует active или crash-partial slots только при совпадении
  journal mutation id. Malformed, mixed и wrong-id state остаётся fail-closed.
- Legacy exact/partial/mixed `PamAuthUpdate` selection не освобождается по
  одному лишь profile name.
- PasswordQuality/PasswordHistory legacy profile backend временно
  observation-only: новая topology mutation и destructive rollback запрещены
  до отдельной доказанной password-slot модели.
- Neutral faillock slot использует `optional pam_deny.so`, а не `pam_permit`,
  чтобы degenerate stack был fail-closed.
- Upgrade с legacy selected FIC PAM profiles блокируется в `preinst`; automatic
  adoption/migration запрещена как причинно недоказуемая.

## Completed

- Добавлены managed-slot grammar, inspection, activation, durability и binding
  journal mutation id в `PamAuthUpdateTopologyManager`.
- Activation policy и rollback проверяют physical ownership witness.
- Debian/Ubuntu profiles используют единый permanent-hook activation domain.
- Debian packaging устанавливает четыре hook profiles и четыре PAM conffile
  slots; maintainer scripts регистрируют и удаляют hook infrastructure.
- Добавлены unit/static/package regressions и документация модели.
- `write_fic_pam_preinst()` вынесен из `write_common_preinst()`; packaging test
  source-ит builder и проверяет наличие обеих top-level functions.
- Fake PAM manager после успешного enable восстанавливает manageable state;
  legacy external-equivalent rollback ожидает ноль destructive disable calls.
- Activation policy регистрируется только при
  `PamPolicySupport::RequiresTopologyActivation`; observation-only option
  policies не получают зависимость на отсутствующую activation policy.

## Changed areas

- `fic/src/modules/identity_access/pam/`, `fic/src/rollback/`,
  `fic/src/platform/profiles/`;
- `packaging/deb/`, `tests/fic/`, `tests/integration/packaging/`;
- `docs/pam-owned-faillock-slots.md`, `docs/rollback.md`.

## Validation

### Follow-up review / patch generation

- Код `626cee143920efdf590238053888cab27acc3e01` повторно сверён по GitHub.
- Исправлены: missing current-snapshot compensation, policy-level
  crash-partial Prepared recovery, permissive neutral `pam_permit`, unsafe
  legacy password-profile release и upgrade-domain mismatch.
- Follow-up patch проходит синтаксический `git apply --stat`; полного checkout
  и build/CTest в среде генерации patch нет, поэтому PASS сборки для follow-up
  не заявляется.

### Validation после применения follow-up

- `pam_auth_update_topology_tests` build + CTest — успешно.
- `pam_packaging_static_checks` и `platform_profile_static_checks` — успешно.
- Direct `PamPackagingChecks.py`, platform `static_checks.py` и `bash -n` для
  Debian builder — успешно.
- Targets `mutation_journal_tests`, `pam_capability_activation_policy_tests`,
  `rollback_executor_tests` и `fic` — успешно собраны после явной сериализации
  optional strategy fields.
- `mutation_journal_tests` — успешно. Два follow-up tests пока падают уже на
  behavioral assertions: `rollback_executor_tests` (`external equivalent PAM
  topology must remain untouched`) и `pam_capability_activation_policy_tests`
  (`journal-bound crash-partial Prepared was not compensated/reapplied`).
- `git diff --check` — успешно.
- После corrective review: targets `fic`,
  `pam_capability_activation_policy_tests`, `rollback_executor_tests` и
  `identity_policy_hierarchy_tests` собраны успешно.
- `pam_capability_activation_policy_tests` и
  `identity_policy_hierarchy_tests` — успешно.
- `rollback_executor_tests`: относящийся к PAM сценарий теперь PASS; общий test
  в текущем окружении падает только на восьми DAC cases из-за
  `could not resolve test group`.
- Direct packaging/platform static checks, shell source regression и `bash -n`
  Debian builder — успешно.

### Validation, зафиксированная в `626cee...`

- Fresh configure Ubuntu 24.04 — успешно.
- `pam_auth_update_topology_tests` build + CTest — успешно.
- `platform_profile_tests` build + CTest — успешно.
- `pam_packaging_static_checks` и `platform_profile_static_checks` — успешно
  после согласования conffile contract.
- `bash -n packaging/deb/build-fic-debian12-deb.sh` — успешно.
- `pam_capability_activation_policy_tests` и `rollback_executor_tests` дошли до
  изменённых PAM sources, но общий build остановился в неизменённом
  `MutationJournal.cpp`: установленный nlohmann-json не сериализует
  `std::optional<std::string>` напрямую.
- `git diff --check` — успешно.

## Remaining

- Native privileged PAM runtime и multi-platform package/install validation не
  выполнялись.
- Полные build и CTest не выполнялись.
