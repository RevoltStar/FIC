# FIC: передача контекста

## Current base

- Ветка `main`, HEAD `b11a23308c58aa0650870f2cb137bbe45179b0b1`.
- Изменения текущей задачи не закоммичены.

## Current task

- Применён PAM ownership patch: Debian/Ubuntu AuthenticationLockout переводится
  на permanent `pam-auth-update` hooks и FIC-owned journal-bound slots.

## Accepted architecture / invariants

- `Prepared` journal record и имя `fic-*` сами по себе не доказывают physical
  ownership и не дают права destructive rollback.
- Четыре permanent hook profile являются package infrastructure; policy меняет
  только strict `/etc/pam.d/fic-faillock-*` slots с exact mutation id.
- Rollback нейтрализует active или crash-partial slots только при совпадении
  journal mutation id. Malformed, mixed и wrong-id state остаётся fail-closed.
- Legacy ambiguous partial/mixed `PamAuthUpdate` selection не освобождается по
  одному лишь profile name.

## Completed

- Добавлены managed-slot grammar, inspection, activation, durability и binding
  journal mutation id в `PamAuthUpdateTopologyManager`.
- Activation policy и rollback проверяют physical ownership witness.
- Debian/Ubuntu profiles используют единый permanent-hook activation domain.
- Debian packaging устанавливает четыре hook profiles и четыре PAM conffile
  slots; maintainer scripts регистрируют и удаляют hook infrastructure.
- Добавлены unit/static/package regressions и документация модели.

## Changed areas

- `fic/src/modules/identity_access/pam/`, `fic/src/rollback/`,
  `fic/src/platform/profiles/`;
- `packaging/deb/`, `tests/fic/`, `tests/integration/packaging/`;
- `docs/pam-owned-faillock-slots.md`, `docs/rollback.md`.

## Validation

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
