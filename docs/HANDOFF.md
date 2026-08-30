# FIC: передача контекста

## Current base

- Ветка: `main`.
- HEAD до текущих незакоммиченных изменений: `1bf2477`.

## Current task

- Исправлены native default semantics legacy `pam_pwhistory` и безопасная
  поддержка штатных PAM service aliases ALT p11.

## Accepted architecture / invariants

- `PamPwhistoryArgumentState` хранит `remember=` как optional override;
  effective native default legacy Linux-PAM равен 10, explicit 0 остаётся
  ineffective.
- `PamTrustedServiceAlias` задаёт exact alias path и exact allowlist targets.
  Обычные top-level/included symlink остаются запрещены.
- ALT p11 разрешает только selectors `system-auth` и `system-policy` с
  package-owned targets, подтверждёнными на `pam-config-1.10.0-alt0.p11.2`.
- Alias target ограничен relative basename в том же PAM directory, читается
  через `openat(O_NOFOLLOW)`, проверяется по owner/mode/type/device/inode и
  повторно разрешается после чтения. `PamRule::source` указывает на regular
  authoritative target.

## Completed

- Разделены absent `remember=`, explicit 0 и explicit N; capability и explicit
  policy postconditions используют effective semantics.
- Добавлены platform metadata validation и production regressions для trusted,
  undeclared, escaping, unapproved, chained, writable, non-regular и cyclic
  aliases, malformed/include-cycle targets и сохранения ALT selectors при
  enable/disable roundtrip.
- Обновлена PAM architecture documentation.

## Changed areas

- `fic/src/modules/identity_access/pam/`.
- PAM platform metadata и ALT p11 profile.
- PAM hierarchy/configuration/topology/profile tests.
- `fic/README.md`, `docs/architecture-diagrams.md`.

## Validation

- На Debian 12/13, Ubuntu 24.04/26.04 и ALT p11 прошли 8/8 targeted
  PAM/profile tests; после уточнения `system-policy` отдельно повторены ALT
  affected tests.
- Package E2E без изменения harness: Debian 12 — 33 PASS/0 FAIL/2 SKIP;
  Debian 13, Ubuntu 24.04 и Ubuntu 26.04 — по 32 PASS/0 FAIL/3 SKIP; финальный
  ALT p11 corrective run — 21 PASS/0 FAIL/14 platform-expected SKIP.
- Full CTest: 49 PASS, 4 environment SKIP, 2 unrelated existing FAIL из 55:
  `path_layout_static_checks`, `ipc_protocol_validation_tests`. Все PAM tests
  прошли.
- `git diff --check` пройден.
- Полная локальная all-target сборка остановилась на отсутствующем development
  header `systemd/sd-login.h`; daemon и все пять package artifacts собирались
  в profile/E2E pipelines.

## Remaining

- Exact allowlists намеренно fail closed: появление нового штатного target в
  будущей версии ALT `pam-config` потребует обновления profile metadata.
- Между финальной проверкой alias и дальнейшим использованием graph остаётся
  неизбежная гонка с внешним privileged writer; target read защищён fd,
  identity comparison и повторным alias resolution.
- E2E reports сохранены вне worktree:
  `/tmp/fic-pam-e2e-results-20260830-184408` и
  `/tmp/fic-pam-e2e-results-20260830-205336`.
