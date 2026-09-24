# FIC: передача контекста

## Current base

- Ветка `main`, базовый HEAD `051a6d4e6579023669678a7efb7afdea55b23040`.
- Финальный узкий hardening Step 4 завершён; изменения включены в коммит
  по запросу пользователя.

## Current task

- Закрыть P1-A/B/C/D и P2-A read-only password slot attach validator.
  Step 5 не начат; production CLI по-прежнему выполняет только faillock
  validation.

## Accepted architecture / invariants

- Три managed password slots: `fic-password-quality`,
  `fic-password-history`, `fic-password-history-initial`.
  Canonical Neutral — одна comment-строка; missing никогда не Neutral.
- Поддерживаются external quality only, FIC quality only,
  external quality + FIC history, FIC quality + FIC history.
  History-only и adoption внешнего pwhistory не поддерживаются.
- `PamPasswordFlowRequirements` явно разделяет quality/history requirements.
  Validator передаёт `{pwqualityCount == 1, historyActive}`. Observations
  вычисляются независимо; нарушения optional capability не создаются.
  History evidence требует `pam_pwhistory.so use_authtok`, успешного quality
  producer раньше history на том же пути и non-bypassable history.
  Неизвестный control/no successful path остаются fail closed.
- Active quality/history требуют MatchingApplied journal provenance,
  exact selected `fic-password-quality-hook` / `fic-password-history-hook`,
  ровно один parsed `password include <normal slot>` и ровно один provider
  с `PamRule.source == <configDirectory>/<normal slot>`.
  Include proof и source proof независимы. Direct equivalent module,
  foreign source, duplicate providers/includes, substack/@include вместо
  managed include не доказывают attachment. History-initial не может быть
  live provider; normal slot требует use_authtok.
- External quality: exact `Module: pwquality` + один parsed provider,
  non-bypassable quality и отсутствие FIC Active quality. Selection читается
  один раз на validation; все configured services проверяются отдельно.
- Rule J: Debian 12 `ModuleArguments` читает remember/enforce_for_root из
  согласованной canonical history pair. Debian 13, Ubuntu 24.04/26.04
  `ProviderConfigFile` требуют no-option slot bodies и effective state
  `pwhistory.conf`. Typed reader находится локально в
  `PamSlotAttachValidator.cpp` (`readPwhistoryConfigState`), НЕ в writer.
  Existing generic provider verifier не вычисляет эти config values.
- Config-file default: remember=10, enforce_for_root=false. Отсутствие файла
  сохраняет defaults, но при AllPamSubjects отсутствие enforce_for_root
  означает FAIL. Canonical flag — отдельная строка `enforce_for_root`;
  boolean assignments не принимаются. remember=0, malformed/overflow,
  любые дубли managed keys, unreadable/non-regular/symlink — FAIL.
  Unrelated syntactically valid keys допустимы.
- Neutral допускает `Unbound` либо `VirginUnbound` (J и W оба отсутствуют).
  Domain classifier использует symlink_status: dangling link не считается
  отсутствием. J без W, W без J, corrupt pair, Prepared/Applied/Conflict
  за Neutral — FAIL. Active всегда требует valid J+W+MatchingApplied.
  Generic MutationJournal semantics не менялись.
- Managed slot inspection использует read-only
  `PamConfigFileTransaction::capture` (lstat/O_NOFOLLOW/fstat).
  Symlink во всех трёх slot paths отклоняется, missing остаётся Unavailable.
- Validator ничего не пишет: не создаёт J/W/directories, не выполняет
  bootstrap, recovery, rollback, pam-auth-update или policy apply.
- Step 3 mutation lifecycle сохранён: Prepared → same-snapshot writes →
  fresh physical proof → Applied; exact-id compensation и накопление
  changedSystemState не менялись. Journal payload содержит permanent hook
  profile IDs, history domain один на обе physical slots.

## Completed

- Conditional flow requirements и use_authtok evidence.
- Exact hook/include/source proof, single history provider и normal-only branch.
- Configuration-mode split Rule J и strict typed config-file reader.
- Virgin Neutral classification без bootstrap; symlink rejection.
- Положительная decision matrix и отрицательные attachment/config/journal
  regressions; read-only fingerprints включают все файлы, каталоги и symlinks
  fixture, включая отсутствие J/W и db directory в virgin case.

## Changed areas

- `fic/src/modules/identity_access/pam/PamSlotAttachValidator.{h,cpp}`.
- `fic/src/modules/identity_access/pam/PamControlFlowAnalyzer.{h,cpp}`.
- `fic/src/modules/identity_access/pam/PamManagedPasswordSlotWriter.{h,cpp}`:
  только read-only domain classification.
- `tests/fic/modules/identity_access/pam/PamPasswordSlotAttachValidatorTests.cpp`.
- `tests/fic/modules/identity_access/pam/PamControlFlowAnalyzerTests.cpp`.
- `docs/HANDOFF.md`.

## Validation

- `cmake -S . -B build-check -DFIC_TARGET_PLATFORM=ubuntu-24.04` — PASS.
- `cmake --build build-check -j4` — PASS (полная сборка).
- `ctest --test-dir build-check -R
  'pam_password|pam_slot_attach|pam_control_flow|pam_managed_password|pam_configuration|journal|rollback'
  --output-on-failure` — 11/11 PASS.
- `ctest --test-dir build-check --output-on-failure` вне sandbox —
  99 passed, 1 skipped (`command_hash_batch_tests`, root-only),
  1 failed (`passwdqc_config_file_tests`: `pwquality policy did not retain
  its topology-dependent state`). Это известный baseline failure.
  Первый sandbox run дополнительно ограничил Unix socket bind и trusted
  root-directory checks; вне sandbox соответствующие тесты прошли.
- `cmake -S . -B build-debian12 -DFIC_TARGET_PLATFORM=debian-12` и
  `cmake --build build-debian12 -j4` — PASS (полная сборка).
- `ctest --test-dir build-debian12 -R
  'pam_password|pam_slot_attach|pam_control_flow|pam_managed_password|pam_configuration|journal|rollback'
  --output-on-failure` — 11/11 PASS (повторно подтверждено 24 сентября).
- Baseline `051a6d4` экспортирован через git archive в отдельный `/tmp`
  checkout; собран `passwdqc_config_file_tests`, затем
  `ctest --test-dir /tmp/fic-step4-baseline-build -R '^passwdqc_config_file_tests$'
  --output-on-failure` воспроизвёл ровно тот же failure.
- `git diff --check` — PASS; запрещённые области не имеют diff.

## Remaining

- Step 5 — следующая отдельная задача: packaging permanent dual-stack hooks,
  conffiles всех трёх slots, guarantees existence, read-only resulting
  attachment proof, затем re-wiring password verdict в maintenance CLI.
  Priority quality 1024, history 1023; history normal использует use_authtok,
  history-initial не использует. Не доверять одному rc=0 pam-auth-update.
- Step 6: Debian12 module-argument option writer; Step 7: runtime capability
  activation integration и lifting ReadOnly; последующие tests/docs — отдельно.
- main.cpp, packaging, platform profiles, PamPolicySupport::ReadOnly,
  activation policies, journal schema, rollback и lockout semantics не менялись.
- Native PAM/package/runtime enforcement не проверялось этим follow-up:
  текущие результаты — build, deterministic fixtures, static/contract tests.
  Межфайловые чтения не являются атомарной транзакцией против concurrent
  административного изменения; mutation/locking lifecycle не расширялся.
