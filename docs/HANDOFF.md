# FIC: передача контекста

## Current base

- Ветка `main`, базовый commit `6c1b0b4`.

## Current task

- Синхронизировать `en.lang` с пользовательскими изменениями описаний PAM
  policy в `ru.lang`.

## Accepted architecture / invariants

- Меняются только локализованные description strings.
- Policy identifiers, names, values, dependencies, PAM configuration и runtime
  implementation не меняются.

## Completed

- Обновлены парные EN descriptions для изменённых RU keys:
  `password_min_length`, `password_check_username`, `password_check_gecos`,
  `password_quality_enforce_for_root`, `password_min_changed_characters`,
  `passwdqc_strength_thresholds`, `passwdqc_match_length`,
  `passwdqc_similar_password`, `passwdqc_retry_count`,
  `password_history_depth`, `failed_authentication_unlock_time`.

## Changed areas

- `fic/src/resources/lang/ru.lang`
- `fic/src/resources/lang/en.lang`
- `docs/HANDOFF.md`

## Validation

- `python3 tests/common/static_checks.py .`: passed.
- `python3 tests/fic-gui/policies/static_checks.py .`: passed.
- `cmake -S . -B build-check -DFIC_TARGET_PLATFORM=ubuntu-24.04`: failed
  before test generation because `gio-2.0` is not installed for
  `fic-session-agent`.
- `git diff --check`: passed.

## Remaining

- Коммит не создавать без отдельного запроса пользователя.
