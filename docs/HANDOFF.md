# FIC: передача контекста

## Current base

- Ветка `main`, базовый commit `c47f4c3`.

## Current task

- Уточнить только RU/EN description политики `OSS/screenlock_timeout`, не
  обещая фактическую блокировку не позднее настроенного времени.

## Accepted architecture / invariants

- Политика задаёт точное целевое значение N и reconciles связанные настройки
  поддерживаемого DE.
- Штатные desktop-environment inhibitors могут отложить фактическую блокировку.
- Runtime semantics, prerequisites и production code не меняются.

## Completed

- Обновлены description keys в `ru.lang` и `en.lang`.
- Literal-description static check обновлён под exact-N и inhibition semantics.

## Changed areas

- `fic/src/resources/lang/ru.lang`
- `fic/src/resources/lang/en.lang`
- `tests/fic/modules/oss/desktop_environment/static_checks.py.in`

## Validation

- `desktop_environment_architecture_static_checks`: passed (1/1).
- Проверены оба literal keys и отсутствие прежней формулировки.
- `git diff --check`: passed.

## Remaining

- Коммит не создавать без отдельного запроса пользователя.
