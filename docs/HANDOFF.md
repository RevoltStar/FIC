# FIC: передача контекста

## Current base

- Ветка `main`, базовый commit `6c1b0b4`.

## Current task

- Уточнить пользовательское RU/EN description политики
  `IDENTITY_ACCESS/enable_password_history` с описанием поведения
  `pam_pwhistory` при отклонённой смене пароля.

## Accepted architecture / invariants

- Меняется только локализованное описание политики.
- Policy identifier/name/value/dependencies, `password_history_depth`, PAM
  configuration и runtime implementation не меняются.

## Completed

- Обновлены парные description keys в `ru.lang` и `en.lang`.
- Исходное описание активации механизма сохранено в начале; примечание о
  поведении `pam_pwhistory` добавлено в конец.
- Проверено отсутствие прежних формулировок и неизменность description
  `password_history_depth`.

## Changed areas

- `fic/src/resources/lang/ru.lang`
- `fic/src/resources/lang/en.lang`

## Validation

- `path_layout_static_checks`, `module_ui_static_checks`,
  `identity_policy_hierarchy_tests`: 3/3 passed.
- `git diff --check`: passed.

## Remaining

- Коммит не создавать без отдельного запроса пользователя.
