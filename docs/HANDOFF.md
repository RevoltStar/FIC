# FIC: передача контекста

## Current base

- Ветка `main`.
- База до текущей правки: `ff7cd9a` (`Fail safe KDE screen lock enforcement`).

## Current task

- Исправить ALT password-history topology для штатного ownership drift,
  создаваемого upstream `pam_pwhistory`.

## Accepted architecture / invariants

- UID `opasswd` и optional `opasswd.old` не является security invariant:
  upstream provider может пересоздать их от UID меняющего пароль пользователя.
- Для обоих history files остаются обязательными regular/non-symlink type,
  `shadow` GID, mode `0660` и `nlink == 1`.
- Parent остаётся строго `root:shadow`, mode `2730`, directory/non-symlink;
  transaction lock сохраняет строгий owner/GID/mode/type/nlink contract.
- FIC не создаёт и не исправляет `opasswd.old`; если provider создал файл,
  manager валидирует его fail-closed.

## Completed

- Existing-file и status validation для `opasswd` больше не сравнивает UID.
- `opasswd.old`, вычисляемый как `<historyFile>.old`, добавлен в status
  verification как optional provider artifact без UID invariant.
- Добавлены regression cases для baseline metadata, provider-owned `opasswd`
  и `opasswd.old`, а также wrong GID/mode/nlink/type/symlink/bad parent.

## Changed areas

- `AltPamPasswordHistoryTopologyManager`.
- `AltPamPasswordHistoryTopologyManagerTests`.

## Validation

- Ubuntu 24.04 build profile: affected targets rebuilt; targeted CTest 3/3
  passed (`pam_capability_activation_policy_tests`,
  `alt_pam_faillock_topology_tests`,
  `alt_pam_password_history_topology_tests`).
- Fresh ALT p11 configure/build: `alt_pam_password_history_topology_tests`
  passed 1/1.
- `git diff --check` — passed.

## Remaining

- На текущем WSL/tmpfs смена GID отвергается filesystem, поэтому wrong-GID
  mutation self-skips; case выполняется полностью на обычном root/container
  filesystem. Остальные negative cases выполнены локально.
- Live ALT TCB password-change smoke после этой source правки не выполнялся.
