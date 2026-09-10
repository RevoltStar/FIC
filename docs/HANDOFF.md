# FIC: передача контекста

## Current base

- Ветка `main`.
- База до текущей правки: `17888fa` (`Исправлена ALT password-history topology`).

## Current task

- Устранить race между ALT TCB password transaction и FIC inspection/mutation
  password-history topology.

## Accepted architecture / invariants

- `pam_fic_pwtxn` остаётся единственным serialization mechanism для provider
  history transaction.
- Manager использует тот же advisory write-lock protocol на
  `/var/lib/fic-pwhistory/.lock`: `F_OFD_SETLK`, fallback `F_SETLK`, timeout 15s.
- Единый порядок manager locks: topology lock, затем transaction lock. PAM
  path берёт только transaction lock, поэтому lock cycle отсутствует.
- Busy transaction означает временно недоступную inspection, а не Broken.
- В стабильном состоянии `opasswd`/`opasswd.old` сохраняют строгий `nlink == 1`.

## Completed

- `status()`/`inspect()` сериализуют live history validation с password change;
  `inspect()` отображает timeout как `PamTopologyState::Unavailable`.
- `prepareStorage()` и `enable()` создают/валидируют history только под обоими
  lock; `disable()` удерживает transaction lock при удалении managed PAM block.
- Transaction lock открывается с `O_NOFOLLOW`, валидируется через `fstat` и
  освобождается закрытием того же descriptor.
- Добавлен fork-based regression: child держит `.lock` и transient hardlink
  `opasswd.old`; до unlock manager сообщает Unavailable, после стабилизации —
  Enabled.
- RPM README уточняет locking и ownership/metadata contract storage topology.

## Changed areas

- `AltPamPasswordHistoryTopologyManager` и его tests.
- `packaging/rpm/README.md`.

## Validation

- Ubuntu 24.04 targeted CTest: 4/4 passed, включая PAM activation/faillock,
  password-history topology и RPM PAM static checks.
- Fresh ALT p11 targeted build/test:
  `alt_pam_password_history_topology_tests` passed 1/1.
- `git diff --check` — passed.

## Remaining

- Live ALT TCB password-change smoke не выполнялся.
- Full project build/CTest и полный RPM Docker build не запускались.
