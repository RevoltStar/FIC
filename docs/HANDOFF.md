# FIC: передача контекста

## Current base

- Ветка `main`.
- База перед текущей задачей: `04391d0e6a4bceb2980d9c0ec39290c1bddeb8fe`.

## Current task

- Corrective fix KDE runtime context: не использовать ownership procfs inode
  `/proc/<pid>/environ` как доказательство UID процесса.

## Accepted architecture / invariants

- KDE и XFCE остаются `SessionOnly`; GNOME и FLY — `MandatoryGlobal`.
- Authoritative KDE context принадлежит текущему owner
  `org.kde.screensaver`, а не `fic-session-agent`.
- Bus address, executable paths, UID/GID, safe base environment и cwd задаёт
  daemon; из locker разрешены только `HOME`, `XDG_CONFIG_HOME`,
  `XDG_CONFIG_DIRS`, `KDE_SKIP_KDERC` с exact absent/empty/value semantics.
- Несколько controlled KDE sessions одного UID неоднозначны и fail closed.
- Process UID доказывается D-Bus identity chain; `st_uid` файла procfs не
  является security invariant.
- KConfig readback не доказывает cached runtime state KScreenLocker.

## Completed

- Удалена ошибочная проверка `fstat.st_uid == D-Bus owner UID`.
- Production reader по-прежнему открывает с `O_NOFOLLOW`, проверяет `S_ISREG`,
  читает один fd с лимитом 1 MiB и закрывает тот же fd.
- Добавлен syscall-level regression: D-Bus UID `1000`, procfs metadata UID
  `root`, читаемое environment — resolver успешно получает snapshot.

## Changed areas

- KDE runtime-context resolver production read path и focused tests.

## Validation

- `kde_runtime_context_tests` — built successfully.
- `kde_runtime_context_tests`, `screenlock_timeout_global_tests`,
  `session_setting_reconciler_tests` и architecture static checks — 4/4 passed.
- Negative control с восстановленной проверкой `st_uid == expectedUid` упал
  на root-owned procfs metadata regression.
- `git diff --check` — passed.
- Полная сборка проекта не запускалась по ограничению задачи.

## Remaining

- Реальная Plasma runtime validation этого corrective commit не выполнялась.
