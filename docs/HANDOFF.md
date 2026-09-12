# FIC: передача контекста

## Current base

- Ветка `main`, база: `d4b2423` (previous session-refactor закоммичен);
  рабочее дерево — незакоммиченный fix reconciliation protocol для
  `disable_kde_lock_screen_media_controls`.

## Current task

- Correctness fix: media-controls KDE reconciliation теперь ВСЕГДА вызывает
  `org.kde.screensaver.configure` (unconditional), KConfig write остаётся
  conditional. Уже корректный `kscreenlockerrc` больше не пропускает
  runtime configure reload — устранён false success при stale cached
  runtime state KScreenLocker.

## Accepted architecture / invariants

- Topology semantics без изменений (см. KdeSessionTopology.h): Unique
  доказан только присутствием exact target (uid + session.id),
  классифицированного KDE, при full inventory; Unknown fail closed;
  precedence: !inventoryComplete -> Unknown; target absent/not KDE ->
  Unknown; kdeSessionCount>1 -> Ambiguous; unknownSessionCount>0 ->
  Unknown; иначе Unique.
- `SessionReconcileContext` (DesktopEnvironmentControl.h): `{const
  ClassifiedGraphicalSession& target; const std::vector<...>& sessions;
  bool inventoryComplete = false;}` — DE-neutral, references, использовать
  синхронно внутри одного reconciliation call. Не содержит KDE-типов.
- KDE topology вычисляется только в KDE-specific consumer path через
  единственный helper `determineKdeSessionTopology`: factory
  (ScreenLockTimeoutHandler.cpp, KDE case) и
  OSS_disable_kde_lock_screen_media_controls. `KdeBackend` по-прежнему
  принимает `(UserSession, SessionContext, KdeSessionTopologyInfo)`.
- Media-controls reconciliation protocol (template helper
  `kde_media_controls::reconcileMediaControls(backend, error)` в
  OSS_disable_kde_lock_screen_media_controls.h, по образцу
  `kde_screen_lock_timeout::applyTimeout`):
  read -> write only if mismatch -> ALWAYS `org.kde.screensaver.configure`
  (ровно один раз на попытку, вне `if (!matches)`) -> final KConfig
  readback -> `validateRuntimeContext` (последняя security boundary).
  Diagnostics: configure failure — `failed to reload KDE lock-screen
  media-control settings: ...`; final mismatch — `KDE lock-screen media
  controls did not reach the requested state`; owner race — `KDE screen
  locker changed during reconciliation: ...`.
- Best-available contract, не более: отдельного runtime getter для
  `showMediaControls` нет; успешный configure + final readback + stable
  captured KScreenLocker identity — максимум доступного доказательства
  конвергенции (как для KDE screenlock timeout). Не заявлять более сильную
  runtime guarantee в коде/docs.
- Factory: `create(const SessionReconcileContext&)`, switch по canonical
  `context.target.desktop`; для non-KDE topology не вычисляется;
  `kindFromName` в factory запрещён.
- Static checks (static_checks.py.in): no `sameUidKdeTopology`/
  `KdeSessionTopology` в control header/session_policy/main; factory и
  media policy содержат `determineKdeSessionTopology`; `switch
  (context.target.desktop)` в factory; media policy делегирует в
  `kde_media_controls::reconcileMediaControls`; в media policy header
  `backend.callDbusMethod` стоит после `if (!matches &&` write-блока и до
  него нет `if (!matches) {` (conditional write / unconditional
  configure), присутствуют `"configure"` и distinct configure diagnostic.

## Completed

- Media-controls protocol: `configure` вынесен из `writeState` в
  unconditional позицию; policy `.cpp` делегирует в header template
  helper; константы (`kscreenlockerrc`, `showMediaControls`, группы
  Greeter/LnF/General, значение `false`) перенесены в namespace
  `kde_media_controls` в header. Topology pipeline, `KdeBackend` API,
  resolver, timeout semantics — без изменений.
- Новый test target `kde_media_controls_tests`
  (tests/fic/modules/oss/desktop_environment/KdeMediaControlsReconcilerTests.cpp,
  fake backend, operations ordering): (1) already-compliant file: writes=0,
  configure=1, final readback, validate, success, exact ordering
  read/configure/read/validate; (2) configure failure на compliant файле
  фатальна (падает на старом коде); (3) mismatch: writes=1, configure=1,
  exact ordering read/write/configure/read/validate; (D) configure failure
  после write фатальна; (4) post-configure mismatch -> failure с исходной
  диагностикой; (5) validateRuntimeContext=false -> failure, owner-race
  диагностика сохранена.
- Negative control: временно возвращён conditional configure (configure
  внутри `if (!matches)`) — `kde_media_controls_tests` упал на test 1
  (`already-compliant file skipped runtime configure reload`), NC_TEST_EXIT=1;
  следов `NEGATIVE CONTROL` нет, fixed implementation восстановлена,
  suite повторно зелёный.

## Validation

- Configure + Build EXIT=0 (`build-fix-check`, ubuntu-24.04): fic,
  kde_media_controls_tests (новый), kde_runtime_context_tests,
  session_aware_policy_tests, screenlock_timeout_global_tests.
- CTest 5/5: перечисленные тесты +
  desktop_environment_architecture_static_checks (обновлённый контракт).
- `git diff --check` чист.
- Live KDE runtime (Plasma session) не валидировался.

## Environment

- `libsystemd-dev` установлен; configure использует системные pkg-config
  пути libsystemd. Никаких stub/fake `libsystemd.pc` не требуется —
  `/tmp/fic-systemd-stubs` удалён и не должен пересоздаваться.
- Build dir: `build-fix-check` (ubuntu-24.04).

## Remaining

- Коммит не сделан (не запрошен).
- KScreenLocker PID -> logind session ID — возможное дальнейшее
  улучшение, отдельная задача.
- Возможный отдельный refactor после закрепления correctness: extraction
  общего KDE config reconciler (timeout + media-controls имеют одинаковый
  protocol) — сознательно НЕ сделан в этой задаче.
