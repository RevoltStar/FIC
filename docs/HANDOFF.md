# FIC: передача контекста

## Current base

- Ветка `main`, база: `ae6bc23` (парсер KDE/XFCE), рабочее дерево — 
  незакоммиченная topology-fix (коммит не запрошен).

## Current task

- KDE SessionOnly topology: `sameUidKdeSessionCount` (int) заменён на 
  typed `KdeSessionTopology {Unique, Ambiguous, Unknown}`.

## Accepted architecture / invariants

- Unique доказан только если: ровно одна same-UID сессия классифицирована
  KDE И ни одной same-UID сессии с Unknown/failed классификацией.
- Достоверно non-KDE same-UID сессия (GNOME/XFCE/FLY) НЕ делает topology
  Ambiguous; KDE+KDE+non-KDE — Ambiguous; KDE+Unknown same UID — Unknown;
  чужой UID (в т.ч. Unknown) не влияет; неполная inventory или KDE target
  вне inventory — Unknown. Unknown fail closed как Ambiguous.
- Общий алгоритм — `determineKdeSessionTopology(target, sessions, 
  inventoryComplete)` в `desktop_environment/KdeSessionTopology.h/.cpp`;
  обе production paths (SessionAwareDesktopEnvironmentPolicy::apply и 
  reconcile_session_ready в main.cpp) используют только его.
- `ClassifiedGraphicalSession.sameUidKdeTopology` — `KdeSessionTopologyInfo`
  (state + counts + unknownSessionId/classificationError для диагностики).
  Промежуточный минимальный refactor по договорённости; полный factory 
  refactor `create(const ClassifiedGraphicalSession&)` — отдельно.
- Resolver принимает `KdeSessionTopologyInfo`, разные диагностики для 
  Ambiguous ("multiple KDE graphical sessions exist for UID ...") и Unknown
  ("KDE session topology is unknown for UID ..." + проблемная сессия). 
  Остальные проверки (D-Bus owner/PID/UID, environ, revalidation) не менялись.
- Static checks фиксируют отсутствие `sameUidKdeSessionCount` в fic и 
  наличие обоих вариантов диагностики в resolver.
- ScreenLockTimeoutHandlerFactory принимает `create(const 
  ClassifiedGraphicalSession&)` и выбирает handler только по canonical
  `session.desktop`; повторная классификация `context.desktop` внутри
  factory запрещена static check. `sameUidKdeTopology` остаётся в
  ClassifiedGraphicalSession (вынос — отдельная задача).
- База для этого: незакоммиченный factory refactor поверх topology-fix.

## Completed

- Новый `KdeSessionTopology.h/.cpp`; замена count на typed topology по всей 
  цепочке (DesktopEnvironmentControl.h, KdeBackend, resolver, KDE handler,
  ScreenLockTimeoutHandlerFactory, OSS_screenlock_timeout, 
  OSS_disable_kde_lock_screen_media_controls); session_ready fallback 0 
  удалён.
- Тесты: 7+ обязательных topology-кейсов в KdeRuntimeContextTests (helper + 
  resolver diagnostics + KdeBackend fail-closed Unknown) и apply-path 
  topology propagation в SessionAwarePolicyTests.
- Factory refactor: regression `testFactoryUsesCanonicalDesktopIdentity` в
  ScreenlockTimeoutGlobalTests (противоречивые desktop/context объекты,
  полная DE-матрица через dynamic_cast); static check kindFromName-off в
  factory. Negative control выполнен для обоих задач.
- Exact-target fix в determineKdeSessionTopology: Unique только при
  присутствии exact target (uid + session.id), классифицированного KDE;
  precedence: !inventoryComplete -> Unknown; target absent -> Unknown;
  target не KDE -> Unknown; kdeSessionCount>1 -> Ambiguous; 
  unknownSessionCount>0 -> Unknown; иначе Unique. Target missing + 
  несколько других KDE same UID = Unknown (не Ambiguous).
- KdeSessionTopologyInfo: diagnostics-only поля targetPresent и
  targetClassifiedKde; resolver Unknown-диагностика различает absent 
  target и unclassified соседа. sameUidKdeTopology по-прежнему в 
  ClassifiedGraphicalSession (перенос — отдельная задача).
- Regression: testKdeSessionTopologyTargetPresence (A-E) + 
  testResolverDiagnosticForMissingTarget; negative control подтверждён 
  (count-only семантика -> "replacement same-UID KDE session masqueraded
  as the target").

## Validation

- Build: kde_runtime_context_tests, session_aware_policy_tests, 
  screenlock_timeout_global_tests, fic — EXIT=0.
- CTest: kde_runtime_context_tests, session_aware_policy_tests, 
  screenlock_timeout_global_tests, desktop_global_config_reconciler_tests,
  session_ready_retry/validation_tests, 
  desktop_environment_architecture_static_checks — все passed.
- Negative control: возврат count-only семантики в helper → оба 
  KDE+Unknown regression упали; код восстановлен, тесты зелёные.
- `git diff --check` — чисто; `sameUidKdeSessionCount` в проде не остался.

## Environment

- Build окружению нужны systemd stubs: /tmp/fic-systemd-stubs 
  (systemd/sd-daemon.h, systemd/sd-login.h, libsystemd.pc) и 
  PKG_CONFIG_PATH=/tmp/fic-systemd-stubs при configure; /tmp очищается 
  между сессиями — пересоздать при необходимости.

## Remaining

- Коммит не сделан (не запрошен).
- KScreenLocker PID -> logind session ID — возможное дальнейшее 
  улучшение, отдельная задача.
