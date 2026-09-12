# FIC: передача контекста

## Current base

- Ветка `main`, HEAD `b5dd79c`; рабочее дерево — незакоммиченная
  type-aware XFCE `screenlock_timeout` compliance (см. `git status`).

## Current task

- Type-aware XFCE screenlock compliance: textually equal, но wrongly-typed
  Xfconf property (например `string "5"` vs ожидаемый `int 5`) считается
  non-compliant, repair выполняется typed `xfconf-query --create --type`
  записью. Чтение фактического GType — через новый session-scoped helper
  `fic-xfconf-inspect` (libxfconf), запускаемый daemon-ом через
  session-scoped execution path.

## Accepted architecture / invariants

- Новый helper `fic-xfconf-inspect` (`fic-session-agent/src/xfconf-inspect/`,
  C++17 + pkg-config `libxfconf-0` REQUIRED):
  - canonical путь инсталляции `${FIC_SESSION_AGENT_BINDIR}/fic-xfconf-inspect`
    (= `/usr/libexec/fic/fic-xfconf-inspect`), 0755 root-owned, component
    `fic-session-agent`;
  - daemon компилирует путь (`FIC_XFCONF_INSPECT_PATH`) и НИКОГДА не
    резолвит helper из session `$PATH`; in-process libxfconf в daemon
    запрещено (static check);
  - line-protocol v1: `fic-xfconf-inspect-protocol=1` / `type=<bool|int|
    uint|double|string|<GType name>>` / optional `value=<...>`; value line
    только для scalar-алиасов; unknown GType → имя типа без value → backend
    трактует как mismatch; malformed output → fail closed;
  - exit codes: 0 ok, 2 usage, 3 absent/unreadable, 4 xfconf init failure;
    любой не-ноль → read failure → policy fail (missing property сохраняет
    прежнюю семантику: не конвертируется в writable mismatch);
  - `--self-test` — GValue→protocol conversion test без D-Bus (ctest
    `fic_xfconf_inspect_self_test`, плюс прогон из layout test).
- Compliance protocol (`XfceScreenLockTimeoutHandler.h`): readState →
  `getPropertyState` для каждого property; exact storage type проверяется
  ДО semantic value compare; любой mismatch → typed repair всех required
  properties; final typed readback обязателен; live
  `xfce4-screensaver-command --query` checks не изменились.
- Writer contract (`XfceBackend::setProperty`): ровно одна команда
  `xfconf-query --channel C --property P --create --type T --set V`
  (typed-first, без leading plain `--set`, fallback удалён; `--create
  --type` меняет type существующего property in-place).
- Packaging: runtime `libxfconf-0-3` (deb) / `libxfconf` (ALT) —
  автоматическая зависимость только пакета `fic-session-agent`
  (dpkg-shlibdeps / RPM find-requires); build deps `libxfconf-0-dev` /
  `libxfconf-devel` добавлены во все 5 Dockerfile-профилей и проверяются
  `session_agent_static_checks`. `fic` package Recommends (не Depends)
  `fic-session-agent`: без установленного session-agent пакета XFCE
  screenlock policy fail closed с "helper was not found".
- API 4.16–4.20 libxfconf идентичен для используемых функций
  (`xfconf_init(GError**)`, `xfconf_channel_get_property(channel, property,
  GValue*)`) — Debian 12 ↔ 4.20 совместимо.

## Completed

- Helper + install + self-test; `XfceBackend::getPropertyState` (typed
  read), text-only `getProperty` удалён; typed-first `setProperty`;
  type check в `readState` (`XfcePropertyType`, `XfcePropertyState`,
  `xfcePropertyTypeName` в `XfceBackend.h`).
- Tests: `XfceBackendTests` переписан (typed argv contract, helper path/
  protocol parse, malformed fail-closed); `SessionSettingReconcilerTests`
  fake хранит type+value, regressions: string("5") vs int 5,
  string("true") bool repair, fullscreen-inhibit string("false") (4.20
  default drift), uint/double mismatch, failed-repair fail-closed.
- Static checks: desktop_environment_architecture_static_checks (typed
  writer/reader, no in-process libxfconf, canonical path),
  session_agent_static_checks (helper pkg-config/install/self-test,
  Dockerfile build deps, deb dep resolution), layout test (helper mode
  0755 + self-test run).
- Negative controls выполнены и откатены: NC1 (type-check disabled →
  главный regression падает), NC2 (untyped `--set` writer + type-preserving
  fake → wrong-type regressions fail closed). Финальный код восстановлен.

## Validation

- Build `build-xi-check` (ubuntu-24.04): `fic` (полный daemon),
  `fic-xfconf-inspect`, `xfce_backend_tests`,
  `session_setting_reconciler_tests`, `screenlock_timeout_global_tests`,
  `session_aware_policy_tests`, `controlled_desktop_environments_tests`,
  `session_ready_retry_tests`, `session_ready_validation_tests`,
  `fic-session-agent` — все OK.
- CTest зелёные: 4 unit XFCE/desktop tests + helper self-test +
  desktop_environment_architecture_static_checks,
  session_agent_static_checks, packaging_build_resource_tests,
  session_agent_install_layout_tests.
- Helper: скомпилирован против реальных libxfconf 4.20 headers; self-test
  (GValue→protocol) passes; fail-closed exit codes 2/3 проверены.
- `git diff --check` чист.
- НЕ валидировалось: live XFCE session (реальный xfconfd, typed repair
  against real daemon), полная сборка всех таргетов, full CTest, реальные
  deb/rpm сборки (Docker недоступен в окружении).

## Environment

- Локальный configure требует pkg-config `libxfconf-0` (REQUIRED в
  fic-session-agent). В данном WSL-окружении использовался extracted
  devroot `/tmp/fic-xi/devroot` (libxfconf-0-dev + libglib2.0-dev debs,
  prefix переписан) + stubs `/tmp/fic-xi/pc-stub` (libpcre2-8, libffi,
  mount, libselinux, zlib), запуск helper/self-test с
  `LD_LIBRARY_PATH=/tmp/fic-xi/devroot/usr/lib/x86_64-linux-gnu`.
  Системной установки dev-пакетов не производилось (нет sudo).
- Build dir: `build-xi-check` (ubuntu-24.04).

## Remaining

- Коммит не сделан (не запрошен).
- Helper line-protocol не поддерживает multi-line string values
  (malformed → fail closed) — для скалярных policy properties некритично.
- `fic` package имеет только Recommends на fic-session-agent; если XFCE
  policy должен работать на системах без session-agent пакета — обсудить
  повышение до Depends (вне scope текущей задачи).
