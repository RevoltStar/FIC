# FIC: передача контекста

## Current base

- Ветка `main`, HEAD `753bd1b`.

## Current task

- XFCE `screenlock_timeout` regression fix: `Present` / `Absent` / `Error` —
  три разных состояния чтения Xfconf property (реализовано, идёт валидация).

## Accepted architecture / invariants

- Историческая регрессия: `50bef33` сделал absent property фатальной ошибкой
  reader'а (exit 3 объединял absent и unreadable), хотя initial implementation
  (`136b4ab`) писала первой с `--create --type` fallback. Свежий XFCE profile
  (все 7 свойств отсутствуют) не мог сойтись.
- Absent vs Error различимы только на уровне D-Bus: публичный C API libxfconf
  (`xfconf_channel_get_property`) проглатывает все ошибки. Только
  `org.xfce.Xfconf.Error.PropertyNotFound` от живого daemon'а означает
  отсутствие; ServiceUnknown / Spawn.ExecFailed / ReadFailure / etc — реальный
  failure. `xfconf_init` подключается лениво, поэтому daemon-down ранее
  выглядел как exit 3 неотличимо от absent.
- Helper `fic-xfconf-inspect` читает через прямой GDBus-вызов
  `org.xfce.Xfconf.GetProperty` c `DO_NOT_AUTO_START` (proxy и call): мёртвый
  daemon не воскресает молча и не маскируется под absent. Protocol v2:
  `state=present` (+`type=`, `value=` для policy-known scalar) или
  `state=absent` (bare); exit 0 = валидный результат, 2 = usage, 3 = реальная
  read/runtime D-Bus ошибка, 4 = недоступен session bus / инициализация.
  Unknown present type остаётся normal present с type mismatch.
- Backend tri-state: `XfcePropertyStateKind {Present, Absent}`;
  `getPropertyState`: true+Present / true+Absent / false = реальный failure.
  Parser строго принимает только protocol v2 (v1 и malformed — fail closed).
- Handler (Model B, explicit-state): Absent → mismatch → typed writer
  (`--create --type`) materialизует свойство, даже если upstream default
  случайно совпадает (fullscreen-inhibit default менялся между 4.18 и 4.20).
  Error → failure, zero writes. Final typed readback обязателен: success только
  при Present + exact type + exact value.
- `reconcileEffectiveSetting()`, typed writer, семь XFCE paths, KDE/GNOME/FLY —
- Helper не имеет libxfconf зависимости (ни build-time, ни runtime): линкуется
  только через `gio-2.0` (`PkgConfig::SESSION_AGENT_GIO`), NEEDED: libgio/libglib/
  libgobject-2.0. `libglib2.0-dev` / `glib2-devel` — обязательный build dep в CI
  и packaging Dockerfiles; runtime GLib-зависимости resolving'ятся из ELF
  (dpkg-shlibdeps / rpm find-requires).

- Dependency cleanup: `libxfconf-0` убран из CMake (→ `gio-2.0`), CI
  (`libxfconf-0-dev` → `libglib2.0-dev`), packaging Dockerfiles (deb ×4 →
  `libglib2.0-dev`, rpm → `glib2-devel`); session agent static checks обновлены.
  Runtime packaging deps не менялись (ELF-driven). Поведение helper не менялось.


  не менялись. XFCE остаётся `SessionOnly`.

## Completed

- Helper: protocol v2, GDBus, exact error-name mapping, расширенный self-test
  (Present/Absent serialization + error classification).
- Backend: tri-state API + строгий v2 parser.
- Handler: Absent → mismatch; Error остаётся фатальным.
- Тесты: XfceBackendTests (v2/absent/malformed/old-version),
  SessionSettingReconcilerTests (fresh-profile absent, all-7 absent, daemon-down
  zero-writes, absent-race), static checks на protocol v2 и tri-state.
- NC1 (Absent снова fatal → suite падает) и NC2 (read failure как Absent →
  blind write пойман) выполнены и production code восстановлен.
- Isolated real probe (dbus-run-session + temp XDG + xfconfd 4.20.0): absent →
  exit 0 + `state=absent`; typed create → `state=present type=int value=1` /
  `type=bool value=false`; daemon down → exit 3 + реальная ошибка (не absent).

## Changed areas

- `.github/workflows/ci.yml`, `packaging/deb/Dockerfile*`, `packaging/rpm/Dockerfile`
- `tests/fic-session-agent/static_checks.py`

- `fic-session-agent/src/xfconf-inspect/main.cpp`, `fic-session-agent/CMakeLists.txt` (комментарий)
- `fic/src/modules/oss/desktop_environment/backends/XfceBackend.{h,cpp}`
- `fic/src/modules/oss/desktop_environment/policies/XfceScreenLockTimeoutHandler.h`
- `tests/fic/modules/oss/desktop_environment/{XfceBackendTests,SessionSettingReconcilerTests}.cpp`
- `tests/fic/modules/oss/desktop_environment/static_checks.py.in`
- `docs/HANDOFF.md`

## Validation

- Целевая сборка (build-fix, ubuntu-24.04): `fic`, `fic-xfconf-inspect`,
  `xfce_backend_tests`, `session_setting_reconciler_tests`,
  `screenlock_timeout_global_tests`, `session_aware_policy_tests` — OK.
- CTest: `fic_xfconf_inspect_self_test`, `xfce_backend_tests`,
  `session_setting_reconciler_tests`, `screenlock_timeout_global_tests`,
  `session_aware_policy_tests`, `desktop_environment_architecture_static_checks`,
  `session_agent_static_checks`, `session_agent_install_layout_tests` — все
  Passed (см. финальный отчёт за full build/CTest).
- После dependency cleanup: targeted build (`fic-xfconf-inspect`,
  `fic-session-agent`, `fic`), full build 100% 0 errors, full CTest 88/88
  passed (1 skipped by design), `readelf -d` helper: NEEDED без libxfconf
  (только gio/glib/gobject + libc++ runtime), `git diff --check` clean.
- Live XFCE screensaver session недоступна в этом окружении; live-проверка на
  реальной XFCE сессии остаётся открытой.

## Remaining

- Живая XFCE-валидация на реальной сессии.
