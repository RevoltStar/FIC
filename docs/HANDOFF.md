# FIC: передача контекста

## Current base

- Ветка `main`.
- База: `3420d1f`.

## Current task

- Исправить install-layout `fic-session-agent`, чтобы XDG Autostart был
  доступен обычному пользователю без ослабления private tree `/opt/fic`, и
  нормализовать staged modes обоих `fic-gui` executables в `0750`.

## Accepted architecture / invariants

- Canonical path `fic-session-agent` —
  `/usr/libexec/fic/fic-session-agent`, `root:root 0755`.
- `/opt/fic` остаётся `root:fic 2750`; private executables, включая
  `/opt/fic/bin/fic-cli`, остаются `0750`.
- XDG Autostart использует exact `Exec=/usr/libexec/fic/fic-session-agent`.

## Completed

- Добавлен общий CMake layout constant `FIC_SESSION_AGENT_BINDIR`.
- CMake component, DEB и RPM staging переведены на `/usr/libexec/fic`.
- DEB/RPM staging явно фиксирует `0755` для public agent и `0750` для
  `fic-cli`, `fic-gui` launcher и `fic-gui.real`; package ownership
  нормализуется в `root:root` существующими DEB/RPM mechanisms.
- Добавлены static и component-install staging regressions для public agent,
  autostart path, отсутствия private copy и сохранения private boundary.
- Packaging README обновлены новым layout.

## Changed areas

- `cmake/FicInstallLayout.cmake` и `fic-session-agent/CMakeLists.txt`.
- XDG Autostart template.
- DEB/RPM build scripts и packaging README.
- Session-agent static/package-layout tests.

## Validation

- Targeted configure: Ubuntu 24.04 profile с локальным `/tmp` libsystemd
  pkg-config shim — passed.
- `cmake --build build-session-layout --target fic-session-agent -j2` — passed.
- Targeted CTest: 7/7 passed (`session_agent_static_checks`,
  `session_agent_install_layout_tests`, `path_layout_static_checks`,
  `platform_profile_static_checks`, `packaging_build_resource_tests`,
  `version_contract_tests`, `release_contract_tests`).
- `bash -n` для DEB/RPM builders и нового staging test — passed.
- Follow-up checks после добавления `fic-gui` modes: session-agent,
  platform-profile и path-layout static checks, GUI runtime compliance test и
  `bash -n` DEB/RPM builders — passed.
- Negative controls: old desktop path, private CMake destination, public agent
  mode `0750` и `fic-cli` mode `0755` — каждый вызвал ожидаемое падение.
- `git diff --check` — passed.
- Полная сборка проекта не запускалась согласно ограничению задачи.

## Remaining

- Follow-up с explicit `0750` для `fic-gui` и `fic-gui.real` не закоммичен.
