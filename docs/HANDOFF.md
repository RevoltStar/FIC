# FIC: передача контекста

Этот файл хранит актуальный снимок незавершенной работы. Обязательные правила и
границы компонентов находятся в `AGENTS.md`.

## Текущий снимок

- Обновлено: 2026-08-02.
- Ветка: `main`.
- Базовый commit: `09d92df9da910b1fb5adaac61ef86712bc73aa44`.
- Текущая задача: единый version/release contract для поколения FIC 2.x.
- Изменения рабочей копии не зафиксированы commit.

## Сделано

- Проект называется `FIC`; каталог `FIC2.0` обозначает второе поколение, а не
  отдельное имя продукта. FIC 1.x зафиксирован как никогда не выпускавшийся
  прототип без compatibility/migration contract.
- Development version по умолчанию — `2.0.0-dev`, первый планируемый stable —
  `2.0.0`. CMake принимает SemVer без build metadata и отдельно хранит полный
  commit, release tag и тип сборки.
- Все пять исполняемых компонентов поддерживают `--build-info`; `--version`,
  GUI metadata и package metadata получают версию из общего контракта.
- Native package builders требуют явную product version. Prerelease
  `2.0.0-rc.1` в бинарниках отображается без изменений, а в DEB/RPM
  преобразуется в `2.0.0~rc.1` для правильного порядка обновлений.
- Package builders проверяют `--version`, `--build-info` и итоговые native
  package metadata. Provenance передается через container wrappers.
- Добавлен fail-closed release entry point
  `packaging/release/build-release.sh`: чистое дерево, точный annotated SemVer
  tag, полный SHA, changelog heading, архив tagged commit, четыре поддерживаемых
  package matrix и SHA-256 manifest для 20 пакетов.
- Удалены package entry points Debian 10/11, которых нет в списке
  поддерживаемых платформ.
- Добавлены `CHANGELOG.md`, release-документация и CTest-проверки version,
  release и build-info контрактов.

## Измененные файлы

- `CMakeLists.txt`, `README.md`, `CHANGELOG.md`;
- `fic-common/fic-version/CMakeLists.txt`, `ProductVersion.h.in`, `BuildInfo.h`;
- `fic/src/main.cpp`, `fic-cli/src/main.cpp`, `fic-gui/src/main.cpp`,
  `fic-session-agent/src/main.cpp`, `fic-dick/src/main.cpp` и относящиеся README;
- `fic-gui/CMakeLists.txt`;
- `packaging/lib/version-contract.sh`, `packaging/lib/release-contract.sh`,
  `packaging/release/build-release.sh`;
- актуальные DEB/RPM builders, container wrappers и packaging README;
- удалены шесть Debian 10/11 Docker/build entry points;
- `tests/CMakeLists.txt`, `tests/version/*`, `tests/platform/static_checks.py`;
- `docs/architecture-diagrams.md`, `docs/upgrade-contract.md`,
  `docs/release-process.md`, `docs/session-agent.md`, `docs/HANDOFF.md`.

## Выполненные проверки

- Полная конфигурация и сборка профиля `alt-p11`:
  `cmake -S . -B build-check -DFIC_TARGET_PLATFORM=alt-p11
  -DFIC_PRODUCT_VERSION=2.0.0-dev` и `cmake --build build-check -j2` — успешно.
- Фактически запущены `--version` и `--build-info` всех пяти binaries; версия,
  build kind, commit/tag и schema/API fields совпали.
- `ctest --test-dir build-check --output-on-failure`: 27 из 27 без ошибок;
  host-dependent IPC/admin-socket/command-hash tests корректно SKIP (3).
- `version-contract-test.sh`, `release-contract-test.sh`, включая
  `--verify-only` и синтетический end-to-end сбор 20 artifacts/manifest, а
  также platform static checks — успешно.
- Все packaging/version shell scripts прошли `bash -n`; все восемь package
  entry points проверены на отказ при пропущенной версии.
- `git diff --check` — успешно.
- Реальная Docker-сборка DEB/RPM не запускалась: release entry point требует
  сначала commit, changelog release heading и annotated tag.
- Службы, политики ОС, `/opt/fic` и package manager host-системы не изменялись.

## Что осталось

- Перед первым релизом перенести changelog entries из `Unreleased` в точный
  dated heading, зафиксировать изменения и создать annotated tag.
- На tagged commit выполнить полный Docker release matrix; эта реализация пока
  проверена сборкой исходников, static/unit tests и release-gate fixture, но не
  реальными DEB/RPM artifacts.
- Отдельные пункты production release engineering остаются открыты: signing,
  SBOM, provenance attestation, publication policy и release notes.
- Синхронизировать DEB/RPM license metadata с `SUL-1.0`, добавить
  `THIRD_PARTY_NOTICES` и включать лицензионные файлы в пакеты.
- Включить GitHub Private Vulnerability Reporting в настройках репозитория.

## Риски и решения

- Любой разработчик технически может вызвать CMake или native builder напрямую;
  официальным релизом считается только результат
  `packaging/release/build-release.sh`, прошедший Git source gate.
- Release build создается из `git archive` tagged commit, а не из live working
  tree. Поэтому локальные build directories и untracked files не могут попасть
  в artifact даже после прохождения проверки чистоты.
- Commit не добавляется в SemVer: он доступен отдельным полем `--build-info` и
  в manifest. Это сохраняет единое product version для GUI, package manager и
  upgrade journal.
- Отсутствие FIC 1.x migration является намеренным решением до первого stable
  release, а не незавершенной совместимостью.
