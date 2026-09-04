# FIC: передача контекста

## Current base

- Ветка: `main`.
- Родитель текущей незакоммиченной правки:
  `f2e98cf0de0173d90f926589fd8ced652281c494`.

## Current task

- Финализировать RPM notice discovery: объединить `%license` с узким ALT
  `qt6-base-common` `%doc` fallback и закрыть mixed-layout regression.

## Accepted architecture / invariants

- FIC остаётся под SUL-1.0; Qt dynamically linked и отдельно лицензируется.
- Bundled Qt root остаётся `/opt/fic/qt`, `FIC_QT_ROOT` остаётся механизмом
  полной замены root.
- Runtime manifest и Corresponding Source schema остаются version 1.
- RPM notice discovery основан только на file flags; filename heuristic нет.
- Изменения не коммитить без отдельной явной команды пользователя.

## Completed

- Все related RPM `%license` notices теперь объединяются с применимым ALT
  fallback вместо раннего возврата при первом `%license`.
- Fallback остался ограничен `qt6-base` / `qt6-base-common`, `%doc` и
  непосредственными regular/readable files versioned documentation root.
- Реальный two-package RPM fixture проверяет mixed union, deterministic order,
  исключение постороннего `%doc`, missing files и symlink rejection.
- Удалено неверное объяснение про отсутствие `%license` в RPM 4.13.
- ALT build/runtime Docker images переключены с `ftp.altlinux.org` на уже
  предусмотренный в base image `mirror.yandex.ru` p11 source list.
- Устранён false negative Xvfb smoke gate: `grep -q` больше не вызывает
  SIGPIPE failure upstream `printf` при большом `LD_DEBUG` output.
- Все пять ALT RPM пересобраны из текущего дерева в `dist/`.

## Changed areas

- RPM manifest discovery: `packaging/lib/gui-runtime-manifest.py`.
- RPM fixtures и smoke gate: `tests/integration/packaging/`,
  `packaging/lib/gui-runtime-compliance.sh`.
- ALT container sources и RPM documentation: `packaging/rpm/`.

## Validation

- Fedora RPM file-flags fixture, включая mixed layout — passed.
- `gui-runtime-compliance-test.sh` — passed.
- Все пять ALT p11 RPM rebuilt successfully через Yandex mirror.
- Итоговый `fic-gui`: no `libQt6*` Requires; manifest schema 1, 12 Qt
  components, 38 notice references и 37 unique packaged notice contents.
- Fresh RPM extraction + manifest/SHA-256 verification — passed.
- Clean ALT p11 ordinary dependency installation — passed; system Qt RPM не
  установлен, default и `FIC_QT_ROOT` Xvfb/loader smoke passed.
- Python compile check, shell syntax checks и `git diff --check` — passed.

## Remaining

- Технических blockers текущей задачи нет.
- Публичный release не создавался; release gate по-прежнему требует exact Corresponding Source set, exact tag/version и clean tree. Package signing, SBOM generation и publication остаются отдельными release-engineering этапами.
