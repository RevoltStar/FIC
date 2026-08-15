# FIC 2.0 — инструкции для coding agents

Этот файл — карта репозитория, архитектурные инварианты и обязательные правила работы.

Не используй его как полную документацию проекта. Для конкретной задачи читай только относящиеся к ней исходники, тесты и документацию.

## 1. Язык общения

Все сообщения пользователю, включая промежуточные пояснения и финальный отчёт о выполненной работе, пиши на русском языке, если пользователь явно не попросил другой язык.

Не переводи без необходимости:

* имена файлов и каталогов;
* identifiers;
* имена классов, функций, API и типов;
* команды;
* код;
* diagnostic output;
* сообщения сторонних инструментов.

Если пользователь явно просит ответ на другом языке, следуй его запросу.

## 2. Перед началом задачи

Всегда:

1. Выполни `git status --short`.
2. Прочитай `docs/HANDOFF.md`.
3. Определи минимальный scope текущей задачи.
4. Читай только файлы и документацию, необходимые для этого scope.

Не делай полный обзор репозитория без необходимости.

Не перечитывай все README и весь `docs/architecture-diagrams.md` заранее. Открывай только относящиеся к задаче компоненты и разделы.

Если архитектурное решение явно зафиксировано в `docs/HANDOFF.md`, релевантной архитектурной документации или acceptance criteria текущей задачи, считай его принятым, если задача прямо не требует его пересмотра.

Не пересматривай уже принятое решение только потому, что существует другой возможный дизайн.

---

## 3. Основные архитектурные границы

* `fic/`

  * привилегированный daemon;
  * единственный владелец изменения policy configuration;
  * единственный компонент, применяющий политики к ОС.

* `fic-cli/`

  * CLI-клиент daemon API;
  * не изменяет системные policy files напрямую.

* `fic-gui/`

  * GUI-клиент daemon API;
  * не изменяет системные policy files напрямую.

* `fic-session-agent/`

  * непривилегированный агент пользовательской графической сессии;
  * сообщает daemon метаданные сессии;
  * не получает и не применяет policy values.

* `fic-dick/`

  * сбор и актуализация device database.

* `fic-common/fic-ipc/`

  * общий Unix socket / JSON IPC contract.

* `fic-common/fic-core/`

  * общие низкоуровневые utilities:
    configs, files, logging, process execution, locks, command hashes.

* `fic-common/fic-device-db/`

  * общий SQLite layer для device database.

* `fic-common/fic-policy/`

  * общая модель `Policy`, policy values и apply result;
  * конкретные политики находятся в `fic/src/modules/`.

Не копируй shared functionality обратно в executable components.

Не подключай внутренние headers одного executable component из другого.

Предпочитай существующие shared abstractions созданию параллельной реализации в конкретном executable component.

---

## 4. Куда идти с задачей

### Daemon

Daemon IPC routing и формирование ответов:

* `fic/src/main.cpp`

`PolicyRegistry` initialization, reload, mutation и apply orchestration:

* `fic/src/core/PolicyRegistry*`
* `fic/src/core/PolicyRegistryInitialization.*`
* `fic/src/core/main_function.*`

Конкретные policies:

* `fic/src/modules/<module>/`

Compile-time platform profiles и `/etc/os-release` validation:

* `fic/src/platform/`
* `cmake/FicTargetPlatform.cmake`

Session handling:

* `fic/src/session/`
* `fic-session-agent/`
* `docs/session-agent.md`

### GUI

Top-level загрузка module descriptors и создание module pages:

* `fic-gui/src/mainwindow.*`

Не начинай исследование policy behavior с `MainWindow`, если задача касается policy parsing, mutation или отображения.

Daemon policy/module descriptors:

* `fic-gui/src/models/`

Policy IPC operations, mutation и apply:

* `fic-gui/src/services/PolicyService.*`

Device operations:

* `fic-gui/src/services/DeviceService.*`

Module-specific UI:

* `fic-gui/src/pages/`

Reusable policy editor:

* `fic-gui/src/widgets/PolicyEditorWidget.*`

Device tree / attributes:

* `fic-gui/src/DeviceTree.*`
* `fic-gui/src/DeviceAttributeList.*`

Logs:

* `fic-gui/src/LogService.*`
* `fic-gui/src/LogModel.*`
* `fic-gui/src/LogViewer.*`

### CLI / shared code / resources

CLI:

* `fic-cli/`

IPC client and protocol helpers:

* `fic-common/fic-ipc/`

Config/file/log/process utilities:

* `fic-common/fic-core/`

Device DB:

* `fic-common/fic-device-db/`

Device collection:

* `fic-dick/src/`

Localization:

* `fic/src/scripts/lang/{ru,en}.lang`

Default configs:

* `fic/src/scripts/config/`

Systemd, udev и другие runtime resources:

* `fic/src/scripts/`

Packaging:

* `packaging/deb/`
* `packaging/rpm/`

---

## 5. PolicyRegistry invariants

Production `PolicyRegistry` initialization is fail-closed.

Required behavior:

* production registry строится во временном состоянии;
* текущий registry заменяется только после полного успешного построения;
* failed runtime rebuild сохраняет последний корректный registry;
* failed rebuild не должен запускать policy apply;
* failed rebuild не должен запускать FIREWALL reconciliation;
* initial registry failure должен предотвращать normal daemon startup;
* unknown module, conflicting metadata и duplicate policy являются registration errors.

Не ослабляй эту семантику без явного требования текущей задачи.

После успешной policy value/state mutation daemon должен reload registry.

Если persistent config уже изменён, но registry reload завершился ошибкой:

* не скрывай факт успешного изменения persistent state;
* не сообщай, что операция полностью откатилась, если это не так;
* точно сообщай об ошибке reload;
* не запускай зависимые apply/reconciliation steps, требующие успешного rebuild.

---

## 6. IPC и security invariants

Administrative daemon API использует Unix socket access control.

Не ослабляй socket ownership, permissions или validation default runtime path без явного требования.

Текущие administrative IPC assumptions включают:

* одно `AF_UNIX/SOCK_SEQPACKET` connection на request;
* request и response содержат integer `api_version`;
* base response содержит:

```json
{
  "ok": true,
  "message": "string",
  "api_version": 1
}
```

* CLI и GUI должны сохранять daemon error messages.

Security audit trail administrative IPC всегда включён и не зависит от обычной фильтрации через `AUDIT/log_level`.

Не направляй security audit trail через обычную `Logger` filtering path, если это изменяет его always-on semantics.

Configuration writes должны сохранять существующую atomic write model.

Перед прямым запуском privileged system utilities сначала изучи существующие:

* `ProcessExecutor`;
* `VerifiedProcessExecutor`.

Не создавай новый путь privileged execution, если существующая abstraction уже покрывает задачу.

Если задача затрагивает точные security-sensitive значения ownership, permissions, runtime limits, socket framing или timeouts, сначала проверь authoritative implementation/documentation и не угадывай значения по памяти.

---

## 7. Versioning и compatibility

У проекта сейчас нет объявленной stable release compatibility guarantee.

Если текущая задача явно не требует совместимости:

* не добавляй migration aliases;
* не добавляй dual-read / dual-write;
* не сохраняй obsolete development formats;
* не добавляй fallback на старый внутренний контракт;
* заменяй старый internal contract чисто;
* обновляй всех актуальных producers и consumers вместе.

Не добавляй compatibility code «на всякий случай».

Product version, IPC version, config schema version и DB schema version независимы.

Меняй только ту версию, которая относится к изменяемому контракту.

Если задача меняет upgrade contract, сначала найди существующую versioning/migration architecture и обновляй её согласованно, а не вводи параллельный механизм.

---

## 8. Scope discipline

Делай минимальное связное изменение, достаточное для выполнения задачи.

Не:

* выполняй unrelated cleanup;
* переделывай соседние компоненты «заодно»;
* переименовывай unrelated code;
* исправляй unrelated warnings;
* меняй public contracts без необходимости;
* обновляй unrelated documentation;
* расширяй targeted task до repo-wide refactoring;
* добавляй новые abstraction layers без реальной необходимости.

Если обнаружена unrelated проблема:

* не исправляй её автоматически;
* упомяни её в финальном результате или `docs/HANDOFF.md`, если она важна для продолжения работы.

Предпочитай существующие abstractions созданию новой параллельной abstraction.

Перед добавлением нового helper, utility, wrapper или service сначала поищи существующий эквивалент.

Если задача может быть решена локальной правкой без изменения контракта, не меняй контракт.

---

## 9. Efficient repository exploration

Предпочитай targeted search открытию больших файлов целиком.

Обычный порядок исследования:

1. Найди symbol / API / path.
2. Изучи declaration.
3. Изучи прямых callers / producers / consumers.
4. Изучи тесты этого контракта.
5. Только после этого расширяй scope, если появились доказательства дополнительных зависимостей.

Не читай большие source trees спекулятивно.

При изменении контракта сначала проверяй только его непосредственных:

* producers;
* consumers;
* contract tests;
* relevant documentation.

Расширяй scope только тогда, когда найденная зависимость действительно затрагивается изменением.

Не открывай весь файл, если нужный symbol можно сначала локализовать поиском.

---

## 10. Validation strategy

Используй самую дешёвую validation, способную поймать ошибки на текущем этапе.

### Inner development loop

Предпочитай:

* build affected target;
* directly related unit/contract tests;
* `git diff --check`.

Не запускай full build + full CTest после каждой небольшой правки.

### End of a focused task

Проверь:

* affected targets;
* affected tests;
* relevant static/contract tests;
* `git diff --check`.

### End of a cross-component или architecture-changing task

Запускай full project configure/build и full CTest, когда это практически возможно.

Полная сборка особенно ожидается для изменений, затрагивающих:

* shared libraries;
* IPC;
* CMake;
* cross-component contracts;
* installation rules;
* packaging-sensitive resources.

Example configuration:

```bash
cmake -S . -B build-check \
  -DFIC_TARGET_PLATFORM=ubuntu-24.04
```

Example targeted build:

```bash
cmake --build build-check --target fic -j2
cmake --build build-check --target fic-gui -j2
```

Example targeted tests:

```bash
ctest --test-dir build-check \
  -R '<relevant-pattern>' \
  --output-on-failure
```

Final broad validation when required:

```bash
cmake --build build-check -j2
ctest --test-dir build-check --output-on-failure
```

Не утверждай, что test, build, lint, runtime check или другая validation была выполнена, если команда фактически не запускалась.

Если validation невозможно выполнить из-за окружения, dependency или ограничений sandbox, явно сообщи об этом.

---

## 11. Unsafe runtime validation

Не запускай как обычную validation:

* real policy apply;
* FIREWALL reconciliation against the host;
* device mutation;
* lock/unlock operations;
* udev triggers;
* package installation;
* writes into `/opt/fic`;
* изменения host security/system state;
* destructive или privileged operations, не требуемые непосредственно задачей.

Такие проверки требуют:

* явного пользовательского запроса либо очевидной необходимости текущей задачи;
* подходящего тестового/staging окружения;
* понимания того, какое состояние хоста будет изменено.

Предпочитай:

* unit tests;
* integration tests;
* staging;
* mocks;
* fault injection;
* static/contract tests.

Не превращай validation в изменение реальной системы пользователя.

---

## 12. Contract-specific checks

### При изменении daemon API

Проверь затронутые:

* daemon producer;
* CLI consumer;
* GUI consumer;
* IPC tests;
* IPC documentation;
* architecture documentation, если изменился lasting/public contract.

Не обновляй незатронутые consumers только ради единообразия.

### При добавлении или переименовании policy

Проверь:

* `PolicyRegistry` registration;
* module config;
* `ru.lang`;
* `en.lang`;
* relevant GUI rendering;
* relevant CLI rendering;
* tests.

### При изменении runtime-installed resources

Проверь:

* CMake install rules;
* Debian staging logic;
* RPM staging logic.

Не считай изменение CMake достаточным, если packaging scripts имеют отдельную staging logic.

### При изменении device DB schema

Проверь:

* `fic-common/fic-device-db`;
* всех актуальных schema consumers;
* relevant schema/version contract;
* upgrade contract, если он затрагивается.

### При изменении shared library или IPC contract

Проверь непосредственных producers и consumers во всех компонентах.

Не предполагай, что успешная сборка одного executable подтверждает совместимость всего shared contract.

---

## 13. Documentation

Не обновляй документацию только потому, что изменился implementation code.

Обновляй docs, если задача меняет lasting contract, включая:

* component responsibility;
* IPC format;
* runtime path;
* configuration/schema behavior;
* daemon lifecycle;
* security invariant;
* user-visible command/API behavior;
* build/install behavior, если оно является поддерживаемым контрактом.

Не документируй временные детали реализации как архитектурный контракт.

Не дублируй одни и те же implementation details во множестве файлов.

Предпочитай одно authoritative описание и ссылки/ссылочные упоминания из других документов.

Если implementation изменился, но внешний или архитектурный контракт остался прежним, documentation update обычно не требуется.

---

## 14. Existing user changes

Никогда не перезаписывай unrelated uncommitted user work.

Перед редактированием проверь:

```bash
git status --short
```

Если изменяемый файл уже содержит unrelated user changes:

* сохрани их;
* не делай blanket replacement файла, если это может уничтожить изменения;
* внимательно проверь итоговый diff.

Не выполняй `git reset --hard`, destructive checkout или аналогичные команды для удаления пользовательских изменений без явного запроса.

Не редактируй generated/build artifacts как source code:

* `build*/`
* `dist/`

Не включай unrelated existing changes в собственную правку только потому, что они уже присутствуют в working tree.

---

## 15. Completion condition

Остановись, когда acceptance criteria текущей задачи выполнены.

Не начинай автоматически следующий refactor, cleanup, redesign или «улучшение», не требуемое задачей.

Перед завершением задачи, изменяющей repository state:

1. Просмотри `git diff`.
2. Убедись, что diff соответствует scope задачи.
3. Выполни validation, подходящую масштабу изменения.
4. Выполни:

```bash
git diff --check
```

5. Обнови `docs/HANDOFF.md`, если задача изменила код, конфигурацию, документацию проекта или иное repository state, которое должен знать следующий агент.

Для read-only задач — analysis, review, investigation, explanation — не изменяй `docs/HANDOFF.md` и другие файлы, если пользователь явно не попросил об этом.

Если задача ничего не изменила в репозитории, не создавай искусственный diff только ради HANDOFF.

В финальном отчёте кратко укажи:

* что сделано;
* какие области изменены;
* какая validation реально выполнена;
* что не проверялось;
* известные remaining risks, если они есть.

Не перечисляй десятки файлов, если достаточно назвать затронутые области.

---

## 16. HANDOFF format

`docs/HANDOFF.md` — текущий снимок рабочего состояния, а не исторический журнал.

Держи его коротким.

Он должен содержать только актуальную информацию, необходимую следующему агенту.

Рекомендуемая структура:

### Current base

* branch;
* commit.

### Current task

* одно краткое описание текущей задачи.

### Accepted architecture / invariants

* только решения и факты, необходимые следующему агенту;
* не копируй сюда весь `AGENTS.md`.

### Completed

* краткий список фактически завершённого.

### Changed areas

* только relevant paths или компоненты.

### Validation

* только реально выполненные команды;
* результаты;
* skipped validation, если она существенна.

### Remaining

* unfinished work;
* known risks;
* intentionally skipped validation;
* blockers, если они есть.

Удаляй stale information вместо накопления истории прошлых сессий.

Не используй `HANDOFF.md` как changelog.

Следующий агент должен иметь возможность продолжить текущую задачу из `docs/HANDOFF.md`, не восстанавливая предыдущую переписку.
