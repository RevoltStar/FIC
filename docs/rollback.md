# Rollback выполненных мутаций (MVP)

Этот документ — авторитетное описание persistent rollback-инфраструктуры FIC.
Один раз описанная семантика в других файлах дублироваться не должна.

## Принцип

Rollback строится не из описания политики, а из **фактически выполненных**
изменений ОС:

```text
Policy → backend → MutationRecord → persistent MutationJournal
       → policy disable → RollbackExecutor → typed UndoAction
```

Инварианты:

* `Policy` не реализует rollback и не содержит стратегии отката.
* Journal — единственный источник provenance: FIC автоматически отменяет
  только то, что записал в journal как свою мутацию.
* Ownership для SYSCTL определяется **содержимым FIC managed-артефакта**
  (`/etc/sysctl.d/zzzz-fic.conf`), а не текущим effective source. Если
  внешний файл перекрывает FIC-запись, disable всё равно обязан удалить
  FIC-запись из managed-файла, иначе она может снова стать effective после
  исчезновения перекрытия. Effective resolution используется только после
  удаления, чтобы определить оставшееся persistent значение для runtime.
* Системное состояние, которое уже соответствовало политике до `apply`
  (`current == desired`), мутацией не считается и при disable не изменяется.
* Drift FIC-owned значения внутри managed-артефакта — fail closed
  (`Conflict`), молчаливая потеря данных и three-way merge не выполняются.
* Rollback выполняется до смены статуса политики. Частичный откат оставляет
  политику ENABLE и отражается в journal.
* Commit provenance (`Prepared → Applied`) после фактического системного
  изменения не может маскироваться как успех: если persist не удался, apply
  завершается ошибкой, а `Prepared`-запись остаётся активной на диске и
  безопасно разрешается rollback executor'ом.

## Расположение

* `fic/src/rollback/MutationRecord.h` — `MutationRecord`, `MutationStatus`,
  `MutationBackend`, типизированные `UndoAction`.
* `fic/src/rollback/MutationJournal.{h,cpp}` — persistent JSON journal
  (atomic write через `AtomicFileWriter`, fail-closed загрузка).
* `fic/src/rollback/DaemonMutationJournal.{h,cpp}` — singleton демона над
  journal'ом (путь из `FicRuntimePaths::mutationJournalFile`; override
  существует только для тестов).
* `fic/src/rollback/RollbackExecutor.{h,cpp}` — `rollbackPolicyBeforeDisable`,
  enrollment матрица, production deps wiring.
* `fic/src/modules/net/ssh/SshRollback.{h,cpp}` — SSH undo: применение reverse
  delta главного `sshd_config`, валидация `sshd -T`, reload сервиса,
  transactional restore.
* `tests/fic/rollback/` — тесты journal и executor.

## Жизненный цикл мутации

```text
Prepared  — journal-запись создана ДО системного изменения
Applied   — backend подтвердил успешную мутацию и postcondition
RolledBack      — undo выполнен (или менять было нечего)
RollbackFailed  — undo не прошёл; запись остаётся активной
Detached        — FIC больше не владеет изменением (не откатывается никогда)
```

Crash-consistency: запись создаётся в состоянии `Prepared` перед системным
изменением и переводится в `Applied` только после подтверждения backend'ом.
Крэш между изменением и коммитом оставляет `Prepared`-запись, поэтому FIC не
теряет provenance. Remaining crash-window между атомарной записью journal и
самим изменением разрешается консервативно: лишняя `Prepared`/`Applied`
запись при disable приводит к проверке фактического состояния
(nothing-to-do / conflict), а не к слепому откату.

Существующие apply-time восстановительные механизмы backend'ов
(restore исходного содержимого при провале postcondition) сохранены;
persistent-запись коммитится только после успешного apply.

## Формат journal

Путь: `FIC_MUTATION_JOURNAL_FILE` (по умолчанию
`/opt/fic/db/mutation-journal.json`), настраивается как остальные product
paths. Формат — JSON:

```json
{
  "schema_version": 1,
  "next_id": 7,
  "records": [
    {
      "id": 3,
      "policy": {"module": "SYSCTL", "submodule": "Global", "policy": "..."},
      "resource": "kernel.dmesg_restrict",
      "backend": "sysctl",
      "status": "applied",
      "undo": {"action": "remove_managed_setting", "key": "...", "applied_value": "..."},
      "created_at_epoch": 0,
      "updated_at_epoch": 0,
      "error": ""
    }
  ]
}
```

Загрузка fail closed: отсутствующий или неизвестный `schema_version`,
битая структура, неизвестные enum-значения, дубликаты `id` приводят к отказу
от использования journal (rollback не выполняется, disable не маскируется
как успешный). Только реальное отсутствие файла означает пустой journal;
если файл существует, но не может быть открыт или прочитан (permission,
I/O), это ошибка загрузки — fail closed. Существующий нулевой длины файл —
повреждённое persistent-состояние: валидный пустой journal обязан содержать
корректную schema-структуру.

Каждая мутирующая операция journal'а имеет сильную гарантию in-memory
состояния: если `persist()` не удался, наблюдаемое состояние journal'а
остаётся логически идентичным состоянию до операции, включая порядок записей
и `next_id`. Повторная операция после неудавшегося persist видит исходную
активную запись (fail closed). Один ресурс может иметь несколько записей от
разных политик.

## Undo actions

Типизированные исполнимые действия (не описательные флаги):

* `UndoRemoveManagedSetting{key, appliedValue}` — SYSCTL и SUDO: удалить
  FIC-owned запись ключа из managed-файла; `appliedValue` — fingerprint
  последнего применённого значения для обнаружения drift. Ownership
  определяется содержимым FIC managed-артефакта, а не текущим effective
  source: внешняя запись (главный sudoers или другой include), перекрывающая
  FIC-запись, не мешает её удалению. Drift внутри managed-артефакта —
  `Conflict`. Для SYSCTL после удаления пересчитывается эффективное значение
  из оставшихся источников precedence и runtime sysctl приводится к нему
  (default не угадывается). Для SUDO результат обязательно валидируется
  `visudo`; FIC-owned файл, ставший пустым, удаляется.
* `UndoRemoveFirewallPolicy{policyName}` — удаление FIC-managed правила и
  обычная firewall reconciliation. Snapshot всего nftables ruleset не
  выполняется.
* `UndoRestoreSshDirective{parameter, appliedValue, reverseEdits,
  appliedGlobalSectionFingerprint}` — SSH: откат точной текстовой мутации FIC
  в global section (от начала файла до первого `Match`) shared-файла
  `sshd_config` (`/etc/ssh/sshd_config` Debian/Ubuntu, `/etc/openssh/sshd_config`
  ALT). Main `sshd_config` **не считается FIC-owned**: full-file snapshot не
  хранится и не восстанавливается, `Match` blocks и included-файлы не
  трогаются. Каждая запись `reverseEdits` описывает одну изменённую строку:
  `beforeLine` — исходная строка (`null` для строк, вставленных FIC — при
  rollback они удаляются), `afterLine` — строка после мутации FIC. Дубликаты
  директив, заменённые/закомментированные FIC, восстанавливаются полностью.
  Rollback выполняется только при совпадении fingerprint текущего global
  section с fingerprint, зафиксированным при apply (консервативный drift
  detection: любое несвязанное изменение global section, включая комментарии,
  даёт `Conflict` без записи в файл; изменения после первого `Match` и во
  внешних include этому не мешают). После reverse-записи обязательны валидация
  `sshd -T` и reload активного сервиса; при провале восстанавливается
  pre-rollback содержимое (reload при активном сервисе), возвращается `Failed`,
  запись остаётся активной. Effective-значение после rollback не проверяется
  на равенство исходному: за время жизни политики администратор мог изменить
  include-файлы, `Match` blocks и package defaults.
  Повторный apply при существующей активной записи не перезаписывает исходный
  baseline (исходная запись используется как provenance; структурный drift
  относительно неё — будущий `Conflict`).
* `UndoDisableDeviceFeature{feature}` — отключение category-level desired
  state DC и пересборка `99-fic-devices.rules` через device daemon;
  per-device пользовательские правила не затрагиваются.

## Enrollment и результаты

`rollbackEnrollment(PolicyRef)` возвращает:

* `Supported` (явный whitelist, без default-positive enrollment):
  * все `SYSCTL` policies;
  * `DAC/SudoEdit` managed Defaults (`sudo_env_reset`, `sudo_passwd_tries`,
    `sudo_securepath`, `sudo_timeout`);
  * `NET/SshEdit` (`ssh_port`, `ssh_max_auth_tries`, `ssh_root_login`,
    `ssh_pubkey_auth`);
  * `FIREWALL/HostFiltering` (`block_ftp`, `block_rdp`, `custom_rules`);
  * `DC/DeviceControl` category features (`block_usb_storage`,
    `block_printers_scanners`, `block_optical_drives`);
* `Unsupported` — модуль в системе rollback, но автоматический откат не
  реализован: `sudo_require_authentication` (чужие NOPASSWD/PASSWD specs),
  `exclusive_firewall_control` (уничтожает внешнее состояние), DC
  non-category policies и **любая неизвестная политика** внутри
  rollback-enrolled submodule — будущая SUDO/FIREWALL policy никогда не
  становится автоматически rollback-Supported без собственной journal
  integration и undo-действия;
* `NotEnrolled` — все остальные модули: `disable` сохраняет прежнее
  поведение (legacy).

Результат отката — типизированный `RollbackStatus`:
`Success / NothingToDo / Conflict / Unsupported / Failed / Partial`.
`NothingToDo` означает, что активные записи не требуют отката: для SYSCTL
и SUDO — FIC-owned запись нет в managed-артефакте (внешнее состояние никогда
не трогается); для SSH — target-директива отсутствует в global section
главного конфига, либо политика ранее уже была отработана (запись
`RolledBack` в journal документирует, что текущее состояние —
post-rollback); это позволяет disable.
Для legacy-установок (политика ENABLE, journal пуст) FIC не угадывает
владение: provenance проверяется по содержимому FIC managed-артефакта
(не по effective source), и при наличии там ресурса возвращается
`Unsupported` (provenance unavailable), disable запрещается; при отсутствии
— `NothingToDo` с диагностикой. Для SSH managed-артефакта нет — роль
provenance-проверки выполняет сам главный `sshd_config`: присутствие
target-директивы в global section без journal-записей означает
`Unsupported` (даже при совпадении значения с политикой), отсутствие —
`NothingToDo`.

## Расширение

Новые backend'ы (PAM, GRUB, fstab, DAC и т.д.) подключаются добавлением
payload'а в `UndoAction`, ветки в `RollbackExecutor` и записи мутации в
момент фактического изменения ресурса — без изменений в `Policy` и без
новых виртуальных методов.
