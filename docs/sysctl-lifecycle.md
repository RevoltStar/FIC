# SYSCTL: persistent ownership и release

Каждая ENABLE SYSCTL-политика после успешного apply имеет собственный параметр
в `/etc/sysctl.d/zzzz-fic.conf` и активную запись MutationJournal. Совпадающее
чужое значение не заменяет ownership. Файл общий, но каждая политика владеет
только своим ключом. Blocks, изменение чужих файлов и adoption отсутствуют.

| Ситуация | Прежнее поведение | Текущий контракт |
|---|---|---|
| Чужая конфигурация уже соответствует | Собственный параметр мог не создаваться | Собственная запись и provenance обязательны |
| Persistent/runtime соответствуют | Повторный prepare мог затронуть provenance | Без записи файла/journal |
| Отличается только runtime | Смешивалось с persistent apply | Только runtime ensure/read-back |
| Изменилось целевое значение | Повторный prepare/discard мог потерять predecessor | REFRESH с прежним ID и сохранённым Applied predecessor |
| Поздний чужой файл | Разбор effective value | Отказ по metadata topology независимо от содержимого |
| Rollback | Собственный resolver effective value и runtime write | Release → durable journal → native exact prefix |
| Ошибка native helper после release | Могла препятствовать disable | Warning, ownership не восстанавливается |

## Apply и приоритет

Поддерживается штатный `systemd-sysctl.service` с единственным default ExecStart
без дополнительных аргументов, root remapping и дополнительных команд.
Платформенный resolver выбирает optional `SystemdSysctl`; CommandHashStore и
VerifiedProcessExecutor сохраняют существующую проверку исполняемого файла.
FIC проверяет loaded unit через typed systemd D-Bus properties и общий mount
namespace с manager. Masked/custom loader, неизвестная topology или отсутствие
доверенного helper означают отказ до policy mutation.

Приоритет проверяется по metadata, без открытия содержимого чужих файлов:
`/etc/sysctl.d`, `/run/sysctl.d`, `/usr/local/lib/sysctl.d`, `/usr/lib/sysctl.d`,
`/lib/sysctl.d`; canonical directory aliases учитываются однократно.
Первый файл с данным basename имеет приоритет, symlink учитывается с целью,
`/dev/null` маскирует нижние одноимённые файлы. Любой выбранный regular `.conf`
с именем после `zzzz-fic.conf` блокирует apply, даже пустой. Проверяется доверие
к каталогам/metadata, повторно проверяется topology. `/etc/sysctl.conf` отдельно
не разбирается: штатная ссылка на него участвует как файл `sysctl.d`.
Это доказательство поддержанного file-loader contract, а не управление всеми
возможными сторонними writers, custom services или будущими изменениями ОС.

Собственный файл читается безопасно и ограниченно: regular single-link artifact,
root-owned без чужой записи, без symlink. Принимаются уникальные простые
assignments, пустые строки и существующий заголовок FIC; неизвестные комментарии,
patterns/exclusions и malformed данные блокируют операцию. Имя и заголовок сами
по себе не доказывают ownership. Каждый существующий owned ключ должен совпасть
с journal; исчезнувшие артефакты автоматически не реконструируются.

Fresh/REFRESH durable intent предшествует CAS. Предыдущее appliedValue и ID
сохраняются при REFRESH; durable attempted checkpoint фиксируется до CAS.
Inline abort разрешён только до попытки либо при прямом результате NotInstalled.
Неопределённая публикация остаётся Prepared, блокируя shared SYSCTL writers.
После restart нельзя вывести отсутствие эффекта из текущего содержимого.
Автоматической компенсации и нового recovery framework нет.

У новых записей сохраняются actual/inherited creation authority и device/inode
общего контейнера. После FIC atomic replacement witnesses всех активных новых
владельцев обновляются одной journal operation вместе с завершением текущей
операции. Подмена контейнера не превращается в новое ownership. Проверяется
точное состояние, установленное AtomicFileWriter, а не только совпадение байтов
при последующем чтении. FIC mutex + существующий optimistic CAS не устраняют
остаточную гонку против несотрудничающего privileged writer между проверкой и
rename/unlink; kernel-level запрет чужих writers здесь не вводится.

## Release

1. Под общим SYSCTL mutex проверить journal, контейнер и own key/value.
2. Условно удалить только свой ключ; остальные строки сохранить. Неизвестные
   простые assignments не присваиваются FIC и не удаляются; оставшийся orphan
   блокирует итоговый uninstall proof.
3. При последнем ключе удалить пустой контейнер только с authority его создания.
   Durability удаления/записи обязательна. Ошибка сохраняет provenance.
4. Одной durable journal operation завершить RolledBack и обновить witnesses
   оставшихся владельцев. При неопределённой записи journal helper не вызывается.
5. Через VerifiedProcessExecutor вызвать платформенный helper с отдельным argv:
   `--prefix=/net/ipv4/ip_forward`. Prefix должен указывать на regular leaf
   `/proc/sys`, не каталог. Runtime values release не читает.

Leading slash сохраняет literal точки в именах интерфейсов:
`net/ipv4/conf/fic.test/forwarding` → `/net/ipv4/conf/fic.test/forwarding`.
Это component prefix systemd; leaf guard исключает захват дочерних параметров.
Нативный loader сам выбирает стороннее значение. Без внешнего источника runtime
может остаться прежним. Read-back, kernel-default/history restoration и полный
reload запрещены. Отсутствие/ошибка/exception вспомогательного helper после
release — диагностическое WARNING; release, disable и uninstall не отменяются.
Повтор уже завершённого release не запускает helper снова; retry store отсутствует.

### Явное legacy-исключение

Старые key/appliedValue records продолжают читаться без миграции. Только для них
сохранён прежний контракт удаления пустого dedicated container после последнего
доказанного параметра. Это сознательная совместимость, **не доказательство
создания файла**. Перед удалением не должно оставаться чужих данных или ключей
без доказанного ownership; при конфликте файл сохраняется.
Новая политика, разделяющая legacy container, хранит reference на конкретную
старую запись, а не ложный creation flag. Origin нельзя удалить из journal, пока
на него ссылаются активные владельцы. Legacy REFRESH сохраняет старый committed
формат. У новых контейнеров такого исключения нет.

## Проверки и воспроизведение

`sysctl_configuration_tests`, `sysctl_ownership_tests`, `mutation_journal_tests`,
`rollback_executor_tests` проверяют no-op, runtime-only, REFRESH и ошибки
публикации/journal, orphan/drift, shared-key preservation, legacy authority,
подмену контейнера, conditional delete и вспомогательные ошибки.

Native fixture: [tests/integration/sysctl-ownership](../tests/integration/sysctl-ownership/README.md).
Он заменяет прежний `RemoteSysctlIntegration.sh`, который проверял удалённый
foreign-effective parser и больше не соответствует архитектуре.
Native PASS ограничен указанными source/harness/image/binary receipts и
приватными network sysctls; не является тестом произвольных kernel parameters,
реального reboot хоста, всех sandbox/unit customizations или текущего SSSD.

## Изменённые production-файлы

* `fic/src/modules/sysctl/Sysctl.cpp`;
  `SysctlConfiguration.{h,cpp}`, `SysctlTransaction.{h,cpp}`,
  `SysctlSystemd.{h,cpp}` в том же каталоге.
* `fic/src/rollback/MutationRecord.h`, `MutationJournal.{h,cpp}`,
  `RollbackExecutor.{h,cpp}`.
* `fic/src/platform/PlatformProfile.h`, `PlatformExecutableResolver.cpp`,
  `PlatformCompatibility.cpp`.
* `fic/src/platform/profiles/Debian12Profile.cpp`, `Debian13Profile.cpp`,
  `Ubuntu2404Profile.cpp`, `Ubuntu2604Profile.cpp`, `AltP11Profile.cpp`.

`SysctlRuntime`/`SysctlKey`, существующие policies, package scripts, lifecycle
states и global journal schema не изменены. Изменение SYSCTL-specific optional
undo payload не меняет значения старых key/value записей.

Основание native-loader семантики:
[sysctl.d](https://www.freedesktop.org/software/systemd/man/latest/sysctl.d.html),
[systemd-sysctl](https://www.freedesktop.org/software/systemd/man/latest/systemd-sysctl.service.html).
Фактические версии и область проверок приведены в native evidence.
