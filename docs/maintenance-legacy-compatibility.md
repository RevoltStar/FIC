> Historical M1 design/research, superseded by [package-lifecycle.md](package-lifecycle.md).
> Runtime/finalizer/coordinator/legacy compatibility guarantees below are not the current production contract.

# M1: совместимость legacy maintainer scripts и препятствие раннему admission

## Принятое требование и текущий статус

Несовместимый legacy package обязан получить отказ **до любых переходов основных
FIC packages**, включая old `prerm/%preun`, а не только в новом `preinst/%pre`.
Проверка должна учитывать installed native version и фактические scripts, не
только package name. Unknown version/script identity не совместимы автоматически.
Подготовительный переход для несовместимых версий отдельно проектируется и пока
**не разрешён к реализации**. Ни installed scripts, ни ownership автоматически
не изменять; сохранять configuration, journal, PAM и incident infrastructure.

Это требование принято, но общей технической гарантии пока нет. Новая проверка
не включена в production scripts: нативные reproductions показали, что dependency
contract предварительного runtime сам по себе не обеспечивает свежий admission
каждой операции. Модельный gate в tests read-only и отвергает любое установленное
старое product package по native version/status и фактическим script digests.
Это **не production compatibility checker**, policy engine или lifecycle finalizer.

## Матрица совместимости

В репозитории нет тегов опубликованных релизов и сертифицированного списка native
release versions + maintainer-script digests. Source commit не является package
version. Не выводить разрешение для установленного пакета из product version,
имени, сходства с шаблоном или отсутствия daemon process.

| Installed version / script identity | Решение |
| --- | --- |
| Legacy `fic-dick`, script bodies из `2c9e69c` (`legacy-deb-fixture`), независимо от заявленной версии | Несовместимы: unconditional metadata mutation при abort-upgrade, без admission |
| Synthetic native `fic-dick=1` с этим frozen body и trace-инструментацией | Несовместимый test fixture; проверена фактическая installed version и SHA256 scripts; не обозначение production release |
| Любая неизвестная native версия или неизвестные/изменённые scripts | Refuse; production allowlist не существует |
| Будущие cooperative FIC packages | Пока не сертифицированы, разрешённых release rows нет; нужны exact version/scripts/native gates |
| Product packages действительно отсутствуют | Нет legacy scripts для классификации; это не proof готовности fresh lifecycle |

`fic-runtime=2` в DEB и `2-alt1` в RPM ниже — только synthetic test versions,
не совместимые версии реального lifecycle runtime. Не публиковать эту таблицу
как реализованную защиту текущих DEB/RPM producers.

## Native dpkg / apt: 7 сценариев × 4 дистрибутива

`tests/integration/maintenance-lifecycle/native_legacy_predepends_deb.py`:

| Сценарий | Результат на Debian 12/13, Ubuntu 24.04/26.04 |
| --- | --- |
| direct `dpkg -i` нового fic-dick, runtime отсутствует | Отказ до любых old/new product scripts, protected snapshot неизменён |
| runtime postinst впервые отказал, затем direct `dpkg -i` | То же: runtime никогда не был настроен |
| После первого отказа `dpkg --configure -a`, затем direct upgrade | Повторный runtime отказ; protected snapshot неизменён; product scripts не запущены |
| runtime этой версии был настроен ранее, затем установлен old product; повторная настройка runtime отказала; `--configure -a` также отказал | **RED:** exact Pre-Depends принимает прежнюю configuration; начинается old prerm → new preinst refusal → old postinst abort-upgrade |
| Runtime ранее настроен, old product появился позже; отдельный direct upgrade fic-dick | **RED:** повторной проверки runtime нет; late guard вызывает old abort path |
| То же, настоящий offline local-repository `apt-get upgrade` | **RED:** runtime уже satisfies dependency, apt не запускает его gate повторно |
| Повторная runtime конфигурация отказала; совместный `dpkg -i fic2 fic-dick2` | **RED:** зависимость не блокирует old product transitions; old fic-dick abort script меняет metadata |

Snapshot включает mode/uid/gid/inode, identity bytes или link target, mtime и ctime;
read-atime намеренно не учитывается. В первых трёх сценариях snapshot конфигурации, PAM, incident/fence sentinels,
содержимого journal sentinel и всех metadata `/opt/fic` совпадает до/после отказа.
В четырёх RED-сценариях меняются metadata `/opt/fic/db` и
`/opt/fic/db/mutation-journal.json` (0600 → 0640, group → fic).
Configuration, lockstatus, PAM и fence sentinels остаются неизменны — этого
недостаточно, чтобы назвать отказ безопасным: journal-path metadata уже изменены.
Новый preinst и runtime gate отказывают; старый postinst всё равно исполнен.

**Граница evidence:** это dummy native packages с точным старым fic-dick mutating
body; main `fic` в совместном сценарии — trace-only fixture. Защищаемые файлы —
sentinels, не валидные configuration/journal/fence authority. Не утверждать
повреждение конкретного production journal, safety actual FIC upgrade или recovery.
Сценарий предполагает, что old package появился после initial runtime configure
(например, обычная установка старого пакета без нового dependency contract).
У согласованной deployment boundary пока нет отдельного запрета/технической
защиты этого package-manager пути. Без force-флагов и без изменения installed
script database воспроизведение использует только обычные dpkg/apt операции.

## Native ALT p11 RPM

`native_legacy_admission_rpm.py` строит dummy RPMs непривилегированным builder.
Реальная transaction показывает порядок:

```text
runtime2 %pre
runtime2 %post -> gate refused, exit 1
main2 %pre -> independent gate refused, exit 1
```

Несмотря на runtime `%post` failure, RPM запустил dependent main `%pre` и оставил
runtime=2-alt1 в rpmdb. Старый main=1-alt1 сохранён, его `%preun/%postun` не
вызваны, protected sentinel не изменён **благодаря независимому main refusal**.
Это не dpkg abort reproduction и не доказательство небезопасности каждого RPM
upgrade: показано, что `Requires(pre)` не означает successful runtime configure.
Нельзя переносить DEB понятие configured prerequisite на RPM без отдельного proof.

## Почему нельзя включить частичный обход

* Более строгий runtime gate не меняет semantics package manager.
* Отказ нового DEB preinst происходит уже после old prerm и вызывает old postinst.
* Успешная когда-то configuration не является snapshot-bound admission текущего
  набора versions/scripts. Durable receipt тоже не заставит dpkg перечитать его
  перед old prerm; проверка только в новом preinst снова запоздает.
* Masks и daemon.lock не сериализуют автоматически старые maintainer scripts.
* Runtime Conflicts/Breaks нельзя считать решением без отдельной проверки: resolver
  может решить конфликт удалением старого пакета со старыми scripts до gate.
  Этот обход не реализован и не объявлен native-проверенным.
* Установленные scripts не патчатся, package-manager DB не редактируется, fence
  не снимается, metadata не «компенсируются» после отказа.

Таким образом, универсальная гарантия для всех согласованных direct dpkg/apt путей
**заблокирована** при текущем ограничении admission проверкой runtime configuration
+ dependencies. Для продолжения необходим дополнительный контракт: например,
согласованный запрет повторного появления non-cooperative packages после runtime
admission с доказанным initial ordering, либо отдельный admission до запуска
package-manager transaction. Последний меняет модель доставки и не реализован.
Ни wrapper произвольных package commands, ни bootstrap migration автоматически
не вводятся. Без нового решения прямой legacy upgrade не считается безопасным.

## Повторение и validation

Только свежий disposable Docker container, source RO, без host security mounts:

```sh
docker run --rm --network none \
  -e FIC_MAINTENANCE_NATIVE=1 -e FIC_LEGACY_PACKAGE_ORDER_NATIVE=1 \
  -v "$PWD:/src:ro" fic-ssh-audit:debian12 \
  python3 /src/tests/integration/maintenance-lifecycle/native_legacy_predepends_deb.py \
  /src previous-refusal
```

Другие modes: `missing`, `first-refusal`, `configure-a`, `already-configured`,
`apt-upgrade`, `joint-upgrade`. Каждый mode требует **новый** container. ALT требует
rpm-build + runuser/Python и выполняет `native_legacy_admission_rpm.py`; script сам
создаёт отдельного непривилегированного builder. Это test-only установка пакетов.
Default CTest пропускает reproductions (77): обычные проверки не устанавливают
пакеты. Отдельные opt-in CTest tests имеют labels research/native/root.

Фактические логи текущего запуска сохранены в ignored `build-m1-evidence/`:
`legacy-predepends-{debian12,debian13,ubuntu2404,ubuntu2604}-{mode}.log` (28),
`legacy-admission-alt-p11.log` (1). Exit 0 означает, что assertions воспроизведения
сошлись; строки **REPRODUCED_RED не являются lifecycle PASS**. Source/fixtures
сохранены в Git; artifacts/logs не заменяют готовность production implementation.
