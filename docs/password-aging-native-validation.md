# PASSWORD_AGING: ownership и native validation

## Контракт семи политик

| Политика | Apply / effective verification | Rollback |
|---|---|---|
| `password_min_age_days` | OwnWhileEnabled, native-effective `PASS_MIN_DAYS`, `0..INT_MAX` | Удалить только доказанный sub-block; PASS relation guard |
| `password_max_age_days` | OwnWhileEnabled, native-effective `PASS_MAX_DAYS`, `-1..INT_MAX` | То же; `MAX=-1` означает unlimited |
| `password_expiration_warning_days` | OwnWhileEnabled, native-effective `PASS_WARN_AGE`, `-1..INT_MAX` | Удалить только доказанный sub-block |
| `regular_user_uid_min` | OwnWhileEnabled, native-effective `UID_MIN`, полный unsigned uid_t | Удалить sub-block; UID relation guard |
| `regular_user_uid_max` | OwnWhileEnabled, native-effective `UID_MAX`, полный unsigned uid_t | То же |
| `password_aging_apply_to_existing_accounts` | Каждый проход читает effective PASS/UID и локальные accounts, исправляет nonzero UID в текущем диапазоне через chage; postcondition + sp_lstchg | NotEnrolled: прекратить enforcement, не восстанавливать accounts |
| `password_aging_enforce_for_root` | Каждый проход читает effective PASS и все локальные accounts UID 0, включая имена кроме root; тот же chage/postcondition | NotEnrolled; per-user journal отсутствует |

Совпадающий foreign default не доказывает ownership: fresh scalar apply всегда
создаёт свой sub-block и Applied journal. Доказанный owned repeat — zero-write;
refresh — одна CAS-замена. Один EOF container общий с USER_CREATION. Foreign
байты не присваиваются FIC и не комментируются. Release сохраняет peer blocks
и текущие foreign строки, без восстановления исторического значения. Drift,
orphan, некогерентный journal и недопустимое отношение после release — Conflict.
Существующие CAS, FIC-locking и crash recovery не изменены.

Operational policies используют fail-fast Failed без Partial. Нет undo ранее
изменённых пользователей или persistent cursor: следующий apply перечитывает
всех и исправляет новый drift. Required-зависимости сохранены. Missing PASS
параметры operational reader не подменяет defaults: штатный planner сначала
требует успешного применения scalar dependencies.

## Native измерения (Docker вместо Podman согласован пользователем)

| Платформа | Установленный passwd / shadow-utils | Хранилище | Native gate |
|---|---|---|---|
| Debian 12 | `1:4.13+dfsg1-1+deb12u2` | `/etc/shadow` | 133 PASS, 0 SKIP |
| Debian 13 | `1:4.17.4-2` | `/etc/shadow` | 133 PASS, 0 SKIP |
| Ubuntu 24.04 | `1:4.13+dfsg1-4ubuntu3.2` | `/etc/shadow` | 133 PASS, 0 SKIP |
| Ubuntu 26.04 | `1:4.17.4-2ubuntu3` | `/etc/shadow` | 133 PASS, 0 SKIP |
| ALT p11 | `shadow-utils-4.17.4-alt4`, `shadow-change-4.17.4-alt4` | `/etc/tcb/<user>/shadow` | 133 PASS, 0 SKIP |

Проверены native useradd/chage, реальный production LocalAccountReader и
production policies/MutationJournal. Для каждой scalar policy — fresh matching
и differing foreign values, durable Applied, repeat без изменения inode/mtime/
ctime конфигурации и journal, refresh, foreign append/recanonicalization,
поэлементный release с USER_CREATION peer. По два отдельных завершения процесса
`_exit(86)` на политику (Prepared до/после physical install), затем другой процесс
восстанавливает операцию и выполняет release: 10 cuts на строку, всего 50.
Это не физические power-loss tests.

Проверен новый реальный пользователь с effective PASS и UID range; несколько
существующих пользователей, один drift, все compliant, UID0 alias, сохранение
sp_lstchg, non-reverting disable и отсутствие operational journal writes.
Второй chage в первом проходе детерминированно возвращает ошибку (fault injection);
первый chage и все команды следующего прохода — настоящие. Между проходами
сторонний chage меняет первого пользователя; retry снова исправляет обоих.
Logger проверяется на `changed_before_failure=ficage1`. Unit regression отдельно
проверяет повторный вызов того же policy object и перечитывание изменившихся
expected параметров; disabled planner и enrollment проверяются unit-тестами.
Native driver для disabled policy использует status gate и не запускает daemon.

### Сборки и CTest

* Debian12: полная configure/build успешна; исходный full CTest —184/185.
  Единственный отказ path_layout_static_checks был вызван Git safe.directory
  при read-only source mount от другого UID. С контейнерным
  GIT_CONFIG_KEY_0=safe.directory / GIT_CONFIG_VALUE_0=/src этот gate и
  окончательный identity_login_defs_tests прошли2/2. Остальные184 full-suite
  tests успешны, включая PASSWORD_AGING/USER_CREATION. Логи:
  /tmp/fic-aging-debian12-full.log, /tmp/fic-aging-debian12-final-rerun.log.
* Остальные четыре профиля: fic build успешен. Final targeted regression
  password_aging_tests/user_creation_tests/identity_login_defs_tests —3/3 PASS
  на каждой платформе после финального изменения fixture; результаты в
  /tmp/fic-aging-focused-<row>-final.log.
* Дополнительный platform_profile_tests PASS на Debian13/Ubuntu24/Ubuntu26.
  На ALT он имеет существующий несвязанный отказ: тест безусловно требует
  /etc/sddm.conf, AltP11Profile.cpp задаёт /etc/X11/sddm/sddm.conf. Оба файла
  идентичны base SHA87af7c6 (git diff HEAD по этим путям пустой). Это не
  PASSWORD_AGING regression; SDDM здесь не изменён. Missing-key profile
  assertions отдельно подтверждены native driver на ALT.
* Существующие CTest targets расширены, поэтому regression cases входят в
  обычный CI full run. Native gate не зарегистрирован для host CTest:
  изменения аккаунтов допускаются только в disposable containers.

### Missing-key semantics

На **каждой** платформе проверены три отдельные пропущенные записи и отсутствие
всех трёх одновременно. Создаётся новый native useradd account, production
LocalAccountReader читает его из настоящего shadow/TCB:

| Отсутствующий ключ | Соответствующее поле нового аккаунта |
|---|---|
| `PASS_MIN_DAYS` | пустое поле хранения / `sp_min=-1` |
| `PASS_MAX_DAYS` | пустое поле хранения / `sp_max=-1` |
| `PASS_WARN_AGE` | пустое поле хранения / `sp_warn=-1` |

Остальные явно заданные параметры сохраняют заданные значения. Все три
`PasswordAgingMissingKeySemantics=-1` подтверждены; platform profiles не менялись.
Это semantics отсутствия, а не разрешение явного scalar `PASS_MIN_DAYS=-1`.
Для UID synthetic missing-key defaults не вводятся.

Source cross-check выполнен на upstream версиях, соответствующих базовым
версиям установленных distro packages: `new_spent()` в
[shadow 4.13 useradd.c](https://github.com/shadow-maint/shadow/blob/4.13/src/useradd.c)
и [shadow 4.17.4 useradd.c](https://github.com/shadow-maint/shadow/blob/4.17.4/src/useradd.c)
читает каждый PASS ключ с fallback -1 (в 4.13 через scale_age).
Это не аудит всех downstream patches: именно native проверки указанных
установленных distro builds подтверждают эффективный результат на пяти ОС.
ALT минимальный builder первоначально имел только shadow-utils-alt2 без chage;
для полного operational gate установлен штатный shadow-change и его matching
shadow-utils-alt4. До этого source/container limitation не считался PASS.

## Воспроизведение и ограничения

```
docker build -t fic-aging-native:alt-p11 \
  -f tests/integration/password_aging/Containerfile.alt-runtime .
CONTAINER_ENGINE=docker bash tests/integration/password_aging/run-native.sh
# либо CONTAINER_ENGINE=podman при наличии тех же builder images
```

Runner по умолчанию использует Podman; Docker выбран явно. Образы в run-native.sh
можно заменить через `FIC_NATIVE_IMAGE` для одной строки. Builder должен иметь
CMake/C++/OpenSSL/json/Python, реальные useradd/chage; ALT требует shadow-change.
Source mounted read-only; build cache writable. Аккаунты и /etc изменяются только
в одноразовых root containers, host /etc не монтируется. Скрипт и driver
отказывают вне container marker. Логи сохраняются в
`build-password-aging-native/<row>/native-{build,gate}.log` при запуске runner.
Финальные текущие native логи: `/tmp/fic-aging-native-<row>-final.log`.

UID allocation `useradd` и `adduser` — отдельный архитектурный вопрос.
`adduser` может выбирать UID через собственные FIRST_UID/LAST_UID и передавать
явный UID в useradd, обходя login.defs allocation defaults. Здесь доказаны
native useradd defaults и существующий UID scope operational policy;
универсального interception всех account-creation frontends нет. Семантика
scope/новые UID policies не менялись. Существующие accounts меняются только
двумя явно вызванными operational policies, а не scalar apply.

Нет real-machine PAM login/logind tests, LDAP/NSS account enforcement или
универсальной атомарности против произвольного стороннего writer.
