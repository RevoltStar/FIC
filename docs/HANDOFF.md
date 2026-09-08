# FIC: передача контекста

## Current base

- Ветка: `main`.
- Родитель текущей правки: `df158ee`.

## Current task

- PAM policy model переработана в три capability activation policies:
  `enable_authentication_lockout`, `enable_password_history` и
  `enable_password_quality`.

## Accepted architecture / invariants

- Activation policy имеет фиксированное значение `ENABLE`, активирует только
  отсутствующую topology и никогда автоматически её не отключает.
- Успех подтверждается новой structural verification после activation; нулевой
  exit code внешней команды сам по себе недостаточен.
- Debian/Ubuntu используют profile-owned activation recipes и доверенный
  `pam-auth-update`; ALT не объявляет этот executable.
- На ALT lockout/history используют существующие `AltPam*TopologyManager`, а
  password quality имеет стратегию `StaticVerifyOnly` для системного passwdqc.
- Option policies рекомендуют соответствующую activation policy; lockout также
  сохраняет рекомендацию `disable_nopasswdlogin`.

## Completed

- Удалена прежняя агрегатная PAM policy из production registration, defaults,
  localization, CMake и тестов.
- Добавлены generic `PamCapabilityActivationPolicy`,
  `PamAuthUpdateTopologyManager` и strategy-driven
  `PamTopologyManagerFactory`.
- Для пяти platform profiles заданы topology strategies и activation recipes;
  Debian/Ubuntu lockout recipe включает `fic-faillock-notify` и
  `fic-faillock`, history — `fic-pwhistory`, quality проверяет системный
  `pwquality`.
- Trust sync обрабатывает только executable IDs, объявленные выбранным platform
  profile; это позволяет RPM post-install успешно работать на ALT без
  `pam-auth-update`.
- DEB dependency дополнена `libpam-pwquality`; package lifecycle не включает
  автоматическое включение capability при установке.
- Обновлены архитектурная документация, daemon README, packaging README,
  defaults, localization и PAM-focused tests.

## Changed areas

- `fic/src/platform/`, `fic/src/trust/` и platform profiles.
- `fic/src/modules/identity_access/pam/` и daemon registration.
- IDENTITY_ACCESS defaults/localization, packaging и документация.
- Unit, static и packaging contract tests.

## Validation

- PAM-focused targeted suite: 12/12 passed.
- После последнего test-only уточнения отдельно пересобран и пройден
  `pam_capability_activation_policy_tests`.
- Текущие `platform_profile_static_checks` и `PamPackagingChecks.py` повторно
  запущены напрямую: passed. Локальный `build-check` не переиспользовать без
  reconfigure: его CTest metadata содержит прежние пути тестов.
- Clean ALT p11 container build всех targets: passed.
- Full CTest в clean ALT p11 container: 72/73 passed. Единственный сбой —
  `corresponding_source_contract_tests`: локальный `rpmbuild` отклоняет fixture
  до проверки продукта с `Bad owner/group`, поскольку NSS не разрешает текущий
  доменный GID `678400513` в имя группы.
- Собраны package sets для Debian 12, Debian 13, Ubuntu 24.04, Ubuntu 26.04 и
  финальный ALT p11 RPM `0.0.1-alt1`.
- Package inspection подтвердила новые defaults, profiles/dependencies и
  отсутствие auto-enable при fresh install; на Debian 12 хеши PAM files до и
  после установки совпали, на ALT обе FIC control facilities остались disabled.
- В disposable Podman containers на всех пяти платформах три activation
  policies успешно применены через daemon/`fic-cli`, затем topology была
  подтверждена по PAM graph/control state.
- Live faillock smoke на Debian 12: две ошибочные аутентификации привели к
  отклонению следующей правильной и созданию tally record.
- Live password-quality/history smoke на Debian 12: две допустимые смены
  пароля прошли; пароль короче `minlen=12` и повтор последнего предыдущего
  пароля при `remember=2` были отклонены. `opasswd` содержал две записи. Для
  rootless builder image перед live-тестом восстановлены штатные mode `0600`
  для `opasswd` и setuid/execute bits `passwd`; исходный image имеет
  нетипичные root-only mode bits.

## Remaining

- Live behavior smoke выполнен на Debian 12; на Debian 13, Ubuntu 24.04,
  Ubuntu 26.04 и ALT p11 подтверждены package install, policy apply и resulting
  topology, но live password transaction/lockout сценарии отдельно не
  повторялись.
- Семантический вопрос `ExplicitPasswordlessLogin` остаётся отдельной задачей и
  не относится к capability activation.
- Коммит не создавать без отдельного явного запроса пользователя.
