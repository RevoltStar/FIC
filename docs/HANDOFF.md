# FIC: передача контекста

## Current base

- Ветка `main`, фактический HEAD
  `57040ba0ea243f3d759c70cdb62ac7f524b68759`.
- Текущий semantic follow-up не закоммичен; commit только по отдельному
  запросу.

## Current task

- Исправлен semantic false positive `PamControlFlowAnalyzer`, обнаруженный
  ручным запуском на ALT Workstation 11.2 после исправления штатного alias
  `/etc/pam.d/system-check-localuser`.
- Наблюдавшийся trace был:
  `pam_userpass PAM_AUTH_ERR` -> поздний
  `pam_localuser PAM_SERVICE_ERR/default=die` -> ошибочный вывод, что
  credential failure обошёл `pam_faillock authfail`.

## Accepted architecture / invariants

- `pam_userpass.so` получает `PAM_USER`/`PAM_AUTHTOK` через PAM conversation,
  но сам не проверяет credentials. Его role — `CredentialCollector`.
- Return codes collector/gate по-прежнему полностью участвуют в PAM control
  flow: `bad`, `die`, `done`, jumps, stack impression/status и termination не
  ослаблены. Но только модули с credential-verification semantics создают
  `authenticationSuccessObserved`/`authenticationFailureObserved`.
- `pam_localuser.so` — identity gate, а не credential authenticator; его
  operational/identity failures не являются password rejection evidence.
- Настоящие authenticators (`pam_tcb`, `pam_unix`, `pam_sss`, `pam_krb5`,
  и т. п.) сохраняют прежнюю fail-closed семантику: credential rejection,
  завершившийся до `pam_faillock authfail`, остаётся
  `failure_accounting_bypass`.
- `Unknown` остаётся conservative/fail-closed. Trusted bypass/exclusion,
  placement faillock и post-enable verification не менялись.

## Historical context

- Git history suggests that the likely origin was the first analyzer in
  `9d56ff97`: negative-list helper `authenticationDecisionModule()` считал
  authentication decision любым auth-модулем, который не был явно известен
  как non-credential.
- При введении explicit `PamModuleRole` в `a4c62791` `pam_userpass` был
  перенесён в `CredentialAuthenticator`, по-видимому сохраняя прежнюю
  conservative heuristic; module-specific semantic justification в истории
  не найдено. Regression из `377e6696` затем закрепил это предположение,
  используя `pam_userpass` как credential failure.
- Precedent `fe4bd82` уже отделил auxiliary credential consumer
  `pam_gnome_keyring` от primary authenticators. Текущая правка аналогично
  уточняет известную семантику, а не ослабляет fail-closed design.

## Completed / changed areas

- `PamControlFlowAnalyzer.cpp`: добавлена роль `CredentialCollector`;
  `pam_userpass` удалён из `CredentialAuthenticator`; `pam_localuser`
  классифицирован как `Gate`. Conservative outcomes `pam_userpass` не
  сужались: исходник ALT доказывает назначение, но не exhaustive result set.
- `PamConfigurationTests`: старый security-negative test переведён на
  настоящий `pam_tcb`; добавлен парный regression, где failure collector и
  gate не создаёт `failure_accounting_bypass`.
- `AltPamFaillockTopologyManagerTests`: SSH fixture повторяет graph
  `sshd -> pam_userpass -> common-login-use_first_pass ->
  system-auth-use_first_pass -> system-check-localuser ->
  system-check-localuser-systemd`, exact trusted alias и control
  `[success=1 perm_denied=ignore default=die]`; capability соответствует
  ALT contract `LocalUsersOnly`.
- Узкий audit `credentialAuthenticators` не выявил другого очевидного
  collector/consumer: остальные entries являются credential-verifying
  providers. Отдельно исследованный `pam_gnome_keyring` оставлен `Auxiliary`.
- Mutation check: при временном возврате только `pam_userpass` в
  `CredentialAuthenticator` новый paired regression падает с исходным
  `failure_accounting_bypass`; production role затем восстановлена.

## Validation

- Mutation check на старой role — ожидаемый FAIL с trace
  `pam_userpass PAM_AUTH_ERR -> pam_localuser PAM_USER_UNKNOWN/default=die`.
- Targeted CTest: `pam_configuration_tests`,
  `pam_control_flow_analyzer_tests`, `alt_pam_faillock_topology_tests`,
  `identity_policy_hierarchy_tests`, `platform_profile_tests` — 5/5 PASS.
- `cmake --build build-check -j4` — PASS.
- `ctest --test-dir build-check --output-on-failure` — 114 PASS,
  1 root-only test skipped (`command_hash_batch_tests`), failures нет.
- Real ALT gate не выполнен: локального Docker image
  `localhost/fic-rpm-builder:alt-p11` нет, попытка pull не продвинулась;
  Podman не установлен. SSH к прежней ВМ `10.88.0.86` завершился timeout.

## Remaining

- При появлении образа или доступа повторить real ALT gate и daemon/CLI path
  `fic-cli policy apply IDENTITY_ACCESS all`, затем проверить четыре
  `failed_authentication_*` policies.
- Отдельная ошибка password history
  `Active PAM provenance has no proven owned topology` не входит в этот fix и
  намеренно не исправлялась.
- Не коммитить без отдельного запроса.
