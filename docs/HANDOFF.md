# FIC: передача контекста

## Current base

- Ветка: `main`.
- Родитель текущей правки: `54432c9`.

## Current task

- Устранить PAM trusted-file check-then-reopen TOCTOU.

## Accepted architecture / invariants

- Security validation и чтение относятся к одному fd: authoritative
  `open(O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK)`, затем `fstat` и `read`.
- Индивидуальные owner/group/mode/nlink contracts задаются typed options;
  hard-link restrictions не добавляются без существующего требования.
- `disable_nopasswdlogin`, pwquality и pwhistory parsing semantics не меняются.

## Completed

- В `fic-core` добавлен reusable `TrustedFileReader` с RAII fd, EINTR retry,
  complete-read/close handling и deterministic post-validation test seam.
- На него переведены identity passwd/group reads, pwhistory config/topology
  reads, transaction-module inspection, `PamOptionFile` и pwquality file reads.
- Добавлены deterministic pathname-replacement regressions для generic reader,
  passwd/group policy и pwhistory config, а также trust/type/mode/module tests.

## Changed areas

- `fic-common/fic-core` trusted-file reader.
- PAM passwordless, pwhistory topology, generic option и pwquality readers.
- Соответствующие core/PAM tests и CMake registration.

## Validation

- Fresh full build Ubuntu 24.04: passed.
- Все 10 PAM/identity-related CTest: passed.
- Fresh `fic` и targeted test builds для Debian 12/13, Ubuntu 24.04/26.04 и
  ALT p11: passed; последовательные profile tests: 8/8 passed на каждом.
- Full CTest: 65 passed, 4 skipped, 3 unrelated/environment failures
  (`module_ui_static_checks`, sandboxed socket bind, `mode_and_owner_tests`).
- `git diff --check`: passed.

## Remaining

- Standalone trusted inspection `pam_fic_pwtxn.so` не может связать inode с
  последующей загрузкой внешним Linux-PAM loader; для этого потребовалось бы
  менять loader/API.
- Полный ALT package не собран: в host environment нет PAM development header;
  ALT `fic` и relevant tests собраны с configure-only include override.
- Baseline `module_ui_static_checks` ожидает старый GUI source pattern.
