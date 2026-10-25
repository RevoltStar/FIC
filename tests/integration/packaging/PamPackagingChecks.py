#!/usr/bin/env python3
"""Static PAM profile contracts; physical hook proofs live in PackagePamHooksTests/native gates."""
from pathlib import Path
import re
import sys

def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def field(profile: str, name: str) -> str:
    match = re.search(rf"^{re.escape(name)}:\s*(.+)$", profile, re.MULTILINE)
    require(match is not None, f"PAM profile has no {name} field")
    return match.group(1).strip()


def optional_field(profile: str, name: str) -> str:
    match = re.search(rf"^{re.escape(name)}:\s*(.+)$", profile, re.MULTILINE)
    return "" if match is None else match.group(1).strip()


def function_body(script: str, name: str) -> str:
    match = re.search(
        rf"^{re.escape(name)}\(\) \{{\n(?P<body>.*?)^\}}$",
        script,
        re.MULTILINE | re.DOTALL,
    )
    require(match is not None, f"packaging builder has no function {name}")
    return match.group("body")


PERMANENT_HOOKS = (
    "fic-faillock-hook-preauth",
    "fic-faillock-hook-authfail",
    "fic-faillock-hook-authsucc",
    "fic-faillock-hook-account",
    "fic-incident-access",
)
AUTH_HOOKS = PERMANENT_HOOKS[:3]
LEGACY_POLICY_PROFILES = (
    "fic-faillock-notify",
    "fic-faillock-preauth-required",
    "fic-faillock-authsucc",
    "fic-pwquality",
    "fic-pwhistory",
)

# C2 managed password hook profiles: package payload, attached only
# through an explicit administrator pam-auth-update selection, never by the
# package itself. Three distinct activation identities: the quality
# producer, the history consumer (use_authtok) and the history initial
# producer — each with ONE semantic include target.
PASSWORD_HOOKS = ("fic-password-quality-hook", "fic-password-history-hook",
                  "fic-password-history-initial-hook")
PASSWORD_HOOK_TARGETS = ("fic-password-quality", "fic-password-history",
                         "fic-password-history-initial")


def main() -> int:
    root = Path(sys.argv[1])
    profile_dir = root / "packaging/deb/pam-configs"
    expected = {
        "fic-faillock-notify": {
            "Name": "FIC PAM faillock pre-authentication and account check",
            "Priority": "1025",
            "rules": (
                "pam_faillock.so preauth",
                "required\t\t\tpam_faillock.so",
            ),
        },
        "fic-faillock-authfail": {
            "Name": "FIC PAM faillock failed authentication counter",
            "Priority": "1",
            "rules": ("[default=die]\t\t\tpam_faillock.so authfail",),
        },
        "fic-faillock-preauth-required": {
            "Name": "FIC PAM faillock pre-authentication and account check (required)",
            "Priority": "1025",
            "rules": (
                "pam_faillock.so preauth",
                "required\t\t\tpam_faillock.so",
            ),
        },
        "fic-faillock-authsucc": {
            "Name": "FIC PAM faillock success accounting and lock denial",
            "Priority": "1025",
            "rules": ("required\t\t\tpam_faillock.so authsucc",),
        },
        "fic-faillock-hook-preauth": {
            "Name": "FIC permanent pam_faillock preauth hook",
            "Priority": "100000",
            "rules": ("include                     fic-faillock-preauth",),
        },
        "fic-faillock-hook-authfail": {
            "Name": "FIC permanent pam_faillock authfail hook",
            "Priority": "-100000",
            "rules": ("include                     fic-faillock-authfail",),
        },
        "fic-faillock-hook-authsucc": {
            "Name": "FIC permanent pam_faillock authsucc hook",
            "Priority": "-100000",
            "rules": ("include                     fic-faillock-authsucc",),
        },
        "fic-faillock-hook-account": {
            "Name": "FIC permanent pam_faillock account hook",
            "Priority": "100000",
            "rules": ("include                     fic-faillock-account",),
        },
        "fic-incident-access": {
            "Name": "FIC permanent incident access account gate",
            "Priority": "100001",
            "rules": ("required                    pam_fic_access.so",),
        },
        "fic-pwquality": {
            "Name": "FIC PAM password quality checking",
            "Priority": "1024",
            "rules": ("requisite\t\t\tpam_pwquality.so retry=3",),
        },
        "fic-pwhistory": {
            "Name": "FIC PAM password history checking",
            "Priority": "1023",
            "rules": (
                "pam_pwhistory.so use_authtok",
                "requisite\t\t\tpam_pwhistory.so",
            ),
        },
        "fic-password-quality-hook": {
            "Name": "FIC password quality hook",
            "Priority": "1024",
            "rules": (
                "include                     fic-password-quality",
            ),
        },
        "fic-password-history-hook": {
            "Name": "FIC password history hook",
            "Priority": "1023",
            "rules": (
                "include                     fic-password-history",
            ),
        },
        "fic-password-history-initial-hook": {
            "Name": "FIC password history initial hook",
            "Priority": "1022",
            "rules": (
                "include                     fic-password-history-initial",
            ),
        },
    }
    prohibited_arguments = (
        "deny=",
        "fail_interval=",
        "unlock_time=",
        "remember=",
        "enforce_for_root",
        "try_first_pass",
    )

    for name, contract in expected.items():
        path = profile_dir / name
        require(path.is_file() and not path.is_symlink(), f"missing physical PAM profile: {name}")
        profile = path.read_text(encoding="utf-8")
        require(field(profile, "Name") == contract["Name"], f"wrong Name in {name}")
        require(field(profile, "Default") == "no", f"{name} must default to disabled")
        require(field(profile, "Priority") == contract["Priority"], f"wrong Priority in {name}")
        for rule in contract["rules"]:
            require(rule in profile, f"{name} is missing rule: {rule}")
        for argument in prohibited_arguments:
            require(argument not in profile, f"{name} embeds policy argument: {argument}")

    # C2: three distinct activation identities for the FIC-owned password
    # hooks. They are immutable package infrastructure: Primary password
    # type, exact priorities, Default: no, and the exact include targets
    # into the package-owned managed slots. They are never enabled by the
    # package (activation-time attach is a later, explicitly separate
    # step), and the initial producer and the consumer are two separate
    # explicit identities — no Password-Initial switching of a single
    # history profile.
    quality_hook = (profile_dir / "fic-password-quality-hook").read_text(encoding="utf-8")
    history_hook = (profile_dir / "fic-password-history-hook").read_text(encoding="utf-8")
    history_initial_hook = (profile_dir / "fic-password-history-initial-hook").read_text(encoding="utf-8")
    for hook_name, hook in (("fic-password-quality-hook", quality_hook),
                            ("fic-password-history-hook", history_hook),
                            ("fic-password-history-initial-hook",
                             history_initial_hook)):
        require(field(hook, "Password-Type") == "Primary",
                f"{hook_name} Password-Type is not Primary")
        require(optional_field(hook, "Auth-Type") == "" and
                optional_field(hook, "Account-Type") == "",
                f"{hook_name} must only register password facility rules")
    require(re.search(r"^Password:\n\s+include\s+fic-password-quality$",
                      quality_hook, re.MULTILINE) is not None,
            "quality hook Password section must include fic-password-quality")
    require(re.search(r"^Password-Initial:\n\s+include\s+fic-password-quality$",
                      quality_hook, re.MULTILINE) is not None,
            "quality hook Password-Initial section must include fic-password-quality")
    require(re.search(r"^Password:\n\s+include\s+fic-password-history$",
                      history_hook, re.MULTILINE) is not None,
            "history consumer hook Password section must include "
            "fic-password-history")
    require(re.search(r"^Password-Initial:\n\s+include\s+fic-password-history$",
                      history_hook, re.MULTILINE) is not None,
            "history consumer hook Password-Initial section must include "
            "fic-password-history")
    require("fic-password-history-initial" not in history_hook,
            "the history consumer hook must not reference the "
            "history-initial identity (separate explicit profile)")
    require(re.search(r"^Password:\n\s+include\s+"
                      r"fic-password-history-initial$",
                      history_initial_hook, re.MULTILINE) is not None,
            "history initial hook Password section must include "
            "fic-password-history-initial")
    require(re.search(r"^Password-Initial:\n\s+include\s+"
                      r"fic-password-history-initial$",
                      history_initial_hook, re.MULTILINE) is not None,
            "history initial hook Password-Initial section must include "
            "fic-password-history-initial")
    require("fic-password-history\n" not in history_initial_hook,
            "the history initial hook must not reference the consumer "
            "identity (separate explicit profile)")

    # C2 priority ordering (pam-auth-update sorts Primary password
    # profiles by descending priority; the stock Debian/Ubuntu `unix`
    # profile has priority 256). The v7-verified stack order is
    # quality producer < history consumer < pam_unix ("<" = earlier in
    # the generated stack). The initial producer profile is never
    # co-selected with the consumer profile, so it only has to keep its
    # producer position before pam_unix.
    quality_priority = int(field(quality_hook, "Priority"))
    history_priority = int(field(history_hook, "Priority"))
    history_initial_priority = int(field(history_initial_hook, "Priority"))
    stock_unix_password_priority = 256
    require(quality_priority > history_priority > stock_unix_password_priority,
            "C2 ordering violated: quality producer must sort before the "
            "history consumer, both before stock unix (256)")
    require(stock_unix_password_priority < history_initial_priority,
            "the history initial producer must sort before stock unix "
            "(256) to keep the producer position")
    require(history_initial_priority != history_priority,
            "the history initial and consumer identities must have "
            "distinct deterministic priorities")

    # The three managed password slots ship as canonical-neutral package
    # payload: package owns existence, runtime policy + journal own state.
    slot_payload_dir = root / "packaging/deb/pam-slots"
    neutral_slot_body = "# FIC managed password slot: state=neutral\n"
    for slot in ("fic-password-quality", "fic-password-history",
                 "fic-password-history-initial"):
        slot_path = slot_payload_dir / slot
        require(slot_path.is_file() and not slot_path.is_symlink(),
                f"missing managed password slot payload: {slot}")
        require(slot_path.read_text(encoding="utf-8") == neutral_slot_body,
                f"managed password slot {slot} payload is not canonical neutral")

    notify = (profile_dir / "fic-faillock-notify").read_text(encoding="utf-8")
    require(field(notify, "Auth-Type") == "Primary", "notify profile Auth-Type is not Primary")
    require(field(notify, "Account-Type") == "Primary", "notify profile Account-Type is not Primary")
    require("requisite\t\t\tpam_faillock.so preauth" in notify, "notify profile has wrong preauth control")

    authfail = (profile_dir / "fic-faillock-authfail").read_text(encoding="utf-8")
    require(field(authfail, "Auth-Type") == "Primary", "authfail profile Auth-Type is not Primary")
    preauth_required = (profile_dir / "fic-faillock-preauth-required").read_text(encoding="utf-8")
    require(field(preauth_required, "Auth-Type") == "Primary",
            "preauth-required profile Auth-Type is not Primary")
    require(field(preauth_required, "Account-Type") == "Primary",
            "preauth-required profile Account-Type is not Primary")
    require("required\t\t\tpam_faillock.so preauth" in preauth_required,
            "preauth-required profile has wrong preauth control")
    authsucc = (profile_dir / "fic-faillock-authsucc").read_text(encoding="utf-8")
    # authsucc must run in the Additional auth block: a Primary authsucc is
    # jumped over by successful primary credential providers (success=N
    # jumps past the whole primary block into pam_permit), which lets a
    # locked user with a correct password authenticate.
    require(field(authsucc, "Auth-Type") == "Additional",
            "authsucc profile Auth-Type is not Additional; Primary authsucc "
            "is bypassed by primary provider success jumps")
    require("required\t\t\tpam_faillock.so authsucc" in authsucc,
            "authsucc profile has wrong control; upstream sufficient must not "
            "be copied blindly and the denial must not be skippable")
    require("sufficient" not in authsucc, "authsucc profile must not use sufficient control")
    require("Account-Type" not in authsucc,
            "authsucc profile must not add an account pam_faillock phase")
    # The three strategy-selector profiles conflict with each other so
    # pam-auth-update cannot generate a mixed strategy. The shared authfail
    # profile must not conflict with them because every strategy recipe
    # enables authfail together with one selector.
    selector_profiles = {
        "fic-faillock-notify",
        "fic-faillock-preauth-required",
        "fic-faillock-authsucc",
    }
    for conflicting in selector_profiles:
        profile = (profile_dir / conflicting).read_text(encoding="utf-8")
        conflicts = optional_field(profile, "Conflicts")
        for other in selector_profiles:
            if other == conflicting:
                continue
            require(other in conflicts,
                    f"{conflicting} does not declare a Conflicts entry for {other}")
        require("fic-faillock-authfail" not in conflicts,
                f"{conflicting} conflicts with the shared authfail profile")
    authfail_conflicts = optional_field(authfail, "Conflicts")
    for selector in selector_profiles:
        require(selector not in authfail_conflicts,
                f"authfail conflicts with required selector {selector}")

    quality = (profile_dir / "fic-pwquality").read_text(encoding="utf-8")
    require(field(quality, "Password-Type") == "Primary",
            "pwquality profile Password-Type is not Primary")
    require("pwquality" not in optional_field(quality, "Conflicts").split(),
            "fic-pwquality must not conflict with the distro pwquality profile")

    history = (profile_dir / "fic-pwhistory").read_text(encoding="utf-8")
    require(field(history, "Password-Type") == "Primary", "history profile Password-Type is not Primary")
    require("Password-Initial:" in history, "history profile has no Password-Initial stanza")


    hooks=(root/'fic/src/daemon/PackagePamHooks.cpp').read_text()
    helper=(root/'fic/package/PackageInfrastructureMain.cpp').read_text()
    for profile in ('fic-faillock-hook-preauth','fic-faillock-hook-authfail',
                    'fic-faillock-hook-authsucc','fic-faillock-hook-account'):
        require(profile in hooks,'missing permanent hook '+profile)
    require('proveDetached' in helper and 'proveStopped' in helper,'package detach lacks physical proofs')
    require('rollbackPolicyBeforeDisable' not in helper and 'MutationJournal' not in helper,
            'infrastructure helper must not be an offline rollback engine')
    for kind,file in [('deb','fic.prerm'),('rpm','fic.preun')]:
        text=(root/'packaging'/kind/'lifecycle'/file).read_text()
        require('fic-package-infrastructure remove' in text,'missing closed infrastructure entrypoint')
        require('control ' not in text and 'prerm-prepare' not in text,'obsolete offline policy release')
    print('PASS: PAM profile/static package boundary checks; no native authentication claim')
    return 0

if __name__ == '__main__':
    sys.exit(main())
