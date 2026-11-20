# Debian 13 Google TOTP topology and StructuralEffective proof

D13-2 supplies the production C++ renderer and verifier in `PamMfaTopology`.
The renderer returns a disabled-by-default `pam-auth-update` Additional
profile with `auth substack fic-mfa`, a neutral slot, and a mandatory slot.
The mandatory slot uses `pam_succeed_if` to reject a slash in `PAM_USER`
before that name is expanded in the credential filename. The Google TOTP
rule uses `[success=ok default=die]`. Only success contributes to the
parent authentication stack and every other result, including
`PAM_IGNORE`, records failure. `ok` lets subsequent rules run. A previous
required failure survives a successful OTP. A substack counts as one
element for jumps from its parent and confines its own `done` and `die`.
See [Debian PAM control syntax](https://manpages.debian.org/trixie/libpam-runtime/pam.conf.5.en.html),
[Debian pam-auth-update](https://manpages.debian.org/trixie/libpam-runtime/pam-auth-update.8.en.html)
and the [Debian Google Authenticator sources](https://packages.debian.org/source/trixie/admin/google-authenticator).

## PROVEN_STATIC

`verifyDebian13Mfa` reads one explicitly selected Debian 13 PAM service
from the existing FIC authentication scope. It requires the effective
`common-auth` route and one canonical MFA substack. Candidate mode
substitutes the mandatory rules for a trusted neutral slot in memory.
Installed mode requires the effective mandatory rules on disk. Both
validate graph sources, the module paths, the rule arguments and the
credential directory. Unknown routes, missing or duplicated slots and
unsupported includes fail closed.

The verifier uses the shared PAM control-flow analyzer. It requires
evidence of a successful primary followed by a successful factor on
every successful path, and a possible two-factor success for each
declared route. An independent local run models a blank password and
requires every outcome to fail. This recognizes strict `pam_unix` and
the effect of the D13-1 guard when present. `sufficient`, `done` and
numeric jumps are evaluated in the effective graph. `reset` is outside
the supported MFA controls.

The supported domain route has the Debian `pam_sss.so use_first_pass`
Primary, one LDAP identity and authentication domain over verified TLS,
fully qualified names, local-only shadow and `passwd: files sss`.
Local accounts cannot occupy the qualified namespace. SSSD certificate
and passkey authentication, password caching and cached authentication
are disabled. The proof uses the trusted SSSD main file and drop-ins.
Debian 13 grants group read at SSSD startup, with root remaining owner
and group. Evidence describes the on-disk snapshot, so an application
must load that PAM stack and the SSSD responder must use the proven
configuration. [Debian pam_sss](https://manpages.debian.org/trixie/libpam-sss/pam_sss.8.en.html),
[Debian sssd.conf](https://manpages.debian.org/trixie/sssd-common/sssd.conf.5.en.html).

The credential contract is a root-owned mode-0700 directory
`/etc/security/fic-mfa`, with single-link root-owned mode-0600 files
named `totp-${USER}`. The admitted format contains a 32-character
uppercase Base32 seed and the TOTP mode marker. The module reads it as
root and prompts separately for the code. A user without a registration
is denied by PAM. The structural proof allows an empty directory and
does not attest enrollment for any user. [Debian Google Authenticator manpage](https://manpages.debian.org/trixie/libpam-google-authenticator/pam_google_authenticator.8.en.html).

## PROVEN_NATIVE

The [container gate](../tests/integration/pam-mfa-d13/README.md) calls
the production verifier and Debian Linux-PAM with the `login` service.
It exercises real `pam_unix`, LDAP-backed `pam_sss`, and
`pam_google_authenticator`. Deterministic test PAM statuses supplement
the real provider cases. The tested FIC-owned faillock hooks count a
wrong primary. A wrong OTP after a correct primary is denied without
adding a faillock failure. D13-1 and faillock can be reapplied with the
canonical experiment attached.

## NOT_TESTED and UNSUPPORTED

The native contract is `pam_authenticate()` with the `login` PAM
service and a conversation that supplies password and OTP independently.
SSH password and keyboard-interactive modes, sudo, su and graphical
login protocol behavior have no native proof here. A service that skips
PAM auth, including SSH public-key-only authentication, has no MFA
guarantee from this verifier. Winbind, homed, smart card, alternative
SSSD providers, unknown PAM routes, HOTP, scratch codes and other MFA
providers are outside the accepted contract. OTP replay prevention and
credential rate limits have no proof in D13-2.

D13-3 owns policy integration, publication, provenance, journal-backed
apply, recovery and rollback. D13-2 neither installs a slot or
registration in production packages nor enables MFA on a production
host.
