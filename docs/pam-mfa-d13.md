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
fully qualified names, `shadow: files` and `passwd: files sss`.
The SSSD NSS password field must stay locked (`*`, the remote LDAP
default), including any per-domain override. `pam_unix` therefore
cannot treat the passwd record from SSSD as a password hash or ask
another shadow provider for a credential.
Local accounts cannot occupy the qualified namespace. SSSD certificate
and passkey authentication, password caching and cached authentication
are disabled. The proof uses the trusted SSSD main file and drop-ins.
Debian 13 grants group read at SSSD startup, with root remaining owner
and group. Evidence describes the on-disk snapshot, so an application
must load that PAM stack and the SSSD responder must use the proven
configuration. [Debian pam_sss](https://manpages.debian.org/trixie/libpam-sss/pam_sss.8.en.html),
[Debian sssd.conf](https://manpages.debian.org/trixie/sssd-common/sssd.conf.5.en.html).

### NSS with libnss-systemd and SSSD

Installing `libnss-systemd` on clean Debian 13 added `systemd` after
`files` in `passwd`, `shadow` and `group`. Installing SSSD afterwards
appended `sss` to all three. The proven mixed password route can retain
both modules in `group`. Group resolution does not establish primary
password evidence.

Both `passwd: files systemd sss` and `passwd: files sss systemd`
are unsupported with SSSD. The first can select a UserDB record before
SSSD and the second can fall back to one when SSSD lookup fails. The
module accepts names containing `@`, so a qualified name alone does
not prove its source. The mixed route also rejects `systemd` in
`shadow`, where UserDB can supply password hashes. Ordinary users
from `files` are covered. DynamicUser and synthesized identities,
systemd-homed and arbitrary UserDB services or drop-ins are outside
the mixed password proof.
[Debian nss-systemd](https://manpages.debian.org/trixie/libnss-systemd/nss-systemd.8.en.html),
[systemd 257.13 NSS lookup](https://github.com/systemd/systemd/blob/v257.13/src/nss-systemd/nss-systemd.c),
[systemd 257.13 name validation](https://github.com/systemd/systemd/blob/v257.13/src/basic/user-util.c).

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

With both NSS modules installed, the gate verifies the mixed password
route and runs the local and LDAP matrix. It repeats the native matrix
for both unsupported passwd orders with `shadow: files systemd` to
observe the fixture accounts. Those results cover only the tested
accounts and do not establish namespace separation. Missing and
corrupt TOTP registration cases supply the same valid code as their
preceding successful call and restore the registration. The
conversation error is a separate case.

## D13-3A topology and SSH evidence

| Form | Auth attachment | Successful path |
|---|---|---|
| `InteractiveTwoPrompt` | Existing D13-2 `fic-mfa` hook | Strict UNIX or proven LDAP/SSSD Primary, then Google TOTP |
| `SingleInputForwardPass` | Exact dedicated `xrdp-sesman` auth substack `fic-mfa-forward` | Google TOTP via `forward_pass`, then strict UNIX or optional proven LDAP/SSSD Primary with `use_first_pass` |
| `SshStagedAuthentication` | Exact dedicated `fic-sshd-mfa` auth substack `fic-mfa-ssh-auth` | Strict password at the initial stage, or Google TOTP at a stage with previously verified password/key |

The original renderer API and the D13-2 Candidate and Installed proof
remain available. The same credential store, module trust checks and
Debian 13 NSS/SSSD restrictions apply to all forms. A dedicated body is
admitted byte-for-byte and bound to its actual expanded substack. Its
neutral candidate is replaced only in memory. The forward-pass proof
counts Primary success only with a token from a previous successful
Google `forward_pass`; the canonical rule uses neither
`try_first_pass` nor `use_first_pass` for Google. Extra auth rules
outside the dedicated substack are rejected. Scratch/HOTP credential
formats remain excluded.

`pam_fic_ssh_stage.so` is compiled as a Debian 13 PAM module, with
only `pam_sm_authenticate` and `pam_sm_setcred` exported. It takes no
arguments and requires the `fic-sshd-mfa` PAM service. It uses the
PAM handle's environment. The tested OpenSSH revision is
`1:10.0p1-7+deb13u4`. Version-0 evidence is bounded to the exact
record forms below. The staged graph assumes OpenSSH has proven the
two allowed SSH chains, including the signature when required.

| `SSH_AUTH_INFO_0` at auth | Result | Meaning |
|---|---|---|
| Present, empty | `PAM_SUCCESS` | First password stage; jump over the two OTP rules |
| Exactly `password\n` | `PAM_AUTH_ERR` | Prior password; deliberate OTP routing result |
| Exactly `publickey ssh-ed25519 <blob>\n` with canonical 68-character base64 and the Ed25519 wire header and length | `PAM_AUTH_ERR` | Prior verified Ed25519; same OTP branch |
| Missing, invalid, unknown identity, or PAM API failure | `PAM_SERVICE_ERR` | Abort |

The selector computes the result before deleting `SSH_AUTH_INFO_0`
with `pam_putenv`. The return value is released only after successful
deletion and a bounded NSS lookup of the PAM identity. The lookup
checks identity existence. SSH remains the authority for any prior
authentication method. The result of deleting evidence is never returned directly.
A failed nonempty publication by OpenSSH cannot recover a previous
empty value after that value has been consumed. The provider records
neither credentials nor key blobs. `pam_sm_setcred` validates the
service and argument contract and returns `PAM_IGNORE` without reading
or consuming evidence.

The stage control is
`[success=2 auth_err=ignore ignore=ignore default=die]`. The
OTP branch stays in the same substack and terminates it on success
with `[success=done default=die]`. Password success jumps to the
explicit permit barrier; missing Primary reaches requisite deny.
The shared name guard has `[success=ignore ignore=ignore default=die]`.
Linux-PAM can use the current result in setcred when there is no
cached auth chain. The mapping handles `pam_succeed_if` returning
`PAM_IGNORE` in setcred while preserving the slash rejection in auth.
Google `PAM_IGNORE` still fails. The conditional graph proof checks
first password, prior successful method, and invalid stages. It
does not authenticate an SSH key or verify the server process.

### Validation and limits

- **PROVEN_UNIT / PROVEN_STATIC** — the built module's PAM ABI and
  evidence grammar, consumption, return codes, and failure on removal
  error. The topology checks cover deterministic rendering and reject
  mutated graphs.
- **PROVEN_NATIVE_PAM** — full `login` and dedicated forward-pass PAM
  lifecycles, actual Google TOTP and UNIX/LDAP Primary, registration
  failures and a pre-existing token fixture. The forward-pass gate
  exercises the PAM conversation without starting xrdp.
- **PROVEN_NATIVE_SSH** — the dedicated test service on Debian 13
  OpenSSH, true client sessions for both methods and both identity
  sources, no remote command or open session on negative routes,
  retries, and injected publication, consumption and setcred errors.
- **NOT_TESTED** — production SSH runtime proof, ownership and package
  detach for MFA, a new LightDM GTK or xrdp end-to-end run with this
  renderer, and other greeters.
- **UNSUPPORTED** — bare SSH methods, other SSH evidence formats,
  other distributions, mixed NSS routes rejected in D13-2, alternative
  providers and HOTP/scratch paths.

### Debian 13 verified SSH backend

The explicit MFA request verifies exactly the two ordered chains
`publickey,keyboard-interactive:pam` and `password,keyboard-interactive:pam`
in either alternative order. It requires `UsePAM yes`,
`PasswordAuthentication yes`, `PubkeyAuthentication yes`,
`KbdInteractiveAuthentication yes`, `PermitEmptyPasswords no` and
`PAMServiceName fic-sshd-mfa`. The closure refuses conditional settings
of these fields and conflicting Includes before `sshd -t` and
`sshd -T -C`. See the [SSH adapter contract](ssh-verified-activation-adapter.md).

The staged service can use the existing FIC-owned `preauth_required` and
`preauth_requisite` graphs. It invokes the current preauth and authfail
slots only on the password stage. A password success does not clear the
tally while OTP is outstanding. The active account slot retains the
existing account-phase handling after final authentication. The SSH
proof requires the real legacy and dedicated account/session routes and
the incident account gate on the target. `authsucc` remains unsupported
by the composed proof pending an independent native compatibility gate.

The adapter accepts an explicit request with caller-authorized digests.
General policy wiring still needs the authoritative obligation to carry
that request through apply, periodic apply, rollback and release, including
daemon restart and drift. Publication of PAM attachments, MutationJournal
ownership and recovery, and MFA package lifecycle gates belong to D13-3C/D.
