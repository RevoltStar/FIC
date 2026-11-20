// SSH_AUTH_INFO_0 grammar pinned to Debian 13 OpenSSH 10.0p1.
#define _POSIX_C_SOURCE 200809L
#include <pwd.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <string.h>

#define FIC_PAM_EXPORT __attribute__((visibility("default")))

static const char evidence_name[] = "SSH_AUTH_INFO_0";

static int configured_service(pam_handle_t *pamh, int argc) {
    const void *service = NULL;
    return pamh != NULL && argc == 0 &&
        pam_get_item(pamh, PAM_SERVICE, &service) == PAM_SUCCESS && service != NULL &&
        strcmp(service, "fic-sshd-mfa") == 0;
}

static int classify(const char *evidence) {
    static const char method[] = "publickey ssh-ed25519 ";
    // Canonical base64 of the SSH wire header: string "ssh-ed25519",
    // then a 32-byte string. The next sextet has its top two bits clear.
    static const char header[] = "AAAAC3NzaC1lZDI1NTE5AAAAI";
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    enum { blob_size = 68, record_size = sizeof(method) - 1 + blob_size + 1 };
    const size_t length = strnlen(evidence, record_size + 1);

    if (length == 0) return PAM_SUCCESS;
    if (length == sizeof("password\n") - 1 && memcmp(evidence, "password\n", length) == 0)
        return PAM_AUTH_ERR;
    if (length != record_size || evidence[length - 1] != '\n' ||
        memcmp(evidence, method, sizeof(method) - 1) != 0) return PAM_SERVICE_ERR;
    const char *blob = evidence + sizeof(method) - 1;
    if (memcmp(blob, header, sizeof(header) - 1) != 0 ||
        blob[sizeof(header) - 1] < 'A' || blob[sizeof(header) - 1] > 'P')
        return PAM_SERVICE_ERR;
    for (size_t i = sizeof(header); i < blob_size; ++i)
        if (strchr(alphabet, blob[i]) == NULL) return PAM_SERVICE_ERR;
    return PAM_AUTH_ERR;
}

FIC_PAM_EXPORT int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                                      const char **argv) {
    (void)flags;
    (void)argv;
    if (!configured_service(pamh, argc)) return PAM_SERVICE_ERR;
    const char *evidence = pam_getenv(pamh, evidence_name);
    if (!evidence) return PAM_SERVICE_ERR;
    // pam_putenv can invalidate the string. Only the classified value
    // survives the call. Never map an API failure into a routing result.
    const int result = classify(evidence);
    if (pam_putenv(pamh, evidence_name) != PAM_SUCCESS) return PAM_SERVICE_ERR;
    if (result == PAM_SERVICE_ERR) return result;
    const void *user = NULL;
    if (pam_get_item(pamh, PAM_USER, &user) != PAM_SUCCESS || !user || !*(const char *)user)
        return PAM_SERVICE_ERR;
    struct passwd entry;
    struct passwd *found = NULL;
    char buffer[16384];
    if (getpwnam_r(user, &entry, buffer, sizeof(buffer), &found) != 0 || !found)
        return PAM_SERVICE_ERR;
    return result;
}

FIC_PAM_EXPORT int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                                const char **argv) {
    (void)flags;
    (void)argv;
    return configured_service(pamh, argc) ? PAM_IGNORE : PAM_SERVICE_ERR;
}
