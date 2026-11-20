// Lab-only instrumentation. Never linked into sshd or the FIC PAM module.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *trace_path;
static const char *fault;

__attribute__((constructor)) static void observer_init(void) {
    // OpenSSH's PAM worker clears environ. Preserve only the laboratory
    // observer configuration before its fork, never authentication data.
    const char *path = getenv("FIC_SSH_PAM_TRACE");
    const char *mode = getenv("FIC_SSH_PAM_FAULT");
    if (path) trace_path = strdup(path);
    if (mode) fault = strdup(mode);
}

static void observe(const char *phase, pam_handle_t *handle, int flags, int rc) {
    const void *service = NULL;
    if (!trace_path || pam_get_item(handle, PAM_SERVICE, &service) != PAM_SUCCESS || !service)
        return;
    FILE *log = fopen(trace_path, "a");
    if (!log) return;
    const char *evidence = pam_getenv(handle, "SSH_AUTH_INFO_0");
    const char *state = !evidence ? "missing" : !*evidence ? "empty" :
        strcmp(evidence, "password\n") == 0 ? "password" :
        strncmp(evidence, "publickey ssh-ed25519 ", sizeof("publickey ssh-ed25519 ") - 1) == 0 ? "ed25519" : "other";
    fprintf(log, "%s %s flags=%d rc=%d evidence=%s\n",
            (const char *)service, phase, flags, rc, state);
    fclose(log);
}

int pam_start(const char *name, const char *user, const struct pam_conv *conv, pam_handle_t **h) {
    int (*real)(const char *, const char *, const struct pam_conv *, pam_handle_t **) =
        dlsym(RTLD_NEXT, "pam_start");
    const int rc = real(name, user, conv, h);
    if (rc == PAM_SUCCESS) observe("start", *h, 0, rc);
    return rc;
}

int pam_end(pam_handle_t *h, int status) {
    int (*real)(pam_handle_t *, int) = dlsym(RTLD_NEXT, "pam_end");
    const void *service = NULL;
    const int dedicated = pam_get_item(h, PAM_SERVICE, &service) == PAM_SUCCESS &&
        service && strcmp(service, "fic-sshd-mfa") == 0;
    const int rc = real(h, status);
    // pam_end has disposed of the handle and its environment.
    FILE *log = trace_path && dedicated ? fopen(trace_path, "a") : NULL;
    if (log) {
        fprintf(log, "fic-sshd-mfa end flags=0 rc=%d evidence=disposed\n", rc);
        fclose(log);
    }
    return rc;
}

#define OBSERVE(function, phase) \
int function(pam_handle_t *h, int flags) { \
    int (*real)(pam_handle_t *, int) = dlsym(RTLD_NEXT, #function); \
    int rc = real(h, flags); \
    observe(phase, h, flags, rc); \
    return rc; \
}

int pam_authenticate(pam_handle_t *h, int flags) {
    int (*real)(pam_handle_t *, int) = dlsym(RTLD_NEXT, "pam_authenticate");
    if (fault && strcmp(fault, "bad-name") == 0 &&
        pam_set_item(h, PAM_USER, "bad/name") != PAM_SUCCESS) return PAM_SYSTEM_ERR;
    const int rc = real(h, flags);
    observe("auth", h, flags, rc);
    return rc;
}

int pam_setcred(pam_handle_t *h, int flags) {
    int (*real)(pam_handle_t *, int) = dlsym(RTLD_NEXT, "pam_setcred");
    const int rc = fault && strcmp(fault, "setcred") == 0 && (flags & PAM_ESTABLISH_CRED)
        ? PAM_PERM_DENIED : real(h, flags);
    observe("setcred", h, flags, rc);
    return rc;
}
OBSERVE(pam_acct_mgmt, "account")
OBSERVE(pam_open_session, "open")
OBSERVE(pam_close_session, "close")

int pam_putenv(pam_handle_t *h, const char *value) {
    static const char prefix[] = "SSH_AUTH_INFO_0=";
    int (*real)(pam_handle_t *, const char *) = dlsym(RTLD_NEXT, "pam_putenv");
    if (fault && strcmp(fault, "remove") == 0 && strcmp(value, "SSH_AUTH_INFO_0") == 0) {
        observe("remove-fault", h, 0, PAM_BUF_ERR);
        return PAM_BUF_ERR;
    }
    if (fault && strncmp(value, prefix, sizeof(prefix) - 1) == 0 && value[sizeof(prefix) - 1]) {
        if (strcmp(fault, "publish") == 0) {
            observe("publish-fault", h, 0, PAM_BUF_ERR);
            return PAM_BUF_ERR;
        }
        if (strcmp(fault, "malformed") == 0)
            return real(h, "SSH_AUTH_INFO_0=password\npassword\n");
    }
    return real(h, value);
}
