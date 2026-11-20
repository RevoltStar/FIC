#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int n, const char **args) {
    (void) flags;
    if (n != 1) return PAM_SYSTEM_ERR;
    if (!strcmp(args[0], "token")) {
        const void *token = NULL;
        const char *expected = getenv("FIC_FIXTURE_PASSWORD");
        if (expected && pam_get_item(pamh, PAM_AUTHTOK, &token) == PAM_SUCCESS &&
            token && strcmp(token, expected) == 0) return PAM_SUCCESS;
        return PAM_AUTH_ERR;
    }
    fprintf(stderr, "mock:%s\n", args[0]);
    if (!strcmp(args[0], "success")) return PAM_SUCCESS;
    if (!strcmp(args[0], "ignore")) return PAM_IGNORE;
    if (!strcmp(args[0], "auth_err")) return PAM_AUTH_ERR;
    return PAM_SYSTEM_ERR;
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int n, const char **args) {
    (void) pamh; (void) flags; (void) n; (void) args;
    return PAM_SUCCESS;
}
