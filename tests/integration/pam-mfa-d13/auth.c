#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct answers {
    char password[512];
    char otp[32];
    int password_prompts;
    int otp_prompts;
};

static int reply(int n, const struct pam_message **messages,
                 struct pam_response **responses, void *data) {
    struct answers *a = data;
    struct pam_response *r = calloc(n, sizeof(*r));
    if (!r) return PAM_BUF_ERR;
    for (int i = 0; i < n; ++i) {
        const char *value = NULL;
        const char *prompt = messages[i]->msg;
        switch (messages[i]->msg_style) {
        case PAM_PROMPT_ECHO_OFF:
            if (strstr(prompt, "Verification code:")) {
                a->otp_prompts++;
                if (strcmp(a->otp, "-") != 0) value = a->otp;
            } else if (strstr(prompt, "Password:")) {
                a->password_prompts++;
                value = a->password;
            }
            if (!value) goto conversation_error;
            break;
        case PAM_TEXT_INFO:
        case PAM_ERROR_MSG:
            continue;
        default:
            goto conversation_error;
        }
        r[i].resp = strdup(value);
        if (!r[i].resp) goto conversation_error;
    }
    *responses = r;
    return PAM_SUCCESS;

conversation_error:
    for (int i = 0; i < n; ++i) free(r[i].resp);
    free(r);
    return PAM_CONV_ERR;
}

int main(int argc, char **argv) {
    struct answers a = {0};
    if (argc != 3 || !fgets(a.password, sizeof(a.password), stdin) ||
        !fgets(a.otp, sizeof(a.otp), stdin)) return 2;
    a.password[strcspn(a.password, "\n")] = 0;
    a.otp[strcspn(a.otp, "\n")] = 0;
    const struct pam_conv conv = {reply, &a};
    pam_handle_t *pamh = NULL;
    int rc = pam_start(argv[1], argv[2], &conv, &pamh);
    if (rc == PAM_SUCCESS) {
        rc = pam_authenticate(pamh, 0);
        pam_end(pamh, rc);
    }
    printf("pam=%d password_prompts=%d otp_prompts=%d\n",
           rc, a.password_prompts, a.otp_prompts);
    return rc != PAM_SUCCESS;
}
