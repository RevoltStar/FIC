/*
 * C2 functional gate PAM probe: performs a REAL pam_chauthtok through the
 * distro "passwd" PAM service (the same service the interactive passwd(1)
 * uses). Modeled after the v7 owner-run harness lessons: single-line
 * RESULT record, all conversation prompts answered with the candidate
 * password (root does not need the current token for target users).
 *
 * Usage: fic-pam-probe USER   (passwords via env)
 *   FIC_GATE_PW      the candidate NEW password
 *   FIC_GATE_CURRENT the CURRENT password (self-change mode: the probe
 *                    is executed AS the target user, so pam_pwhistory
 *                    and friends enforce for non-root)
 * Exit 0 + "RESULT ok ..." on success; exit 1 + "RESULT fail ..." on
 * PAM rejection. The passwords are NEVER printed.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* strcasestr */
#endif
#include <security/pam_appl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static const char *candidate_password = NULL;
static const char *current_password = NULL;

static int gate_conversation(int num_msg,
        const struct pam_message **messages,
        struct pam_response **responses, void *appdata_ptr) {
    (void)appdata_ptr;
    if (num_msg <= 0 || messages == NULL || responses == NULL) {
        return PAM_CONV_ERR;
    }
    struct pam_response *reply =
        calloc((size_t)num_msg, sizeof(struct pam_response));
    if (reply == NULL) {
        return PAM_BUF_ERR;
    }
    for (int i = 0; i < num_msg; ++i) {
        const char *token = candidate_password;
        /* Deterministic prompt routing by TEXT (the first-prompt
         * heuristic breaks on stacks where pam_pwquality prompts for the
         * NEW password before pam_unix prompts for the current one):
         * a "current"/"old" password prompt gets the CURRENT password,
         * everything else (new/retype prompts) gets the candidate. */
        if (current_password != NULL &&
            messages[i]->msg_style == PAM_PROMPT_ECHO_OFF) {
            const char *text = messages[i]->msg;
            if (text != NULL &&
                (strcasestr(text, "current") != NULL ||
                 strcasestr(text, "old") != NULL)) {
                token = current_password;
            }
        }
        reply[i].resp = strdup(token);
        reply[i].resp_retcode = 0;
        if (reply[i].resp == NULL) {
            for (int j = 0; j < i; ++j) {
                free(reply[j].resp);
            }
            free(reply);
            return PAM_BUF_ERR;
        }
    }
    *responses = reply;
    return PAM_SUCCESS;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: fic-pam-probe USER\n");
        return 2;
    }
    candidate_password = getenv("FIC_GATE_PW");
    if (candidate_password == NULL || candidate_password[0] == '\0') {
        fprintf(stderr, "FIC_GATE_PW is not set\n");
        return 2;
    }
    current_password = getenv("FIC_GATE_CURRENT");
    struct pam_conv conversation = {gate_conversation, NULL};
    pam_handle_t *handle = NULL;
    int rc = pam_start("passwd", argv[1], &conversation, &handle);
    if (rc != PAM_SUCCESS) {
        printf("RESULT fail pam_start %s\n",
            pam_strerror(handle, rc));
        return 1;
    }
    rc = pam_chauthtok(handle, 0);
    printf("RESULT %s %s\n", rc == PAM_SUCCESS ? "ok" : "fail",
        pam_strerror(handle, rc));
    pam_end(handle, rc);
    return rc == PAM_SUCCESS ? 0 : 1;
}
