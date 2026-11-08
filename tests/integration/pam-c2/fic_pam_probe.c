/*
 * C2 functional gate PAM probe: performs a REAL pam_chauthtok through the
 * distro "passwd" PAM service (the same service the interactive passwd(1)
 * uses). Modeled after the v7 owner-run harness lessons: single-line
 * RESULT record, password prompts answered with the candidate
 * password (current-token prompts use FIC_GATE_CURRENT). INFO/ERROR
 * messages receive no response.
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
#include <unistd.h>

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
        if (messages[i] == NULL) goto conversation_error;
        if (messages[i]->msg_style == PAM_TEXT_INFO ||
            messages[i]->msg_style == PAM_ERROR_MSG) continue;
        if (messages[i]->msg_style != PAM_PROMPT_ECHO_OFF &&
            messages[i]->msg_style != PAM_PROMPT_ECHO_ON) goto conversation_error;
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
conversation_error:
    for (int j = 0; j < num_msg; ++j) free(reply[j].resp);
    free(reply);
    return PAM_CONV_ERR;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--conversation-test") == 0) {
        candidate_password = "candidate"; current_password = "current";
        struct pam_message a={PAM_TEXT_INFO,"information"}, b={PAM_PROMPT_ECHO_OFF,"Current password:"},
            c={PAM_PROMPT_ECHO_OFF,"New password:"}, d={PAM_ERROR_MSG,"notice"};
        const struct pam_message *messages[]={&a,&b,&c,&d};
        struct pam_response *reply=NULL;
        int rc=gate_conversation(4,messages,&reply,NULL);
        int ok=rc==PAM_SUCCESS && reply && !reply[0].resp && !reply[3].resp &&
            strcmp(reply[1].resp,current_password)==0 && strcmp(reply[2].resp,candidate_password)==0;
        if(reply){for(int i=0;i<4;++i)free(reply[i].resp);free(reply);}
        printf("CONVERSATION %s\n",ok?"PASS":"FAIL");return ok?0:1;
    }
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
    const char *service=getenv("FIC_GATE_SERVICE");
    const int auth=getenv("FIC_GATE_AUTH")!=NULL;
    int rc = pam_start(service?service:"passwd", argv[1], &conversation, &handle);
    if (rc != PAM_SUCCESS) {
        printf("RESULT fail pam_start %s\n",
            pam_strerror(handle, rc));
        return 1;
    }
    rc = auth ? pam_authenticate(handle,0) : pam_chauthtok(handle, 0);
    if (auth && rc==PAM_SUCCESS) rc=pam_acct_mgmt(handle,0);
    printf("IDENTITY uid=%lu euid=%lu mode=%s\n",(unsigned long)getuid(),
           (unsigned long)geteuid(),auth?"auth-account":"chauthtok");
    printf("RESULT %s %s\n", rc == PAM_SUCCESS ? "ok" : "fail",
        pam_strerror(handle, rc));
    pam_end(handle, rc);
    return rc == PAM_SUCCESS ? 0 : 1;
}
