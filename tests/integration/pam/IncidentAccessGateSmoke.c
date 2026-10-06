#include <security/pam_appl.h>

#include <stdio.h>
#include <string.h>

static int conversation(int count, const struct pam_message** messages,
                        struct pam_response** responses, void* data) {
    (void)count;
    (void)messages;
    (void)responses;
    (void)data;
    return PAM_CONV_ERR;
}

int main(int argc, char** argv) {
    if (argc != 4 && argc != 5) return 2;
    const struct pam_conv conv = {conversation, NULL};
    pam_handle_t* handle = NULL;
    int result = pam_start(argc == 5 ? argv[4] : "login",
                           argv[1], &conv, &handle);
    if (result != PAM_SUCCESS) return 3;
    if (strcmp(argv[2], "local") != 0) {
        result = pam_set_item(handle, PAM_RHOST, argv[2]);
        if (result != PAM_SUCCESS) {
            pam_end(handle, result);
            return 4;
        }
    }
    result = pam_acct_mgmt(handle, 0);
    printf("PAM_RESULT=%d\n", result);
    const int expected = strcmp(argv[3], "pass") == 0
        ? PAM_SUCCESS : PAM_PERM_DENIED;
    pam_end(handle, result);
    return result == expected ? 0 : 1;
}
