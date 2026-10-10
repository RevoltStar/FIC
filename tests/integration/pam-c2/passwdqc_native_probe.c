/* Integration-only probe: use the distro library used by pam_passwdqc.so.
 * Compile with the distro libpasswdqc-devel header, never a FIC evaluator. */
#include <passwdqc.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    passwdqc_params_t params;
    char *reason = NULL;
    passwdqc_params_reset(&params);
    if (passwdqc_params_load(&params, &reason, argv[1])) {
        fprintf(stderr, "native passwdqc parse failed: %s\n", reason ? reason : "unknown");
        free(reason); passwdqc_params_free(&params); return 1;
    }
    printf("min=");
    for (int i = 0; i < 5; ++i) {
        if (i) putchar(',');
        if (params.qc.min[i] == INT_MAX) printf("disabled");
        else printf("%d", params.qc.min[i]);
    }
    printf("\npassphrase=%d\nmatch=%d\nsimilar=%s\nretry=%d\nenforce=%s\n",
        params.qc.passphrase_words, params.qc.match_length,
        params.qc.similar_deny ? "deny" : "permit", params.pam.retry,
        (params.pam.flags & F_ENFORCE_MASK) == F_ENFORCE_EVERYONE ? "everyone" :
        (params.pam.flags & F_ENFORCE_MASK) == F_ENFORCE_USERS ? "users" : "other");
    passwdqc_params_free(&params); return 0;
}
