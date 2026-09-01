#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <security/pam_ext.h>
#include <security/pam_modules.h>

#define LOCK_FILE "/var/lib/fic-pwhistory/.lock"
#define DEFAULT_TIMEOUT_SECONDS 15U
#define MAX_TIMEOUT_SECONDS 300U
#define DATA_NAME "pam_fic_pwtxn.state"

struct lock_state {
    int fd;
    int held;
};

struct options {
    const char *operation;
    unsigned int timeout_seconds;
};

static void cleanup(pam_handle_t *pamh, void *data, int error_status)
{
    struct lock_state *state = data;
    (void)pamh;
    (void)error_status;
    if (state != NULL && state->held)
        (void)close(state->fd);
    free(state);
}

static int parse_timeout(const char *value, unsigned int *result)
{
    char *end = NULL;
    unsigned long parsed;
    errno = 0;
    parsed = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed == 0 ||
        parsed > MAX_TIMEOUT_SECONDS)
        return -1;
    *result = (unsigned int)parsed;
    return 0;
}

static int parse_options(pam_handle_t *pamh, int argc, const char **argv,
                         struct options *options)
{
    int index;
    memset(options, 0, sizeof(*options));
    options->timeout_seconds = DEFAULT_TIMEOUT_SECONDS;
    for (index = 0; index < argc; ++index) {
        if (strcmp(argv[index], "begin") == 0 ||
            strcmp(argv[index], "end") == 0) {
            if (options->operation != NULL) {
                pam_syslog(pamh, LOG_ERR, "multiple operations specified");
                return PAM_SERVICE_ERR;
            }
            options->operation = argv[index];
        } else if (strncmp(argv[index], "timeout=", 8) == 0) {
            if (parse_timeout(argv[index] + 8, &options->timeout_seconds) != 0) {
                pam_syslog(pamh, LOG_ERR, "invalid timeout option: %s",
                           argv[index]);
                return PAM_SERVICE_ERR;
            }
        } else {
            pam_syslog(pamh, LOG_ERR, "unknown option: %s", argv[index]);
            return PAM_SERVICE_ERR;
        }
    }
    if (options->operation == NULL) {
        pam_syslog(pamh, LOG_ERR, "begin or end operation is required");
        return PAM_SERVICE_ERR;
    }
    return PAM_SUCCESS;
}

static int validate_lock_file(pam_handle_t *pamh, int fd)
{
    struct group *shadow;
    struct stat info;
    shadow = getgrnam("shadow");
    if (shadow == NULL) {
        pam_syslog(pamh, LOG_ERR, "group shadow does not exist");
        return PAM_SYSTEM_ERR;
    }
    if (fstat(fd, &info) != 0) {
        pam_syslog(pamh, LOG_ERR, "cannot stat lock file %s: %m", LOCK_FILE);
        return PAM_SYSTEM_ERR;
    }
    if (!S_ISREG(info.st_mode) || info.st_uid != 0 ||
        info.st_gid != shadow->gr_gid ||
        (info.st_mode & 0777) != 0660 || info.st_nlink != 1) {
        pam_syslog(pamh, LOG_ERR,
                   "unsafe lock file %s (expected root-owned regular 0660 file with one link)",
                   LOCK_FILE);
        return PAM_PERM_DENIED;
    }
    return PAM_SUCCESS;
}

static int64_t monotonic_milliseconds(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int acquire_lock(pam_handle_t *pamh, int fd, unsigned int timeout_seconds)
{
    const struct timespec pause = {.tv_sec = 0, .tv_nsec = 100000000};
    struct flock lock;
    int64_t deadline;
    memset(&lock, 0, sizeof(lock));
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;
    deadline = monotonic_milliseconds();
    if (deadline < 0)
        return PAM_SYSTEM_ERR;
    deadline += (int64_t)timeout_seconds * 1000;
    for (;;) {
#ifdef F_OFD_SETLK
        if (fcntl(fd, F_OFD_SETLK, &lock) == 0)
#else
        if (fcntl(fd, F_SETLK, &lock) == 0)
#endif
            return PAM_SUCCESS;
        if (errno != EACCES && errno != EAGAIN && errno != EINTR) {
            pam_syslog(pamh, LOG_ERR,
                       "cannot acquire password transaction lock: %m");
            return PAM_SYSTEM_ERR;
        }
        if (monotonic_milliseconds() >= deadline) {
            pam_syslog(pamh, LOG_ERR, "password transaction lock timed out");
            return PAM_AUTHTOK_LOCK_BUSY;
        }
        (void)nanosleep(&pause, NULL);
    }
}

static int begin_transaction(pam_handle_t *pamh,
                             const struct options *options)
{
    const void *existing = NULL;
    struct lock_state *state;
    int fd;
    int result;
    if (pam_get_data(pamh, DATA_NAME, &existing) == PAM_SUCCESS &&
        existing != NULL) {
        pam_syslog(pamh, LOG_ERR, "password transaction is already active");
        return PAM_SYSTEM_ERR;
    }
    fd = open(LOCK_FILE, O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NOCTTY);
    if (fd < 0) {
        pam_syslog(pamh, LOG_ERR, "cannot open lock file %s: %m", LOCK_FILE);
        return errno == EACCES ? PAM_PERM_DENIED : PAM_SYSTEM_ERR;
    }
    result = validate_lock_file(pamh, fd);
    if (result == PAM_SUCCESS)
        result = acquire_lock(pamh, fd, options->timeout_seconds);
    if (result != PAM_SUCCESS) {
        (void)close(fd);
        return result;
    }
    state = calloc(1, sizeof(*state));
    if (state == NULL) {
        (void)close(fd);
        return PAM_BUF_ERR;
    }
    state->fd = fd;
    state->held = 1;
    result = pam_set_data(pamh, DATA_NAME, state, cleanup);
    if (result != PAM_SUCCESS)
        cleanup(pamh, state, result);
    return result;
}

static int end_transaction(pam_handle_t *pamh)
{
    const void *data = NULL;
    struct lock_state *state;
    if (pam_get_data(pamh, DATA_NAME, &data) != PAM_SUCCESS || data == NULL) {
        pam_syslog(pamh, LOG_ERR, "password transaction is not active");
        return PAM_SYSTEM_ERR;
    }
    state = (struct lock_state *)data;
    if (!state->held || state->fd < 0) {
        pam_syslog(pamh, LOG_ERR, "password transaction was already ended");
        return PAM_SYSTEM_ERR;
    }
    if (close(state->fd) != 0) {
        pam_syslog(pamh, LOG_ERR,
                   "cannot release password transaction lock: %m");
        state->fd = -1;
        state->held = 0;
        return PAM_SYSTEM_ERR;
    }
    state->fd = -1;
    state->held = 0;
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc,
                                const char **argv)
{
    struct options options;
    int result = parse_options(pamh, argc, argv, &options);
    if (result != PAM_SUCCESS)
        return result;
    if (flags & PAM_PRELIM_CHECK)
        return PAM_SUCCESS;
    if (!(flags & PAM_UPDATE_AUTHTOK))
        return PAM_SERVICE_ERR;
    if (strcmp(options.operation, "begin") == 0)
        return begin_transaction(pamh, &options);
    return end_transaction(pamh);
}

#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("pam_fic_pwtxn");
#endif
