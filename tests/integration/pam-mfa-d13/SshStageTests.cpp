#include <security/pam_appl.h>
#include <dlfcn.h>

#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unistd.h>

namespace {
bool failRemove = false;

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
}

extern "C" int pam_putenv(pam_handle_t* handle, const char* value) {
    if (failRemove && std::strcmp(value, "SSH_AUTH_INFO_0") == 0) return PAM_BUF_ERR;
    using Putenv = int (*)(pam_handle_t*, const char*);
    static const auto real = reinterpret_cast<Putenv>(dlsym(RTLD_NEXT, "pam_putenv"));
    return real ? real(handle, value) : PAM_SYSTEM_ERR;
}

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    char directory[] = "/tmp/fic-ssh-stage-unit.XXXXXX";
    if (!mkdtemp(directory)) return 2;
    void* library = nullptr;
    pam_handle_t* handle = nullptr;
    int status = 0;
    try {
        std::ofstream(std::filesystem::path(directory) / "fic-sshd-mfa") << "auth required pam_deny.so\n";
        library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
        require(library != nullptr, "cannot load built SSH stage PAM module");
        using Entry = int (*)(pam_handle_t*, int, int, const char**);
        const auto auth = reinterpret_cast<Entry>(dlsym(library, "pam_sm_authenticate"));
        const auto setcred = reinterpret_cast<Entry>(dlsym(library, "pam_sm_setcred"));
        require(auth && setcred, "PAM exports missing");
        const pam_conv conversation{};
        require(pam_start_confdir("fic-sshd-mfa", "root", &conversation, directory, &handle) ==
                PAM_SUCCESS, "cannot start test PAM handle");

        const auto verify = [&](const std::string& record, int expected) {
            require(pam_putenv(handle, ("SSH_AUTH_INFO_0=" + record).c_str()) == PAM_SUCCESS,
                    "cannot seed PAM environment");
            require(auth(handle, 0, 0, nullptr) == expected, "unexpected SSH stage verdict");
            require(!pam_getenv(handle, "SSH_AUTH_INFO_0"), "stage evidence was not consumed");
        };
        require(auth(handle, 0, 0, nullptr) == PAM_SERVICE_ERR, "missing evidence admitted");
        verify("", PAM_SUCCESS);
        require(auth(handle, 0, 0, nullptr) == PAM_SERVICE_ERR, "stale empty stage was reused");
        verify("password\n", PAM_AUTH_ERR);
        const std::string prefix = "publickey ssh-ed25519 ";
        const std::string blob = "AAAAC3NzaC1lZDI1NTE5AAAAI" + std::string(43, 'A');
        verify(prefix + blob + "\n", PAM_AUTH_ERR);
        verify(prefix + blob.substr(0, 25) + "Q" + blob.substr(26) + "\n", PAM_SERVICE_ERR);
        verify(prefix + blob.substr(0, 67) + "_\n", PAM_SERVICE_ERR);
        verify(prefix + blob + "\r\n", PAM_SERVICE_ERR);
        verify("password", PAM_SERVICE_ERR);
        verify("password\npassword\n", PAM_SERVICE_ERR);
        verify("keyboard-interactive/pam\n", PAM_SERVICE_ERR);
        verify("publickey ssh-rsa " + blob + "\n", PAM_SERVICE_ERR);
        verify(std::string(4096, 'x'), PAM_SERVICE_ERR);
        require(pam_putenv(handle, "SSH_AUTH_INFO_0=") == PAM_SUCCESS, "cannot seed empty stage");
        failRemove = true;
        require(auth(handle, 0, 0, nullptr) == PAM_SERVICE_ERR, "removal fault admitted");
        failRemove = false;
        require(auth(handle, 0, 1, nullptr) == PAM_SERVICE_ERR, "unknown argument accepted");
        require(setcred(handle, PAM_ESTABLISH_CRED, 0, nullptr) == PAM_IGNORE &&
                pam_getenv(handle, "SSH_AUTH_INFO_0"), "setcred reclassified or consumed stage");
        require(setcred(handle, PAM_DELETE_CRED, 1, nullptr) == PAM_SERVICE_ERR,
                "setcred argument error hidden");
        require(pam_set_item(handle, PAM_USER, "") == PAM_SUCCESS &&
                auth(handle, 0, 0, nullptr) == PAM_SERVICE_ERR &&
                !pam_getenv(handle, "SSH_AUTH_INFO_0"), "missing PAM identity admitted");
        require(pam_set_item(handle, PAM_USER, "fic-no-such-stage-test-user") == PAM_SUCCESS,
                "cannot seed unknown PAM identity");
        verify("password\n", PAM_SERVICE_ERR);
        verify(prefix + blob + "\n", PAM_SERVICE_ERR);
        require(pam_set_item(handle, PAM_SERVICE, "sshd") == PAM_SUCCESS &&
                auth(handle, 0, 0, nullptr) == PAM_SERVICE_ERR &&
                setcred(handle, PAM_ESTABLISH_CRED, 0, nullptr) == PAM_SERVICE_ERR,
                "foreign PAM service accepted");
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        status = 1;
    }
    if (handle) pam_end(handle, status);
    if (library) dlclose(library);
    std::filesystem::remove_all(directory);
    return status;
}
