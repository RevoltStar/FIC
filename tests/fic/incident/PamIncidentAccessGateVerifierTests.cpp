#include "incident/PamIncidentAccessGateVerifier.h"

#include <sys/stat.h>
#include <unistd.h>

#include <filesystem>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace {
void require(bool value) {
    if (!value) throw std::runtime_error("PAM incident gate proof regression");
}

void write(const std::filesystem::path& path, const std::string& content) {
    std::ofstream output(path);
    output << content;
    output.close();
    ::chmod(path.c_str(), 0644);
}
}

int main(int argc, char** argv) {
    if (argc == 2 && std::string(argv[1]) == "--installed") {
        std::string diagnostic;
        if (!fic::incident::PamIncidentAccessGateVerifier::prove(
                fic::platform::makeBuildPlatformProfile().pam, diagnostic)) {
            throw std::runtime_error(diagnostic);
        }
        std::cout << diagnostic << '\n';
        return 0;
    }
    require(argc == 1);
    char pattern[] = "/tmp/fic-incident-pam-proof-XXXXXX";
    const char* created = ::mkdtemp(pattern);
    if (created == nullptr) throw std::runtime_error("mkdtemp failed");
    const std::filesystem::path root(created);
    try {
        const auto services = root / "pam.d";
        const auto modules = root / "security";
        std::filesystem::create_directories(services);
        std::filesystem::create_directories(modules);
        write(modules / "pam_fic_access.so", "fixture");
        write(services / "login", "account include common-account\n");
        write(services / "gdm-autologin", "account include common-account\n");
        write(services / "common-account",
              "account required pam_fic_access.so\n"
              "account [success=1 default=ignore] pam_unix.so\n"
              "account requisite pam_deny.so\n");
        fic::platform::PamPlatformConfig config;
        config.configDirectories = {services};
        config.moduleDirectories = {modules};
        config.incidentAccessGate.controlledServices = {
            "login", "gdm-autologin"};
        std::string diagnostic;
        auto prove = [&] {
            return fic::incident::PamIncidentAccessGateVerifier::proveForTests(
                config, ::geteuid(), diagnostic);
        };
        require(prove());
        write(services / "gdm-autologin",
              "account sufficient pam_permit.so\n"
              "account include common-account\n");
        require(!prove());
        write(services / "gdm-autologin", "account include common-account\n");
        write(services / "login",
              "account sufficient pam_permit.so\n"
              "account include common-account\n");
        require(!prove());
        write(services / "login", "account include common-account\n");
        write(services / "common-account",
              "account required pam_fic_access.so\n"
              "account [success=reset default=ignore] pam_permit.so\n");
        require(!prove());
        write(services / "common-account",
              "account required pam_fic_access.so\n");
        require(prove());
        ::chmod((modules / "pam_fic_access.so").c_str(), 0666);
        require(!prove());
        ::chmod((modules / "pam_fic_access.so").c_str(), 0644);
        ::chmod(modules.c_str(), 0777);
        require(!prove());
        ::chmod(modules.c_str(), 0755);
        ::chmod(services.c_str(), 0777);
        require(!prove());
        ::chmod(services.c_str(), 0755);

        const auto stateDir = root / "pam-state";
        const auto vendor = root / "vendor-pam.d";
        std::filesystem::create_directory(stateDir);
        const auto selection = stateDir / "account";
        write(selection, "Module: pam_unix\n");
        write(services / "common-account", "account required pam_unix.so\n");
        config.configDirectories = {services, vendor};
        auto detached = [&] {
            return fic::incident::PamIncidentAccessGateVerifier::
                proveDetachedForTests(config, selection, ::geteuid(),
                                      diagnostic);
        };
        using Proof = fic::incident::IncidentGateDetachProof;
        require(detached() == Proof::ProvenDetached); // absent optional dir
        std::filesystem::create_directory(vendor);
        write(vendor / "vendor-login", "account required pam_unix.so\n");
        require(detached() == Proof::ProvenDetached);
        write(services / "common-account",
              "account required pam_fic_access.so\n");
        require(detached() == Proof::Referenced);
        write(services / "common-account", "account required pam_unix.so\n");
        write(vendor / "vendor-login",
              "account required pam_fic_access.so\n");
        require(detached() == Proof::Referenced);
        write(vendor / "vendor-login", "account required pam_unix.so\n");
        write(selection, "Module: fic-incident-access\n");
        require(detached() == Proof::Referenced);
        write(selection, "Module: pam_unix\n");
        std::filesystem::create_symlink(
            vendor / "vendor-login", services / "unprovable-alias");
        require(detached() == Proof::Unprovable);
        std::filesystem::remove(services / "unprovable-alias");
        write(services / "*", "# a literal glob-like service name\n");
        require(detached() == Proof::ProvenDetached);
        std::filesystem::remove(vendor / "vendor-login");
        std::filesystem::remove(vendor);
        require(detached() == Proof::ProvenDetached);
    } catch (...) {
        std::filesystem::remove_all(root);
        throw;
    }
    std::filesystem::remove_all(root);
}
