#include "incident/AltIncidentAccessGateTopology.h"

#include <sys/stat.h>
#include <unistd.h>

#include <filesystem>
#include <cstdlib>
#include <fstream>
#include <stdexcept>
#include <string>

namespace {
void require(bool value) {
    if (!value) throw std::runtime_error("ALT incident gate topology regression");
}

void write(const std::filesystem::path& path, const std::string& content) {
    std::ofstream output(path);
    output << content;
    output.close();
    ::chmod(path.c_str(), 0644);
}
}

int main() {
    char pattern[] = "/tmp/fic-alt-incident-gate-XXXXXX";
    const char* created = ::mkdtemp(pattern);
    if (created == nullptr) throw std::runtime_error("mkdtemp failed");
    const std::filesystem::path root(created);
    const auto target = root / "system-auth-common";
    using fic::incident::AltIncidentAccessGateTopology;
    try {
        write(target, "#%PAM-1.0\naccount required pam_permit.so\n");
        bool attached = true;
        std::string error;
        require(AltIncidentAccessGateTopology::inspectForTests(
            target, ::geteuid(), attached, error) && !attached);
        require(AltIncidentAccessGateTopology::attachForTests(
            target, ::geteuid(), error));
        require(AltIncidentAccessGateTopology::inspectForTests(
            target, ::geteuid(), attached, error) && attached);
        require(AltIncidentAccessGateTopology::attachForTests(
            target, ::geteuid(), error));
        write(root / "foreign-service", "account required pam_fic_access.so\n");
        require(!AltIncidentAccessGateTopology::detachForTests(
            target, ::geteuid(), error));
        std::filesystem::remove(root / "foreign-service");
        require(AltIncidentAccessGateTopology::detachForTests(
            target, ::geteuid(), error));
        require(AltIncidentAccessGateTopology::inspectForTests(
            target, ::geteuid(), attached, error) && !attached);
        std::ifstream input(target);
        const std::string restored((std::istreambuf_iterator<char>(input)),
                                   std::istreambuf_iterator<char>());
        require(restored == "#%PAM-1.0\naccount required pam_permit.so\n");
        write(target, "# BEGIN FIC incident access gate\n"
                      "account optional pam_fic_access.so\n"
                      "# END FIC incident access gate\n");
        require(!AltIncidentAccessGateTopology::attachForTests(
            target, ::geteuid(), error));
    } catch (...) {
        std::filesystem::remove_all(root);
        throw;
    }
    std::filesystem::remove_all(root);
}
