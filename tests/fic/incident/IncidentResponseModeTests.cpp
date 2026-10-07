#include "incident/IncidentResponseMode.h"

#include <fic/core/config/ConfigAuthority.h>

#include <sys/stat.h>
#include <unistd.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <stdexcept>

namespace {
void require(bool ok) {
    if (!ok) throw std::runtime_error("incident response mode regression");
}
}

int main() {
    char pattern[] = "/tmp/fic-mode-reader-XXXXXX";
    const char* created = ::mkdtemp(pattern);
    require(created != nullptr);
    const std::filesystem::path root(created);
    try {
        const auto config = root / "config";
        std::filesystem::create_directory(config);
        ::chmod(root.c_str(), 02750);
        ::chmod(config.c_str(), 02750);
        const auto path = config / "GLOBAL.conf";
        fic::core::SecureStateFileExpectation expected;
        expected.owner = ::geteuid();
        expected.group = ::getegid();
        expected.exactMode = 0640;
        expected.maxSize = fic::core::MAX_WORKING_CONFIG_BYTES;
        expected.requireSingleLink = true;
        expected.parentOwner = ::geteuid();
        expected.parentGroup = ::getegid();
        expected.exactParentMode = 02750;
        const auto read = [&] {
            return fic::incident::IncidentResponseModeResolver::read(path, expected);
        };
        const auto write = [&](const std::string& value) {
            std::ofstream stream(path);
            stream << "_schema_version=1\n" << value;
            stream.close();
            ::chmod(path.c_str(), 0640);
        };
        require(read().mode == fic::incident::IncidentResponseMode::Active &&
                !read().proven);
        write("incident_response_mode.status=DISABLE\n"
              "incident_response_mode.value=PASSIVE\n");
        require(read().mode == fic::incident::IncidentResponseMode::Off && read().proven);
        write("incident_response_mode.status=ENABLE\n"
              "incident_response_mode.value=PASSIVE\n");
        require(read().mode == fic::incident::IncidentResponseMode::Passive && read().proven);
        write("incident_response_mode.status=ENABLE\n"
              "incident_response_mode.value=ACTIVE\n");
        require(read().mode == fic::incident::IncidentResponseMode::Active && read().proven);
        write("incident_response_mode.status=ENABLE\n"
              "incident_response_mode.value=UNKNOWN\n");
        require(read().mode == fic::incident::IncidentResponseMode::Active &&
                !read().proven);
        write("incident_response_mode.status=DISABLE\n"
              "incident_response_mode.value=PASSIVE\n"
              "incident_response_mode.value=ACTIVE\n");
        require(!read().proven);
        write("incident_response_mode.status=DISABLE\n"
              "incident_response_mode.value=PASSIVE\n"
              "incident_response_mode.status =ENABLE\n");
        require(read().mode == fic::incident::IncidentResponseMode::Active &&
                !read().proven);
        write("incident_response_mode.status=DISABLE\n"
              "incident_response_mode.value=PASSIVE\n");
        ::chmod(path.c_str(), 0666);
        require(read().mode == fic::incident::IncidentResponseMode::Active &&
                !read().proven);
        ::chmod(path.c_str(), 0640);
        std::filesystem::remove(path);
        std::filesystem::create_symlink("/etc/passwd", path);
        require(!read().proven);
    } catch (...) {
        std::filesystem::remove_all(root);
        throw;
    }
    std::filesystem::remove_all(root);
}
