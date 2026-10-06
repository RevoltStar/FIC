#pragma once

#include <filesystem>
#include <string>
#include <sys/types.h>

namespace fic::incident {

// Package-owned, permanent ALT account hook. The incident controller never
// calls these mutations; package lifecycle invokes them offline.
class AltIncidentAccessGateTopology {
public:
    static bool inspect(const std::filesystem::path& target,
                        bool& attached, std::string& error);
    static bool attach(const std::filesystem::path& target, std::string& error);
    static bool detach(const std::filesystem::path& target, std::string& error);
    static bool inspectForTests(const std::filesystem::path& target,
                                uid_t expectedOwner, bool& attached,
                                std::string& error);
    static bool attachForTests(const std::filesystem::path& target,
                               uid_t expectedOwner, std::string& error);
    static bool detachForTests(const std::filesystem::path& target,
                               uid_t expectedOwner, std::string& error);
};

} // namespace fic::incident
