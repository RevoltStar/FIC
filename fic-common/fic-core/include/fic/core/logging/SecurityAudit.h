#ifndef FIC_CORE_LOGGING_SECURITY_AUDIT_H
#define FIC_CORE_LOGGING_SECURITY_AUDIT_H

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>

#include <nlohmann/json_fwd.hpp>

namespace fic::core::security_audit {

inline constexpr std::size_t MAX_STRING_BYTES = 240U;
inline constexpr std::size_t MAX_RECORD_BYTES = 16U * 1024U;

struct PeerCredentials {
    bool available = false;
    std::int64_t uid = -1;
    std::int64_t gid = -1;
    std::int64_t pid = -1;
    std::string error;
};

nlohmann::json makeEvent(const std::string& component,
                         nlohmann::json fields,
                         const std::string& timestamp);
nlohmann::json makeEvent(const std::string& component,
                         nlohmann::json fields);

nlohmann::json makeIpcEvent(const std::string& component,
                            const PeerCredentials& peer,
                            const std::string& command,
                            nlohmann::json requestFields,
                            bool ok,
                            const std::string& message,
                            const std::string& timestamp);
nlohmann::json makeIpcEvent(const std::string& component,
                            const PeerCredentials& peer,
                            const std::string& command,
                            nlohmann::json requestFields,
                            bool ok,
                            const std::string& message);

std::string serializeJsonLine(const nlohmann::json& event);
bool appendJsonLine(const std::filesystem::path& path,
                    const nlohmann::json& event,
                    std::string& error);

} // namespace fic::core::security_audit

#endif // FIC_CORE_LOGGING_SECURITY_AUDIT_H
