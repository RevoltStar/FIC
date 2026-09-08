#include <fic/core/logging/SecurityAudit.h>

#include <fic/core/logging/Logger.h>

#include <fstream>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

namespace fic::core::security_audit {
namespace {

constexpr const char* TRUNCATION_MARKER = "...[truncated]";

std::string jsonPointerToken(const std::string& value) {
    std::string result;
    result.reserve(value.size());
    for (const char ch : value) {
        if (ch == '~') {
            result += "~0";
        } else if (ch == '/') {
            result += "~1";
        } else {
            result += ch;
        }
    }
    return result;
}

std::string limitString(const std::string& value) {
    if (value.size() <= MAX_STRING_BYTES) {
        return value;
    }

    const std::size_t markerBytes = std::char_traits<char>::length(TRUNCATION_MARKER);
    std::size_t prefixBytes = MAX_STRING_BYTES - markerBytes;
    while (prefixBytes > 0 &&
           (static_cast<unsigned char>(value[prefixBytes]) & 0xc0U) == 0x80U) {
        --prefixBytes;
    }
    return value.substr(0, prefixBytes) + TRUNCATION_MARKER;
}

void limitStrings(nlohmann::json& value,
                  const std::string& path,
                  std::vector<std::string>& truncatedFields) {
    if (value.is_string()) {
        const std::string original = value.get<std::string>();
        if (original.size() > MAX_STRING_BYTES) {
            value = limitString(original);
            truncatedFields.push_back(path.empty() ? "/" : path);
        }
        return;
    }

    if (value.is_array()) {
        for (std::size_t index = 0; index < value.size(); ++index) {
            limitStrings(value[index], path + "/" + std::to_string(index), truncatedFields);
        }
        return;
    }

    if (value.is_object()) {
        for (auto& [key, child] : value.items()) {
            limitStrings(child, path + "/" + jsonPointerToken(key), truncatedFields);
        }
    }
}

std::string dump(const nlohmann::json& event) {
    return event.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}

std::string limitedStringField(const nlohmann::json& event, const char* field) {
    if (!event.is_object() || !event.contains(field) || !event[field].is_string()) {
        return {};
    }
    return limitString(event[field].get<std::string>());
}

nlohmann::json oversizeFallback(const nlohmann::json& event,
                                const std::size_t originalSize) {
    nlohmann::json fallback = {
        {"timestamp", limitedStringField(event, "timestamp")},
        {"component", limitedStringField(event, "component")},
        {"record_truncated", true},
        {"original_size_bytes", originalSize}
    };
    if (event.contains("command") && event["command"].is_string()) {
        fallback["command"] = limitString(event["command"].get<std::string>());
    }
    if (event.contains("event") && event["event"].is_string()) {
        fallback["event"] = limitString(event["event"].get<std::string>());
    }
    return fallback;
}

} // namespace

nlohmann::json makeEvent(const std::string& component,
                         nlohmann::json fields,
                         const std::string& timestamp) {
    nlohmann::json event = fields.is_object()
        ? std::move(fields)
        : nlohmann::json{{"event", "invalid_audit_fields"}};
    event["timestamp"] = timestamp;
    event["component"] = component;

    std::vector<std::string> truncatedFields;
    limitStrings(event, "", truncatedFields);
    if (!truncatedFields.empty()) {
        event["truncated_fields"] = std::move(truncatedFields);
    }

    const std::size_t serializedSize = dump(event).size();
    if (serializedSize > MAX_RECORD_BYTES) {
        return oversizeFallback(event, serializedSize);
    }
    return event;
}

nlohmann::json makeEvent(const std::string& component,
                         nlohmann::json fields) {
    return makeEvent(component, std::move(fields), Logger::get_current_time());
}

nlohmann::json makeIpcEvent(const std::string& component,
                            const PeerCredentials& peer,
                            const std::string& command,
                            nlohmann::json requestFields,
                            const bool ok,
                            const std::string& message,
                            const std::string& timestamp) {
    nlohmann::json peerFields = {{"available", peer.available}};
    if (peer.available) {
        peerFields["uid"] = peer.uid;
        peerFields["gid"] = peer.gid;
        peerFields["pid"] = peer.pid;
    } else {
        peerFields["error"] = peer.error;
    }

    return makeEvent(component, {
        {"peer", std::move(peerFields)},
        {"command", command},
        {"request", requestFields.is_object()
            ? std::move(requestFields)
            : nlohmann::json::object()},
        {"result", {{"ok", ok}, {"message", message}}}
    }, timestamp);
}

nlohmann::json makeIpcEvent(const std::string& component,
                            const PeerCredentials& peer,
                            const std::string& command,
                            nlohmann::json requestFields,
                            const bool ok,
                            const std::string& message) {
    return makeIpcEvent(component, peer, command, std::move(requestFields), ok,
                        message, Logger::get_current_time());
}

std::string serializeJsonLine(const nlohmann::json& event) {
    const std::string line = dump(event);
    if (line.size() > MAX_RECORD_BYTES) {
        return dump(oversizeFallback(event, line.size()));
    }
    return line;
}

bool appendJsonLine(const std::filesystem::path& path,
                    const nlohmann::json& event,
                    std::string& error) {
    error.clear();
    const std::string line = serializeJsonLine(event);
    std::ofstream stream(path, std::ios::app | std::ios::binary);
    if (!stream.is_open()) {
        error = "failed to open audit log: " + path.string();
        return false;
    }

    stream.write(line.data(), static_cast<std::streamsize>(line.size()));
    stream.put('\n');
    stream.flush();
    if (!stream) {
        error = "failed to write audit log: " + path.string();
        return false;
    }
    return true;
}

} // namespace fic::core::security_audit
