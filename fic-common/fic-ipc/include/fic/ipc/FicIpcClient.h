#ifndef FIC_IPC_CLIENT_H
#define FIC_IPC_CLIENT_H

#include <fic/ipc/FicIpcPathDefaults.h>
#include <fic/ipc/FicIpcTransport.h>
#include <fic/version/ProductVersion.h>

#include <nlohmann/json.hpp>

#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <string>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <utility>

namespace fic::ipc {

using json = nlohmann::json;
inline constexpr int API_VERSION = fic::version::IPC_API_VERSION;

inline constexpr const char* DEFAULT_RUNTIME_DIR = path_defaults::RUNTIME_DIR;
inline constexpr const char* DEFAULT_SOCKET_PATH = path_defaults::DAEMON_SOCKET;
inline constexpr const char* DEFAULT_DEVICE_SOCKET_PATH = path_defaults::DEVICE_SOCKET;

enum class Endpoint {
    PolicyDaemon,
    DeviceDaemon
};

inline std::string endpoint_socket_path(Endpoint endpoint) {
    const char* environmentName = endpoint == Endpoint::PolicyDaemon
        ? "FIC_SOCKET_PATH"
        : "FIC_DEVICE_SOCKET_PATH";
    const char* environmentPath = std::getenv(environmentName);
    if (environmentPath != nullptr && environmentPath[0] != '\0') {
        return environmentPath;
    }
    return endpoint == Endpoint::PolicyDaemon
        ? DEFAULT_SOCKET_PATH
        : DEFAULT_DEVICE_SOCKET_PATH;
}

inline json make_error_response(const std::string& message) {
    return json{{"ok", false}, {"message", message}, {"api_version", API_VERSION}};
}

inline json make_ok_response(const std::string& message = "OK") {
    return json{{"ok", true}, {"message", message}, {"api_version", API_VERSION}};
}

inline bool validate_json_value(const json& value,
                                std::size_t depth,
                                std::string& error) {
    if (depth > MAX_JSON_DEPTH) {
        error = "JSON nesting exceeds the transport limit";
        return false;
    }
    if (value.is_string() && value.get_ref<const std::string&>().size() > MAX_JSON_STRING_BYTES) {
        error = "JSON string exceeds the transport limit";
        return false;
    }
    if ((value.is_array() || value.is_object()) && value.size() > MAX_JSON_CONTAINER_ITEMS) {
        error = "JSON container exceeds the transport item limit";
        return false;
    }
    if (value.is_array()) {
        for (const json& item : value) {
            if (!validate_json_value(item, depth + 1U, error)) {
                return false;
            }
        }
    } else if (value.is_object()) {
        for (auto item = value.begin(); item != value.end(); ++item) {
            if (item.key().size() > MAX_JSON_STRING_BYTES ||
                !validate_json_value(item.value(), depth + 1U, error)) {
                if (error.empty()) {
                    error = "JSON object key exceeds the transport limit";
                }
                return false;
            }
        }
    }
    return true;
}

inline bool parse_request_json(const std::string& text,
                               json& request,
                               std::string& error) {
    try {
        request = json::parse(text, [](int depth, json::parse_event_t, json&) {
            if (depth > static_cast<int>(MAX_JSON_DEPTH)) {
                throw std::runtime_error("JSON nesting exceeds the transport limit");
            }
            return true;
        });
    } catch (const std::exception& exception) {
        error = exception.what();
        return false;
    }
    if (!request.is_object()) {
        error = "request must be a JSON object";
        return false;
    }
    const auto command = request.find("command");
    if (command == request.end() || !command->is_string() || command->get_ref<const std::string&>().empty()) {
        error = "request.command must be a non-empty string";
        return false;
    }
    const auto apiVersion = request.find("api_version");
    const bool supportedApiVersion = apiVersion != request.end() &&
        ((apiVersion->is_number_unsigned() &&
          apiVersion->get<std::uint64_t>() == static_cast<std::uint64_t>(API_VERSION)) ||
         (apiVersion->is_number_integer() &&
          apiVersion->get<std::int64_t>() == API_VERSION));
    if (!supportedApiVersion) {
        error = "request.api_version is unsupported; expected " +
            std::to_string(API_VERSION);
        return false;
    }
    return validate_json_value(request, 0, error);
}

inline bool request_has_only_fields(const json& request,
                                    std::initializer_list<const char*> allowed,
                                    std::string& error) {
    for (auto item = request.begin(); item != request.end(); ++item) {
        if (item.key() == "api_version") {
            continue;
        }
        bool known = false;
        for (const char* field : allowed) {
            if (item.key() == field) {
                known = true;
                break;
            }
        }
        if (!known) {
            error = "field is not allowed for this command: " + item.key();
            return false;
        }
    }
    return true;
}

inline bool write_all(int fd, const std::string& data, std::string& error) {
    const char* ptr = data.c_str();
    size_t left = data.size();
    while (left > 0) {
        ssize_t written = ::write(fd, ptr, left);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            error = std::strerror(errno);
            return false;
        }
        if (written == 0) {
            error = "socket write returned 0";
            return false;
        }
        ptr += written;
        left -= static_cast<size_t>(written);
    }
    return true;
}

inline bool read_until_eof(int fd,
                           std::string& output,
                           std::string& error,
                           std::size_t maximumBytes = MAX_RESPONSE_BYTES) {
    char buffer[4096];
    while (true) {
        ssize_t received = ::read(fd, buffer, sizeof(buffer));
        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            error = std::strerror(errno);
            return false;
        }
        if (received == 0) {
            return true;
        }
        if (output.size() > maximumBytes ||
            static_cast<std::size_t>(received) > maximumBytes - output.size()) {
            error = "message exceeds " + std::to_string(maximumBytes) + " bytes";
            return false;
        }
        output.append(buffer, static_cast<size_t>(received));
    }
}

class Client {
public:
    struct RequestResult {
        bool hasResponse = false;
        json response;
        std::string error;
    };

    Client();

    explicit Client(Endpoint endpoint);

    explicit Client(std::string socketPath);

    Client(std::string socketPath, std::chrono::milliseconds timeout);

    RequestResult requestWithStatus(const json& payload) const;
    json request(const json& payload) const;

private:
    std::string socketPath_;
    std::chrono::milliseconds timeout_{DEFAULT_CLIENT_TIMEOUT};
};

} // namespace fic::ipc

#endif // FIC_IPC_CLIENT_H
