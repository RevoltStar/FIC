#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <clocale>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <locale>
#include <string>
#include <sys/socket.h>
#include <sys/select.h>
#include <grp.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>

#include <nlohmann/json.hpp>

#include "core/main_function.h"
#include "ipc/FicIpcClient.h"

using json = nlohmann::json;

namespace {
std::atomic_bool g_stop{false};

void handle_signal(int) {
    g_stop = true;
}

std::string get_arg_value(int argc, char* argv[], int index) {
    if (index >= argc) {
        return "";
    }
    return argv[index];
}

int get_interval_seconds(int argc, char* argv[]) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (std::string(argv[i]) == "--interval") {
            try {
                int value = std::stoi(argv[i + 1]);
                return value > 0 ? value : 1800;
            } catch (...) {
                return 1800;
            }
        }
    }
    return 1800;
}

std::string get_socket_path(int argc, char* argv[]) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (std::string(argv[i]) == "--socket") {
            return argv[i + 1];
        }
    }
    return fic::ipc::DEFAULT_SOCKET_PATH;
}

std::string to_lower_ascii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

std::string canonical_module_name(
    const std::map<std::string, std::map<std::string, std::map<std::string, std::shared_ptr<CheckAndFix>>>>& cafMap,
    const std::string& module
) {
    if (module.empty() || module == "all") {
        return module;
    }

    auto exact = cafMap.find(module);
    if (exact != cafMap.end()) {
        return module;
    }

    const std::string lowered = to_lower_ascii(module);
    for (const auto& [moduleName, _] : cafMap) {
        if (to_lower_ascii(moduleName) == lowered) {
            return moduleName;
        }
    }

    return module;
}
json policy_list_json(const std::map<std::string, std::map<std::string, std::map<std::string, std::shared_ptr<CheckAndFix>>>>& cafMap,
                      const std::string& module) {
    json result = json::array();
    auto moduleIt = cafMap.find(module);
    if (moduleIt == cafMap.end()) {
        return result;
    }

    for (const auto& [submoduleName, policyMap] : moduleIt->second) {
        for (const auto& [policyName, policyClass] : policyMap) {
            result.push_back({
                {"module", module},
                {"submodule", submoduleName},
                {"policy", policyName},
                {"enabled", policyClass->isEnable()},
                {"set", policyClass->isPolicySet()}
            });
        }
    }
    return result;
}

json handle_request(json request,
                    std::map<std::string, std::map<std::string, std::map<std::string, std::shared_ptr<CheckAndFix>>>>& cafMap) {
    const std::string command = request.value("command", "");
    const std::string requestedModule = request.value("module", "");
    const std::string module = canonical_module_name(cafMap, requestedModule);
    const std::string policy = request.value("policy", "");
    const std::string value = request.value("value", "");

    try {
        if (command == "status") {
            return fic::ipc::make_ok_response("fic daemon is running");
        }
        if (command == "shutdown") {
            g_stop = true;
            return fic::ipc::make_ok_response("shutdown requested");
        }
        if (command == "module_list") {
            json modules = json::array();
            for (const auto& [moduleName, _] : cafMap) {
                modules.push_back(moduleName);
            }
            return json{{"ok", true}, {"message", "modules listed"}, {"modules", modules}};
        }
        if (command == "policy_list") {
            if (module == "all") {
                json all = json::array();
                for (const auto& [moduleName, _] : cafMap) {
                    for (const auto& item : policy_list_json(cafMap, moduleName)) {
                        all.push_back(item);
                    }
                }
                return json{{"ok", true}, {"message", "policies listed"}, {"policies", all}};
            }
            if (module.empty()) {
                return fic::ipc::make_error_response("module is required");
            }
            return json{{"ok", true}, {"message", "policies listed"}, {"policies", policy_list_json(cafMap, module)}};
        }
        if (command == "set_policy_value") {
            if (module.empty() || policy.empty()) {
                return fic::ipc::make_error_response("module and policy are required");
            }
            bool ok = set(cafMap, module, policy, value);
            if (ok) {
                cafMap = init_cafMap();
            }
            return ok ? fic::ipc::make_ok_response("policy value updated")
                      : fic::ipc::make_error_response("failed to update policy value");
        }
        if (command == "enable_policy") {
            bool ok = enable(cafMap, module, policy);
            if (ok) {
                cafMap = init_cafMap();
            }
            return ok ? fic::ipc::make_ok_response("policy enabled")
                      : fic::ipc::make_error_response("failed to enable policy");
        }
        if (command == "disable_policy") {
            bool ok = disable(cafMap, module, policy);
            if (ok) {
                cafMap = init_cafMap();
            }
            return ok ? fic::ipc::make_ok_response("policy disabled")
                      : fic::ipc::make_error_response("failed to disable policy");
        }
        if (command == "reload_config") {
            cafMap = init_cafMap();
            return fic::ipc::make_ok_response("config reloaded");
        }
        if (command == "apply_all") {
            cafMap = init_cafMap();
            bool ok = check(cafMap, "all", "");
            return ok ? fic::ipc::make_ok_response("all enabled policies applied")
                      : fic::ipc::make_error_response("failed to apply one or more policies");
        }
        if (command == "apply_module") {
            if (module.empty()) {
                return fic::ipc::make_error_response("module is required");
            }
            cafMap = init_cafMap();
            bool ok = check(cafMap, module, "all");
            return ok ? fic::ipc::make_ok_response("module policies applied")
                      : fic::ipc::make_error_response("failed to apply module policies");
        }
        if (command == "apply_policy") {
            if (module.empty() || policy.empty()) {
                return fic::ipc::make_error_response("module and policy are required");
            }
            cafMap = init_cafMap();
            bool ok = check(cafMap, module, policy);
            return ok ? fic::ipc::make_ok_response("policy applied")
                      : fic::ipc::make_error_response("failed to apply policy");
        }
        if (command == "calc_hash") {
            bool ok = calcHash(value);
            return ok ? fic::ipc::make_ok_response("command hash updated")
                      : fic::ipc::make_error_response("failed to update command hash");
        }
        if (command == "lock") {
            bool ok = lock();
            return ok ? fic::ipc::make_ok_response("computer locked")
                      : fic::ipc::make_error_response("failed to lock computer");
        }
        if (command == "unlock") {
            bool ok = unlock();
            return ok ? fic::ipc::make_ok_response("computer unlocked")
                      : fic::ipc::make_error_response("failed to unlock computer");
        }
        if (command == "lockstatus") {
            bool ok = lockstatus();
            return ok ? fic::ipc::make_ok_response("lock status printed to daemon log")
                      : fic::ipc::make_error_response("failed to read lock status");
        }

        return fic::ipc::make_error_response("unknown command: " + command);
    } catch (const std::exception& e) {
        return fic::ipc::make_error_response("exception: " + std::string(e.what()));
    }
}

bool serve_one_client(int clientFd,
                      std::map<std::string, std::map<std::string, std::map<std::string, std::shared_ptr<CheckAndFix>>>>& cafMap) {
    std::string requestText;
    std::string error;
    if (!fic::ipc::read_until_eof(clientFd, requestText, error)) {
        json response = fic::ipc::make_error_response("read failed: " + error);
        std::string text = response.dump() + "\n";
        fic::ipc::write_all(clientFd, text, error);
        return false;
    }

    json response;
    try {
        response = handle_request(json::parse(requestText), cafMap);
    } catch (const std::exception& e) {
        response = fic::ipc::make_error_response("invalid request: " + std::string(e.what()));
    }

    std::string responseText = response.dump() + "\n";
    return fic::ipc::write_all(clientFd, responseText, error);
}

int create_server_socket(const std::string& socketPath) {
    const auto runtimeDir = std::filesystem::path(socketPath).parent_path();
    const bool runtimeDirAlreadyExisted = std::filesystem::exists(runtimeDir);
    std::filesystem::create_directories(runtimeDir);

    group* ficGroup = ::getgrnam("fic");
    const bool manageRuntimeDirPermissions = !runtimeDirAlreadyExisted || runtimeDir == std::filesystem::path("/run/fic");
    if (manageRuntimeDirPermissions) {
        if (ficGroup != nullptr) {
            ::chown(runtimeDir.c_str(), static_cast<uid_t>(-1), ficGroup->gr_gid);
        }
        ::chmod(runtimeDir.c_str(), 0770);
    }

    ::unlink(socketPath.c_str());

    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        std::cerr << "socket() failed: " << std::strerror(errno) << std::endl;
        return -1;
    }

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (socketPath.size() >= sizeof(addr.sun_path)) {
        std::cerr << "socket path is too long: " << socketPath << std::endl;
        ::close(fd);
        return -1;
    }
    std::strncpy(addr.sun_path, socketPath.c_str(), sizeof(addr.sun_path) - 1);

    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::cerr << "bind(" << socketPath << ") failed: " << std::strerror(errno) << std::endl;
        ::close(fd);
        return -1;
    }

    if (ficGroup != nullptr) {
        ::chown(socketPath.c_str(), static_cast<uid_t>(-1), ficGroup->gr_gid);
    }
    ::chmod(socketPath.c_str(), 0660);

    if (::listen(fd, 32) < 0) {
        std::cerr << "listen() failed: " << std::strerror(errno) << std::endl;
        ::close(fd);
        return -1;
    }

    return fd;
}
} // namespace

int main(int argc, char* argv[]) {
    try {
        std::locale::global(std::locale("ru_RU.UTF-8"));
    } catch (const std::exception&) {
        std::setlocale(LC_ALL, "");
    }

    const bool once = get_arg_value(argc, argv, 1) == "--oneshot";
    auto cafMap = init_cafMap();

    if (once) {
        return check(cafMap, "all", "") ? 0 : 1;
    }

    const std::string socketPath = get_socket_path(argc, argv);
    const int intervalSeconds = get_interval_seconds(argc, argv);

    std::signal(SIGTERM, handle_signal);
    std::signal(SIGINT, handle_signal);

    int serverFd = create_server_socket(socketPath);
    if (serverFd < 0) {
        return 1;
    }

    std::cout << "fic daemon started, socket=" << socketPath
              << ", interval=" << intervalSeconds << "s" << std::endl;

    auto nextPeriodicCheck = std::chrono::steady_clock::now() + std::chrono::seconds(intervalSeconds);

    while (!g_stop) {
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(serverFd, &readSet);

        timeval timeout{};
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        int ready = ::select(serverFd + 1, &readSet, nullptr, nullptr, &timeout);
        if (ready > 0 && FD_ISSET(serverFd, &readSet)) {
            int clientFd = ::accept(serverFd, nullptr, nullptr);
            if (clientFd >= 0) {
                serve_one_client(clientFd, cafMap);
                ::close(clientFd);
            }
        }

        auto now = std::chrono::steady_clock::now();
        if (now >= nextPeriodicCheck) {
            cafMap = init_cafMap();
            check(cafMap, "all", "");
            nextPeriodicCheck = now + std::chrono::seconds(intervalSeconds);
        }
    }

    ::close(serverFd);
    ::unlink(socketPath.c_str());
    std::cout << "fic daemon stopped" << std::endl;
    return 0;
}
