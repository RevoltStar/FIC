#include "device/StaticInventoryProof.h"

#include <fic/core/runtime/FicRuntimePaths.h>

#include <nlohmann/json.hpp>

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>

namespace fic::device_control {
namespace {

constexpr const char* PROOF_BASENAME = "static-inventory.state";
constexpr std::size_t MAX_PROOF_BYTES = 4096U;

using json = nlohmann::json;

bool writeAll(int fd, const std::string& data, std::string& error) {
    std::size_t offset = 0;
    while (offset < data.size()) {
        const ssize_t written =
            ::write(fd, data.data() + offset, data.size() - offset);
        if (written < 0) {
            if (errno == EINTR) continue;
            error = std::strerror(errno);
            return false;
        }
        offset += static_cast<std::size_t>(written);
    }
    return true;
}

} // namespace

std::filesystem::path static_inventory_proof_path() {
    return fic::core::FicRuntimePaths::get().runtimeDir / PROOF_BASENAME;
}

bool StaticInventoryProof::proven(const std::string& subsystem,
                                  const std::string& currentBootId) const {
    if (currentBootId.empty() || bootId != currentBootId) {
        return false;
    }
    if (subsystem == "cpu") return cpu;
    if (subsystem == "board") return board;
    if (subsystem == "memory") return memory;
    return false;
}

bool write_static_inventory_proof(const StaticInventoryProof& proof,
                                  std::string& error) {
    error.clear();
    if (proof.bootId.empty()) {
        error = "static inventory proof requires the current boot id";
        return false;
    }
    const std::filesystem::path path = static_inventory_proof_path();
    std::error_code filesystemError;
    if (!std::filesystem::is_directory(path.parent_path(), filesystemError) ||
        filesystemError) {
        error = "runtime directory is unavailable: " + path.parent_path().string();
        return false;
    }

    const json payload{
        {"boot_id", proof.bootId},
        {"cpu", proof.cpu},
        {"board", proof.board},
        {"memory", proof.memory}};
    const std::string content = payload.dump() + "\n";

    const std::filesystem::path temporary = path.string() + ".tmp";
    const int fd = ::open(temporary.c_str(),
                          O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                          0600);
    if (fd < 0) {
        error = "cannot open static inventory proof: " +
                std::string(std::strerror(errno));
        return false;
    }
    bool ok = ::fchmod(fd, 0600) == 0;
    if (!ok) {
        error = "cannot set static inventory proof permissions: " +
                std::string(std::strerror(errno));
    }
    if (ok) ok = writeAll(fd, content, error);
    if (ok && ::fsync(fd) != 0) {
        error = "cannot fsync static inventory proof: " +
                std::string(std::strerror(errno));
        ok = false;
    }
    if (::close(fd) != 0 && ok) {
        error = "cannot close static inventory proof: " +
                std::string(std::strerror(errno));
        ok = false;
    }
    if (!ok) {
        ::unlink(temporary.c_str());
        return false;
    }
    if (::rename(temporary.c_str(), path.c_str()) != 0) {
        error = "cannot publish static inventory proof: " +
                std::string(std::strerror(errno));
        ::unlink(temporary.c_str());
        return false;
    }
    return true;
}

std::optional<StaticInventoryProof> read_static_inventory_proof(
    std::string& error) {
    error.clear();
    const std::filesystem::path path = static_inventory_proof_path();
    const int fd =
        ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        if (errno == ENOENT) {
            error = "static inventory proof is absent";
        } else {
            error = "cannot open static inventory proof: " +
                    std::string(std::strerror(errno));
        }
        return std::nullopt;
    }
    struct stat info {};
    if (::fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) ||
        info.st_uid != ::geteuid() || (info.st_mode & 077) != 0 ||
        static_cast<std::size_t>(info.st_size) > MAX_PROOF_BYTES) {
        ::close(fd);
        error = "static inventory proof has unsafe metadata";
        return std::nullopt;
    }
    std::string content;
    char buffer[512];
    for (;;) {
        const ssize_t read = ::read(fd, buffer, sizeof(buffer));
        if (read < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (read == 0) break;
        content.append(buffer, static_cast<std::size_t>(read));
        if (content.size() > MAX_PROOF_BYTES) break;
    }
    ::close(fd);

    const json payload = json::parse(content, nullptr, false);
    if (payload.is_discarded() || !payload.is_object()) {
        error = "static inventory proof is malformed";
        return std::nullopt;
    }
    StaticInventoryProof proof;
    proof.bootId = payload.value("boot_id", "");
    proof.cpu = payload.value("cpu", false);
    proof.board = payload.value("board", false);
    proof.memory = payload.value("memory", false);
    if (proof.bootId.empty()) {
        error = "static inventory proof has no boot id";
        return std::nullopt;
    }
    return proof;
}

} // namespace fic::device_control
