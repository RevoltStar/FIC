// Research protocol fixture only: NO FIC proofs, security mutations or startup.
// 250 ms is a scaled test interval, never a production timeout.
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <sys/file.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <stdexcept>
namespace fs = std::filesystem;
const fs::path root = "/var/lib/m1-retry";
std::string read(const fs::path& path) {
    std::ifstream file(path); std::string s; std::getline(file, s); return s;
}
void write(const fs::path& path, const std::string& value) {
    auto temp = path.string() + ".tmp";
    int fd = open(temp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) throw std::runtime_error("open");
    if (::write(fd, value.data(), value.size()) != static_cast<ssize_t>(value.size()) || fsync(fd))
        throw std::runtime_error("write/fsync");
    close(fd);
    if (rename(temp.c_str(), path.c_str())) throw std::runtime_error("rename");
    fd = open(root.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0 || fsync(fd)) throw std::runtime_error("directory fsync");
    close(fd);
}
int main() try {
    int lock = open((root / "lock").c_str(), O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    if (lock < 0) return 1;
    if (flock(lock, LOCK_EX | LOCK_NB)) return 0;
    // Neither absence nor corruption is authorization to finish an operation.
    if (read(root / "fence") != "pending") return 0;
    timespec time{};
    if (clock_gettime(CLOCK_BOOTTIME, &time)) return 1;
    const auto now = time.tv_sec * 1000LL + time.tv_nsec / 1000000;
    const auto boot = read("/proc/sys/kernel/random/boot_id");
    if (boot.empty()) return 1;
    std::ifstream previous(root / "last");
    std::string oldBoot; long long last = 0;
    if (previous >> oldBoot >> last) {
        if (oldBoot == boot && now >= last && now - last < 250) return 0;
        if (oldBoot == boot && now < last) return 1;
    } else if (fs::exists(root / "last")) return 1;
    // Persist admission BEFORE proof/crash; fresh processes cannot reset cooldown.
    write(root / "last", boot + " " + std::to_string(now));
    if (fs::exists(root / "blocked")) return 0;
    std::ofstream(root / "attempts", std::ios::app) << now << '\n';
    const auto state = read(root / "package-state");
    if (state == "structural") {
        write(root / "blocked", "fixture structural error; explicit repair required");
    } else if (state == "installed") {
        write(root / "accepted", "fixture proof only");
        write(root / "fence", "completed");
    } else if (state == "crash") {
        _exit(42);
    } else if (state == "timeout") {
        // Deliberately stuck proof: native systemd TimeoutStartSec must kill it.
        while (true) pause();
    }
    // All other inputs model temporary unavailability; no total attempt budget.
    return 0;
} catch (const std::exception& e) {
    std::cerr << e.what() << '\n'; return 1;
}
