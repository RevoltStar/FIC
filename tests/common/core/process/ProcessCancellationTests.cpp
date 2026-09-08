#include <fic/core/process/VerifiedProcessExecutor.h>
#include <fic/core/runtime/FicRuntimePaths.h>
#include "integrity/CommandHashStoreInternal.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <filesystem>
#include <fcntl.h>
#include <fstream>
#include <string>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

namespace fs = std::filesystem;
namespace {
constexpr std::size_t InputSize = 2 * 1024 * 1024;

void writeBytes(int fd, const std::string& value) {
    std::size_t offset = 0;
    while (offset < value.size()) {
        const auto count = ::write(fd, value.data() + offset, value.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        assert(count > 0);
        offset += static_cast<std::size_t>(count);
    }
}

int fixture(const std::string& mode, const std::string& pidFile) {
    ::alarm(5); // Also bounds a broken executor that still relies on EOF.
    for (int fd : {STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO}) {
        assert((::fcntl(fd, F_GETFL) & O_NONBLOCK) == 0);
    }
    if (mode == "normal") {
        std::string input;
        char buffer[4096];
        for (;;) {
            const auto count = ::read(STDIN_FILENO, buffer, sizeof(buffer));
            if (count < 0 && errno == EINTR) continue;
            assert(count >= 0);
            if (!count) break;
            input.append(buffer, static_cast<std::size_t>(count));
        }
        assert(input == "normal stdin\n");
        writeBytes(STDOUT_FILENO, "normal stdout\n");
        writeBytes(STDERR_FILENO, "normal stderr\n");
        return 0;
    }

    int ready[2];
    assert(::pipe(ready) == 0);
    const pid_t leader = ::getpid();
    const pid_t descendant = ::fork();
    assert(descendant >= 0);
    if (descendant == 0) {
        ::alarm(5);
        assert(::setsid() == ::getpid()); // Guaranteed escape, before leader proceeds.
        ::signal(SIGPIPE, SIG_IGN); // Closing executor readers must not clean up the fixture for us.
        ::close(ready[0]);
        if (mode.find("stdout") != std::string::npos || mode == "flood-exit") {
            ::close(STDIN_FILENO);
            ::close(STDERR_FILENO);
        } else if (mode.find("stderr") != std::string::npos) {
            ::close(STDIN_FILENO);
            ::close(STDOUT_FILENO);
        } else if (mode == "stdin-exit") {
            assert(::fcntl(STDIN_FILENO, F_GETPIPE_SZ) < static_cast<int>(InputSize));
            ::close(STDOUT_FILENO);
            ::close(STDERR_FILENO);
        }
        { std::ofstream(pidFile) << ::getpid(); }
        writeBytes(ready[1], "R");
        ::close(ready[1]);
        if (mode == "flood-exit") {
            while (::getppid() == leader) ::usleep(1000);
            const std::string chunk(4096, 'x');
            for (;;) {
                const auto count = ::write(STDOUT_FILENO, chunk.data(), chunk.size());
                if (count < 0 && errno == EINTR) continue;
                if (count < 0 && errno == EPIPE) break;
                assert(count > 0);
                ::usleep(1000);
            }
        }
        for (;;) ::pause(); // Keep escaped descriptors open until test cleanup/watchdog.
    }
    ::close(ready[1]);
    char token;
    assert(::read(ready[0], &token, 1) == 1);
    ::close(ready[0]);
    if (mode == "overflow") {
        writeBytes(STDOUT_FILENO, std::string(1025, 'x'));
    }
    if (mode == "overflow" || mode.find("timeout") != std::string::npos) {
        for (;;) ::pause();
    }
    return 0;
}

std::size_t entryCount(const char* directory) {
    std::size_t count = 0;
    for ([[maybe_unused]] const auto& entry : fs::directory_iterator(directory)) ++count;
    return count;
}

// Cleanup precedes assertions about the executor's return, including on a
// negative control. No escaped process is left alive after a successful test.
bool cleanupEscaped(const fs::path& pidFile) {
    pid_t child = -1;
    std::ifstream(pidFile) >> child;
    assert(child > 0);
    int status = 0;
    pid_t waited;
    do { waited = ::waitpid(child, &status, WNOHANG); } while (waited < 0 && errno == EINTR);
    const bool stillRunning = waited == 0;
    const bool escaped = stillRunning && ::getsid(child) == child && ::getpgid(child) == child;
    if (stillRunning) {
        assert(::kill(child, SIGKILL) == 0);
        do { waited = ::waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
    }
    assert(waited == child);
    assert(::waitpid(-1, &status, WNOHANG) == -1 && errno == ECHILD);
    return escaped;
}
} // namespace

int main(int argc, char** argv) {
    if (argc == 4 && std::string(argv[1]) == "--fixture") return fixture(argv[2], argv[3]);
    ::alarm(30); // Independent whole-suite watchdog, in addition to CTest TIMEOUT.
    assert(::prctl(PR_SET_CHILD_SUBREAPER, 1) == 0);
    char directory[] = "/tmp/fic-cancellation-XXXXXX";
    assert(::mkdtemp(directory));
    const fs::path root(directory);
    const auto executable = root / "fixture";
    fs::copy_file("/proc/self/exe", executable);
    auto paths = fic::core::FicProductPaths::production();
    paths.commandHashFile = root / "commandhash.txt";
    std::string hash, error;
    assert(fic::core::FicRuntimePaths::initialize(paths, error));
    assert(command_hash_store_detail::calculateValidatedExecutableSha256(executable.string(), hash, error));
    std::ofstream(paths.commandHashFile) << executable.string() << '=' << hash << '\n';
    const auto fdCount = entryCount("/proc/self/fd");
    const auto threadCount = entryCount("/proc/self/task");
    for (const bool verified : {false, true}) {
        for (int repeat = 0; repeat < 2; ++repeat) {
            for (const std::string mode : {"normal", "stdout-exit", "stderr-exit", "stdout-timeout",
                                           "stderr-timeout", "stdin-exit", "overflow", "flood-exit"}) {
                const bool overflow = mode == "overflow" || mode == "flood-exit";
                const auto pidFile = root / "escaped.pid";
                ProcessOptions options;
                options.maxOutputBytes = 1024;
                options.timeout = overflow ? std::chrono::seconds(10) : std::chrono::milliseconds(250);
                options.standardInput = mode == "normal" ? "normal stdin\n" : std::string(InputSize, 'i');
                const auto start = std::chrono::steady_clock::now();
                const std::vector<std::string> args = {"--fixture", mode, pidFile.string()};
                const auto result = verified
                    ? VerifiedProcessExecutor::execute(executable.string(), args, options)
                    : ProcessExecutor::execute(executable.string(), args, options);
                const auto elapsed = std::chrono::steady_clock::now() - start;
                const bool escapedAlive = mode != "normal" && cleanupEscaped(pidFile);
                assert(elapsed < std::chrono::seconds(2));
                assert(result.started);
                assert(result.standardOutput.size() + result.standardError.size() <= options.maxOutputBytes);
                if (mode == "normal") {
                    assert(result.success() && !result.timedOut && !result.outputLimitExceeded);
                    assert(result.standardOutput == "normal stdout\n" && result.standardError == "normal stderr\n");
                } else {
                    assert(escapedAlive); // Return is independent of escaped process exit/EOF.
                    assert(!result.success());
                    assert(result.outputLimitExceeded == overflow && result.timedOut == !overflow);
                    if (overflow) {
                        assert(result.error.find("configured process output limit exceeded") != std::string::npos);
                        assert(result.standardOutput.size() == options.maxOutputBytes);
                    }
                    if (mode.find("exit") != std::string::npos) assert(result.exitCode == 0);
                    else assert(result.exitCode == 128 + SIGKILL);
                }
                assert(entryCount("/proc/self/fd") == fdCount);
                assert(entryCount("/proc/self/task") == threadCount);
            }
        }
    }
    fs::remove_all(root);
    ::alarm(0);
    return 0;
}
