#include <fic/core/process/VerifiedProcessExecutor.h>
#include <fic/core/runtime/FicRuntimePaths.h>
#include "integrity/CommandHashStoreInternal.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <algorithm>
#include <atomic>
#include <cassert>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <filesystem>
#include <fcntl.h>
#include <fstream>
#include <string>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

namespace {
namespace fs = std::filesystem;

// Restores the process umask even when an assert fails.
class ScopedUmask {
public:
    explicit ScopedUmask(mode_t value) : previous_(::umask(value)) {}
    ~ScopedUmask() { ::umask(previous_); }
    ScopedUmask(const ScopedUmask&) = delete;
    ScopedUmask& operator=(const ScopedUmask&) = delete;
private:
    mode_t previous_;
};

void emit(int fd, std::size_t bytes, char value) {
    const std::string chunk(4096, value);
    while (bytes) {
        const auto written = ::write(fd, chunk.data(), std::min(bytes, chunk.size()));
        if (written < 0 && errno == EINTR) continue;
        assert(written > 0);
        bytes -= static_cast<std::size_t>(written);
    }
}

void flood() {
    // Safety watchdog and pacing also bound a broken implementation's test run.
    ::alarm(4);
    for (;;) {
        emit(STDOUT_FILENO, 4096, 'o');
        ::usleep(1000);
    }
}

int fixture(const std::string& mode, std::size_t bytes, const fs::path& pidFile) {
    ::alarm(4);
    if (mode == "stdout" || mode == "stderr") {
        emit(mode == "stdout" ? STDOUT_FILENO : STDERR_FILENO, bytes,
             mode == "stdout" ? 'o' : 'e');
    } else if (mode == "both") {
        std::atomic<unsigned> ready{0};
        const auto writer = [&](int fd, char value) {
            ready.fetch_add(1);
            while (ready.load() != 2) std::this_thread::yield();
            emit(fd, bytes, value);
        };
        std::thread out(writer, STDOUT_FILENO, 'o');
        std::thread err(writer, STDERR_FILENO, 'e');
        out.join();
        err.join();
    } else if (mode == "infinite") {
        flood();
    } else if (mode == "stdin") {
        char buffer[4096];
        std::size_t received = 0;
        for (;;) {
            const auto count = ::read(STDIN_FILENO, buffer, sizeof(buffer));
            if (count < 0 && errno == EINTR) continue;
            assert(count >= 0);
            if (count == 0) break;
            received += static_cast<std::size_t>(count);
        }
        assert(received == bytes);
        emit(STDOUT_FILENO, 1, 'o');
    } else if (mode == "descendant-holds" || mode == "descendant-output") {
        int ready[2];
        assert(::pipe(ready) == 0);
        const pid_t originalParent = ::getpid();
        const pid_t child = ::fork();
        assert(child >= 0);
        if (child == 0) {
            ::alarm(4);
            ::close(ready[0]);
            // Publish the PID before the ready token so the parent-side
            // verification always observes exactly this descendant.
            { std::ofstream(pidFile) << ::getpid(); }
            assert(::write(ready[1], "R", 1) == 1);
            ::close(ready[1]);
            if (mode == "descendant-output") {
                // Output begins only after the group leader has exited.
                while (::getppid() == originalParent) ::usleep(1000);
                flood();
            }
            for (;;) ::pause();
        }
        ::close(ready[1]);
        char token;
        assert(::read(ready[0], &token, 1) == 1);
        ::close(ready[0]);
        if (mode == "descendant-output") return 0;
        emit(STDOUT_FILENO, bytes, 'o');
        for (;;) ::pause();
    } else if (mode == "quiet") {
        for (;;) ::pause();
    } else {
        assert(false);
    }
    return 0;
}

// Verifies that the executor's group kill reached the fixture's descendant.
// The descendant publishes its PID before signaling readiness, so the status
// of exactly that process is awaited. With PR_SET_CHILD_SUBREAPER set in
// main(), a descendant whose leader is reaped is re-parented to this test
// process, making it directly waitable. The previously used global
// `waitpid(-1) == -1 && errno == ECHILD` probe was racy: a group member can
// remain a transient zombie between SIGKILL and its reaping, and unrelated
// waitable children make the probe flaky.
void assertDescendantKilled(const fs::path& pidFile) {
    pid_t descendant = -1;
    std::ifstream(pidFile) >> descendant;
    assert(descendant > 0);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    int status = 0;
    pid_t waited;
    do {
        waited = ::waitpid(descendant, &status, WNOHANG);
        if (waited < 0 && errno == EINTR) continue;
        if (waited != 0) break;
        assert(std::chrono::steady_clock::now() < deadline);
        ::usleep(1000);
    } while (true);
    assert(waited == descendant);
    assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
}
} // namespace

int main(int argc, char** argv) {
    if (argc == 5 && std::string(argv[1]) == "--fixture") {
        return fixture(argv[2], std::stoull(argv[3]), argv[4]);
    }
    if (argc == 3 && std::string(argv[1]) == "--umask-fixture") {
        // Fixture child: create a file with mode 0666 under the requested
        // path; the resulting mode reveals whatever umask the executor gave
        // this child (inherited or overridden via childUmask).
        const int fd = ::open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0666);
        assert(fd >= 0);
        assert(::write(fd, "x", 1) == 1);
        assert(::close(fd) == 0);
        return 0;
    }
    // Adopt orphan fixtures so group termination is proven by wait status,
    // without depending on the host's PID 1 reaping behavior.
    assert(::prctl(PR_SET_CHILD_SUBREAPER, 1) == 0);
    char directory[] = "/tmp/fic-output-limit-XXXXXX";
    assert(::mkdtemp(directory));
    const fs::path root(directory);
    const auto executable = root / "fixture";
    fs::copy_file("/proc/self/exe", executable);
    assert(::chmod(executable.c_str(), 0700) == 0);
    auto paths = fic::core::FicProductPaths::production();
    paths.commandHashFile = root / "commandhash.txt";
    std::string error, hash;
    assert(fic::core::FicRuntimePaths::initialize(paths, error));
    assert(command_hash_store_detail::calculateValidatedExecutableSha256(
        executable.string(), hash, error));
    std::ofstream(paths.commandHashFile) << executable.string() << '=' << hash << '\n';

    for (const bool verified : {false, true}) {
        ProcessOptions options;
        options.timeout = std::chrono::seconds(10);

        // childUmask applies to the child only; the parent umask is untouched.
        {
            ScopedUmask guard(0027);
            const fs::path maskProbe = root / "umask-probe";
            ProcessOptions maskedOptions = options;
            maskedOptions.childUmask = 0022;
            const std::vector<std::string> maskArgs = {
                "--umask-fixture", (maskProbe.string() + std::to_string(verified))};
            const auto maskedResult = verified
                ? VerifiedProcessExecutor::execute(executable.string(), maskArgs, maskedOptions)
                : ProcessExecutor::execute(executable.string(), maskArgs, maskedOptions);
            assert(maskedResult.success());
            struct stat info {};
            assert(::stat((maskProbe.string() + std::to_string(verified)).c_str(),
                          &info) == 0);
            // child umask 0022: 0666 & ~0022 = 0644. A 0027 child umask would
            // have produced 0640; the inherited daemon mask would too.
            assert((info.st_mode & 0777) == 0644);
            assert(::umask(0) == 0027);
        }
        // Without childUmask the child keeps the inherited umask.
        {
            ScopedUmask guard(0027);
            const fs::path probe = root / "inherit-probe";
            const std::vector<std::string> inheritArgs = {
                "--umask-fixture", probe.string()};
            const auto inherited = verified
                ? VerifiedProcessExecutor::execute(executable.string(), inheritArgs, options)
                : ProcessExecutor::execute(executable.string(), inheritArgs, options);
            assert(inherited.success());
            struct stat info {};
            assert(::stat(probe.c_str(), &info) == 0);
            assert((info.st_mode & 0777) == 0640); // 0666 & ~0027
            assert(::umask(0) == 0027);
        }
        const auto pidFile = root / "descendant.pid";
        const auto run = [&](const std::string& mode, std::size_t bytes) {
            const auto start = std::chrono::steady_clock::now();
            const std::vector<std::string> args = {"--fixture", mode, std::to_string(bytes), pidFile.string()};
            const auto result = verified
                ? VerifiedProcessExecutor::execute(executable.string(), args, options)
                : ProcessExecutor::execute(executable.string(), args, options);
            assert(result.started);
            assert(result.standardOutput.size() + result.standardError.size() <= options.maxOutputBytes);
            assert(std::all_of(result.standardOutput.begin(), result.standardOutput.end(), [](char ch) { return ch == 'o'; }));
            assert(std::all_of(result.standardError.begin(), result.standardError.end(), [](char ch) { return ch == 'e'; }));
            assert(std::chrono::steady_clock::now() - start < std::chrono::seconds(2));
            return result;
        };
        const auto normal = [&](const std::string& mode, std::size_t bytes) {
            const auto result = run(mode, bytes);
            assert(result.success() && !result.outputLimitExceeded && !result.timedOut);
            assert(result.error.empty());
            assert(result.standardOutput.size() == (mode == "stderr" ? 0 : bytes));
            assert(result.standardError.size() == (mode == "stdout" ? 0 : bytes));
        };
        const auto overflow = [&](const std::string& mode, std::size_t bytes) {
            const auto result = run(mode, bytes);
            assert(!result.success() && result.outputLimitExceeded && !result.timedOut);
            assert(result.standardOutput.size() + result.standardError.size() == options.maxOutputBytes);
            assert(result.error == "configured process output limit exceeded (" +
                   std::to_string(options.maxOutputBytes) + " bytes)");
            return result;
        };

        // The production default is bounded without a caller override.
        assert(options.maxOutputBytes == 4 * 1024 * 1024);
        overflow("stdout", options.maxOutputBytes + 1);
        options.maxOutputBytes = 17;
        normal("stdout", 12);
        normal("stderr", 12);
        normal("stdout", 17);
        normal("stderr", 17);
        overflow("stdout", 18);
        overflow("stderr", 18);
        options.maxOutputBytes = 0;
        normal("stdout", 0);
        normal("stderr", 0);
        overflow("stdout", 1);
        overflow("stderr", 1);
        options.maxOutputBytes = 1;
        normal("stdout", 1);
        overflow("stdout", 2);
        options.maxOutputBytes = 12000;
        normal("both", 6000);
        // Each stream fits individually; only a shared budget can reject this.
        overflow("both", 8192);
        options.maxOutputBytes = 257;
        overflow("infinite", 0);
        overflow("descendant-holds", 258);
        assertDescendantKilled(pidFile);
        const auto orphanOutput = overflow("descendant-output", 0);
        assert(orphanOutput.exitCode == 0); // leader exited successfully before overflow
        assertDescendantKilled(pidFile);
        options.standardInput = std::string(128 * 1024, 'i');
        options.maxOutputBytes = 1;
        const auto input = run("stdin", options.standardInput->size());
        assert(input.success() && !input.outputLimitExceeded);
        assert(input.standardOutput == "o" && input.standardError.empty());
        // A blocked stdin writer must also finish when the group is killed.
        overflow("infinite", 0);
        options.standardInput.reset();
        options.timeout = std::chrono::milliseconds(60);
        const auto timeout = run("quiet", 0);
        assert(timeout.timedOut && !timeout.outputLimitExceeded && !timeout.success());
    }
    fs::remove_all(root);
    return 0;
}
