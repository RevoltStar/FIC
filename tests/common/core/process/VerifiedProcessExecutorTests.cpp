#include <fic/core/integrity/CommandHashStore.h>
#include <fic/core/process/VerifiedProcessExecutor.h>
#include <fic/core/runtime/FicRuntimePaths.h>

#include "integrity/CommandHashStoreInternal.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;

namespace {
std::function<void()> beforeFork;
bool failFork = false;
int failPipe = 0;
int forkCalls = 0;

void writeScript(const fs::path& path, const std::string& body) {
    std::ofstream(path) << "#!/bin/sh\n" << body;
    assert(::chmod(path.c_str(), 0700) == 0);
}

void writePerlScript(const fs::path& path, const std::string& body) {
    std::ofstream(path) << "#!/usr/bin/perl -w\n" << body;
    assert(::chmod(path.c_str(), 0700) == 0);
}

void trust(const fs::path& path) {
    std::string hash, error;
    assert(command_hash_store_detail::calculateValidatedExecutableSha256(
        path.string(), hash, error));
    std::ofstream(fic::core::FicRuntimePaths::get().commandHashFile)
        << path.string() << '=' << hash << '\n';
    assert(CommandHashStore::verifyHash(path.string(), error));
}

std::size_t fdCount() {
    std::size_t count = 0;
    for ([[maybe_unused]] const auto& entry : fs::directory_iterator("/proc/self/fd")) {
        ++count;
    }
    return count;
}

ProcessResult execute(const fs::path& path, const ProcessOptions& options = {}) {
    const auto before = fdCount();
    auto result = VerifiedProcessExecutor::execute(path.string(), {"--payload"}, options);
    assert(fdCount() == before);
    return result;
}
} // namespace

// Linker wrapping keeps the synchronization and fault injection out of production.
// This boundary is reached only after verification, immediately before execution.
extern "C" pid_t __real_fork();
extern "C" pid_t __wrap_fork() {
    ++forkCalls;
    if (beforeFork) {
        auto action = std::move(beforeFork);
        beforeFork = {};
        action();
    }
    if (failFork) {
        errno = EAGAIN;
        return -1;
    }
    return __real_fork();
}

extern "C" int __real_pipe(int descriptors[2]);
extern "C" int __wrap_pipe(int descriptors[2]) {
    if (failPipe > 0 && --failPipe == 0) {
        errno = EMFILE;
        return -1;
    }
    return __real_pipe(descriptors);
}

int main(int argc, char** argv) {
    if (argc == 2 && std::string(argv[1]) == "--payload") {
        // The binary must not inherit its executable descriptor.
        struct stat self {};
        assert(::stat("/proc/self/exe", &self) == 0);
        for (const auto& entry : fs::directory_iterator("/proc/self/fd")) {
            struct stat info {};
            const int fd = std::stoi(entry.path().filename().string());
            if (fd > STDERR_FILENO && ::fstat(fd, &info) == 0) {
                assert(info.st_dev != self.st_dev || info.st_ino != self.st_ino);
            }
        }
        std::cout << "A:" << argv[0] << '\n';
        return 0;
    }

    char directory[] = "/tmp/fic-verified-executor-XXXXXX";
    assert(::mkdtemp(directory));
    const fs::path root(directory);
    auto paths = fic::core::FicProductPaths::production();
    paths.commandHashFile = root / "commandhash.txt";
    std::string error;
    assert(fic::core::FicRuntimePaths::initialize(paths, error));

    const auto target = root / "executable with spaces";
    const auto replacement = root / "replacement";
    const auto binaryOutput = "A:" + target.string() + '\n';
    auto installBinary = [&] {
        fs::remove(target);
        fs::copy_file("/proc/self/exe", target);
        assert(::chmod(target.c_str(), 0700) == 0);
        trust(target);
    };

    installBinary();
    writeScript(replacement, "echo B\n");
    beforeFork = [&] { fs::rename(replacement, target); };
    auto result = execute(target);
    assert(!beforeFork);
    assert(result.success() && result.standardOutput == binaryOutput);
    // The replacement really is executable B; ordinary execution still uses it.
    result = ProcessExecutor::execute(target.string());
    assert(result.success() && result.standardOutput == "B\n");
    const int callsBeforeMismatch = forkCalls;
    result = execute(target);
    assert(!result.started && result.error.find("does not match") != std::string::npos);
    assert(forkCalls == callsBeforeMismatch);

    // No lookup (including access) may reject a now missing original pathname.
    installBinary();
    beforeFork = [&] { fs::remove(target); };
    result = execute(target);
    assert(result.success() && result.standardOutput == binaryOutput);

    // Shebang scripts use fd-exec first, then fall back to the original
    // pathname when the close-on-exec fd cannot be reopened by the interpreter.
    writeScript(target, "echo script-A\n");
    trust(target);
    result = execute(target);
    assert(result.success() && result.standardOutput == "script-A\n");
    writeScript(replacement, "echo script-B\n");
    beforeFork = [&] { fs::rename(replacement, target); };
    result = execute(target);
    assert(!beforeFork);
    assert(result.started && result.exitCode == 127);
    assert(result.standardError.find("verified executable path changed") != std::string::npos);

    writePerlScript(target, "print \"perl-script-A\\n\";\n");
    trust(target);
    result = execute(target);
    assert(result.success() && result.standardOutput == "perl-script-A\n");

    writePerlScript(target,
        "if (!$ENV{FIC_SELF_REEXECED}) {\n"
        "    $ENV{FIC_SELF_REEXECED} = 1;\n"
        "    exec $0, @ARGV;\n"
        "    die \"self reexec failed: $!\\n\";\n"
        "}\n"
        "print \"self-reexec:$0:$ARGV[0]\\n\";\n");
    trust(target);
    result = execute(target);
    assert(result.success());
    assert(result.standardOutput == "self-reexec:" + target.string() + ":--payload\n");

    writePerlScript(target,
        "if (@ARGV && $ARGV[0] eq '--helper') {\n"
        "    print \"helper:$0\\n\";\n"
        "    exit 0;\n"
        "}\n"
        "system($0, '--helper') == 0 or die \"helper exec failed: $? $!\\n\";\n");
    trust(target);
    result = execute(target);
    assert(result.success());
    assert(result.standardOutput == "helper:" + target.string() + "\n");

    writeScript(target,
        "IFS= read -r line\n"
        "printf '%s|%s|%s|%s|%s\\n' \"$1\" \"$line\" \"$FIC_EXEC_TEST\" \"${FIC_EXEC_PARENT-unset}\" \"$PWD\"\n"
        "printf 'stderr-value\\n' >&2\n");
    trust(target);
    assert(::setenv("FIC_EXEC_PARENT", "inherited", 1) == 0);
    ProcessOptions options;
    options.standardInput = "input value\n";
    options.clearEnvironment = true;
    options.environment = {{"FIC_EXEC_TEST", "environment value"}};
    options.workingDirectory = root.string();
    options.uid = ::getuid();
    options.gid = ::getgid();
    result = execute(target, options);
    assert(result.success());
    assert(result.standardOutput == "--payload|input value|environment value|unset|" + root.string() + '\n');
    assert(result.standardError == "stderr-value\n");
    options.clearEnvironment = false;
    result = execute(target, options);
    assert(result.success());
    assert(result.standardOutput.find("|inherited|") != std::string::npos);
    assert(::unsetenv("FIC_EXEC_PARENT") == 0);

    // Empty environ and an executable initially opened in fd 0 are supported.
    writeScript(target, "IFS= read -r line; printf '%s\\n' \"$line\"\n");
    trust(target);
    options = {};
    options.clearEnvironment = true;
    options.standardInput = "empty environment\n";
    result = execute(target, options);
    assert(result.success() && result.standardOutput == "empty environment\n");
    const int savedStdin = ::dup(STDIN_FILENO);
    assert(savedStdin >= 0);
    assert(::close(STDIN_FILENO) == 0);
    result = execute(target, options);
    assert(::dup2(savedStdin, STDIN_FILENO) == STDIN_FILENO);
    assert(::close(savedStdin) == 0);
    assert(result.success() && result.standardOutput == "empty environment\n");

    // The owning fd must close on every parent return, including setup failures.
    for (int pipe = 1; pipe <= 3; ++pipe) {
        failPipe = pipe;
        result = execute(target, options);
        assert(!result.started && result.error.find("pipe() failed") != std::string::npos);
    }
    failFork = true;
    result = execute(target);
    failFork = false;
    assert(!result.started && result.error.find("fork() failed") != std::string::npos);
    options.workingDirectory = (root / "missing-directory").string();
    result = execute(target, options);
    assert(result.started && result.exitCode == 126);
    assert(result.standardError.find("chdir() failed") != std::string::npos);

    std::ofstream(target) << "invalid executable format\n";
    trust(target);
    result = execute(target);
    assert(result.started && result.exitCode == 127);
    assert(result.standardError.find("execveat() failed") != std::string::npos);
    std::ofstream(target) << "#!/nonexistent-fic-interpreter\n";
    trust(target);
    result = execute(target);
    assert(result.started && result.exitCode == 127);

    writeScript(target, "sleep 10 &\nwait\n");
    trust(target);
    options = {};
    options.timeout = std::chrono::milliseconds(100);
    const auto start = std::chrono::steady_clock::now();
    result = execute(target, options);
    assert(result.started && result.timedOut);
    // Descendants keep the output pipes open unless the process group is killed.
    assert(std::chrono::steady_clock::now() - start < std::chrono::seconds(3));

    assert(!ProcessExecutor::execute("relative/path").started);
    assert(!ProcessExecutor::execute((root / "missing").string()).started);
    fs::remove_all(root);
    return 0;
}
