#include <fic/core/process/ProcessExecutor.h>

#include "ProcessPipeIo.h"

#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <cstdlib>
#include <functional>
#include <fcntl.h>
#include <grp.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

namespace {
using process_executor_detail::ProcessPipeIo;

void write_child_error(const std::string& message) {
    const std::string line = message + ": " + std::strerror(errno) + "\n";
    auto res = ::write(STDERR_FILENO, line.data(), line.size());
}
} // namespace

ProcessResult ProcessExecutor::execute(
    const std::string& executable,
    const std::vector<std::string>& arguments,
    const ProcessOptions& options
) {
    ProcessResult result;
    if (executable.empty() || executable.front() != '/') {
        result.error = "executable path must be absolute";
        return result;
    }
    if (::access(executable.c_str(), X_OK) != 0) {
        result.error = "executable is unavailable: " + executable;
        return result;
    }

    return executeImpl(executable, arguments, options, -1);
}

ProcessResult ProcessExecutor::executeImpl(
    const std::string& executable,
    const std::vector<std::string>& arguments,
    const ProcessOptions& options,
    int executableFd
) {
    ProcessResult result;
    int stdoutPipe[2];
    int stderrPipe[2];
    int stdinPipe[2] = {-1, -1};
    if (::pipe(stdoutPipe) != 0) {
        result.error = "pipe() failed: " + std::string(std::strerror(errno));
        return result;
    }
    if (::pipe(stderrPipe) != 0) {
        result.error = "pipe() failed: " + std::string(std::strerror(errno));
        ::close(stdoutPipe[0]);
        ::close(stdoutPipe[1]);
        return result;
    }
    if (options.standardInput.has_value() && ::pipe(stdinPipe) != 0) {
        result.error = "pipe() failed: " + std::string(std::strerror(errno));
        ::close(stdoutPipe[0]);
        ::close(stdoutPipe[1]);
        ::close(stderrPipe[0]);
        ::close(stderrPipe[1]);
        return result;
    }

    // Only parent endpoints are nonblocking. The child's opposite pipe ends
    // retain ordinary blocking stdin/stdout/stderr semantics.
    if (!ProcessPipeIo::makeNonBlocking(stdoutPipe[0]) ||
        !ProcessPipeIo::makeNonBlocking(stderrPipe[0]) ||
        (stdinPipe[1] >= 0 && !ProcessPipeIo::makeNonBlocking(stdinPipe[1]))) {
        result.error = "fcntl(O_NONBLOCK) failed: " + std::string(std::strerror(errno));
        ::close(stdoutPipe[0]);
        ::close(stdoutPipe[1]);
        ::close(stderrPipe[0]);
        ::close(stderrPipe[1]);
        if (stdinPipe[0] >= 0) {
            ::close(stdinPipe[0]);
            ::close(stdinPipe[1]);
        }
        return result;
    }

    const pid_t pid = ::fork();
    if (pid < 0) {
        result.error = "fork() failed: " + std::string(std::strerror(errno));
        ::close(stdoutPipe[0]);
        ::close(stdoutPipe[1]);
        ::close(stderrPipe[0]);
        ::close(stderrPipe[1]);
        if (stdinPipe[0] >= 0) {
            ::close(stdinPipe[0]);
            ::close(stdinPipe[1]);
        }
        return result;
    }

    if (pid == 0) {
        ::setpgid(0, 0);
        ::close(stdoutPipe[0]);
        ::close(stderrPipe[0]);
        if (stdinPipe[0] >= 0) {
            ::close(stdinPipe[1]);
            ::dup2(stdinPipe[0], STDIN_FILENO);
            ::close(stdinPipe[0]);
        }
        ::dup2(stdoutPipe[1], STDOUT_FILENO);
        ::dup2(stderrPipe[1], STDERR_FILENO);
        ::close(stdoutPipe[1]);
        ::close(stderrPipe[1]);

        if (!options.workingDirectory.empty() && ::chdir(options.workingDirectory.c_str()) != 0) {
            write_child_error("chdir() failed");
            _exit(126);
        }

        if (options.gid.has_value()) {
            if (!options.user.empty() && ::initgroups(options.user.c_str(), options.gid.value()) != 0) {
                write_child_error("initgroups() failed");
                _exit(126);
            }
            if (::setgid(options.gid.value()) != 0) {
                write_child_error("setgid() failed");
                _exit(126);
            }
        }
        if (options.uid.has_value() && ::setuid(options.uid.value()) != 0) {
            write_child_error("setuid() failed");
            _exit(126);
        }

        if (options.clearEnvironment) {
            ::clearenv();
        }
        for (const auto& [name, value] : options.environment) {
            ::setenv(name.c_str(), value.c_str(), 1);
        }

        std::vector<char*> argv;
        argv.reserve(arguments.size() + 2);
        argv.push_back(const_cast<char*>(executable.c_str()));
        for (const std::string& argument : arguments) {
            argv.push_back(const_cast<char*>(argument.c_str()));
        }
        argv.push_back(nullptr);

        if (executableFd >= 0) {
            char* emptyEnvironment[] = {nullptr};
            char** childEnvironment = environ ? environ : emptyEnvironment;
            ::fexecve(executableFd, argv.data(), childEnvironment);
            if (errno == ENOENT) {
                // Linux cannot start a shebang script with FD_CLOEXEC: the
                // interpreter needs this fd. Clear it only in the forked child
                // and retry the SAME object, never the original pathname.
                const int flags = ::fcntl(executableFd, F_GETFD);
                if (flags < 0 ||
                    ::fcntl(executableFd, F_SETFD, flags & ~FD_CLOEXEC) < 0) {
                    write_child_error("fcntl() failed for executable fd");
                    _exit(127);
                }
                ::fexecve(executableFd, argv.data(), childEnvironment);
            }
            write_child_error("fexecve() failed: " + executable);
        } else {
            ::execv(executable.c_str(), argv.data());
            write_child_error("execv() failed");
        }
        _exit(127);
    }

    result.started = true;
    ::setpgid(pid, pid);
    ::close(stdoutPipe[1]);
    ::close(stderrPipe[1]);
    if (stdinPipe[0] >= 0) {
        ::close(stdinPipe[0]);
    }

    ProcessPipeIo io(options.maxOutputBytes, stdinPipe[1] >= 0);
    std::thread stdoutReader(
        &ProcessPipeIo::read, &io, stdoutPipe[0], std::ref(result.standardOutput));
    std::thread stderrReader(
        &ProcessPipeIo::read, &io, stderrPipe[0], std::ref(result.standardError));
    std::thread stdinWriter;
    if (stdinPipe[1] >= 0) {
        stdinWriter = std::thread(
            &ProcessPipeIo::write, &io, stdinPipe[1], std::cref(*options.standardInput));
    }

    const auto killGroup = [pid] {
        if (::kill(-pid, SIGKILL) != 0) {
            ::kill(pid, SIGKILL);
        }
    };
    bool childExited = false;
    bool terminationSent = false;
    const auto deadline = std::chrono::steady_clock::now() + options.timeout;
    while (true) {
        if (!childExited) {
            // Retain the leader's PID until draining is complete: descendants
            // may still need a group kill after their original parent exits.
            siginfo_t info {};
            if (::waitid(P_PID, pid, &info, WEXITED | WNOHANG | WNOWAIT) < 0 && errno != EINTR) {
                result.error = "waitid() failed: " + std::string(std::strerror(errno));
                killGroup();
                io.cancel();
                break;
            }
            childExited = info.si_pid == pid;
        }
        // Read completion before exceeded: completed readers have published
        // their final overflow flag, even if the leader already exited cleanly.
        const bool ioCompleted = io.completed();
        if (!terminationSent && io.outputLimitExceeded()) {
            killGroup();
            io.cancel();
            terminationSent = true;
        }
        if (childExited && ioCompleted) {
            break;
        }
        if (!terminationSent && std::chrono::steady_clock::now() >= deadline) {
            result.timedOut = true;
            killGroup();
            io.cancel();
            terminationSent = true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

    int status = 0;
    pid_t waited;
    do {
        waited = ::waitpid(pid, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited < 0 && result.error.empty()) {
        result.error = "waitpid() failed: " + std::string(std::strerror(errno));
    }

    stdoutReader.join();
    stderrReader.join();
    if (stdinWriter.joinable()) {
        stdinWriter.join();
    }

    // An overflow observed before cancellation retains priority over timeout.
    if (io.outputLimitExceeded()) {
        result.outputLimitExceeded = true;
        result.timedOut = false;
        result.error = "configured process output limit exceeded (" +
            std::to_string(options.maxOutputBytes) + " bytes)";
    }

    if (waited == pid && WIFEXITED(status)) {
        result.exitCode = WEXITSTATUS(status);
    } else if (waited == pid && WIFSIGNALED(status)) {
        result.exitCode = 128 + WTERMSIG(status);
    }
    return result;
}
