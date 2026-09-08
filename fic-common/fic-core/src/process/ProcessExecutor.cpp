#include <fic/core/process/ProcessExecutor.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <cstdlib>
#include <functional>
#include <fcntl.h>
#include <grp.h>
#include <pthread.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

namespace {
struct OutputCapture {
    explicit OutputCapture(std::size_t limit) : remaining(limit) {}
    std::atomic<std::size_t> remaining;
    std::atomic<bool> exceeded{false};
    std::atomic<unsigned> completedReaders{0};
};

void read_pipe(int fd, std::string& output, OutputCapture& capture) {
    char buffer[4096];
    while (true) {
        const ssize_t count = ::read(fd, buffer, sizeof(buffer));
        if (count > 0) {
            const auto bytes = static_cast<std::size_t>(count);
            std::size_t available = capture.remaining.load();
            std::size_t retained;
            do {
                retained = std::min(available, bytes);
            } while (!capture.remaining.compare_exchange_weak(
                available, available - retained));
            output.append(buffer, retained);
            if (retained < bytes) {
                capture.exceeded.store(true);
            }
            // Keep draining after overflow so a full pipe cannot block exit.
            continue;
        }
        if (count < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
    ::close(fd);
    capture.completedReaders.fetch_add(1);
}

void write_pipe(int fd, const std::string& input, std::atomic<bool>& completed) {
    sigset_t blockedSignals;
    ::sigemptyset(&blockedSignals);
    ::sigaddset(&blockedSignals, SIGPIPE);
    ::pthread_sigmask(SIG_BLOCK, &blockedSignals, nullptr);

    size_t offset = 0;
    while (offset < input.size()) {
        const ssize_t count = ::write(
            fd, input.data() + offset, input.size() - offset);
        if (count > 0) {
            offset += static_cast<size_t>(count);
            continue;
        }
        if (count < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
    ::close(fd);
    completed.store(true);
}

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

    OutputCapture capture(options.maxOutputBytes);
    std::atomic<bool> stdinCompleted{stdinPipe[1] < 0};
    std::thread stdoutReader(
        read_pipe, stdoutPipe[0], std::ref(result.standardOutput), std::ref(capture));
    std::thread stderrReader(
        read_pipe, stderrPipe[0], std::ref(result.standardError), std::ref(capture));
    std::thread stdinWriter;
    if (stdinPipe[1] >= 0) {
        stdinWriter = std::thread(
            write_pipe, stdinPipe[1], std::cref(*options.standardInput), std::ref(stdinCompleted));
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
                break;
            }
            childExited = info.si_pid == pid;
        }
        // Read completion before exceeded: completed readers have published
        // their final overflow flag, even if the leader already exited cleanly.
        const bool ioCompleted = capture.completedReaders.load() == 2 && stdinCompleted.load();
        if (!terminationSent && capture.exceeded.load()) {
            killGroup();
            terminationSent = true;
        }
        if (childExited && ioCompleted) {
            break;
        }
        if (!terminationSent && std::chrono::steady_clock::now() >= deadline) {
            result.timedOut = true;
            killGroup();
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

    // Overflow has priority, including bytes discovered during final draining.
    if (capture.exceeded.load()) {
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
