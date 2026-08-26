#include <fic/core/process/ProcessExecutor.h>

#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <cstdlib>
#include <functional>
#include <grp.h>
#include <pthread.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

namespace {
void read_pipe(int fd, std::string& output) {
    char buffer[4096];
    while (true) {
        const ssize_t count = ::read(fd, buffer, sizeof(buffer));
        if (count > 0) {
            output.append(buffer, static_cast<size_t>(count));
            continue;
        }
        if (count < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
    ::close(fd);
}

void write_pipe(int fd, const std::string& input) {
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

        ::execv(executable.c_str(), argv.data());
        write_child_error("execv() failed");
        _exit(127);
    }

    result.started = true;
    ::setpgid(pid, pid);
    ::close(stdoutPipe[1]);
    ::close(stderrPipe[1]);
    if (stdinPipe[0] >= 0) {
        ::close(stdinPipe[0]);
    }

    std::thread stdoutReader(read_pipe, stdoutPipe[0], std::ref(result.standardOutput));
    std::thread stderrReader(read_pipe, stderrPipe[0], std::ref(result.standardError));
    std::thread stdinWriter;
    if (stdinPipe[1] >= 0) {
        stdinWriter = std::thread(
            write_pipe, stdinPipe[1], std::cref(*options.standardInput));
    }

    int status = 0;
    const auto deadline = std::chrono::steady_clock::now() + options.timeout;
    while (true) {
        const pid_t waitResult = ::waitpid(pid, &status, WNOHANG);
        if (waitResult == pid) {
            break;
        }
        if (waitResult < 0 && errno != EINTR) {
            result.error = "waitpid() failed: " + std::string(std::strerror(errno));
            if (::kill(-pid, SIGKILL) != 0) {
                ::kill(pid, SIGKILL);
            }
            ::waitpid(pid, &status, 0);
            break;
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            result.timedOut = true;
            if (::kill(-pid, SIGKILL) != 0) {
                ::kill(pid, SIGKILL);
            }
            ::waitpid(pid, &status, 0);
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

    stdoutReader.join();
    stderrReader.join();
    if (stdinWriter.joinable()) {
        stdinWriter.join();
    }

    if (WIFEXITED(status)) {
        result.exitCode = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        result.exitCode = 128 + WTERMSIG(status);
    }
    return result;
}
