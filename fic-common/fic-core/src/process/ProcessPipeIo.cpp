#include "ProcessPipeIo.h"

#include <algorithm>
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <unistd.h>

namespace process_executor_detail {

bool ProcessPipeIo::makeNonBlocking(int fd) {
    const int flags = ::fcntl(fd, F_GETFL);
    return flags >= 0 && ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

void ProcessPipeIo::cancel() {
    // Preserve an already observed overflow; otherwise freeze cancellation so
    // an in-flight read cannot turn a timeout into a later output-limit failure.
    Reason expected = Reason::Running;
    reason_.compare_exchange_strong(expected, Reason::Cancelled);
    cancelled_.store(true);
}

bool ProcessPipeIo::waitReady(int fd, short events) const {
    while (!cancelled_.load()) {
        pollfd descriptor{fd, events, 0};
        const int ready = ::poll(&descriptor, 1, 20);
        if (ready < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (ready > 0) {
            return !cancelled_.load() && !(descriptor.revents & POLLNVAL);
        }
    }
    return false;
}

void ProcessPipeIo::finish(int fd) {
    ::close(fd);
    pending_.fetch_sub(1);
}

void ProcessPipeIo::read(int fd, std::string& output) {
    char buffer[4096];
    while (waitReady(fd, POLLIN)) {
        const ssize_t count = ::read(fd, buffer, sizeof(buffer));
        if (count > 0) {
            const auto bytes = static_cast<std::size_t>(count);
            std::size_t available = remaining_.load();
            std::size_t retained;
            do {
                retained = std::min(available, bytes);
            } while (!remaining_.compare_exchange_weak(available, available - retained));
            output.append(buffer, retained);
            if (retained < bytes) {
                Reason expected = Reason::Running;
                reason_.compare_exchange_strong(expected, Reason::OutputLimit);
            }
            continue;
        }
        if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
            continue;
        }
        break;
    }
    finish(fd);
}

void ProcessPipeIo::write(int fd, const std::string& input) {
    sigset_t blockedSignals;
    ::sigemptyset(&blockedSignals);
    ::sigaddset(&blockedSignals, SIGPIPE);
    ::pthread_sigmask(SIG_BLOCK, &blockedSignals, nullptr);

    std::size_t offset = 0;
    while (offset < input.size() && waitReady(fd, POLLOUT)) {
        const ssize_t count = ::write(
            fd, input.data() + offset, std::min<std::size_t>(4096, input.size() - offset));
        if (count > 0) {
            offset += static_cast<std::size_t>(count);
            continue;
        }
        if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
            continue;
        }
        break;
    }
    finish(fd);
}

} // namespace process_executor_detail
