#ifndef KDE_SCREEN_LOCKER_RUNTIME_CONTEXT_RESOLVER_INTERNAL_H
#define KDE_SCREEN_LOCKER_RUNTIME_CONTEXT_RESOLVER_INTERNAL_H

#include <functional>
#include <string>

#include <sys/stat.h>
#include <sys/types.h>

namespace kde_screen_locker_runtime_context_detail {

struct ProcessEnvironmentFileOperations {
    std::function<int(const std::string&, int)> open;
    std::function<int(int, struct stat&)> fstat;
    std::function<ssize_t(int, char*, std::size_t)> read;
    std::function<int(int)> close;
};

bool readProcessEnvironment(
    pid_t pid,
    std::string& content,
    std::string& error,
    const ProcessEnvironmentFileOperations& operations);

} // namespace kde_screen_locker_runtime_context_detail

#endif // KDE_SCREEN_LOCKER_RUNTIME_CONTEXT_RESOLVER_INTERNAL_H
