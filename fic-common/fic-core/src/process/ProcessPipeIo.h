#ifndef FIC_PROCESS_PIPE_IO_H
#define FIC_PROCESS_PIPE_IO_H

#include <atomic>
#include <cstddef>
#include <string>

namespace process_executor_detail {

// Internal shared capture/cancellation state. Each I/O worker exclusively owns
// and closes its fd; cancellation never closes another thread's descriptor.
class ProcessPipeIo {
public:
    ProcessPipeIo(std::size_t limit, bool hasInput)
        : remaining_(limit), pending_(hasInput ? 3 : 2) {}

    static bool makeNonBlocking(int fd);
    void read(int fd, std::string& output);
    void write(int fd, const std::string& input);
    void cancel();
    bool completed() const { return pending_.load() == 0; }
    bool outputLimitExceeded() const { return reason_.load() == Reason::OutputLimit; }

private:
    enum class Reason { Running, Cancelled, OutputLimit };
    bool waitReady(int fd, short events) const;
    void finish(int fd);

    std::atomic<std::size_t> remaining_;
    std::atomic<unsigned> pending_;
    std::atomic<Reason> reason_{Reason::Running};
    // An overflow signals the parent first; it sends group kill before allowing
    // workers to close pipes (and potentially deliver SIGPIPE to the child).
    std::atomic<bool> cancelled_{false};
};

} // namespace process_executor_detail
#endif // FIC_PROCESS_PIPE_IO_H
