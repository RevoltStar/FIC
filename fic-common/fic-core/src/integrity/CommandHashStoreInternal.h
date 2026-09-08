#ifndef FIC_COMMAND_HASH_STORE_INTERNAL_H
#define FIC_COMMAND_HASH_STORE_INTERNAL_H

#include <string>
#include <unistd.h>

namespace command_hash_store_detail {

class UniqueFd {
public:
    UniqueFd() = default;
    explicit UniqueFd(int fd) : fd_(fd) {}
    ~UniqueFd() { reset(); }

    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;

    UniqueFd(UniqueFd&& other) noexcept : fd_(other.fd_) {
        other.fd_ = -1;
    }
    UniqueFd& operator=(UniqueFd&& other) noexcept {
        if (this != &other) {
            reset();
            fd_ = other.fd_;
            other.fd_ = -1;
        }
        return *this;
    }

    int get() const { return fd_; }

private:
    void reset() {
        if (fd_ >= 0) ::close(fd_);
        fd_ = -1;
    }

    int fd_ = -1;
};

// On success the caller owns the validated and hashed descriptor (CLOEXEC,
// above the stdio slots). On failure descriptor is empty.
bool openVerifiedExecutable(const std::string& executable,
                            UniqueFd& descriptor, std::string& error);

bool validateExecutablePathSyntax(const std::string& executable,
                                  std::string& error);
bool validateCommandHashStoreKey(const std::string& executable,
                                 std::string& error);
bool calculateSha256FromFd(int descriptor, std::string& hash,
                           std::string& error);
bool calculateValidatedExecutableSha256(const std::string& executable,
                                        std::string& hash,
                                        std::string& error);

} // namespace command_hash_store_detail

#endif // FIC_COMMAND_HASH_STORE_INTERNAL_H
