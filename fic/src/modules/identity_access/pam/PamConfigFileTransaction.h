#ifndef FIC_IDENTITY_ACCESS_PAM_CONFIG_FILE_TRANSACTION_H
#define FIC_IDENTITY_ACCESS_PAM_CONFIG_FILE_TRANSACTION_H

#include <fic/core/fs/AtomicFileWriter.h>

#include <filesystem>
#include <functional>
#include <string>

#include <sys/types.h>

namespace fic::identity::pam {

enum class PamConfigFileTransactionState {
    Uninitialized,
    Captured,
    MutationCommitted
};

struct PamConfigFileSnapshot {
    std::filesystem::path path;
    bool existed = false;
    std::string content;
    mode_t mode = 0;
    uid_t owner = 0;
    gid_t group = 0;
    dev_t device = 0;
    ino_t inode = 0;
    PamConfigFileTransactionState state =
        PamConfigFileTransactionState::Uninitialized;
    std::string mutatedContent;
    dev_t mutatedDevice = 0;
    ino_t mutatedInode = 0;
    mode_t mutatedMode = 0;
    uid_t mutatedOwner = 0;
    gid_t mutatedGroup = 0;
};

class PamConfigFileTransaction {
public:
    using Writer = std::function<bool(
        const std::string&,
        const std::string&,
        const AtomicWriteOptions&,
        std::string*)>;
    using Mutation = std::function<bool(const Writer&, std::string&)>;

    static bool capture(const std::filesystem::path& path,
                        PamConfigFileSnapshot& snapshot,
                        std::string& error);

    static bool mutate(PamConfigFileSnapshot& snapshot,
                       const Mutation& mutation,
                       std::string& error);

    static bool rollback(const PamConfigFileSnapshot& snapshot,
                         std::string& error);
};

} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_CONFIG_FILE_TRANSACTION_H
