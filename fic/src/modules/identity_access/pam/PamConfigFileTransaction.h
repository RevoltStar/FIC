#ifndef FIC_IDENTITY_ACCESS_PAM_CONFIG_FILE_TRANSACTION_H
#define FIC_IDENTITY_ACCESS_PAM_CONFIG_FILE_TRANSACTION_H

#include <filesystem>
#include <string>

#include <sys/types.h>

namespace fic::identity::pam {

struct PamConfigFileSnapshot {
    std::filesystem::path path;
    bool existed = false;
    std::string content;
    mode_t mode = 0;
    uid_t owner = 0;
    gid_t group = 0;
    bool mutationRecorded = false;
    std::string mutatedContent;
    dev_t mutatedDevice = 0;
    ino_t mutatedInode = 0;
    mode_t mutatedMode = 0;
    uid_t mutatedOwner = 0;
    gid_t mutatedGroup = 0;
};

class PamConfigFileTransaction {
public:
    static bool capture(const std::filesystem::path& path,
                        PamConfigFileSnapshot& snapshot,
                        std::string& error);

    static bool recordMutation(PamConfigFileSnapshot& snapshot,
                               std::string& error);

    static bool rollback(const PamConfigFileSnapshot& snapshot,
                         std::string& error);
};

} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_CONFIG_FILE_TRANSACTION_H
