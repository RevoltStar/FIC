#include "incident/AltIncidentAccessGateTopology.h"

#include "modules/identity_access/pam/PamConfigFileTransaction.h"
#include "modules/identity_access/pam/PamConfiguration.h"

#include <fic/core/fs/AtomicFileWriter.h>

#include <sys/stat.h>

#include <fstream>
#include <vector>

namespace fic::incident {
namespace {
using ::fic::identity::pam::PamConfigFileSnapshot;
using ::fic::identity::pam::PamConfigFileTransaction;
using ::fic::identity::pam::PamConfigFileTransactionState;

constexpr const char* Begin = "# BEGIN FIC incident access gate\n";
constexpr const char* Rule = "account required pam_fic_access.so\n";
constexpr const char* End = "# END FIC incident access gate\n";
const std::string Block = std::string(Begin) + Rule + End;

bool classify(const std::string& content, bool& attached,
              std::string& error) {
    attached = false;
    const bool markerSeen = content.find("FIC incident access gate") !=
        std::string::npos;
    const bool moduleSeen = content.find("pam_fic_access.so") !=
        std::string::npos;
    if (!markerSeen && !moduleSeen) return true;
    if (content.rfind(Block, 0) != 0 ||
        content.find("FIC incident access gate", Block.size()) !=
            std::string::npos ||
        content.find("pam_fic_access.so", Block.size()) !=
            std::string::npos) {
        error = "ALT incident access gate block is ambiguous or modified";
        return false;
    }
    attached = true;
    return true;
}

bool captureTrusted(const std::filesystem::path& target,
                    uid_t expectedOwner,
                    PamConfigFileSnapshot& snapshot, std::string& error) {
    struct stat parentInfo {};
    if (::lstat(target.parent_path().c_str(), &parentInfo) != 0 ||
        !S_ISDIR(parentInfo.st_mode) || parentInfo.st_uid != expectedOwner ||
        (parentInfo.st_mode & 0022) != 0) {
        error = "ALT PAM directory has unsafe metadata";
        return false;
    }
    if (!PamConfigFileTransaction::capture(target, snapshot, error)) return false;
    if (!snapshot.existed || snapshot.owner != expectedOwner ||
        (snapshot.mode & 0022) != 0) {
        error = "ALT PAM account target is absent or has unsafe metadata";
        return false;
    }
    std::vector<::fic::identity::pam::PamRule> rules;
    if (!::fic::identity::pam::PamConfiguration::parseRulesContent(
            target, snapshot.content, rules, error)) return false;
    return true;
}

bool inspectImpl(const std::filesystem::path& target, uid_t expectedOwner,
                 bool& attached, std::string& error) {
    PamConfigFileSnapshot snapshot;
    if (!captureTrusted(target, expectedOwner, snapshot, error)) return false;
    return classify(snapshot.content, attached, error);
}

bool mutate(const std::filesystem::path& target, uid_t expectedOwner,
            bool attach,
            std::string& error) {
    PamConfigFileSnapshot snapshot;
    if (!captureTrusted(target, expectedOwner, snapshot, error)) return false;
    bool alreadyAttached = false;
    if (!classify(snapshot.content, alreadyAttached, error)) return false;
    if (alreadyAttached == attach) return true;
    const std::string desired = attach
        ? Block + snapshot.content
        : snapshot.content.substr(Block.size());
    if (!PamConfigFileTransaction::mutate(
            snapshot,
            [&](const PamConfigFileTransaction::Writer& writer,
                std::string& mutationError) {
                AtomicWriteOptions options;
                options.createIfMissing = false;
                options.rejectSymlink = true;
                options.metadataPolicy = FileMetadataPolicy::PreserveExisting;
                return writer(target.string(), desired, options, &mutationError);
            }, error)) {
        if (snapshot.state == PamConfigFileTransactionState::MutationCommitted) {
            std::string rollbackError;
            if (!PamConfigFileTransaction::rollback(snapshot, rollbackError)) {
                error += "; rollback failed: " + rollbackError;
            }
        }
        return false;
    }
    bool observed = false;
    if (!inspectImpl(target, expectedOwner, observed, error) ||
        observed != attach) {
        if (error.empty())
            error = "ALT incident access gate mutation was not proven";
        std::string rollbackError;
        if (!PamConfigFileTransaction::rollback(snapshot, rollbackError))
            error += "; rollback failed: " + rollbackError;
        return false;
    }
    return true;
}

bool noOtherReferences(const std::filesystem::path& target,
                       std::string& error) {
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(
             target.parent_path(), ec)) {
        if (ec) break;
        if (entry.path() == target) continue;
        if (!entry.is_regular_file(ec) || ec) {
            if (ec) break;
            continue;
        }
        std::ifstream input(entry.path(), std::ios::binary);
        if (!input) {
            error = "cannot inspect another PAM service before module removal";
            return false;
        }
        std::string content(131073, '\0');
        input.read(content.data(), content.size());
        const auto bytes = input.gcount();
        if (input.bad() || bytes >= static_cast<std::streamsize>(content.size())) {
            error = "unbounded or unreadable PAM service before module removal";
            return false;
        }
        content.resize(static_cast<std::size_t>(bytes));
        if (content.find("pam_fic_access.so") != std::string::npos) {
            error = "another PAM service still references pam_fic_access.so";
            return false;
        }
    }
    if (ec) {
        error = "cannot enumerate PAM services before module removal";
        return false;
    }
    return true;
}
} // namespace

bool AltIncidentAccessGateTopology::inspect(
    const std::filesystem::path& target, bool& attached, std::string& error) {
    return inspectImpl(target, 0, attached, error);
}

bool AltIncidentAccessGateTopology::attach(
    const std::filesystem::path& target, std::string& error) {
    return mutate(target, 0, true, error);
}

bool AltIncidentAccessGateTopology::detach(
    const std::filesystem::path& target, std::string& error) {
    if (!noOtherReferences(target, error)) return false;
    return mutate(target, 0, false, error);
}

bool AltIncidentAccessGateTopology::inspectForTests(
    const std::filesystem::path& target, uid_t expectedOwner,
    bool& attached, std::string& error) {
    return inspectImpl(target, expectedOwner, attached, error);
}

bool AltIncidentAccessGateTopology::attachForTests(
    const std::filesystem::path& target, uid_t expectedOwner,
    std::string& error) {
    return mutate(target, expectedOwner, true, error);
}

bool AltIncidentAccessGateTopology::detachForTests(
    const std::filesystem::path& target, uid_t expectedOwner,
    std::string& error) {
    if (!noOtherReferences(target, error)) return false;
    return mutate(target, expectedOwner, false, error);
}

} // namespace fic::incident
