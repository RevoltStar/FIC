#include "modules/identity_access/alt_groups/AltGroupTransaction.h"

#include "modules/identity_access/IdentityAccessPolicy.h"
#include "platform/PlatformExecutableResolver.h"
#include "rollback/MutationJournal.h"

#include <fic/core/process/ProcessExecutor.h>
#include <openssl/evp.h>
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <map>
#include <sstream>
#include <utility>

#include <fcntl.h>
#include <linux/fs.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace fic::identity::alt_groups {
namespace {

using fic::rollback::MutationId;
using fic::rollback::MutationJournal;
namespace fs = std::filesystem;

bool reject(std::string& error, std::string message) {
    error = std::move(message);
    return false;
}

bool ioError(std::string& error, std::string message) {
    const int failure = errno;
    return reject(error, std::move(message) + ": " + std::strerror(failure));
}

bool lookup(const int dir, const std::string& name, std::optional<struct stat>& result,
            std::string& error) {
    result.reset();
    struct stat info{};
    if (::fstatat(dir, name.c_str(), &info, AT_SYMLINK_NOFOLLOW) == 0) {
        result = info;
        return true;
    }
    return errno == ENOENT || ioError(error, "Inspect " + name);
}

bool trusted(const struct stat& info) {
    return info.st_uid == 0 && (info.st_mode & 07022) == 0;
}

bool openTrustedDirectory(const fs::path& directory, const bool optional,
                          int& fd, std::string& error) {
    // No path component may redirect the writer or be writable by another UID.
    for (auto part = directory; !part.empty(); part = part.parent_path()) {
        std::optional<struct stat> info;
        if (!lookup(AT_FDCWD, part.string(), info, error)) return false;
        if (!info) {
            if (optional) return true;
            return reject(error, "Missing ALT group policy directory: " + part.string());
        }
        if (!S_ISDIR(info->st_mode) || !trusted(*info)) {
            return reject(error, "Untrusted ALT group policy directory: " + part.string());
        }
        if (part == part.root_path()) break;
    }
    fd = ::open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    return fd >= 0 || ioError(error, "Open " + directory.string());
}

class Directory {
public:
    int fd = -1;
    ~Directory() { if (fd >= 0) ::close(fd); }
};

struct Config {
    std::optional<AtomicTargetState> full;
    std::optional<AtomicTargetState> projected;
    std::size_t offset = 0;
};

bool loadConfig(const std::string& path, const bool ldap, Config& config,
                std::string& error) {
    Directory dir;
    const fs::path file(path);
    if (!openTrustedDirectory(file.parent_path(), ldap, dir.fd, error)) return false;
    if (dir.fd < 0) return true;
    std::optional<struct stat> info;
    if (!lookup(dir.fd, file.filename().string(), info, error)) return false;
    if (!info) return true;
    if (!S_ISREG(info->st_mode) || !trusted(*info) || info->st_nlink != 1) {
        return reject(error, "Untrusted ALT group policy file: " + path);
    }
    AtomicTargetState state;
    if (!AtomicFileWriter::captureTargetState(path, state, &error)) return false;
    if (state.content.size() > 1024 * 1024 ||
        state.identity.device != info->st_dev || state.identity.inode != info->st_ino ||
        state.owner != info->st_uid || state.group != info->st_gid ||
        state.mode != (info->st_mode & 07777)) {
        return reject(error, "ALT group policy file changed during read or is too large: " + path);
    }
    config.full = state;
    if (ldap) {
        // The packaged shell backend declares one simple top-level assignment.
        // Refuse ambiguous or unsupported forms and preserve all adjacent bytes.
        std::string_view content(state.content);
        constexpr std::string_view key = "default_groups=";
        std::optional<std::string_view> found;
        for (std::size_t start = 0; start < content.size();) {
            const auto end = content.find('\n', start);
            const auto line = content.substr(start, end == content.npos ? end : end - start);
            if (line.substr(0, key.size()) == key) {
                if (found || !validAssignment(line)) {
                    return reject(error, "Ambiguous or unsupported default_groups assignment");
                }
                found = line;
                config.offset = start;
            }
            if (end == content.npos) break;
            start = end + 1;
        }
        if (!found) return reject(error, "Missing default_groups assignment");
        state.content = *found;
    }
    config.projected = std::move(state);
    return true;
}

bool syncConfig(const std::string& path, const Config& current, std::string& error) {
    if (current.full) {
        return AtomicFileWriter::ensureTargetDurableIfCurrentState(path, *current.full, &error);
    }
    return AtomicFileWriter::ensureTargetAbsentDurableIfCurrentState(path, &error);
}

bool proveStockAlterator(const Config& current, std::string& error) {
    if (!current.full) return reject(error, "Alterator RPM backend is missing");
    fic::platform::PlatformExecutableResolver resolver(
        fic::platform::makeBuildPlatformProfile().executables);
    fs::path rpm;
    if (!resolver.resolve(fic::platform::ExecutableId::PackageQuery, rpm, error)) return false;
    ProcessOptions options;
    options.clearEnvironment = true;
    options.environment = {{"LC_ALL", "C"}};
    const auto query = ProcessExecutor::execute(rpm.string(),
        {"-qf", "--qf", "%{NAME}\\n[%{FILENAMES}\\t%{FILEDIGESTS}\\n]", ldapPath}, options);
    std::istringstream output(query.standardOutput);
    std::string line;
    if (!query.success() || !std::getline(output, line) || line != "alterator-ldap-users") {
        return reject(error, "Cannot prove Alterator backend RPM ownership");
    }
    std::string expected;
    while (std::getline(output, line)) {
        const auto tab = line.find('\t');
        if (tab == line.npos) return reject(error, "Ambiguous Alterator RPM ownership");
        if (line.compare(0, tab, ldapPath) != 0) continue;
        if (!expected.empty()) return reject(error, "Duplicate Alterator RPM file digest");
        expected = line.substr(tab + 1);
        if (expected.empty()) return reject(error, "Missing Alterator RPM file digest");
    }
    // ALT p11 currently ships legacy MD5 file digests. Select the same digest
    // formats as PackageTrustSync, hashing the captured bytes used by CAS.
    const EVP_MD* algorithm = nullptr;
    switch (expected.size()) {
    case 32: algorithm = EVP_md5(); break;
    case 40: algorithm = EVP_sha1(); break;
    case 64: algorithm = EVP_sha256(); break;
    case 128: algorithm = EVP_sha512(); break;
    default: return reject(error, "Unsupported Alterator RPM file digest");
    }
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned size = 0;
    const auto& bytes = current.full->content;
    if (EVP_Digest(bytes.data(), bytes.size(), digest, &size, algorithm, nullptr) != 1 ||
        hexEncode({reinterpret_cast<const char*>(digest), size}) != expected) {
        return reject(error, "Alterator backend differs from installed RPM metadata");
    }
    return syncConfig(ldapPath, current, error);
}

bool writeConfig(const PolicyRef& policy, const std::string& path, const Config& current,
                 const std::optional<AtomicTargetState>& original, const std::string& desired,
                 const bool releasing, const bool beforeOwned, MutationJournal& journal, MutationId& id,
                 std::string& error) {
    const bool ldap = policy == ldapPolicy;
    std::string content = desired;
    if (ldap) {
        content = current.full->content;
        content.replace(current.offset, current.projected->content.size(), desired);
    }
    AtomicWriteOptions options;
    options.createIfMissing = !current.full;
    options.exclusiveCreate = !current.full;
    options.rejectSymlink = true;
    options.expectedTargetState = current.full;
    options.fileOwner = 0;
    options.fileGroup = 0;
    options.fileMode = 0644;
    if (!ldap && releasing && original) {
        options.metadataPolicy = FileMetadataPolicy::EnforceProvided;
        options.fileOwner = original->owner;
        options.fileGroup = original->group;
        options.fileMode = original->mode;
    }
    std::optional<AtomicTargetState> published;
    options.beforePublish = [&](const AtomicTargetState& receipt, std::string& diagnostic) {
        published = receipt;
        if (ldap) published->content = desired;
        MutationRecord record;
        record.policy = policy;
        record.resource = path;
        record.undo = {MutationBackend::AltGroups,
            UndoAltGroupConfig{original, current.projected, published, releasing, beforeOwned}};
        return journal.prepareMutation(std::move(record), id, diagnostic);
    };
    if (!AtomicFileWriter::write(path, content, options, &error)) return false;

    Config readback;
    return loadConfig(path, ldap, readback, error) &&
        (sameState(readback.projected, published) ||
         reject(error, "ALT group configuration changed after publication"));
}

bool ownsBefore(const MutationRecord& record, const Config& config) {
    const auto& undo = std::get<UndoAltGroupConfig>(record.undo.payload);
    const bool canRecoverBefore = record.status == MutationStatus::Prepared ||
        (record.status == MutationStatus::RollbackFailed &&
         (record.policy == ldapPolicy || undo.releasing));
    return sameState(config.projected, undo.published) ||
        (canRecoverBefore && undo.beforeOwned &&
         sameState(config.projected, undo.before));
}

bool applyConfig(const PolicyRef& policy, const std::string& path, const std::string& desired,
                 const Config& current, const std::map<std::string, MutationRecord>& records,
                 MutationJournal& journal, std::string& error) {
    auto original = current.projected;
    bool beforeOwned = true;
    const auto active = records.find(path);
    if (active != records.end()) {
        const auto& record = active->second;
        const auto& undo = std::get<UndoAltGroupConfig>(record.undo.payload);
        const bool published = sameState(current.projected, undo.published);
        if (published && current.projected->content == desired) {
            return record.status == MutationStatus::Applied ||
                (syncConfig(path, current, error) &&
                 journal.setStatus(record.id, MutationStatus::Applied, error));
        }
        original = undo.original;
        beforeOwned = ownsBefore(record, current);
    }
    if (current.projected && current.projected->content == desired) {
        // Matching bytes on an unproven inode do not renew rollback authority.
        return true;
    }
    MutationId id = 0;
    return writeConfig(policy, path, current, original, desired, false, beforeOwned, journal, id, error) &&
        journal.setStatus(id, MutationStatus::Applied, error);
}

bool releaseConfig(const MutationRecord& record, const UndoAltGroupConfig& undo,
                   MutationJournal& journal, std::string& error) {
    const auto& path = record.resource;
    Config current;
    if (!loadConfig(path, record.policy == ldapPolicy, current, error)) return false;
    const bool published = sameState(current.projected, undo.published);
    if (undo.releasing && published) return syncConfig(path, current, error);
    if (!ownsBefore(record, current)) {
        if (record.policy == ldapPolicy) return proveStockAlterator(current, error);
        return reject(error, "ALT group rollback ownership conflict: " + path);
    }
    if (!undo.releasing && sameState(current.projected, undo.original)) {
        return syncConfig(path, current, error);
    }
    MutationId id = 0;
    if (undo.original) {
        return writeConfig(record.policy, path, current, undo.original, undo.original->content,
                           true, true, journal, id, error);
    }
    MutationRecord intent;
    intent.policy = record.policy;
    intent.resource = path;
    intent.undo = {MutationBackend::AltGroups,
        UndoAltGroupConfig{std::nullopt, current.projected, std::nullopt, true}};
    if (!journal.prepareMutation(std::move(intent), id, error)) return false;
    AtomicRemoveResult result;
    return AtomicFileWriter::removeIfCurrentState(path, *current.full, &error, &result) &&
        ((result.removed && result.durabilityConfirmed) ||
         reject(error, "ALT group configuration changed before durable removal"));
}

std::string backupName(const std::string& name) {
    return name.substr(0, name.size() - std::string_view(".role").size()) + ".fic";
}

bool exactFile(const std::optional<struct stat>& info, const UndoAltRoleFile& proof) {
    return info && S_ISREG(info->st_mode) && trusted(*info) &&
           info->st_dev == proof.device && info->st_ino == proof.fileInode;
}

bool exactLink(const int fd, const std::string& name, const std::string& target,
               const std::optional<struct stat>& info, const UndoAltRoleFile& proof) {
    if (!info || !S_ISLNK(info->st_mode) || info->st_uid != 0 ||
        info->st_dev != proof.device || info->st_ino != proof.linkInode) return false;
    std::string observed(target.size() + 1, '\0');
    const auto bytes = ::readlinkat(fd, name.c_str(), observed.data(), observed.size());
    return bytes >= 0 && static_cast<std::size_t>(bytes) == target.size() &&
           std::string_view(observed.data(), target.size()) == target;
}

enum class DropInState { Original, Staged, Disabled };

bool inspectDropIn(const int fd, const std::string& name, const UndoAltRoleFile& proof,
                   DropInState& state, std::string& error) {
    const auto backup = backupName(name);
    std::optional<struct stat> original, alternate;
    if (!lookup(fd, name, original, error) || !lookup(fd, backup, alternate, error)) return false;
    if (exactFile(original, proof)) {
        if (!alternate) {
            state = DropInState::Original;
            return true;
        }
        if (exactLink(fd, backup, backup, alternate, proof)) {
            state = DropInState::Staged;
            return true;
        }
    }
    if (exactFile(alternate, proof) && exactLink(fd, name, backup, original, proof)) {
        state = DropInState::Disabled;
        return true;
    }
    return reject(error, "ALT role file ownership conflict: " + name);
}

bool syncDirectory(const int fd, std::string& error) {
    return ::fsync(fd) == 0 || ioError(error, "Synchronize /etc/role.d");
}

bool isCurrentRoleDirectory(const int fd, std::string& error) {
    struct stat opened{};
    if (::fstat(fd, &opened) != 0) return ioError(error, "Inspect open ALT role directory");
    std::optional<struct stat> current;
    if (!lookup(AT_FDCWD, roleDirectory, current, error)) return false;
    return (current && trusted(*current) && S_ISDIR(current->st_mode) &&
            opened.st_dev == current->st_dev && opened.st_ino == current->st_ino) ||
        reject(error, "ALT role directory changed during transaction");
}

bool exchange(const int fd, const std::string& name, const UndoAltRoleFile& proof,
              const DropInState expected, const DropInState target, std::string& error) {
    DropInState observed;
    if (!isCurrentRoleDirectory(fd, error) || !inspectDropIn(fd, name, proof, observed, error)) return false;
    if (observed != expected) return reject(error, "ALT role file changed before exchange: " + name);
    const auto backup = backupName(name);
    if (::syscall(SYS_renameat2, fd, name.c_str(), fd, backup.c_str(), RENAME_EXCHANGE) != 0) {
        return ioError(error, "Exchange ALT role file and link: " + name);
    }
    return syncDirectory(fd, error) && isCurrentRoleDirectory(fd, error) &&
        inspectDropIn(fd, name, proof, observed, error) &&
        (observed == target || reject(error, "ALT role file changed after exchange: " + name));
}

bool stageDropIn(const int fd, const std::string& name, const struct stat& initial,
                 MutationJournal& journal, std::string& error) {
    const auto backup = backupName(name);
    if (!isCurrentRoleDirectory(fd, error)) return false;
    // Stage the relative link in the backup slot. After persisting both inode
    // proofs, exchange atomically publishes the renamed regular file and link.
    if (::symlinkat(backup.c_str(), fd, backup.c_str()) != 0) {
        return ioError(error, "Stage ALT role symlink: " + backup);
    }
    std::optional<struct stat> link;
    if (!lookup(fd, backup, link, error)) return false;
    UndoAltRoleFile proof{initial.st_dev, initial.st_ino, link ? link->st_ino : 0};
    if (!exactLink(fd, backup, backup, link, proof)) {
        return reject(error, "ALT role staging link changed: " + backup);
    }
    MutationRecord record;
    record.policy = rolePolicy;
    record.resource = std::string(dropInPrefix) + hexEncode(name);
    record.undo = {MutationBackend::AltGroups, proof};
    MutationId id = 0;
    if (!syncDirectory(fd, error) || !journal.prepareMutation(std::move(record), id, error)) {
        if (journal.usable()) {
            std::string cleanupError;
            DropInState state;
            if (inspectDropIn(fd, name, proof, state, cleanupError) && state == DropInState::Staged &&
                ::unlinkat(fd, backup.c_str(), 0) == 0) {
                syncDirectory(fd, cleanupError);
            }
        }
        return false;
    }
    return exchange(fd, name, proof, DropInState::Staged, DropInState::Disabled, error) &&
           journal.setStatus(id, MutationStatus::Applied, error);
}

bool applyDropIns(const std::map<std::string, MutationRecord>& records, MutationJournal& journal,
                  std::string& error) {
    Directory dir;
    if (!openTrustedDirectory(roleDirectory, true, dir.fd, error)) return false;
    const bool hadDropIns = std::any_of(records.begin(), records.end(),
        [](const auto& item) { return item.first.compare(0, dropInPrefix.size(), dropInPrefix) == 0; });
    if (dir.fd < 0) return !hadDropIns || reject(error, "Owned ALT role directory is missing");

    std::map<std::string, struct stat> newcomers;
    std::vector<std::pair<std::string, MutationRecord>> pending;
    for (const auto& [resource, record] : records) {
        if (resource.compare(0, dropInPrefix.size(), dropInPrefix) != 0) continue;
        const auto name = roleName(resource);
        if (!name) return reject(error, "Invalid ALT role file resource");
        DropInState state;
        const auto& proof = std::get<UndoAltRoleFile>(record.undo.payload);
        if (!inspectDropIn(dir.fd, *name, proof, state, error)) return false;
        if (proof.releasing) return reject(error, "ALT role file has unresolved rollback: " + *name);
        if (record.status == MutationStatus::Applied && state == DropInState::Disabled) continue;
        if (record.status != MutationStatus::Prepared || state == DropInState::Original) {
            return reject(error, "ALT role file has unresolved rollback: " + *name);
        }
        pending.emplace_back(*name, record);
    }

    std::error_code scanError;
    // Traverse the opened directory, so a replacement pathname cannot redirect the scan.
    const fs::path opened = "/proc/self/fd/" + std::to_string(dir.fd);
    for (fs::directory_iterator it(opened, scanError), end;
         !scanError && it != end; it.increment(scanError)) {
        const auto name = it->path().filename().string();
        if (!isRoleName(name) || records.count(std::string(dropInPrefix) + hexEncode(name))) continue;
        std::optional<struct stat> info, alternate;
        if (!lookup(dir.fd, name, info, error)) return false;
        if (!info || !S_ISREG(info->st_mode)) continue;
        if (!trusted(*info)) return reject(error, "Untrusted ALT role file: " + name);
        if (!lookup(dir.fd, backupName(name), alternate, error)) return false;
        if (alternate) return reject(error, "ALT role backup name is occupied: " + backupName(name));
        newcomers.emplace(name, *info);
    }
    if (scanError) return reject(error, "Scan ALT role directory: " + scanError.message());

    for (const auto& [name, record] : pending) {
        const auto& proof = std::get<UndoAltRoleFile>(record.undo.payload);
        DropInState state;
        if (!inspectDropIn(dir.fd, name, proof, state, error)) return false;
        if (state == DropInState::Staged &&
            !exchange(dir.fd, name, proof, DropInState::Staged, DropInState::Disabled, error)) return false;
        if (state == DropInState::Original ||
            !syncDirectory(dir.fd, error) ||
            !journal.setStatus(record.id, MutationStatus::Applied, error)) return false;
    }
    for (const auto& [name, info] : newcomers) {
        if (!stageDropIn(dir.fd, name, info, journal, error)) return false;
    }
    return isCurrentRoleDirectory(dir.fd, error);
}

bool releaseDropIn(const MutationRecord& record, const UndoAltRoleFile& proof,
                   MutationJournal& journal, std::string& error) {
    const auto name = roleName(record.resource);
    Directory dir;
    if (!name) return reject(error, "Invalid ALT role file rollback resource");
    if (!openTrustedDirectory(roleDirectory, false, dir.fd, error)) return false;
    DropInState state;
    if (!inspectDropIn(dir.fd, *name, proof, state, error)) return false;
    if (!proof.releasing && state != DropInState::Original) {
        MutationRecord intent = record;
        intent.status = MutationStatus::Prepared;
        std::get<UndoAltRoleFile>(intent.undo.payload).releasing = true;
        MutationId id = 0;
        if (!journal.prepareMutation(std::move(intent), id, error)) return false;
    }
    if (state == DropInState::Disabled) {
        if (!exchange(dir.fd, *name, proof, DropInState::Disabled, DropInState::Staged, error)) return false;
        state = DropInState::Staged;
    }
    if (state == DropInState::Staged) {
        if (!isCurrentRoleDirectory(dir.fd, error) ||
            !inspectDropIn(dir.fd, *name, proof, state, error)) return false;
        if (state != DropInState::Staged) return reject(error, "ALT role staging link changed during release");
        if (::unlinkat(dir.fd, backupName(*name).c_str(), 0) != 0) {
            return ioError(error, "Remove owned ALT role link: " + *name);
        }
    }
    return syncDirectory(dir.fd, error) && isCurrentRoleDirectory(dir.fd, error) &&
        inspectDropIn(dir.fd, *name, proof, state, error) &&
        (state == DropInState::Original || reject(error, "ALT role file rollback was not published"));
}

} // namespace

bool apply(const PolicyRef& policy, const std::string& desired,
           MutationJournal& journal, std::string& error) {
    if (!journal.usable() || (policy != ldapPolicy && policy != rolePolicy)) {
        return reject(error, "ALT group policy requires a healthy mutation journal");
    }
    const bool ldap = policy == ldapPolicy;
    const std::string path = ldap ? ldapPath : rolePath;
    Config current;
    if (!loadConfig(path, ldap, current, error)) return false;
    std::map<std::string, MutationRecord> records;
    for (auto record : journal.activeRecords(policy)) {
        const auto resource = record.resource;
        if (!validRecord(record, error) || record.undo.backend != MutationBackend::AltGroups) {
            return reject(error, "Invalid ALT group policy journal route");
        }
        records.emplace(resource, std::move(record));
    }
    if (ldap && !current.full) {
        return records.empty() || reject(error, "Owned Alterator LDAP backend is missing");
    }
    if (ldap && !validAssignment(desired)) return reject(error, "Unsupported default_groups assignment");
    if (desired.size() > 1024 * 1024) return reject(error, "ALT group configuration is too large");
    if (const auto active = records.find(path); active != records.end()) {
        const auto& record = active->second;
        if (ldap && !ownsBefore(record, current)) {
            // Close the old cycle durably before preparing a fresh CAS.
            // A crash here leaves the proven stock file untouched.
            if (!proveStockAlterator(current, error) ||
                !journal.setStatus(record.id, MutationStatus::RolledBack, error)) return false;
            records.erase(active);
        } else if (std::get<UndoAltGroupConfig>(record.undo.payload).releasing ||
                   record.status == MutationStatus::RollbackFailed) {
            return reject(error, "ALT group policy has unresolved rollback");
        }
    }
    return (ldap || applyDropIns(records, journal, error)) &&
        applyConfig(policy, path, desired, current, records, journal, error);
}

bool release(const MutationRecord& record, MutationJournal& journal, std::string& error) {
    const std::lock_guard lock(IdentityAccessPolicy::configurationMutex());
    if (!journal.usable() || record.undo.backend != MutationBackend::AltGroups ||
        !validRecord(record, error)) return reject(error, "Invalid ALT group policy release authority");
    if (const auto* config = std::get_if<UndoAltGroupConfig>(&record.undo.payload)) {
        return releaseConfig(record, *config, journal, error);
    }
    return releaseDropIn(record, std::get<UndoAltRoleFile>(record.undo.payload), journal, error);
}

} // namespace fic::identity::alt_groups
