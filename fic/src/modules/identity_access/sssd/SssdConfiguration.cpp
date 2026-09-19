#include "modules/identity_access/sssd/SssdConfiguration.h"

#include <fic/core/fs/AtomicFileWriter.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <functional>
#include <memory>
#include <set>
#include <sstream>
#include <utility>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace fic::identity::sssd {
namespace {

struct Assignment {
    std::string section;
    std::string option;
    std::string value;
    std::size_t line = 0;
};

struct ParsedConfiguration {
    std::vector<std::string> lines;
    bool trailingNewline = false;
    std::vector<std::pair<std::string, std::size_t>> sections;
    std::vector<Assignment> assignments;
};

std::string trimCopy(std::string value) {
    const auto first = std::find_if_not(
        value.begin(), value.end(), [](unsigned char character) {
            return std::isspace(character) != 0;
        });
    if (first == value.end()) {
        return {};
    }
    const auto last = std::find_if_not(
        value.rbegin(), value.rend(), [](unsigned char character) {
            return std::isspace(character) != 0;
        }).base();
    return std::string(first, last);
}

bool validSection(const std::string& section) {
    return !section.empty() &&
        section.find_first_of("[]\r\n") == std::string::npos;
}

bool validOption(const std::string& option) {
    return !option.empty() &&
        std::all_of(option.begin(), option.end(), [](unsigned char character) {
            return std::isalnum(character) != 0 || character == '_' ||
                character == '-';
        });
}

bool validValue(const std::string& value) {
    return value.find_first_of("\r\n") == std::string::npos;
}

ParsedConfiguration splitDocument(const std::string& content) {
    ParsedConfiguration result;
    result.trailingNewline = !content.empty() && content.back() == '\n';
    std::istringstream input(content);
    std::string line;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        result.lines.push_back(std::move(line));
    }
    return result;
}

std::string joinDocument(const ParsedConfiguration& document) {
    std::string result;
    for (std::size_t index = 0; index < document.lines.size(); ++index) {
        if (index != 0) {
            result.push_back('\n');
        }
        result += document.lines[index];
    }
    if (document.trailingNewline && !document.lines.empty()) {
        result.push_back('\n');
    }
    return result;
}

bool parseConfiguration(const std::string& content,
                        ParsedConfiguration& result,
                        std::string& error) {
    result = splitDocument(content);
    std::string currentSection;
    for (std::size_t index = 0; index < result.lines.size(); ++index) {
        const std::string trimmed = trimCopy(result.lines[index]);
        if (trimmed.empty() || trimmed.front() == '#' ||
            trimmed.front() == ';') {
            continue;
        }
        if (trimmed.front() == '[') {
            if (trimmed.size() < 3 || trimmed.back() != ']') {
                error = "invalid SSSD section header at line " +
                    std::to_string(index + 1);
                return false;
            }
            currentSection = trimCopy(
                trimmed.substr(1, trimmed.size() - 2));
            if (!validSection(currentSection)) {
                error = "invalid SSSD section name at line " +
                    std::to_string(index + 1);
                return false;
            }
            result.sections.emplace_back(currentSection, index);
            continue;
        }
        if (currentSection.empty()) {
            error = "SSSD option appears before a section at line " +
                std::to_string(index + 1);
            return false;
        }
        const std::size_t equals = trimmed.find('=');
        if (equals == std::string::npos) {
            error = "invalid SSSD option at line " +
                std::to_string(index + 1);
            return false;
        }
        const std::string option = trimCopy(trimmed.substr(0, equals));
        const std::string value = trimCopy(trimmed.substr(equals + 1));
        if (!validOption(option) || !validValue(value)) {
            error = "invalid SSSD assignment at line " +
                std::to_string(index + 1);
            return false;
        }
        result.assignments.push_back(
            {currentSection, option, value, index});
    }
    return true;
}

SecureConfigurationFileOptions optionsForPath(
    const SecureConfigurationFileOptions& base,
    const std::filesystem::path& path) {
    auto result = base;
    result.path = path;
    return result;
}

bool listSnippetFiles(const SssdConfigurationOptions& options,
                      std::vector<std::filesystem::path>& files,
                      std::string& error) {
    files.clear();
    for (const auto& directory : options.snippetDirectories) {
        struct stat status {};
        if (::lstat(directory.c_str(), &status) != 0) {
            if (errno == ENOENT) {
                continue;
            }
            error = "could not inspect SSSD snippet directory: " +
                directory.string();
            return false;
        }
        if (!verifySecureConfigurationDirectory(
                directory, options.mainFile, error)) {
            return false;
        }
        std::vector<std::filesystem::path> directoryFiles;
        std::error_code iteratorError;
        for (std::filesystem::directory_iterator iterator(directory, iteratorError);
             !iteratorError && iterator != std::filesystem::directory_iterator();
             iterator.increment(iteratorError)) {
            const std::string name = iterator->path().filename().string();
            if (!name.empty() && name.front() != '.' &&
                iterator->path().extension() == ".conf") {
                directoryFiles.push_back(iterator->path());
            }
        }
        if (iteratorError) {
            error = "could not enumerate SSSD snippet directory " +
                directory.string() + ": " + iteratorError.message();
            return false;
        }
        std::sort(directoryFiles.begin(), directoryFiles.end());
        files.insert(files.end(), directoryFiles.begin(), directoryFiles.end());
    }
    return true;
}

bool readAndParse(const SecureConfigurationFileOptions& options,
                  ParsedConfiguration& parsed,
                  std::string& error) {
    ConfigurationFileSnapshot snapshot;
    if (!readSecureConfigurationFile(options, snapshot, error)) {
        return false;
    }
    if (!parseConfiguration(snapshot.content, parsed, error)) {
        error += " in " + options.path.string();
        return false;
    }
    return true;
}

bool validateSettings(const std::vector<SssdSetting>& settings,
                      std::string& error) {
    if (settings.empty()) {
        error = "SSSD edit contains no settings";
        return false;
    }
    std::set<std::pair<std::string, std::string>> unique;
    for (const auto& setting : settings) {
        if (!validSection(setting.section) || !validOption(setting.option) ||
            !validValue(setting.value)) {
            error = "invalid SSSD setting";
            return false;
        }
        if (!unique.emplace(setting.section, setting.option).second) {
            error = "duplicate SSSD edit for [" + setting.section + "]/" +
                setting.option;
            return false;
        }
    }
    return true;
}

bool snippetsOverride(const SssdConfigurationOptions& options,
                      const std::vector<SssdSetting>& settings,
                      std::string& error) {
    std::vector<std::filesystem::path> snippets;
    if (!listSnippetFiles(options, snippets, error)) {
        return false;
    }
    for (const auto& path : snippets) {
        ParsedConfiguration parsed;
        if (!readAndParse(optionsForPath(options.mainFile, path), parsed, error)) {
            return false;
        }
        for (const auto& assignment : parsed.assignments) {
            const auto match = std::find_if(
                settings.begin(), settings.end(), [&](const SssdSetting& setting) {
                    return setting.section == assignment.section &&
                        setting.option == assignment.option;
                });
            if (match != settings.end()) {
                error = "SSSD setting [" + assignment.section + "]/" +
                    assignment.option + " is owned by snippet " + path.string();
                return false;
            }
        }
    }
    return true;
}

bool applyOneSetting(std::string& content,
                     const SssdSetting& setting,
                     std::string& error) {
    ParsedConfiguration parsed;
    if (!parseConfiguration(content, parsed, error)) {
        return false;
    }

    bool found = false;
    for (const auto& assignment : parsed.assignments) {
        if (assignment.section != setting.section ||
            assignment.option != setting.option) {
            continue;
        }
        const std::string& current = parsed.lines[assignment.line];
        const std::size_t indentationEnd = current.find_first_not_of(" \t");
        const std::string indentation = indentationEnd == std::string::npos
            ? std::string()
            : current.substr(0, indentationEnd);
        parsed.lines[assignment.line] = indentation + setting.option +
            " = " + setting.value;
        found = true;
    }

    if (!found) {
        auto section = std::find_if(
            parsed.sections.rbegin(),
            parsed.sections.rend(),
            [&](const auto& entry) { return entry.first == setting.section; });
        if (section == parsed.sections.rend()) {
            if (!parsed.lines.empty() && !parsed.lines.back().empty()) {
                parsed.lines.push_back({});
            }
            parsed.lines.push_back("[" + setting.section + "]");
            parsed.lines.push_back(setting.option + " = " + setting.value);
            parsed.trailingNewline = true;
        } else {
            std::size_t insertAt = section->second + 1;
            for (const auto& assignment : parsed.assignments) {
                if (assignment.section == setting.section &&
                    assignment.line >= section->second) {
                    insertAt = std::max(insertAt, assignment.line + 1);
                }
            }
            parsed.lines.insert(
                parsed.lines.begin() + static_cast<std::ptrdiff_t>(insertAt),
                setting.option + " = " + setting.value);
        }
    }
    content = joinDocument(parsed);
    return true;
}

bool verifyExpectedValues(const SssdConfigurationOptions& options,
                          const std::vector<SssdSetting>& settings,
                          const std::string& mainContent,
                          std::string& error) {
    ParsedConfiguration parsed;
    if (!parseConfiguration(mainContent, parsed, error)) {
        return false;
    }
    for (const auto& setting : settings) {
        bool found = false;
        for (const auto& assignment : parsed.assignments) {
            if (assignment.section == setting.section &&
                assignment.option == setting.option) {
                found = true;
                if (assignment.value != setting.value) {
                    error = "unexpected SSSD value for [" + setting.section +
                        "]/" + setting.option;
                    return false;
                }
            }
        }
        if (!found) {
            error = "missing SSSD value for [" + setting.section + "]/" +
                setting.option;
            return false;
        }
    }
    return snippetsOverride(options, settings, error);
}

} // namespace

namespace {

// A prepared FIC-owned managed-snippet change. Unlike the plain
// PreparedFileChange this class supports the full managed-artifact lifecycle:
// exclusive creation of a missing drop-in, CAS rewrite of an existing one and
// CAS-verified removal when the drop-in becomes semantically empty. Every
// commit re-proves the pre-change state immediately before writing/removing
// and refuses to overwrite or delete any externally replaced content.
class ManagedSnippetChange final : public PreparedConfigurationChange {
public:
    enum class Mode { CreateFile, WriteFile, RemoveFile };

    ManagedSnippetChange(std::string identifier,
                         SecureConfigurationFileOptions options,
                         Mode mode,
                         ConfigurationFileSnapshot original,
                         std::string candidate,
                         ConfigurationContentVerifier verifier)
        : identifier_(std::move(identifier)),
          options_(std::move(options)),
          mode_(mode),
          original_(std::move(original)),
          candidate_(std::move(candidate)),
          verifier_(std::move(verifier)) {
    }

    std::string id() const override {
        return identifier_;
    }

    bool needsCommit() const noexcept override {
        if (mode_ != Mode::WriteFile) {
            return true;
        }
        return original_.content != candidate_;
    }

    bool needsActivation() const noexcept override {
        return false;
    }

    ConfigurationStepResult commitPersistent() override;
    ConfigurationStepResult verifyPersistent() override;
    ConfigurationStepResult activate() override;
    ConfigurationStepResult verifyEffective() override;
    ConfigurationStepResult rollbackPersistent() override;
    ConfigurationStepResult restoreRuntimeAfterRollback() override;
    ConfigurationStepResult verifyRollback() override;

private:
    std::string identifier_;
    SecureConfigurationFileOptions options_;
    Mode mode_;
    ConfigurationFileSnapshot original_;
    std::string candidate_;
    ConfigurationContentVerifier verifier_;
};

} // namespace

SssdConfigurationOptions SssdConfigurationOptions::production() {
    SssdConfigurationOptions options;
    options.mainFile.path = "/etc/sssd/sssd.conf";
    options.mainFile.expectedOwner = 0;
    options.mainFile.expectedGroup = 0;
    options.mainFile.exactMode = 0600;
    options.mainFile.forbiddenMode = 0022;
    options.snippetDirectories = {"/etc/sssd/conf.d"};
    options.managedSnippetFile = "/etc/sssd/conf.d/zzzz-fic.conf";
    return options;
}

namespace {

bool snapshotsEqualSnapshots(const ConfigurationFileSnapshot& left,
                             const ConfigurationFileSnapshot& right) {
    return left.content == right.content && left.owner == right.owner &&
        left.group == right.group && left.mode == right.mode;
}

// Snapshot shape of the installed candidate: content = candidate, metadata
// = the values AtomicFileWriter enforces for the FIC-owned drop-in.
ConfigurationFileSnapshot installedCandidateSnapshot(
    const SecureConfigurationFileOptions& options,
    const ConfigurationFileSnapshot& fallback,
    const std::string& candidate) {
    ConfigurationFileSnapshot snapshot;
    snapshot.content = candidate;
    snapshot.owner = options.expectedOwner.value_or(fallback.owner);
    snapshot.group = options.expectedGroup.value_or(fallback.group);
    snapshot.mode = options.exactMode.value_or(fallback.mode);
    return snapshot;
}

AtomicWriteOptions managedSnippetWriteOptions(
    const SecureConfigurationFileOptions& options,
    const ConfigurationFileSnapshot& metadata) {
    AtomicWriteOptions result;
    result.createIfMissing = false;
    result.rejectSymlink = true;
    result.metadataPolicy = FileMetadataPolicy::EnforceProvided;
    result.fileOwner = options.expectedOwner.value_or(metadata.owner);
    result.fileGroup = options.expectedGroup.value_or(metadata.group);
    result.fileMode = options.exactMode.value_or(metadata.mode);
    return result;
}

// Test-only deterministic seam between the removal proof and the atomic
// rename-away removal step: it lets a test atomically replace the drop-in
// with a foreign file exactly in the race window that the proof-bound
// removal must detect. Production code must never set the hook.
std::function<void()>& removalRaceHook() {
    static std::function<void()> hook;
    return hook;
}

// Captures the exact current target state through a single O_NOFOLLOW
// descriptor: identity (dev, ino), metadata and exact content. Refuses
// symlinks and non-regular files. The captured identity is the removal
// proof: only this exact inode may ever be removed.
bool captureRemovalProof(const SecureConfigurationFileOptions& options,
                         ConfigurationFileSnapshot& snapshot,
                         dev_t& device,
                         ino_t& inode,
                         std::string& error) {
    int descriptor = ::open(
        options.path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        if (errno == ENOENT) {
            error = "managed SSSD drop-in disappeared before removal: " +
                options.path.string();
        } else {
            error = "could not open managed SSSD drop-in for removal (" +
                options.path.string() + "): " + std::strerror(errno);
        }
        return false;
    }
    struct stat status {};
    if (::fstat(descriptor, &status) != 0) {
        error = "could not inspect managed SSSD drop-in " +
            options.path.string() + ": " + std::strerror(errno);
        ::close(descriptor);
        return false;
    }
    if (S_ISLNK(status.st_mode) || !S_ISREG(status.st_mode)) {
        error = "refusing to remove a non-regular managed SSSD drop-in: " +
            options.path.string();
        ::close(descriptor);
        return false;
    }
    std::string content;
    content.reserve(static_cast<std::size_t>(status.st_size));
    std::vector<char> buffer(16384);
    while (true) {
        const ssize_t count =
            ::read(descriptor, buffer.data(), buffer.size());
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            error = "could not read managed SSSD drop-in " +
                options.path.string() + ": " + std::strerror(errno);
            ::close(descriptor);
            return false;
        }
        if (count == 0) {
            break;
        }
        if (content.size() + static_cast<std::size_t>(count) >
            options.maximumBytes) {
            error = "managed SSSD drop-in exceeds size limit: " +
                options.path.string();
            ::close(descriptor);
            return false;
        }
        content.append(buffer.data(), static_cast<std::size_t>(count));
    }
    ::close(descriptor);
    snapshot.content = std::move(content);
    snapshot.owner = status.st_uid;
    snapshot.group = status.st_gid;
    snapshot.mode = status.st_mode & 07777;
    device = status.st_dev;
    inode = status.st_ino;
    return true;
}

// State classification of the compensation target. A read failure must
// NEVER be interpreted as "the file is already gone": only a proven ENOENT
// classifies as Missing, everything else fails closed without writing.
enum class CompensationReadState {
    Missing,            // proven ENOENT on the target path
    Unreadable,         // unsafe object (symlink/non-regular) or a regular
                        // file that cannot be read securely
    ReadableForCompare, // readable: compare with the expected snapshot
    OtherError          // any other failure
};

CompensationReadState classifyForCompensation(
    const SecureConfigurationFileOptions& options,
    ConfigurationFileSnapshot& snapshot,
    std::string& error) {
    std::string dirError;
    if (!verifySecureConfigurationDirectory(
            options.path.parent_path(), options, dirError)) {
        error = dirError;
        return CompensationReadState::OtherError;
    }
    struct stat status {};
    if (::lstat(options.path.c_str(), &status) != 0) {
        if (errno == ENOENT) {
            error.clear();
            return CompensationReadState::Missing;
        }
        error = "could not inspect managed SSSD drop-in " +
            options.path.string() + ": " + std::strerror(errno);
        return CompensationReadState::OtherError;
    }
    if (S_ISLNK(status.st_mode) || !S_ISREG(status.st_mode)) {
        error = "refusing to touch an unsafe managed SSSD drop-in object: " +
            options.path.string();
        return CompensationReadState::Unreadable;
    }
    std::string readError;
    if (!readSecureConfigurationFile(options, snapshot, readError)) {
        // A proven ENOENT inside the secure read (the file vanished between
        // lstat and open) is still a proven Missing; anything else is
        // unreadable and must never be overwritten.
        if (errno == ENOENT) {
            return CompensationReadState::Missing;
        }
        error = readError;
        return CompensationReadState::Unreadable;
    }
    return CompensationReadState::ReadableForCompare;
}

// Exclusive-create compensation write of the original content: creates the
// file ONLY when the target path is genuinely free (O_EXCL) and enforces
// the exact FIC metadata. A foreign object appearing between the Missing
// proof and the create fails closed instead of being replaced.
bool exclusiveCreateOriginal(
    const SecureConfigurationFileOptions& options,
    const std::string& content,
    std::string& error) {
    std::string dirError;
    if (!verifySecureConfigurationDirectory(
            options.path.parent_path(), options, dirError)) {
        error = dirError;
        return false;
    }
    int descriptor = ::open(
        options.path.c_str(),
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
        options.exactMode.value_or(0600));
    if (descriptor < 0) {
        if (errno == EEXIST) {
            error = "managed SSSD drop-in path was re-created externally "
                    "before the exclusive compensation create: " +
                options.path.string();
            return false;
        }
        error = "could not exclusively create managed SSSD drop-in " +
            options.path.string() + ": " + std::strerror(errno);
        return false;
    }
    if (options.expectedOwner.has_value() ||
        options.expectedGroup.has_value()) {
        const uid_t owner = options.expectedOwner.value_or(static_cast<uid_t>(-1));
        const gid_t group = options.expectedGroup.value_or(static_cast<gid_t>(-1));
        if (::fchown(descriptor, owner, group) != 0) {
            error = "could not set metadata of managed SSSD drop-in " +
                options.path.string() + ": " + std::strerror(errno);
            ::close(descriptor);
            return false;
        }
    }
    if (options.exactMode.has_value() &&
        ::fchmod(descriptor, *options.exactMode) != 0) {
        error = "could not set mode of managed SSSD drop-in " +
            options.path.string() + ": " + std::strerror(errno);
        ::close(descriptor);
        return false;
    }
    std::size_t written = 0;
    while (written < content.size()) {
        const ssize_t count = ::write(
            descriptor, content.data() + written, content.size() - written);
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            error = "could not write managed SSSD drop-in " +
                options.path.string() + ": " + std::strerror(errno);
            ::close(descriptor);
            return false;
        }
        written += static_cast<std::size_t>(count);
    }
    if (::fsync(descriptor) != 0) {
        error = "could not fsync managed SSSD drop-in " +
            options.path.string() + ": " + std::strerror(errno);
        ::close(descriptor);
        return false;
    }
    if (::close(descriptor) != 0) {
        error = "could not close managed SSSD drop-in " +
            options.path.string() + ": " + std::strerror(errno);
        return false;
    }
    return AtomicFileWriter::fsyncParentDirectoryForPath(
        options.path.string(), &error);
}

// Proof-bound removal of the FIC-owned drop-in: only the EXACT target
// state that was proven owned may ever be removed. The proof is captured
// through a single descriptor (identity, metadata, exact content). The
// removal is NOT unlink-by-path: the file is atomically renamed away to a
// private name and the moved-away object is re-proved against the captured
// identity. If a foreign actor replaced the target between the proof and
// the rename, the foreign object is restored byte-exact at the original
// path and the removal fails closed: FIC never deletes a pathname whose
// proven state was already replaced.
ConfigurationStepResult removeManagedSnippetFile(
    const SecureConfigurationFileOptions& options,
    const ConfigurationFileSnapshot& expected) {
    ConfigurationFileSnapshot proven;
    dev_t device = 0;
    ino_t inode = 0;
    std::string error;
    if (!captureRemovalProof(options, proven, device, inode, error)) {
        return ConfigurationStepResult::failure(std::move(error));
    }
    if (!snapshotsEqualSnapshots(proven, expected)) {
        return ConfigurationStepResult::failure(
            "refusing to remove an externally modified managed SSSD "
            "drop-in: " +
            options.path.string());
    }
    if (auto hook = removalRaceHook()) {
        // Deterministic test seam: model a foreign atomic replacement
        // exactly in the window between the proof and the removal step.
        hook();
    }
    // Atomically move the CURRENT directory entry away. Whatever occupies
    // the path at rename time is moved; the identity re-proof below
    // decides whether it was the proven inode or a foreign replacement.
    static std::atomic<unsigned long long> removalSequence;
    const std::string privateTarget = options.path.string() +
        ".fic-removing-" + std::to_string(::getpid()) + "-" +
        std::to_string(removalSequence.fetch_add(1));
    if (::rename(options.path.c_str(), privateTarget.c_str()) != 0) {
        return ConfigurationStepResult::failure(
            "could not remove managed SSSD drop-in: " +
            options.path.string());
    }
    struct stat moved {};
    if (::lstat(privateTarget.c_str(), &moved) != 0 ||
        moved.st_dev != device || moved.st_ino != inode) {
        // The moved-away object is NOT the proven inode: a foreign
        // replacement occupied the path at rename time. Restore it
        // byte-exact at the original path and fail closed: the foreign
        // replacement must survive.
        std::string restoreNote;
        if (::rename(privateTarget.c_str(), options.path.c_str()) != 0) {
            restoreNote = " (foreign object left staged at " + privateTarget +
                ": " + std::strerror(errno) + ")";
        }
        return ConfigurationStepResult::failure(
            "refusing to remove a foreign replacement of the managed SSSD "
            "drop-in" + restoreNote + ": " + options.path.string());
    }
    // The proven inode was moved away: the exact proven target state is
    // removed. Delete the now-private FIC-owned object.
    if (::unlink(privateTarget.c_str()) != 0) {
        // The snippet path itself is already free; a leftover private
        // object is a cleanup failure, not a removal failure.
        return ConfigurationStepResult::failure(
            "could not delete the staged managed SSSD drop-in " +
            privateTarget + ": " + std::strerror(errno));
    }
    if (!AtomicFileWriter::fsyncParentDirectoryForPath(
            options.path.string(), &error)) {
        return ConfigurationStepResult::failure(std::move(error));
    }
    return ConfigurationStepResult::success(true);
}

} // namespace

// Commits the FIC-owned drop-in change: exclusive atomic creation for a
// missing artifact, CAS rewrite for an existing one and CAS-verified unlink
// when the artifact became semantically empty.
ConfigurationStepResult ManagedSnippetChange::commitPersistent() {
    if (mode_ == Mode::CreateFile) {
        struct stat status {};
        if (::lstat(options_.path.c_str(), &status) == 0) {
            return ConfigurationStepResult::failure(
                "managed SSSD drop-in appeared after preflight: " +
                options_.path.string());
        }
        if (errno != ENOENT) {
            return ConfigurationStepResult::failure(
                "could not inspect managed SSSD drop-in path: " +
                options_.path.string());
        }
        AtomicWriteOptions createOptions;
        createOptions.createIfMissing = true;
        createOptions.exclusiveCreate = true;
        createOptions.rejectSymlink = true;
        createOptions.metadataPolicy = FileMetadataPolicy::EnforceProvided;
        createOptions.fileMode = options_.exactMode;
        createOptions.fileOwner = options_.expectedOwner;
        createOptions.fileGroup = options_.expectedGroup;
        std::string error;
        if (!AtomicFileWriter::write(
                options_.path.string(), candidate_, createOptions, &error)) {
            return ConfigurationStepResult::failure(std::move(error));
        }
        return ConfigurationStepResult::success(true);
    }
    if (mode_ == Mode::RemoveFile) {
        return removeManagedSnippetFile(options_, original_);
    }
    ConfigurationFileSnapshot current;
    std::string error;
    if (!readSecureConfigurationFile(options_, current, error)) {
        return ConfigurationStepResult::failure(std::move(error));
    }
    if (!snapshotsEqualSnapshots(current, original_)) {
        return ConfigurationStepResult::failure(
            "managed SSSD drop-in changed after preflight: " +
            options_.path.string());
    }
    if (candidate_ == original_.content) {
        return ConfigurationStepResult::success(false);
    }
    if (!AtomicFileWriter::write(
            options_.path.string(),
            candidate_,
            managedSnippetWriteOptions(options_, original_),
            &error)) {
        return ConfigurationStepResult::failure(std::move(error));
    }
    return ConfigurationStepResult::success(true);
}

ConfigurationStepResult ManagedSnippetChange::verifyPersistent() {
    if (mode_ == Mode::RemoveFile) {
        struct stat status {};
        if (::lstat(options_.path.c_str(), &status) == 0) {
            return ConfigurationStepResult::failure(
                "managed SSSD drop-in still exists after removal: " +
                options_.path.string());
        }
        if (errno != ENOENT) {
            return ConfigurationStepResult::failure(
                "could not inspect managed SSSD drop-in after removal: " +
                options_.path.string());
        }
        return ConfigurationStepResult::success(false);
    }
    ConfigurationFileSnapshot current;
    std::string error;
    if (!readSecureConfigurationFile(options_, current, error)) {
        return ConfigurationStepResult::failure(std::move(error));
    }
    ConfigurationFileSnapshot expected = mode_ == Mode::CreateFile
        ? installedCandidateSnapshot(options_, original_, candidate_)
        : [&] {
              ConfigurationFileSnapshot value = original_;
              value.content = candidate_;
              return value;
          }();
    if (!snapshotsEqualSnapshots(current, expected)) {
        return ConfigurationStepResult::failure(
            "managed SSSD drop-in does not match prepared candidate: " +
            options_.path.string());
    }
    if (verifier_ && !verifier_(current.content, error)) {
        return ConfigurationStepResult::failure(std::move(error));
    }
    return ConfigurationStepResult::success(false);
}

ConfigurationStepResult ManagedSnippetChange::activate() {
    return ConfigurationStepResult::success(false);
}

ConfigurationStepResult ManagedSnippetChange::verifyEffective() {
    return verifyPersistent();
}

ConfigurationStepResult ManagedSnippetChange::rollbackPersistent() {
    std::string error;
    ConfigurationFileSnapshot current;
    if (mode_ == Mode::RemoveFile) {
        // Compensation of the removal. Recreating the original content is
        // allowed ONLY when the target is PROVEN missing (ENOENT); an
        // unreadable, unsafe or changed file must never be overwritten —
        // the provenance stays active and the recovery is retried later.
        const CompensationReadState state = classifyForCompensation(
            options_, current, error);
        if (state == CompensationReadState::Missing) {
            // Exclusive create / no-replace semantics: a foreign object
            // appearing between the Missing proof and the create fails
            // closed instead of being replaced.
            if (!exclusiveCreateOriginal(
                    options_, original_.content, error)) {
                return ConfigurationStepResult::failure(std::move(error));
            }
            return ConfigurationStepResult::success(true);
        }
        if (state == CompensationReadState::ReadableForCompare) {
            if (snapshotsEqualSnapshots(current, original_)) {
                // A previous exclusive recreate may have reached disk but
                // failed its directory barrier. Re-prove the exact current
                // object and finish durability before declaring compensation.
                AtomicTargetState target;
                if (!AtomicFileWriter::captureTargetState(
                        options_.path.string(), target, &error)) {
                    return ConfigurationStepResult::failure(std::move(error));
                }
                if (target.content != original_.content ||
                    target.owner != original_.owner ||
                    target.group != original_.group ||
                    target.mode != original_.mode) {
                    return ConfigurationStepResult::failure(
                        "managed SSSD drop-in changed before compensation "
                        "durability confirmation");
                }
                if (!AtomicFileWriter::ensureTargetDurableIfCurrentState(
                        options_.path.string(), target, &error)) {
                    return ConfigurationStepResult::failure(std::move(error));
                }
                return ConfigurationStepResult::success(false);
            }
            return ConfigurationStepResult::failure(
                "refusing to overwrite an external managed SSSD drop-in "
                "change: " +
                options_.path.string());
        }
        // Unsafe / Unreadable / OtherError: fail closed, write nothing.
        return ConfigurationStepResult::failure(error);
    }
    if (!readSecureConfigurationFile(options_, current, error)) {
        return ConfigurationStepResult::failure(std::move(error));
    }
    if (mode_ == Mode::CreateFile) {
        if (current.content == candidate_) {
            // Compensation for a FIC-created file: CAS-verified unlink
            // back to the legitimately missing state.
            return removeManagedSnippetFile(options_, current);
        }
        return ConfigurationStepResult::failure(
            "refusing to remove an externally modified managed SSSD "
            "drop-in: " +
            options_.path.string());
    }
    if (snapshotsEqualSnapshots(current, original_)) {
        return ConfigurationStepResult::success(false);
    }
    ConfigurationFileSnapshot expected = original_;
    expected.content = candidate_;
    if (!snapshotsEqualSnapshots(current, expected)) {
        return ConfigurationStepResult::failure(
            "refusing to overwrite an external managed SSSD drop-in "
            "change: " +
            options_.path.string());
    }
    if (!AtomicFileWriter::write(
            options_.path.string(),
            original_.content,
            managedSnippetWriteOptions(options_, original_),
            &error)) {
        return ConfigurationStepResult::failure(std::move(error));
    }
    return ConfigurationStepResult::success(true);
}

ConfigurationStepResult ManagedSnippetChange::restoreRuntimeAfterRollback() {
    return ConfigurationStepResult::success(false);
}

ConfigurationStepResult ManagedSnippetChange::verifyRollback() {
    if (mode_ == Mode::CreateFile) {
        struct stat status {};
        if (::lstat(options_.path.c_str(), &status) == 0) {
            return ConfigurationStepResult::failure(
                "managed SSSD drop-in creation was not rolled back: " +
                options_.path.string());
        }
        if (errno != ENOENT) {
            return ConfigurationStepResult::failure(
                "could not inspect managed SSSD drop-in after rollback: " +
                options_.path.string());
        }
        return ConfigurationStepResult::success(false);
    }
    ConfigurationFileSnapshot current;
    std::string error;
    if (!readSecureConfigurationFile(options_, current, error)) {
        return ConfigurationStepResult::failure(std::move(error));
    }
    if (!snapshotsEqualSnapshots(current, original_)) {
        return ConfigurationStepResult::failure(
            "managed SSSD drop-in rollback was not exact: " +
            options_.path.string());
    }
    return ConfigurationStepResult::success(false);
}

void setManagedSnippetRemovalRaceHookForTests(
    std::function<void()> hook) {
    if (hook) {
        removalRaceHook() = std::move(hook);
    } else {
        removalRaceHook() = nullptr;
    }
}

SssdConfiguration::SssdConfiguration(SssdConfigurationOptions options)
    : options_(std::move(options)) {
}

bool SssdConfiguration::tryGetEffectiveValue(
    const std::string& section,
    const std::string& option,
    std::optional<std::string>& value,
    std::string& error) const {
    if (!validSection(section) || !validOption(option)) {
        error = "invalid SSSD lookup";
        return false;
    }
    ConfigurationFileSnapshot mainSnapshot;
    if (!readSecureConfigurationFile(options_.mainFile, mainSnapshot, error)) {
        return false;
    }
    ParsedConfiguration mainParsed;
    if (!parseConfiguration(mainSnapshot.content, mainParsed, error)) {
        return false;
    }
    value.reset();
    for (const auto& assignment : mainParsed.assignments) {
        if (assignment.section == section && assignment.option == option) {
            value = assignment.value;
        }
    }

    std::vector<std::filesystem::path> snippets;
    if (!listSnippetFiles(options_, snippets, error)) {
        return false;
    }
    for (const auto& path : snippets) {
        ParsedConfiguration parsed;
        if (!readAndParse(optionsForPath(options_.mainFile, path), parsed, error)) {
            return false;
        }
        for (const auto& assignment : parsed.assignments) {
            if (assignment.section == section && assignment.option == option) {
                value = assignment.value;
            }
        }
    }
    return true;
}

ConfigurationPreparationResult SssdConfiguration::prepareSetValue(
    const std::string& section,
    const std::string& option,
    const std::string& value) const {
    return prepareSetValues({{section, option, value}});
}

ConfigurationPreparationResult SssdConfiguration::prepareSetValues(
    const std::vector<SssdSetting>& settings) const {
    std::string error;
    if (!validateSettings(settings, error)) {
        return {nullptr, std::move(error)};
    }
    ConfigurationFileSnapshot original;
    if (!readSecureConfigurationFile(options_.mainFile, original, error)) {
        return {nullptr, std::move(error)};
    }
    ParsedConfiguration parsed;
    if (!parseConfiguration(original.content, parsed, error)) {
        return {nullptr, std::move(error)};
    }
    if (!snippetsOverride(options_, settings, error)) {
        return {nullptr, std::move(error)};
    }

    std::string candidate = original.content;
    for (const auto& setting : settings) {
        if (!applyOneSetting(candidate, setting, error)) {
            return {nullptr, std::move(error)};
        }
    }
    if (!verifyExpectedValues(options_, settings, candidate, error)) {
        return {nullptr, std::move(error)};
    }

    const auto verifier = [options = options_, settings](
        const std::string& content,
        std::string& verifyError) {
        return verifyExpectedValues(options, settings, content, verifyError);
    };
    return {
        makePreparedFileChange(
            "sssd:" + options_.mainFile.path.string(),
            options_.mainFile,
            std::move(original),
            std::move(candidate),
            verifier),
        {}};
}

bool SssdConfiguration::setValue(const std::string& section,
                                 const std::string& option,
                                 const std::string& value,
                                 std::string& error) const {
    return setValues({{section, option, value}}, error);
}

bool SssdConfiguration::setValues(
    const std::vector<SssdSetting>& settings,
    std::string& error) const {
    auto prepared = prepareSetValues(settings);
    if (!prepared.ok()) {
        error = std::move(prepared.error);
        return false;
    }
    return executePreparedFileChange(std::move(prepared.change), error);
}

namespace {

// Verifies that the given managed drop-in content parses and carries
// exactly the expected value for (section, option).
bool verifyManagedSnippetContent(const std::string& content,
                                 const SssdSetting& setting,
                                 std::string& error) {
    ParsedConfiguration parsed;
    if (!parseConfiguration(content, parsed, error)) {
        return false;
    }
    bool found = false;
    for (const auto& assignment : parsed.assignments) {
        if (assignment.section != setting.section ||
            assignment.option != setting.option) {
            continue;
        }
        if (assignment.value != setting.value) {
            error = "unexpected SSSD managed value for [" + setting.section +
                "]/" + setting.option;
            return false;
        }
        found = true;
    }
    if (!found) {
        error = "missing SSSD managed value for [" + setting.section + "]/" +
            setting.option;
        return false;
    }
    return true;
}

// Verifies that the given managed drop-in content parses and does NOT
// contain the target option at all.
bool verifyManagedSnippetOptionAbsent(const std::string& content,
                                      const std::string& section,
                                      const std::string& option,
                                      std::string& error) {
    ParsedConfiguration parsed;
    if (!parseConfiguration(content, parsed, error)) {
        return false;
    }
    for (const auto& assignment : parsed.assignments) {
        if (assignment.section == section && assignment.option == option) {
            error = "SSSD managed option [" + section + "]/" + option +
                " still present after removal";
            return false;
        }
    }
    return true;
}

SecureConfigurationFileOptions managedSnippetOptions(
    const SssdConfigurationOptions& options) {
    auto result = options.mainFile;
    result.path = options.managedSnippetFile;
    return result;
}

std::unique_ptr<PreparedConfigurationChange> makeManagedSnippetChange(
    std::string identifier,
    SecureConfigurationFileOptions options,
    ManagedSnippetChange::Mode mode,
    ConfigurationFileSnapshot original,
    std::string candidate,
    ConfigurationContentVerifier verifier) {
    return std::make_unique<ManagedSnippetChange>(
        std::move(identifier),
        std::move(options),
        mode,
        std::move(original),
        std::move(candidate),
        std::move(verifier));
}

} // namespace

bool SssdConfiguration::inspectManagedSnippet(
    const std::string& section,
    const std::string& option,
    SssdManagedSnippetObservation& observation,
    std::string& error) const {
    observation = SssdManagedSnippetObservation{};
    if (!validSection(section) || !validOption(option)) {
        error = "invalid SSSD managed lookup";
        return false;
    }
    if (options_.managedSnippetFile.empty()) {
        error = "SSSD managed drop-in file is not configured";
        return false;
    }
    // The managed drop-in directory must exist and be secure: FIC never
    // creates directories implicitly.
    if (!verifySecureConfigurationDirectory(
            options_.managedSnippetFile.parent_path(),
            options_.mainFile,
            error)) {
        error = "SSSD managed drop-in directory is unsafe: " + error;
        return false;
    }
    // Effective semantics are undefined when the foreign main configuration
    // cannot be read safely and parsed.
    ConfigurationFileSnapshot mainSnapshot;
    if (!readSecureConfigurationFile(options_.mainFile, mainSnapshot, error)) {
        return false;
    }
    ParsedConfiguration mainParsed;
    if (!parseConfiguration(mainSnapshot.content, mainParsed, error)) {
        error = "could not parse foreign SSSD main configuration: " + error;
        return false;
    }
    std::optional<std::string> effective;
    for (const auto& assignment : mainParsed.assignments) {
        if (assignment.section == section && assignment.option == option) {
            effective = assignment.value;
        }
    }

    std::vector<std::filesystem::path> snippets;
    if (!listSnippetFiles(options_, snippets, error)) {
        return false;
    }
    // The managed drop-in occupies the position where its path sorts within
    // the snippet list; snippets at later positions would override FIC
    // values and must make apply fail closed.
    const auto managedPosition = std::lower_bound(
        snippets.begin(), snippets.end(), options_.managedSnippetFile);
    const bool managedInList = managedPosition != snippets.end() &&
        *managedPosition == options_.managedSnippetFile;
    const std::size_t managedIndex = static_cast<std::size_t>(
        managedPosition - snippets.begin());
    for (std::size_t index = 0; index < snippets.size(); ++index) {
        const bool isManaged = snippets[index] == options_.managedSnippetFile;
        ParsedConfiguration parsed;
        if (!readAndParse(
                optionsForPath(options_.mainFile, snippets[index]),
                parsed,
                error)) {
            return false;
        }
        for (const auto& assignment : parsed.assignments) {
            if (assignment.section != section || assignment.option != option) {
                continue;
            }
            effective = assignment.value;
            if (isManaged) {
                observation.optionPresent = true;
                observation.optionValue = assignment.value;
            } else if (managedInList ? index > managedIndex
                                     : index >= managedIndex) {
                observation.laterConflictingSnippets.push_back(
                    snippets[index]);
            }
        }
    }
    observation.effectiveValue = effective;

    // Classify the managed drop-in artifact itself.
    struct stat status {};
    if (::lstat(options_.managedSnippetFile.c_str(), &status) != 0) {
        if (errno == ENOENT) {
            observation.dropInState =
                SssdManagedSnippetObservation::DropInState::Missing;
            return true;
        }
        error = "could not inspect SSSD managed drop-in: " +
            options_.managedSnippetFile.string();
        return false;
    }
    if (S_ISLNK(status.st_mode) || !S_ISREG(status.st_mode)) {
        observation.dropInState =
            SssdManagedSnippetObservation::DropInState::Unsafe;
        observation.optionPresent = false;
        observation.optionValue.clear();
        return true;
    }
    ConfigurationFileSnapshot snapshot;
    std::string readError;
    if (!readSecureConfigurationFile(
            managedSnippetOptions(options_), snapshot, readError)) {
        observation.dropInState =
            SssdManagedSnippetObservation::DropInState::Unsafe;
        observation.optionPresent = false;
        observation.optionValue.clear();
        return true;
    }
    ParsedConfiguration parsed;
    std::string parseError;
    if (!parseConfiguration(snapshot.content, parsed, parseError)) {
        observation.dropInState =
            SssdManagedSnippetObservation::DropInState::Malformed;
        observation.optionPresent = false;
        observation.optionValue.clear();
        return true;
    }
    observation.dropInState = SssdManagedSnippetObservation::DropInState::Ok;
    for (const auto& assignment : parsed.assignments) {
        if (assignment.section == section && assignment.option == option) {
            observation.optionPresent = true;
            observation.optionValue = assignment.value;
        }
    }
    return true;
}

ConfigurationPreparationResult SssdConfiguration::prepareManagedSnippetValue(
    const std::string& section,
    const std::string& option,
    const std::string& value) const {
    const SssdSetting setting{section, option, value};
    std::string error;
    if (!validSection(section) || !validOption(option) ||
        !validValue(value)) {
        return {nullptr, "invalid SSSD managed setting"};
    }
    if (options_.managedSnippetFile.empty()) {
        return {nullptr, "SSSD managed drop-in file is not configured"};
    }
    SssdManagedSnippetObservation observation;
    if (!inspectManagedSnippet(section, option, observation, error)) {
        return {nullptr, std::move(error)};
    }
    // Fail closed: a later foreign snippet would silently override the FIC
    // drop-in, so FIC could never become effective. Foreign files are never
    // modified.
    if (!observation.laterConflictingSnippets.empty()) {
        return {nullptr,
                "SSSD managed drop-in cannot become effective: later snippet "
                "'" +
                    observation.laterConflictingSnippets.front().string() +
                    "' defines [" +
                    section +
                    "]/" +
                    option};
    }
    if (observation.dropInState ==
        SssdManagedSnippetObservation::DropInState::Unsafe) {
        return {nullptr,
                "SSSD managed drop-in path is unsafe: " +
                    options_.managedSnippetFile.string()};
    }
    if (observation.dropInState ==
        SssdManagedSnippetObservation::DropInState::Malformed) {
        return {nullptr,
                "SSSD managed drop-in is malformed: " +
                    options_.managedSnippetFile.string()};
    }
    const auto snippetOptions = managedSnippetOptions(options_);
    const auto verifier = [setting](const std::string& content,
                                    std::string& verifyError) {
        return verifyManagedSnippetContent(content, setting, verifyError);
    };
    if (observation.dropInState ==
        SssdManagedSnippetObservation::DropInState::Missing) {
        std::string candidate =
            std::string("# FIC managed configuration\n") + "[" + section +
            "]\n" + option + " = " + value + "\n";
        ConfigurationFileSnapshot original;
        return {
            makeManagedSnippetChange(
                "sssd-managed:" + options_.managedSnippetFile.string(),
                snippetOptions,
                ManagedSnippetChange::Mode::CreateFile,
                std::move(original),
                std::move(candidate),
                verifier),
            {}};
    }
    ConfigurationFileSnapshot original;
    if (!readSecureConfigurationFile(snippetOptions, original, error)) {
        return {nullptr, std::move(error)};
    }
    ParsedConfiguration parsed;
    if (!parseConfiguration(original.content, parsed, error)) {
        return {nullptr, "SSSD managed drop-in is malformed: " + error};
    }
    std::string candidate = original.content;
    if (!applyOneSetting(candidate, setting, error)) {
        return {nullptr, std::move(error)};
    }
    return {
        makeManagedSnippetChange(
            "sssd-managed:" + options_.managedSnippetFile.string(),
            snippetOptions,
            ManagedSnippetChange::Mode::WriteFile,
            std::move(original),
            std::move(candidate),
            verifier),
        {}};
}

ConfigurationPreparationResult SssdConfiguration::prepareManagedSnippetRemoval(
    const std::string& section,
    const std::string& option) const {
    std::string error;
    if (!validSection(section) || !validOption(option)) {
        return {nullptr, "invalid SSSD managed setting removal"};
    }
    if (options_.managedSnippetFile.empty()) {
        return {nullptr, "SSSD managed drop-in file is not configured"};
    }
    SssdManagedSnippetObservation observation;
    if (!inspectManagedSnippet(section, option, observation, error)) {
        return {nullptr, std::move(error)};
    }
    if (!observation.laterConflictingSnippets.empty() ||
        observation.dropInState !=
            SssdManagedSnippetObservation::DropInState::Ok) {
        return {nullptr,
                "SSSD managed drop-in removal requires a valid FIC-owned "
                "drop-in with the target option"};
    }
    if (!observation.optionPresent) {
        return {nullptr,
                "SSSD managed option [" + section + "]/" + option +
                    " is not present in the FIC-owned drop-in"};
    }
    const auto snippetOptions = managedSnippetOptions(options_);
    ConfigurationFileSnapshot original;
    if (!readSecureConfigurationFile(snippetOptions, original, error)) {
        return {nullptr, std::move(error)};
    }
    ParsedConfiguration parsed;
    if (!parseConfiguration(original.content, parsed, error)) {
        return {nullptr, "SSSD managed drop-in is malformed: " + error};
    }
    // Remove ONLY the target option lines.
    std::vector<std::size_t> removeLines;
    for (const auto& assignment : parsed.assignments) {
        if (assignment.section == section && assignment.option == option) {
            removeLines.push_back(assignment.line);
        }
    }
    for (auto it = removeLines.rbegin(); it != removeLines.rend(); ++it) {
        parsed.lines.erase(parsed.lines.begin() +
                           static_cast<std::ptrdiff_t>(*it));
    }
    if (parsed.assignments.size() == removeLines.size()) {
        // The drop-in became semantically empty: remove the FIC-owned file
        // entirely. The pre-removal state is kept as the CAS original for
        // the compensation path.
        return {
            makeManagedSnippetChange(
                "sssd-managed:" + options_.managedSnippetFile.string(),
                snippetOptions,
                ManagedSnippetChange::Mode::RemoveFile,
                std::move(original),
                {},
                nullptr),
            {}};
    }
    std::string candidate = joinDocument(parsed);
    const auto verifier = [section, option](
                              const std::string& content,
                              std::string& verifyError) {
        return verifyManagedSnippetOptionAbsent(
            content, section, option, verifyError);
    };
    return {
        makeManagedSnippetChange(
            "sssd-managed:" + options_.managedSnippetFile.string(),
            snippetOptions,
            ManagedSnippetChange::Mode::WriteFile,
            std::move(original),
            std::move(candidate),
            verifier),
        {}};
}

} // namespace fic::identity::sssd
