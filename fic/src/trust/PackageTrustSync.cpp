#include "trust/PackageTrustSync.h"

#include <fic/core/integrity/CommandHashStore.h>
#include <fic/core/process/ProcessExecutor.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <openssl/evp.h>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace fic::trust {
namespace {

std::string trim(std::string value) {
    const auto first = std::find_if_not(value.begin(), value.end(), [](unsigned char ch) {
        return std::isspace(ch) != 0;
    });
    const auto last = std::find_if_not(value.rbegin(), value.rend(), [](unsigned char ch) {
        return std::isspace(ch) != 0;
    }).base();
    return first < last ? std::string(first, last) : std::string();
}

bool validateBootstrapExecutable(const std::filesystem::path& path,
                                 std::string& error) {
    struct stat info {};
    if (!path.is_absolute() || path != path.lexically_normal()) {
        error = "package query path is not absolute and normalized: " + path.string();
        return false;
    }
    if (::lstat(path.c_str(), &info) != 0) {
        error = std::string("cannot inspect package query executable ") +
                path.string() + ": " + std::strerror(errno);
        return false;
    }
    if (S_ISLNK(info.st_mode) || !S_ISREG(info.st_mode) ||
        info.st_uid != 0 || (info.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
        ::access(path.c_str(), X_OK) != 0) {
        error = "package query executable is not a trusted root-owned regular file: " +
                path.string();
        return false;
    }
    return true;
}

bool resolvePackageQuery(
    const fic::platform::PackageManagerPlatformConfig& config,
    std::filesystem::path& executable,
    std::string& error) {
    std::string lastError;
    for (const std::filesystem::path& candidate : config.queryCandidates) {
        if (validateBootstrapExecutable(candidate, lastError)) {
            executable = candidate;
            return true;
        }
    }
    error = "no trusted package query executable was found";
    if (!lastError.empty()) {
        error += ": " + lastError;
    }
    return false;
}

ProcessResult query(const std::filesystem::path& executable,
                    const std::vector<std::string>& arguments) {
    ProcessOptions options;
    options.timeout = std::chrono::seconds(20);
    options.clearEnvironment = true;
    options.environment = {{"LC_ALL", "C"}, {"LANG", "C"}};
    return ProcessExecutor::execute(executable.string(), arguments, options);
}

std::string queryFailure(const ProcessResult& result) {
    if (!result.error.empty()) {
        return result.error;
    }
    if (result.timedOut) {
        return "query timed out";
    }
    const std::string details = trim(result.standardError);
    return "query exited with code " + std::to_string(result.exitCode) +
           (details.empty() ? "" : ": " + details);
}

bool calculateDigest(const std::filesystem::path& path,
                     const EVP_MD* algorithm,
                     std::string& digest,
                     std::string& error) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream.is_open()) {
        error = "cannot open package-managed executable: " + path.string();
        return false;
    }

    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (context == nullptr || EVP_DigestInit_ex(context, algorithm, nullptr) != 1) {
        EVP_MD_CTX_free(context);
        error = "OpenSSL failed to initialize package digest";
        return false;
    }

    char buffer[16 * 1024];
    while (stream.read(buffer, sizeof(buffer)) || stream.gcount() > 0) {
        if (EVP_DigestUpdate(context, buffer,
                             static_cast<std::size_t>(stream.gcount())) != 1) {
            EVP_MD_CTX_free(context);
            error = "OpenSSL failed to update package digest";
            return false;
        }
    }

    unsigned char bytes[EVP_MAX_MD_SIZE];
    unsigned int length = 0;
    if (EVP_DigestFinal_ex(context, bytes, &length) != 1) {
        EVP_MD_CTX_free(context);
        error = "OpenSSL failed to finalize package digest";
        return false;
    }
    EVP_MD_CTX_free(context);

    std::ostringstream encoded;
    encoded << std::hex << std::setfill('0');
    for (unsigned int index = 0; index < length; ++index) {
        encoded << std::setw(2) << static_cast<unsigned int>(bytes[index]);
    }
    digest = encoded.str();
    return true;
}

bool validHexDigest(const std::string& digest, std::size_t length) {
    return digest.size() == length &&
           std::all_of(digest.begin(), digest.end(), [](unsigned char ch) {
               return std::isxdigit(ch) != 0;
           });
}

bool sameFile(const std::filesystem::path& left,
              const std::filesystem::path& right) {
    struct stat leftInfo {};
    struct stat rightInfo {};
    return ::stat(left.c_str(), &leftInfo) == 0 &&
           ::stat(right.c_str(), &rightInfo) == 0 &&
           leftInfo.st_dev == rightInfo.st_dev &&
           leftInfo.st_ino == rightInfo.st_ino;
}

bool verifyDigest(const std::filesystem::path& path,
                  std::string expected,
                  const EVP_MD* algorithm,
                  std::string& error) {
    std::transform(expected.begin(), expected.end(), expected.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    std::string actual;
    if (!calculateDigest(path, algorithm, actual, error)) {
        return false;
    }
    if (actual != expected) {
        error = "installed file differs from package metadata: " + path.string();
        return false;
    }
    return true;
}

bool verifyDpkg(const std::filesystem::path& queryExecutable,
                const std::filesystem::path& path,
                const std::vector<std::filesystem::path>& aliases,
                std::string& error) {
    std::string package;
    std::filesystem::path metadataPath;
    std::vector<std::filesystem::path> queryPaths = {path};
    for (const std::filesystem::path& alias : aliases) {
        if (alias != path && sameFile(path, alias)) {
            queryPaths.push_back(alias);
        }
    }
    for (const std::filesystem::path& queryPath : queryPaths) {
        const ProcessResult owner =
            query(queryExecutable, {"--search", queryPath.string()});
        if (!owner.success()) {
            continue;
        }
        std::istringstream ownerLines(owner.standardOutput);
        for (std::string line; std::getline(ownerLines, line);) {
            const std::size_t delimiter = line.rfind(": ");
            if (delimiter != std::string::npos &&
                line.substr(delimiter + 2) == queryPath.string()) {
                package = line.substr(0, delimiter);
                metadataPath = queryPath;
                break;
            }
        }
        if (!package.empty()) {
            break;
        }
    }
    if (package.empty() ||
        !std::all_of(package.begin(), package.end(), [](unsigned char ch) {
            return std::isalnum(ch) != 0 || ch == '+' || ch == '-' ||
                   ch == '.' || ch == ':';
        })) {
        error = "dpkg did not identify an exact package owner for " + path.string();
        return false;
    }

    const ProcessResult sums =
        query(queryExecutable, {"--control-show", package, "md5sums"});
    if (!sums.success()) {
        error = "dpkg checksum query failed for package " + package + ": " +
                queryFailure(sums);
        return false;
    }

    const std::string relativePath = metadataPath.string().substr(1);
    std::istringstream checksumLines(sums.standardOutput);
    for (std::string line; std::getline(checksumLines, line);) {
        std::istringstream fields(line);
        std::string checksum;
        std::string filename;
        if ((fields >> checksum >> filename) && filename == relativePath) {
            if (!validHexDigest(checksum, 32)) {
                break;
            }
            return verifyDigest(path, checksum, EVP_md5(), error);
        }
    }
    error = "dpkg package metadata has no MD5 checksum for " + path.string();
    return false;
}

bool verifyRpm(const std::filesystem::path& queryExecutable,
               const std::filesystem::path& path,
               const std::vector<std::filesystem::path>& aliases,
               std::string& error) {
    std::vector<std::filesystem::path> queryPaths = {path};
    for (const std::filesystem::path& alias : aliases) {
        if (alias != path && sameFile(path, alias)) {
            queryPaths.push_back(alias);
        }
    }

    for (const std::filesystem::path& queryPath : queryPaths) {
        const ProcessResult files = query(
            queryExecutable,
            {"-qf", "--qf", "[%{FILENAMES}\\t%{FILEDIGESTS}\\n]",
             queryPath.string()});
        if (!files.success()) {
            continue;
        }
        std::istringstream lines(files.standardOutput);
        for (std::string line; std::getline(lines, line);) {
            const std::size_t tab = line.find('\t');
            if (tab == std::string::npos ||
                line.substr(0, tab) != queryPath.string()) {
                continue;
            }
            const std::string checksum = trim(line.substr(tab + 1));
            const EVP_MD* algorithm = nullptr;
            if (validHexDigest(checksum, 32)) {
                algorithm = EVP_md5();
            } else if (validHexDigest(checksum, 40)) {
                algorithm = EVP_sha1();
            } else if (validHexDigest(checksum, 64)) {
                algorithm = EVP_sha256();
            } else if (validHexDigest(checksum, 128)) {
                algorithm = EVP_sha512();
            }
            if (algorithm == nullptr) {
                error = "rpm package metadata has an unsupported digest for " +
                        path.string();
                return false;
            }
            return verifyDigest(path, checksum, algorithm, error);
        }
    }
    error = "rpm did not return exact package metadata for " + path.string();
    return false;
}

bool anyCandidateExists(const fic::platform::PlatformExecutableSpec& spec) {
    return std::any_of(
        spec.candidates.begin(), spec.candidates.end(),
        [](const std::filesystem::path& candidate) {
            struct stat info {};
            return ::lstat(candidate.c_str(), &info) == 0;
        });
}

bool syncPackageManagedExecutableIds(
    const fic::platform::PlatformProfile& platform,
    const fic::platform::PlatformExecutableResolver& executables,
    const std::vector<fic::platform::ExecutableId>& executableIds,
    PackageTrustSyncResult& result,
    std::string& error) {
    result = {};
    if (executableIds.empty()) {
        error.clear();
        return true;
    }

    std::filesystem::path packageQuery;
    if (!resolvePackageQuery(platform.packageManager, packageQuery, error)) {
        return false;
    }

    std::vector<std::string> verifiedPaths;
    std::vector<std::string> candidatePaths;
    for (const fic::platform::ExecutableId id : executableIds) {
        const fic::platform::PlatformExecutableSpec* spec =
            fic::platform::findExecutableSpec(platform.executables, id);
        if (spec == nullptr) {
            error = std::string("platform profile has no executable entry for ") +
                    fic::platform::executableIdName(id);
            return false;
        }
        for (const std::filesystem::path& candidate : spec->candidates) {
            const std::string candidatePath = candidate.string();
            if (std::find(candidatePaths.begin(), candidatePaths.end(),
                          candidatePath) == candidatePaths.end()) {
                candidatePaths.push_back(candidatePath);
            }
        }
        if (!anyCandidateExists(*spec)) {
            ++result.unavailable;
            continue;
        }

        std::filesystem::path path;
        if (!executables.resolve(id, path, error)) {
            return false;
        }
        const bool trusted =
            platform.packageManager.kind == fic::platform::PackageManagerKind::Dpkg
                ? verifyDpkg(packageQuery, path, spec->candidates, error)
                : verifyRpm(packageQuery, path, spec->candidates, error);
        if (!trusted) {
            return false;
        }
        if (std::find(verifiedPaths.begin(), verifiedPaths.end(), path.string()) ==
            verifiedPaths.end()) {
            verifiedPaths.push_back(path.string());
        }
    }

    if (!CommandHashStore::updateHashes(
            verifiedPaths, candidatePaths, error)) {
        return false;
    }
    result.updated = verifiedPaths.size();
    error.clear();
    return true;
}

} // namespace

bool syncPackageManagedExecutables(
    const fic::platform::PlatformProfile& platform,
    const fic::platform::PlatformExecutableResolver& executables,
    PackageTrustSyncResult& result,
    std::string& error) {
    return syncPackageManagedExecutableIds(
        platform, executables, fic::platform::allExecutableIds(), result, error);
}

bool syncSelectedPackageManagedExecutables(
    const fic::platform::PlatformProfile& platform,
    const fic::platform::PlatformExecutableResolver& executables,
    const std::vector<fic::platform::ExecutableId>& executableIds,
    PackageTrustSyncResult& result,
    std::string& error) {
    return syncPackageManagedExecutableIds(
        platform, executables, executableIds, result, error);
}

} // namespace fic::trust
