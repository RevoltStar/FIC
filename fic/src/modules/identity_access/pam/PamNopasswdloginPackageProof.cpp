#include "modules/identity_access/pam/PamNopasswdloginPackageProof.h"
#include "platform/PlatformExecutableResolver.h"

#include <openssl/evp.h>
#include <algorithm>
#include <sstream>

namespace fic::identity::pam {
namespace {

bool reject(std::string& error, const std::string& message) {
    error = message;
    return false;
}

bool digestMatches(const std::string& content, const std::string& expected) {
    if (expected.find_first_not_of("0123456789abcdef") != std::string::npos) return false;
    const EVP_MD* algorithm = nullptr;
    switch (expected.size()) {
    case 32: algorithm = EVP_md5(); break;
    case 40: algorithm = EVP_sha1(); break;
    case 64: algorithm = EVP_sha256(); break;
    case 128: algorithm = EVP_sha512(); break;
    default: return false;
    }
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned size = 0;
    if (EVP_Digest(content.data(), content.size(), digest, &size, algorithm, nullptr) != 1) return false;
    constexpr char hex[] = "0123456789abcdef";
    std::string observed;
    for (unsigned i = 0; i < size; ++i) {
        observed += hex[digest[i] >> 4];
        observed += hex[digest[i] & 15];
    }
    return observed == expected;
}

bool allowed(const std::vector<std::string>& packages, const std::string& package) {
    return std::find(packages.begin(), packages.end(), package) != packages.end();
}

} // namespace

bool provePackagedPamContent(
    const fic::platform::PamPlatformConfig::PasswordlessLoginTarget& target,
    fic::platform::PackageManagerKind kind, const std::string& content,
    const PamPackageQuery& query, std::string& error) {
    error.clear();
    std::string expected;
    const auto path = target.source.string();
    if (kind == fic::platform::PackageManagerKind::Rpm) {
        const auto result = query({"-qf", "--qf", "%{NAME}\\n[%{FILENAMES}\\t%{FILEDIGESTS}\\n]", path});
        std::istringstream output(result.standardOutput);
        std::string package, line;
        if (!result.success() || !std::getline(output, package) || !allowed(target.packages, package)) {
            return reject(error, "Cannot prove PAM file RPM owner");
        }
        while (std::getline(output, line)) {
            const auto tab = line.find('\t');
            if (tab == std::string::npos) return reject(error, "Ambiguous PAM RPM metadata");
            if (line.substr(0, tab) != path) continue;
            if (!expected.empty()) return reject(error, "Multiple PAM RPM file digests");
            expected = line.substr(tab + 1);
            if (expected.empty()) return reject(error, "Missing PAM RPM file digest");
        }
    } else {
        const auto owner = query({"-S", path});
        const auto separator = owner.standardOutput.find(": ");
        if (!owner.success() || separator == std::string::npos ||
            owner.standardOutput.substr(separator + 2) != path + "\n") {
            return reject(error, "Cannot prove unique PAM DEB owner");
        }
        const auto binaryPackage = owner.standardOutput.substr(0, separator);
        const auto package = binaryPackage.substr(0, binaryPackage.find(':'));
        if (!allowed(target.packages, package)) return reject(error, "Unexpected PAM DEB owner");
        const auto metadata = query({"-W", "-f=${db:Status-Status}\n${Conffiles}\n", binaryPackage});
        std::istringstream output(metadata.standardOutput);
        std::string status, line;
        if (!metadata.success() || !std::getline(output, status) || status != "installed") {
            return reject(error, "PAM DEB package is not installed");
        }
        while (std::getline(output, line)) {
            std::istringstream fields(line);
            std::string filename, digest, extra;
            if (!(fields >> filename)) continue;
            if (!(fields >> digest)) return reject(error, "Malformed PAM DEB conffile metadata");
            if (filename != path) continue;
            if ((fields >> extra) || !expected.empty()) {
                return reject(error, "Obsolete or ambiguous PAM DEB conffile");
            }
            expected = digest;
        }
        if (expected.size() != 32) return reject(error, "Missing PAM DEB conffile digest");
    }
    if (!digestMatches(content, expected)) return reject(error, "PAM content differs from installed package");
    return true;
}

PamNopasswdloginOptions productionNopasswdloginOptions(
    const fic::platform::PamPlatformConfig& platform) {
    PamNopasswdloginOptions options;
    options.platform = platform;
    for (const auto& target : platform.passwordlessLoginTargets) options.services.push_back(target.service);
    options.proveStock = [platform](const std::filesystem::path& source,
                                   const std::string& bytes, std::string& error) {
        const auto target = std::find_if(platform.passwordlessLoginTargets.begin(),
            platform.passwordlessLoginTargets.end(), [&](const auto& target) {
                return target.source == source;
            });
        if (target == platform.passwordlessLoginTargets.end()) return reject(error, "Unknown PAM package route");
        const auto build = fic::platform::makeBuildPlatformProfile();
        fic::platform::PlatformExecutableResolver resolver(build.executables);
        std::filesystem::path executable;
        if (!resolver.resolve(fic::platform::ExecutableId::PackageQuery, executable, error)) return false;
        ProcessOptions processOptions;
        processOptions.clearEnvironment = true;
        processOptions.environment = {{"LC_ALL", "C"}};
        const auto query = [&](const auto& arguments) {
            return ProcessExecutor::execute(executable.string(), arguments, processOptions);
        };
        return provePackagedPamContent(*target, build.packageManager.kind, bytes, query, error);
    };
    return options;
}

} // namespace fic::identity::pam
