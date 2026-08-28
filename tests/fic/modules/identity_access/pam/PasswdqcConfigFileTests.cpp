#include "modules/identity_access/pam/PasswdqcConfigFile.h"
#include "modules/identity_access/pam/PamProviderCatalog.h"

#include <fic/core/fs/AtomicFileWriter.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <stdexcept>
#include <string>

#include <sys/stat.h>
#include <unistd.h>

namespace {

class TemporaryDirectory {
public:
    TemporaryDirectory() {
        char pattern[] = "/tmp/fic-passwdqc-tests-XXXXXX";
        const char* created = ::mkdtemp(pattern);
        if (created == nullptr) {
            throw std::runtime_error("mkdtemp failed");
        }
        path = created;
    }

    ~TemporaryDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
    }

    std::filesystem::path path;
};

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void writeFile(const std::filesystem::path& path,
               const std::string& content) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    require(output.is_open(), "could not write fixture");
    output << content;
}

std::string readFile(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(input),
                       std::istreambuf_iterator<char>());
}

void testMinimumsCodec() {
    using fic::identity::pam::PasswdqcMinimums;
    using fic::identity::pam::PasswdqcMinimumsCodec;

    PasswdqcMinimums parsed;
    std::string error;
    require(PasswdqcMinimumsCodec::parse(
                "disabled,24,11,8,7", parsed, error), error);
    require(PasswdqcMinimumsCodec::serialize(parsed) ==
                "disabled,24,11,8,7",
            "passwdqc minimums round-trip failed");
    require(PasswdqcMinimumsCodec::parse("24,24,11,8,7", parsed, error),
            "equal boundary must be permitted");
    require(!PasswdqcMinimumsCodec::parse("24,11,8,7", parsed, error),
            "four minimum fields were accepted");
    require(!PasswdqcMinimumsCodec::parse(
                "24,11,8,7,7,6", parsed, error),
            "six minimum fields were accepted");
    require(!PasswdqcMinimumsCodec::parse("24,25,8,7,6", parsed, error),
            "increasing minimums were accepted");
    require(!PasswdqcMinimumsCodec::parse(
                "24,disabled,8,7,6", parsed, error),
            "numeric minimum after disabled was accepted");
    require(!PasswdqcMinimumsCodec::parse("24,-1,8,7,6", parsed, error),
            "negative minimum was accepted");
    require(!PasswdqcMinimumsCodec::parse("24,x,8,7,6", parsed, error),
            "non-numeric minimum was accepted");
    const std::string maximum = std::to_string(
        std::numeric_limits<int>::max());
    require(PasswdqcMinimumsCodec::parse(
                maximum + ",24,11,8,7", parsed, error),
            "maximum native integer boundary was rejected");
    require(!PasswdqcMinimumsCodec::parse(
                "2147483648,24,11,8,7", parsed, error),
            "out-of-range native integer was accepted");
}

void testNativeSyntaxAndPreservation() {
    TemporaryDirectory temp;
    const auto path = temp.path / "passwdqc.conf";
    writeFile(path,
              "# administrator comment\n"
              "unknown=value\n"
              "min=24,11,8,7,7\n");
    std::string error;
    require(fic::identity::pam::PasswdqcConfigFile::setValue(
                path, "min", "disabled,24,11,8,7", error), error);
    const std::string content = readFile(path);
    require(content ==
                "# administrator comment\n"
                "unknown=value\n"
                "min=disabled,24,11,8,7\n",
            "passwdqc writer did not preserve comments/unknown options or "
            "did not emit exact option=value syntax");
    require(fic::identity::pam::PasswdqcConfigFile::setValue(
                path, "retry", "3", error), error);
    require(readFile(path).find("retry=3\n") != std::string::npos,
            "passwdqc writer did not append an exact assignment");
}

void testMalformedAndDuplicateFailClosed() {
    TemporaryDirectory temp;
    const auto path = temp.path / "passwdqc.conf";
    std::string error;
    writeFile(path, "min = 24,11,8,7,7\n");
    const std::string whitespaceOriginal = readFile(path);
    require(!fic::identity::pam::PasswdqcConfigFile::setValue(
                path, "min", "disabled,24,11,8,7", error),
            "whitespace around passwdqc assignment was accepted");
    require(readFile(path) == whitespaceOriginal,
            "malformed passwdqc config was modified");

    writeFile(path, "retry=3\nretry=4\n");
    const std::string duplicateOriginal = readFile(path);
    require(!fic::identity::pam::PasswdqcConfigFile::setValue(
                path, "retry", "5", error),
            "duplicate passwdqc option was accepted");
    require(readFile(path) == duplicateOriginal,
            "duplicate passwdqc config was modified");
    require(!fic::identity::pam::PasswdqcConfigFile::setValue(
                path, "similar", "maybe", error),
            "invalid passwdqc enum was accepted");

    writeFile(path, "retry=invalid\nmin=24,11,8,7,7\n");
    const std::string invalidValueOriginal = readFile(path);
    require(!fic::identity::pam::PasswdqcConfigFile::setValue(
                path, "min", "disabled,24,11,8,7", error),
            "an invalid existing managed passwdqc value was ignored");
    require(readFile(path) == invalidValueOriginal,
            "config with an invalid managed passwdqc value was modified");
}

void testSymlinkAndNonRegularRejection() {
    TemporaryDirectory temp;
    const auto target = temp.path / "target";
    const auto link = temp.path / "passwdqc.conf";
    writeFile(target, "retry=3\n");
    require(::symlink(target.c_str(), link.c_str()) == 0,
            "could not create symlink fixture");
    std::string error;
    require(!fic::identity::pam::PasswdqcConfigFile::setValue(
                link, "retry", "4", error) &&
                error.find("symbolic link") != std::string::npos,
            "passwdqc writer followed a symlink");
    require(readFile(target) == "retry=3\n",
            "symlink target was modified");
    require(!fic::identity::pam::PasswdqcConfigFile::setValue(
                temp.path, "retry", "4", error) &&
                error.find("non-regular") != std::string::npos,
            "passwdqc writer accepted a non-regular target");
}

void testPostconditionRollback() {
    TemporaryDirectory temp;
    const auto path = temp.path / "passwdqc.conf";
    const std::string original = "# keep\nretry=3\n";
    writeFile(path, original);
    std::size_t writes = 0;
    const auto writer = [&](const std::string& target,
                            const std::string& content,
                            const AtomicWriteOptions& options,
                            std::string* error) {
        ++writes;
        const std::string actual = writes == 1
            ? "# externally changed\nretry=999\n"
            : content;
        return AtomicFileWriter::write(target, actual, options, error);
    };
    std::string error;
    require(!fic::identity::pam::PasswdqcConfigFile::setValue(
                path, "retry", "4", error, writer),
            "failed passwdqc postcondition was reported as success");
    require(writes == 2 && readFile(path) == original,
            "passwdqc postcondition failure was not rolled back");
}

void testProviderCatalogAndSupport() {
    using namespace fic::platform;
    using namespace fic::identity::pam;
    const auto& passwdqc = pamProviderDescriptor(PamProviderKind::PamPasswdqc);
    require(std::string(passwdqc.externalConfigArgument) == "config" &&
                passwdqc.grammar == PamConfigGrammar::Passwdqc,
            "passwdqc descriptor has the wrong config contract");
    std::string native;
    std::string error;
    require(encodePamNativeValue(
                PamNativeValueEncoding::PasswdqcEnforceForRoot,
                "yes", native, error) && native == "everyone",
            error);
    require(encodePamNativeValue(
                PamNativeValueEncoding::PasswdqcEnforceForRoot,
                "no", native, error) && native == "users",
            error);
    std::string logical;
    require(decodePamNativeValue(
                PamNativeValueEncoding::PasswdqcEnforceForRoot,
                "everyone", logical, error) && logical == "yes",
            error);
    require(!decodePamNativeValue(
                PamNativeValueEncoding::PasswdqcEnforceForRoot,
                "none", logical, error),
            "passwdqc enforce=none was given an inexact logical mapping");

    PamPlatformConfig platform;
    platform.scopes = {
        {PamScope::LocalPasswordChange, {"system-auth-local-only"}}
    };
    platform.capabilities = {
        {PamCapability::PasswordQuality, PamProviderKind::PamPasswdqc,
         PamScope::LocalPasswordChange, "/etc/passwdqc.conf",
         PamConfigGrammar::Passwdqc,
         PamTopologyStrategyKind::StaticReadOnly, {}}
    };
    require(pamPolicySupport(platform, PamPolicyFeature::PasswdqcRetryCount) ==
                PamPolicySupport::Supported,
            "passwdqc native policy is not supported");
    require(pamPolicySupport(platform, PamPolicyFeature::PasswordMinLength) ==
                PamPolicySupport::Unsupported,
            "pwquality-only policy was exposed for passwdqc");
    require(pamPolicySupport(
                platform,
                PamPolicyFeature::PasswordQualityEnforceForRoot) ==
                PamPolicySupport::Supported,
            "cross-provider enforce-for-root policy is not supported");

    platform.capabilities[0] = {
        PamCapability::PasswordQuality, PamProviderKind::PamPwquality,
        PamScope::LocalPasswordChange, "/etc/security/pwquality.conf",
        PamConfigGrammar::KeyValue,
        PamTopologyStrategyKind::ExternalOptIn, {}};
    require(pamPolicySupport(platform, PamPolicyFeature::PasswordMinLength) ==
                PamPolicySupport::RequiresTopologyActivation,
            "pwquality policy did not retain its topology-dependent state");
    require(pamPolicySupport(platform, PamPolicyFeature::PasswdqcRetryCount) ==
                PamPolicySupport::Unsupported,
            "passwdqc-native policy was exposed for pwquality");

    platform.capabilities[0] = {
        PamCapability::AuthenticationLockout, PamProviderKind::PamFaillock,
        PamScope::LocalPasswordChange, "/etc/security/faillock.conf",
        PamConfigGrammar::KeyValue,
        PamTopologyStrategyKind::AltTcbManaged,
        "/etc/pam.d/system-auth-local-only"};
    require(pamPolicySupport(
                platform,
                PamPolicyFeature::FailedAuthenticationAttempts) ==
                PamPolicySupport::RequiresTopologyActivation,
            "managed lockout policy did not report topology dependency");
}

} // namespace

int main() {
    try {
        testMinimumsCodec();
        testNativeSyntaxAndPreservation();
        testMalformedAndDuplicateFailClosed();
        testSymlinkAndNonRegularRejection();
        testPostconditionRollback();
        testProviderCatalogAndSupport();
    } catch (const std::exception& error) {
        std::cerr << "PasswdqcConfigFileTests failed: " << error.what() << '\n';
        return 1;
    }
    std::cout << "PasswdqcConfigFileTests passed\n";
    return 0;
}
