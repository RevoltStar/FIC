#include "modules/identity_access/pam/PasswdqcConfigFile.h"
#include "modules/identity_access/pam/PamProviderCatalog.h"

#include <fic/core/fs/AtomicFileWriter.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <set>
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
    std::filesystem::create_directories(path.parent_path());
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
              "  # administrator comment\n"
              "  max=72  \n"
              " non-unix\n"
              "min=24,11,8,7,7\n");
    std::string error;
    require(fic::identity::pam::PasswdqcConfigFile::setValue(
                path, "min", "disabled,24,11,8,7", error), error);
    const std::string content = readFile(path);
    require(content ==
                "  # administrator comment\n"
                "  max=72  \n"
                " non-unix\n"
                "min=disabled,24,11,8,7\n",
            "passwdqc writer did not preserve native comments/options or "
            "did not emit exact option=value syntax");
    require(fic::identity::pam::PasswdqcConfigFile::setValue(
                path, "retry", "3", error), error);
    require(readFile(path).find("retry=3\n") != std::string::npos,
            "passwdqc writer did not append an exact assignment");
}

void testNativeValidationAndDuplicateOrdering() {
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
    fic::identity::pam::PasswdqcEffectiveState duplicateState;
    require(fic::identity::pam::PasswdqcConfigEvaluator::evaluate(
                path, duplicateState, error) && duplicateState.retry == 4,
            "native last-wins duplicate semantics were not preserved");
    require(fic::identity::pam::PasswdqcConfigFile::setValue(
                path, "retry", "5", error),
            error);
    require(readFile(path) == "retry=5\n",
            "managed duplicates were not canonicalized deterministically");

    writeFile(path, "min=+24,24,11,8,7\n");
    fic::identity::pam::PasswdqcEffectiveState nativeMinimums;
    require(fic::identity::pam::PasswdqcConfigEvaluator::evaluate(
                path, nativeMinimums, error),
            "native passwdqc minimum syntax accepted upstream was rejected: " +
                error);
    std::string nativeMinimumValue;
    require(nativeMinimums.managedValue(
                "min", nativeMinimumValue, error) &&
                nativeMinimumValue == "24,24,11,8,7",
            "native passwdqc minimums were not canonicalized effectively");
    require(!fic::identity::pam::PasswdqcConfigFile::setValue(
                path, "similar", "maybe", error),
            "invalid passwdqc enum was accepted");

    writeFile(path, "max=garbage\nmin=24,11,8,7,7\n");
    const std::string invalidValueOriginal = readFile(path);
    require(!fic::identity::pam::PasswdqcConfigFile::setValue(
                path, "min", "disabled,24,11,8,7", error),
            "an invalid existing native passwdqc value was ignored");
    require(readFile(path) == invalidValueOriginal,
            "config with an invalid native passwdqc value was modified");

    writeFile(path, "vendor_option=value\nmin=24,11,8,7,7\n");
    const std::string unknownOriginal = readFile(path);
    require(!fic::identity::pam::PasswdqcConfigFile::setValue(
                path, "min", "disabled,24,11,8,7", error),
            "unknown native passwdqc parameter was treated as safe");
    require(readFile(path) == unknownOriginal,
            "config with an unknown native parameter was modified");

    writeFile(path,
              "ask_oldauthtok=update\n"
              "check_oldauthtok\n"
              "use_authtok\n"
              "noaudit\n");
    fic::identity::pam::PasswdqcEffectiveState flags;
    require(fic::identity::pam::PasswdqcConfigEvaluator::evaluate(
                path, flags, error) && flags.askOldAuthTokenDuringUpdate &&
                flags.checkOldAuthToken && flags.useAuthToken && flags.noAudit,
            "valid native passwdqc flags were rejected");
}

void testIncludesAndEffectiveOrdering() {
    using fic::identity::pam::PasswdqcConfigEvaluator;
    using fic::identity::pam::PasswdqcEffectiveState;
    TemporaryDirectory temp;
    const auto root = temp.path / "passwdqc.conf";
    const auto child = temp.path / "child.conf";
    const auto grandchild = temp.path / "grandchild.conf";
    std::string error;

    writeFile(child, "min=disabled,20,10,8,7\n");
    writeFile(root,
              "min=disabled,24,11,8,7\n"
              "config=" + child.string() + "\n");
    PasswdqcEffectiveState state;
    require(PasswdqcConfigEvaluator::evaluate(root, state, error), error);
    std::string value;
    require(state.managedValue("min", value, error) &&
                value == "disabled,20,10,8,7",
            "include after assignment did not override effective min");

    writeFile(root,
              "config=" + child.string() + "\n"
              "min=disabled,24,11,8,7\n");
    require(PasswdqcConfigEvaluator::evaluate(root, state, error), error);
    require(state.managedValue("min", value, error) &&
                value == "disabled,24,11,8,7",
            "assignment after include did not override effective min");

    writeFile(grandchild, "retry=9\n");
    writeFile(child, "config=" + grandchild.string() + "\nretry=8\n");
    writeFile(root, "config=" + child.string() + "\n");
    require(PasswdqcConfigEvaluator::evaluate(root, state, error) &&
                state.retry == 8,
            "nested include ordering is incorrect");

    writeFile(child, "config=" + root.string() + "\n");
    require(!PasswdqcConfigEvaluator::evaluate(root, state, error) &&
                error.find("loop") != std::string::npos,
            "passwdqc config include loop was accepted");

    writeFile(root, "config=" + (temp.path / "missing").string() + "\n");
    require(!PasswdqcConfigEvaluator::evaluate(root, state, error),
            "missing nested passwdqc config was accepted");

    writeFile(child, "retry=4\n");
    const auto link = temp.path / "child-link.conf";
    require(::symlink(child.c_str(), link.c_str()) == 0,
            "could not create nested symlink fixture");
    writeFile(root, "config=" + link.string() + "\n");
    require(!PasswdqcConfigEvaluator::evaluate(root, state, error) &&
                error.find("symbolic link") != std::string::npos,
            "nested passwdqc symlink was followed");

    writeFile(root, "config=" + temp.path.string() + "\n");
    require(!PasswdqcConfigEvaluator::evaluate(root, state, error) &&
                error.find("non-regular") != std::string::npos,
            "nested non-regular passwdqc target was accepted");

    writeFile(child, "retry=4\n");
    require(::chmod(child.c_str(), 0666) == 0,
            "could not create unsafe permissions fixture");
    writeFile(root, "config=" + child.string() + "\n");
    require(!PasswdqcConfigEvaluator::evaluate(root, state, error) &&
                error.find("writable by group or others") != std::string::npos,
            "unsafe nested passwdqc permissions were accepted");
}

void testManagedEffectiveValuesAndMutation() {
    TemporaryDirectory temp;
    const auto root = temp.path / "passwdqc.conf";
    const auto child = temp.path / "child.conf";
    writeFile(child,
              "min=disabled,20,10,8,7\n"
              "passphrase=4\nmatch=5\nsimilar=permit\n"
              "enforce=users\nretry=6\n");
    writeFile(root, "config=" + child.string() + "\n");
    const std::vector<std::pair<std::string, std::string>> requested{
        {"min", "disabled,24,11,8,7"},
        {"passphrase", "3"},
        {"match", "4"},
        {"similar", "deny"},
        {"enforce", "everyone"},
        {"retry", "0"}
    };
    std::string error;
    for (const auto& [option, value] : requested) {
        require(fic::identity::pam::PasswdqcConfigFile::setValue(
                    root, option, value, error), error);
        require(fic::identity::pam::PasswdqcConfigFile::hasEffectiveValue(
                    root, option, value, error), error);
    }
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

    const auto unsafe = temp.path / "unsafe.conf";
    writeFile(unsafe, "retry=3\n");
    require(::chmod(unsafe.c_str(), 0666) == 0,
            "could not create unsafe root permissions fixture");
    require(!fic::identity::pam::PasswdqcConfigFile::setValue(
                unsafe, "retry", "4", error) &&
                error.find("writable by group or others") != std::string::npos,
            "passwdqc writer accepted unsafe root permissions");
    require(readFile(unsafe) == "retry=3\n",
            "unsafe passwdqc root was modified");
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

    const auto child = temp.path / "child.conf";
    writeFile(child, "retry=9\n");
    writes = 0;
    const auto nestedOverrideWriter =
        [&](const std::string& target,
            const std::string& content,
            const AtomicWriteOptions& options,
            std::string* writerError) {
            ++writes;
            const std::string actual = writes == 1
                ? "retry=4\nconfig=" + child.string() + "\n"
                : content;
            return AtomicFileWriter::write(
                target, actual, options, writerError);
        };
    require(!fic::identity::pam::PasswdqcConfigFile::setValue(
                path, "retry", "4", error, nestedOverrideWriter),
            "nested effective override was reported as success");
    require(writes == 2 && readFile(path) == original,
            "nested effective override failure was not rolled back");

    const auto failingWriter =
        [](const std::string&,
           const std::string&,
           const AtomicWriteOptions&,
           std::string* writerError) {
            if (writerError != nullptr) {
                *writerError = "injected write failure";
            }
            return false;
        };
    require(!fic::identity::pam::PasswdqcConfigFile::setValue(
                path, "retry", "4", error, failingWriter),
            "injected passwdqc write failure was reported as success");
    require(readFile(path) == original,
            "failed passwdqc write changed the original config");
}

void testProviderCatalogAndSupport() {
    using namespace fic::platform;
    using namespace fic::identity::pam;
    const auto& passwdqc = pamProviderDescriptor(PamProviderKind::PamPasswdqc);
    require(std::string(passwdqc.externalConfigArgument) == "config" &&
                passwdqc.externalConfigMode ==
                    PamExternalConfigMode::Required &&
                passwdqc.grammar == PamConfigGrammar::Passwdqc,
            "passwdqc descriptor has the wrong config contract");
    std::set<PamProviderKind> providerKinds;
    for (const auto& descriptor : pamProviderDescriptors()) {
        require(providerKinds.insert(descriptor.kind).second,
                "duplicate PAM provider descriptor");
        require(descriptor.name[0] != '\0' && descriptor.moduleName[0] != '\0',
                "PAM provider descriptor has empty identity metadata");
        require(
            (descriptor.externalConfigMode == PamExternalConfigMode::None) ==
                (descriptor.externalConfigArgument[0] == '\0'),
            "PAM provider external config mode/argument are inconsistent");
        std::set<PamPolicyFeature> features;
        for (const auto& binding : descriptor.policies) {
            require(features.insert(binding.feature).second,
                    "duplicate feature in PAM provider descriptor");
            require(pamPolicyCapability(binding.feature) ==
                        descriptor.capability,
                    "PAM provider binding belongs to another capability");
        }
    }
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
    platform.capabilities.push_back({
        PamCapability::PasswordHistory, PamProviderKind::PamPwhistory,
        PamScope::LocalPasswordChange, "/etc/security/pwhistory.conf",
        PamTopologyStrategyKind::StaticReadOnly, {}});
    require(pamPolicySupport(
                platform, PamPolicyFeature::PasswordHistoryDepth) ==
                PamPolicySupport::Supported,
            "synthetic passwdqc composition lost pwhistory support");
    platform.capabilities.pop_back();

    platform.capabilities[0] = {
        PamCapability::PasswordQuality, PamProviderKind::PamPwquality,
        PamScope::LocalPasswordChange, "/etc/security/pwquality.conf",
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
        testNativeValidationAndDuplicateOrdering();
        testIncludesAndEffectiveOrdering();
        testManagedEffectiveValuesAndMutation();
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
