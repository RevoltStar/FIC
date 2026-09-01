#include "modules/identity_access/pam/AltPamPasswordHistoryTopologyManager.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>

#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;
using fic::identity::pam::AltPamPasswordHistoryTopologyManager;
using fic::identity::pam::AltPamPasswordHistoryTopologyOptions;
using fic::identity::pam::AltPamPasswordHistoryTopologyState;

namespace {

const std::string kCanonical =
    "#%PAM-1.0\n"
    "password\trequired\tpam_passwdqc.so config=/etc/passwdqc.conf\n"
    "password\trequired\tpam_tcb.so use_authtok shadow fork nullok write_to=tcb\n";

void require(bool condition, const std::string& message) {
    if (!condition)
        throw std::runtime_error(message);
}

class TemporaryTree {
public:
    TemporaryTree() {
        std::string pattern =
            (fs::temp_directory_path() / "fic-alt-pwhistory-XXXXXX").string();
        char* created = ::mkdtemp(pattern.data());
        if (created == nullptr)
            throw std::runtime_error("cannot create temporary tree");
        root = created;
        fs::create_directories(root / "pam.d");
        fs::create_directories(root / "security-modules");
        fs::create_directories(root / "run");
        write(target(), kCanonical);
    }

    ~TemporaryTree() {
        std::error_code ignored;
        fs::remove_all(root, ignored);
    }

    static void write(const fs::path& path, const std::string& content) {
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        output << content;
        output.close();
        ::chmod(path.c_str(), 0644);
    }

    static std::string read(const fs::path& path) {
        std::ifstream input(path, std::ios::binary);
        return {std::istreambuf_iterator<char>(input),
                std::istreambuf_iterator<char>()};
    }

    fs::path target() const { return root / "pam.d/system-auth-local-only"; }

    fic::platform::PamPlatformConfig platform() const {
        fic::platform::PamPlatformConfig result;
        result.configDirectories = {root / "pam.d"};
        result.moduleDirectories = {root / "security-modules"};
        result.scopes = {
            {fic::platform::PamScope::LocalPasswordChange,
             {"system-auth-local-only"}}
        };
        result.capabilities = {{
            fic::platform::PamCapability::PasswordHistory,
            fic::platform::PamProviderKind::PamPwhistory,
            fic::platform::PamScope::LocalPasswordChange,
            "/etc/security/fic-pwhistory.conf",
            fic::platform::PamTopologyStrategyKind::AltTcbManaged,
            target()}};
        return result;
    }

    AltPamPasswordHistoryTopologyOptions options(bool semantic = true) const {
        AltPamPasswordHistoryTopologyOptions result;
        result.lockFilePath = root / "run/topology.lock";
        result.lockDebugLogPath = root / "lock-debug.log";
        result.stateDirectory = root / "state";
        result.historyFile = result.stateDirectory / "opasswd";
        result.transactionLockFile = result.stateDirectory / ".lock";
        result.storageOwner = ::geteuid();
        result.storageGroup = ::getegid();
        result.semanticVerifier = [semantic](std::string& error) {
            if (!semantic) {
                error = "injected semantic failure";
                return false;
            }
            error.clear();
            return true;
        };
        return result;
    }

    fs::path root;
};

void testRoundTripAndStorage() {
    TemporaryTree tree;
    AltPamPasswordHistoryTopologyManager manager(
        tree.platform(), tree.options());
    std::string error;
    AltPamPasswordHistoryTopologyState state;
    require(manager.status(state, error) &&
                state == AltPamPasswordHistoryTopologyState::Disabled,
            error);
    require(manager.enable(error), error);
    const std::string enabled = TemporaryTree::read(tree.target());
    require(enabled.find(AltPamPasswordHistoryTopologyManager::LOCK_RULE) !=
                std::string::npos &&
                enabled.find(AltPamPasswordHistoryTopologyManager::HISTORY_RULE) !=
                    std::string::npos,
            "managed password-history rules are missing");
    require(manager.enable(error), "enable must be idempotent: " + error);
    require(manager.status(state, error) &&
                state == AltPamPasswordHistoryTopologyState::Enabled,
            error);
    struct stat info {};
    require(::lstat((tree.root / "state").c_str(), &info) == 0 &&
                (info.st_mode & 07777) == 02730,
            "storage directory mode is incorrect");
    require(::lstat((tree.root / "state/opasswd").c_str(), &info) == 0 &&
                (info.st_mode & 0777) == 0660 && info.st_nlink == 1,
            "history file metadata is incorrect");
    require(manager.disable(error), error);
    require(TemporaryTree::read(tree.target()) == kCanonical,
            "disable did not restore exact PAM content");
    require(manager.disable(error), "disable must be idempotent: " + error);
}

void testExternalProviderIsRejected() {
    TemporaryTree tree;
    TemporaryTree::write(tree.target(), kCanonical +
        "password required pam_pwhistory.so use_authtok\n");
    AltPamPasswordHistoryTopologyManager manager(
        tree.platform(), tree.options());
    std::string error;
    require(!manager.enable(error),
            "external pam_pwhistory topology was accepted");
    require(TemporaryTree::read(tree.target()).find(
                AltPamPasswordHistoryTopologyManager::BEGIN) ==
                std::string::npos,
            "rejected topology changed the target");
}

void testExternalIncludedProviderIsRejected() {
    TemporaryTree tree;
    TemporaryTree::write(tree.root / "pam.d/external-history",
        "password required pam_pwhistory.so use_authtok\n");
    TemporaryTree::write(tree.target(), kCanonical +
        "password include external-history\n");
    AltPamPasswordHistoryTopologyManager manager(
        tree.platform(), tree.options());
    std::string error;
    require(!manager.enable(error),
            "included external pam_pwhistory topology was accepted");
    require(TemporaryTree::read(tree.target()).find(
                AltPamPasswordHistoryTopologyManager::BEGIN) ==
                std::string::npos,
            "included-provider rejection changed the target");
}

void testBrokenMarkersFailClosed() {
    TemporaryTree tree;
    TemporaryTree::write(tree.target(),
        std::string(AltPamPasswordHistoryTopologyManager::BEGIN) + "\n" +
        kCanonical);
    AltPamPasswordHistoryTopologyManager manager(
        tree.platform(), tree.options());
    std::string error;
    require(!manager.disable(error), "broken managed block was removed");
}

void testPostconditionFailureRollsBack() {
    TemporaryTree tree;
    AltPamPasswordHistoryTopologyManager manager(
        tree.platform(), tree.options(false));
    std::string error;
    require(!manager.enable(error), "injected verification failure was ignored");
    require(TemporaryTree::read(tree.target()) == kCanonical,
            "failed enable did not restore exact original content");
}

} // namespace

int main() {
    try {
        testRoundTripAndStorage();
        testExternalProviderIsRejected();
        testExternalIncludedProviderIsRejected();
        testBrokenMarkersFailClosed();
        testPostconditionFailureRollsBack();
    } catch (const std::exception& exception) {
        std::cerr << exception.what() << std::endl;
        return 1;
    }
    return 0;
}
