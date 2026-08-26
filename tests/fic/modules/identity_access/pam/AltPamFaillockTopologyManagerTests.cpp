#include "modules/identity_access/pam/AltPamFaillockTopologyManager.h"

#include <fic/core/fs/AtomicFileWriter.h>

#include <cassert>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <utility>

#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;
using fic::identity::pam::AltPamFaillockTopologyManager;
using fic::identity::pam::AltPamFaillockTopologyOptions;
using fic::identity::pam::AltPamFaillockTopologyState;

namespace {

const std::string kCanonical =
    "#%PAM-1.0\n"
    "auth\t\trequired\tpam_tcb.so shadow fork nullok\n"
    "account\t\trequired\tpam_tcb.so shadow fork\n"
    "password\trequired\tpam_passwdqc.so config=/etc/passwdqc.conf\n"
    "password\trequired\tpam_tcb.so use_authtok shadow fork nullok write_to=tcb\n"
    "session\t\trequired\tpam_tcb.so\n";

class TemporaryTree {
public:
    TemporaryTree() {
        std::string pattern =
            (fs::temp_directory_path() / "fic-alt-pam-topology-XXXXXX").string();
        char* created = ::mkdtemp(pattern.data());
        if (created == nullptr) {
            throw std::runtime_error("cannot create temporary tree");
        }
        root = created;
        fs::create_directories(root / "pam.d");
        fs::create_directories(root / "security-modules");
        fs::create_directories(root / "run");
        write(root / "pam.d/system-auth",
              "auth include system-auth-local-only\n"
              "account include system-auth-local-only\n"
              "password include system-auth-local-only\n"
              "session include system-auth-local-only\n");
        write(root / "pam.d/system-auth-local-only", kCanonical);
        write(root / "security-modules/pam_faillock.so", "fixture\n", 0555);
    }

    ~TemporaryTree() {
        std::error_code ignored;
        fs::remove_all(root, ignored);
    }

    static void write(const fs::path& path,
                      const std::string& content,
                      mode_t mode = 0644) {
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        if (!output.is_open()) {
            throw std::runtime_error("cannot write " + path.string());
        }
        output << content;
        output.close();
        ::chmod(path.c_str(), mode);
    }

    static std::string read(const fs::path& path) {
        std::ifstream input(path, std::ios::binary);
        return std::string(
            std::istreambuf_iterator<char>(input),
            std::istreambuf_iterator<char>());
    }

    fic::platform::PamPlatformConfig platform() const {
        fic::platform::PamPlatformConfig result;
        result.configDirectories = {root / "pam.d"};
        result.moduleDirectories = {root / "security-modules"};
        result.authenticationServices = {"system-auth"};
        result.passwordServices = {"system-auth"};
        result.faillockConfigPath = root / "faillock.conf";
        result.passwordQualityConfigPath = root / "pwquality.conf";
        result.passwordHistoryConfigPath = root / "pwhistory.conf";
        result.localAuthenticationStackPath =
            root / "pam.d/system-auth-local-only";
        return result;
    }

    AltPamFaillockTopologyOptions options() const {
        AltPamFaillockTopologyOptions result;
        result.lockFilePath = root / "run/pam-faillock.lock";
        result.lockDebugLogPath = root / "lock-debug.log";
        return result;
    }

    fs::path target() const {
        return root / "pam.d/system-auth-local-only";
    }

    fs::path root;
};

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

std::size_t count(const std::string& value, const std::string& needle) {
    std::size_t result = 0;
    std::size_t offset = 0;
    while ((offset = value.find(needle, offset)) != std::string::npos) {
        ++result;
        offset += needle.size();
    }
    return result;
}

std::string enabledFixture() {
    TemporaryTree tree;
    AltPamFaillockTopologyManager manager(tree.platform(), tree.options());
    std::string error;
    require(manager.enable(error), error);
    return TemporaryTree::read(tree.target());
}

void testCanonicalRoundTrip() {
    TemporaryTree tree;
    AltPamFaillockTopologyManager manager(tree.platform(), tree.options());
    std::string error;
    AltPamFaillockTopologyState state;
    require(manager.status(state, error) &&
                state == AltPamFaillockTopologyState::Disabled,
            error);
    require(manager.enable(error), error);
    const std::string enabled = TemporaryTree::read(tree.target());
    require(enabled.find(
                std::string(AltPamFaillockTopologyManager::PREAUTH_BEGIN) +
                "\n" + AltPamFaillockTopologyManager::PREAUTH_RULE + "\n") !=
                std::string::npos,
            "preauth block is missing");
    require(enabled.find(
                std::string(AltPamFaillockTopologyManager::AUTHFAIL_BEGIN) +
                "\n" + AltPamFaillockTopologyManager::AUTHFAIL_RULE + "\n") !=
                std::string::npos,
            "authfail block is missing");
    require(enabled.find(
                std::string(AltPamFaillockTopologyManager::ACCOUNT_BEGIN) +
                "\n" + AltPamFaillockTopologyManager::ACCOUNT_RULE + "\n") !=
                std::string::npos,
            "account block is missing");
    require(manager.status(state, error) &&
                state == AltPamFaillockTopologyState::Enabled,
            error);
    require(manager.enable(error), error);
    require(TemporaryTree::read(tree.target()) == enabled,
            "second enable changed the file");
    require(manager.disable(error), error);
    require(TemporaryTree::read(tree.target()) == kCanonical,
            "enable-disable did not restore exact original bytes");
    require(manager.disable(error), error);
}

void testWhitespaceAndUnrelatedContent() {
    TemporaryTree tree;
    const std::string fixture =
        "# administrator comment\n"
        "auth    required    pam_tcb.so   shadow fork nullok\n"
        "auth optional pam_env.so\n"
        "account    required    pam_tcb.so shadow fork\n"
        "password required pam_passwdqc.so config=/etc/passwdqc.conf\n"
        "session required pam_tcb.so";
    TemporaryTree::write(tree.target(), fixture);
    AltPamFaillockTopologyManager manager(tree.platform(), tree.options());
    std::string error;
    require(manager.enable(error), error);
    require(manager.disable(error), error);
    require(TemporaryTree::read(tree.target()) == fixture,
            "whitespace/unrelated bytes were not preserved");
}

void testExternalTopologyRejected() {
    TemporaryTree tree;
    const std::string external =
        "#%PAM-1.0\n"
        "auth requisite pam_faillock.so preauth\n"
        "auth sufficient pam_tcb.so shadow fork nullok\n"
        "auth [default=die] pam_faillock.so authfail\n"
        "account required pam_faillock.so\n"
        "account required pam_tcb.so shadow fork\n";
    TemporaryTree::write(tree.target(), external);
    AltPamFaillockTopologyManager manager(tree.platform(), tree.options());
    std::string error;
    require(!manager.enable(error) &&
                error.find("external pam_faillock topology") != std::string::npos,
            "external topology was not rejected");
    require(TemporaryTree::read(tree.target()) == external,
            "external topology was modified");

    const std::string partial =
        "auth required pam_tcb.so\n"
        "auth [default=die] pam_faillock.so authfail\n"
        "account required pam_tcb.so\n";
    TemporaryTree::write(tree.target(), partial);
    require(!manager.enable(error), "partial external topology was accepted");
    require(TemporaryTree::read(tree.target()) == partial,
            "partial external topology was modified");
}

void testBrokenMarkersRejected() {
    for (const std::string& broken : {
             std::string(AltPamFaillockTopologyManager::PREAUTH_BEGIN) + "\n" +
                 AltPamFaillockTopologyManager::PREAUTH_RULE + "\n" + kCanonical,
             std::string(AltPamFaillockTopologyManager::PREAUTH_BEGIN) + "\n" +
                 AltPamFaillockTopologyManager::PREAUTH_RULE + "\n" +
                 AltPamFaillockTopologyManager::PREAUTH_END + "\n" +
                 AltPamFaillockTopologyManager::PREAUTH_BEGIN + "\n" +
                 AltPamFaillockTopologyManager::PREAUTH_RULE + "\n" +
                 AltPamFaillockTopologyManager::PREAUTH_END + "\n" + kCanonical,
             std::string(AltPamFaillockTopologyManager::ORIGINAL_AUTH_PREFIX) +
                 "00\n" + kCanonical}) {
        TemporaryTree tree;
        TemporaryTree::write(tree.target(), broken);
        AltPamFaillockTopologyManager manager(tree.platform(), tree.options());
        std::string error;
        AltPamFaillockTopologyState state;
        require(!manager.status(state, error), "broken markers have a status");
        require(!manager.enable(error), "broken markers were enabled");
        require(!manager.disable(error), "broken markers were disabled");
        require(TemporaryTree::read(tree.target()) == broken,
                "broken managed state was modified");
    }

    TemporaryTree tree;
    AltPamFaillockTopologyManager manager(tree.platform(), tree.options());
    std::string error;
    require(manager.enable(error), error);
    std::string modified = TemporaryTree::read(tree.target());
    const std::size_t rule = modified.find(
        AltPamFaillockTopologyManager::AUTHFAIL_RULE);
    require(rule != std::string::npos, "authfail fixture rule is missing");
    modified.replace(rule, std::strlen(
                         AltPamFaillockTopologyManager::AUTHFAIL_RULE),
                     "auth optional pam_faillock.so authfail");
    TemporaryTree::write(tree.target(), modified);
    AltPamFaillockTopologyState state;
    require(!manager.status(state, error),
            "modified managed block has a status");
    require(!manager.enable(error), "modified managed block was enabled");
    require(!manager.disable(error), "modified managed block was disabled");
    require(TemporaryTree::read(tree.target()) == modified,
            "modified managed block was changed");
}

void testManagedPlacementChangeRejectedButRemovable() {
    TemporaryTree tree;
    AltPamFaillockTopologyManager manager(tree.platform(), tree.options());
    std::string error;
    require(manager.enable(error), error);
    std::string moved = TemporaryTree::read(tree.target());
    const std::string boundary =
        std::string(AltPamFaillockTopologyManager::PREAUTH_END) + "\n" +
        AltPamFaillockTopologyManager::AUTHFAIL_BEGIN;
    const std::size_t position = moved.find(boundary);
    require(position != std::string::npos,
            "managed block boundary is missing");
    const std::string external = "auth optional pam_env.so\n";
    moved.insert(position + std::strlen(
                     AltPamFaillockTopologyManager::PREAUTH_END) + 1,
                 external);
    TemporaryTree::write(tree.target(), moved);
    AltPamFaillockTopologyState state;
    require(!manager.status(state, error),
            "moved managed topology has enabled status");
    require(!manager.enable(error),
            "moved managed topology was accepted by enable");
    require(manager.disable(error), error);
    require(TemporaryTree::read(tree.target()) ==
                std::string("#%PAM-1.0\n") +
                    "auth\t\trequired\tpam_tcb.so shadow fork nullok\n" +
                    external +
                    "account\t\trequired\tpam_tcb.so shadow fork\n" +
                    "password\trequired\tpam_passwdqc.so "
                    "config=/etc/passwdqc.conf\n" +
                    "password\trequired\tpam_tcb.so use_authtok shadow fork "
                    "nullok write_to=tcb\n" +
                    "session\t\trequired\tpam_tcb.so\n",
            "disable did not preserve the line outside moved managed blocks");
}

void testMissingAndAmbiguousAnchors() {
    for (const std::string& fixture : {
             std::string("account required pam_tcb.so\n"),
             std::string("auth required pam_tcb.so\nauth required pam_tcb.so\n") +
                 "account required pam_tcb.so\n",
             std::string("auth required pam_tcb.so\n"),
             std::string("auth optional pam_tcb.so\n") +
                 "account required pam_tcb.so\n"}) {
        TemporaryTree tree;
        TemporaryTree::write(tree.target(), fixture);
        AltPamFaillockTopologyManager manager(tree.platform(), tree.options());
        std::string error;
        require(!manager.enable(error), "invalid anchors were accepted");
        require(TemporaryTree::read(tree.target()) == fixture,
                "invalid-anchor file was modified");
    }
}

void testDisablePostconditionRollback() {
    TemporaryTree tree;
    AltPamFaillockTopologyManager setup(tree.platform(), tree.options());
    std::string error;
    require(setup.enable(error), error);
    const std::string enabled = TemporaryTree::read(tree.target());

    auto options = tree.options();
    std::size_t writes = 0;
    options.writer = [&writes](const std::string& path,
                               const std::string& content,
                               const AtomicWriteOptions& writeOptions,
                               std::string* writeError) {
        ++writes;
        const std::string actual = writes == 1
            ? content + "# BEGIN FIC pam_faillock unexpected\n"
            : content;
        return AtomicFileWriter::write(
            path, actual, writeOptions, writeError);
    };
    AltPamFaillockTopologyManager manager(
        tree.platform(), std::move(options));
    require(!manager.disable(error) &&
                error.find("original PAM configuration restored") !=
                    std::string::npos,
            "disable postcondition failure did not trigger rollback");
    require(TemporaryTree::read(tree.target()) == enabled,
            "disable rollback did not restore enabled bytes");
    AltPamFaillockTopologyState state;
    require(manager.status(state, error) &&
                state == AltPamFaillockTopologyState::Enabled,
            "disable rollback did not restore effective enabled state: " + error);
}

void testSymlinkRejected() {
    TemporaryTree tree;
    const fs::path real = tree.root / "pam.d/real-stack";
    TemporaryTree::write(real, kCanonical);
    fs::remove(tree.target());
    fs::create_symlink(real.filename(), tree.target());
    AltPamFaillockTopologyManager manager(tree.platform(), tree.options());
    std::string error;
    require(!manager.enable(error) && error.find("symbolic-link") != std::string::npos,
            "symlink target was accepted");
    require(TemporaryTree::read(real) == kCanonical,
            "symlink target was modified");
}

void testPostconditionRollback() {
    TemporaryTree tree;
    auto options = tree.options();
    options.semanticVerifier = [](std::string& error) {
        error = "injected semantic failure";
        return false;
    };
    AltPamFaillockTopologyManager manager(tree.platform(), std::move(options));
    std::string error;
    require(!manager.enable(error) &&
                error.find("original PAM configuration restored") !=
                    std::string::npos,
            "semantic failure did not trigger verified rollback");
    require(TemporaryTree::read(tree.target()) == kCanonical,
            "rollback did not restore original bytes");
}

void testRollbackFailureIsCritical() {
    TemporaryTree tree;
    auto options = tree.options();
    std::size_t writes = 0;
    options.writer = [&writes](const std::string& path,
                               const std::string& content,
                               const AtomicWriteOptions& writeOptions,
                               std::string* error) {
        ++writes;
        if (writes == 2) {
            if (error != nullptr) {
                *error = "injected rollback write failure";
            }
            return false;
        }
        return AtomicFileWriter::write(path, content, writeOptions, error);
    };
    options.semanticVerifier = [](std::string& error) {
        error = "injected semantic failure";
        return false;
    };
    AltPamFaillockTopologyManager manager(tree.platform(), std::move(options));
    std::string error;
    require(!manager.enable(error) && error.find("CRITICAL") != std::string::npos &&
                error.find("may be inconsistent") != std::string::npos,
            "rollback failure was not reported as critical");
}

void testDisablePreservesExternalLines() {
    TemporaryTree tree;
    AltPamFaillockTopologyManager manager(tree.platform(), tree.options());
    std::string error;
    require(manager.enable(error), error);
    std::string mixed = TemporaryTree::read(tree.target());
    const std::string external = "auth optional pam_faillock.so silent\n";
    mixed += external;
    TemporaryTree::write(tree.target(), mixed);
    require(manager.disable(error), error);
    const std::string disabled = TemporaryTree::read(tree.target());
    require(disabled == kCanonical + external,
            "disable removed or changed administrator-owned faillock line");
}

void testGeneratedRulesContainNoPolicyValues() {
    const std::string enabled = enabledFixture();
    for (const char* forbidden : {
             "deny=", "fail_interval=", "unlock_time=", "even_deny_root",
             "root_unlock_time="}) {
        require(enabled.find(forbidden) == std::string::npos,
                std::string("generated topology contains policy value: ") + forbidden);
    }
    require(count(enabled, "pam_faillock.so") == 3,
            "generated topology has an unexpected faillock call count");
}

} // namespace

int main() {
    try {
        testCanonicalRoundTrip();
        testWhitespaceAndUnrelatedContent();
        testExternalTopologyRejected();
        testBrokenMarkersRejected();
        testManagedPlacementChangeRejectedButRemovable();
        testMissingAndAmbiguousAnchors();
        testSymlinkRejected();
        testPostconditionRollback();
        testDisablePostconditionRollback();
        testRollbackFailureIsCritical();
        testDisablePreservesExternalLines();
        testGeneratedRulesContainNoPolicyValues();
        return 0;
    } catch (const std::exception& exception) {
        std::cerr << exception.what() << std::endl;
        return 1;
    }
}
