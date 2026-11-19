#include "modules/identity_access/pam/PamEmptyPasswordLogin.h"
#include "rollback/MutationJournal.h"

#include <fic/core/fs/AtomicFileWriter.h>

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <unistd.h>

namespace {
namespace fs = std::filesystem;
using namespace fic::identity::pam;
using namespace fic::rollback;

const PolicyRef policy{"IDENTITY_ACCESS", "PAM", emptyPasswordPolicy};

void require(bool condition, const std::string& error) {
    if (!condition) throw std::runtime_error(error);
}

void write(const fs::path& path, const std::string& content) {
    std::ofstream output(path);
    output << content;
    output.close();
    require(bool(output), "write failed: " + path.string());
}

std::string read(const fs::path& path) {
    std::ifstream input(path);
    return {std::istreambuf_iterator<char>(input), {}};
}

void exercise(const fs::path& root) {
    fic::platform::PamPlatformConfig platform;
    platform.configDirectories = {root / "pam.d"};
    platform.moduleDirectories = {root / "modules"};
    platform.emptyPasswordAuthSelection = root / "auth";
    fs::create_directory(platform.configDirectories.front());
    fs::create_directory(platform.moduleDirectories.front());
    for (const char* module : {"pam_deny.so", "pam_unix.so", "pam_localuser.so", "pam_sss.so"})
        write(platform.moduleDirectories.front() / module, "");
    write(platform.emptyPasswordAuthSelection, "Module: unix\nModule: sss\nModule: fic-empty-password-hook\n");
    const auto pam = platform.configDirectories.front();
    const auto slot = pam / emptyPasswordSlot;
    const auto common = pam / "common-auth";
    const auto login = pam / "login";
    const std::string unixRule = "auth [success=2 default=ignore] pam_unix.so";
    const std::string rest =
        "auth [success=1 default=ignore] pam_sss.so use_first_pass\n"
        "auth requisite pam_deny.so\n"
        "auth required pam_permit.so\n"
        "auth substack fic-empty-password\n";
    const auto graph = unixRule + " nullok\n" + rest;
    const auto strictGraph = unixRule + "\n" + rest;
    write(slot, emptyPasswordNeutral);
    write(common, graph);
    write(login, "@include common-auth\n");

    std::string error;
    MutationJournal journal(root / "journal.json");
    require(journal.initializeOrLoad(error), error);
    const auto active = [&] { return journal.activeRecords(policy); };
    const auto apply = [&] { return applyEmptyPasswordLogin(platform, journal, error); };
    const auto release = [&](MutationId id) {
        bool changed = false;
        return releaseEmptyPasswordLogin(platform, id, changed, error);
    };
    const auto prepare = [&] {
        MutationRecord record;
        record.policy = policy;
        record.resource = "capability/" + std::string(emptyPasswordPolicy);
        record.undo.backend = MutationBackend::Pam;
        UndoDisablePamCapability undo;
        undo.capability = emptyPasswordPolicy;
        undo.topology = PamTopologyKind::PamAuthUpdate;
        undo.activationIdentifiers = {emptyPasswordHook};
        record.undo.payload = undo;
        MutationId id = 0;
        require(journal.prepareMutation(record, id, error), error);
        return id;
    };

    write(common, strictGraph);
    require(apply() && active().empty() && read(common) == strictGraph, "observation-only");
    require(release(0) && read(common) == strictGraph, "foreign release");
    write(common,
          "auth [success=3 default=ignore] pam_unix.so nullok\n"
          "auth requisite pam_deny.so\n"
          "auth required pam_permit.so\n"
          "auth substack fic-empty-password\n"
          "auth required pam_permit.so\n");
    require(!apply() && active().empty() && read(slot) == emptyPasswordNeutral,
            "numeric jump must reject candidate and leave no provenance");
    write(common, graph);

    bool sawCandidate = false;
    AtomicFileWriter::setDirectoryFsyncHookForTests([&](const std::string& path) {
        if (path != slot || sawCandidate) return true;
        sawCandidate = read(slot) != emptyPasswordNeutral;
        return false;
    });
    const bool applyAfterFailedFsync = apply();
    AtomicFileWriter::setDirectoryFsyncHookForTests({});
    require(!applyAfterFailedFsync && sawCandidate &&
            read(slot) == emptyPasswordNeutral && active().empty(), "post-rename compensation");

    AtomicFileWriter::setPreInstallHookForTests([&](const std::string& path) {
        if (path == slot) write(slot, "# foreign competing state\n");
    });
    const bool appliedOverForeign = apply();
    AtomicFileWriter::setPreInstallHookForTests({});
    require(!appliedOverForeign && read(slot) == "# foreign competing state\n",
            "CAS conflict must preserve foreign bytes");
    require(active().size() == 1 && active().front().status == MutationStatus::Prepared,
            "unknown effects must retain Prepared");
    require(!apply(), "unknown Prepared must not be re-adopted");
    const auto interrupted = active().front().id;
    write(slot, emptyPasswordNeutral);
    require(apply() && active().size() == 1 && active().front().id != interrupted,
            "neutral Prepared is recovered before new acquire");

    const auto id = active().front().id;
    const auto bytes = read(slot);
    require(apply() && active().front().id == id && read(slot) == bytes, "reapply");
    require(!release(id + 1) && read(slot) == bytes, "wrong ID");
    fs::remove(slot);
    require(!apply() && !release(id) && !fs::exists(slot) && active().front().id == id,
            "missing slot must not be recreated or lose provenance");
    write(slot, bytes);
    bool sawNeutral = false;
    AtomicFileWriter::setDirectoryFsyncHookForTests([&](const std::string& path) {
        if (path != slot || sawNeutral) return true;
        sawNeutral = read(slot) == emptyPasswordNeutral;
        return false;
    });
    const bool releasedAfterFailedFsync = release(id);
    AtomicFileWriter::setDirectoryFsyncHookForTests({});
    require(!releasedAfterFailedFsync && sawNeutral && read(slot) == bytes &&
            active().front().id == id, "post-rename release compensation");
    write(slot, bytes + "# external edit\n");
    require(!release(id) && !apply(), "changed slot must be preserved");
    write(slot, emptyPasswordNeutral);
    write(common, strictGraph);
    require(!apply(), "foreign strict graph must not conceal loss of owned slot");
    write(slot, bytes);
    fs::remove(platform.moduleDirectories.front() / "pam_unix.so");
    require(release(id) && read(slot) == emptyPasswordNeutral &&
            read(common) == strictGraph && release(id), "release without available module");
    require(journal.setStatus(id, MutationStatus::RolledBack, error), error);

    write(platform.moduleDirectories.front() / "pam_unix.so", "");
    write(common, graph);
    const auto prepared = prepare();
    write(slot, bytes);
    require(!apply() && !proveEmptyPasswordSlot(platform, journal, error),
            "Prepared cannot adopt previous physical witness");
    const auto marker = bytes.find("mutation=");
    require(marker != std::string::npos, "missing physical witness");
    const auto target = bytes.substr(0, marker) + "mutation=" + std::to_string(prepared) +
                        bytes.substr(bytes.find('\n', marker));
    write(slot, target);
    require(apply() && active().front().id == prepared &&
            active().front().status == MutationStatus::Applied, "durable Prepared AFTER recovery");
    require(release(prepared), error);
    require(journal.setStatus(prepared, MutationStatus::RolledBack, error), error);
    write(slot, target);
    require(!apply() && !release(0) && !proveEmptyPasswordSlot(platform, journal, error),
            "orphan cannot be adopted or released");
}
}

int main() {
    // This test is opt-in for the disposable Debian container. The writer
    // requires root-controlled ancestors, so a fixture below /tmp is unsafe.
    if (geteuid() != 0 || !std::getenv("FIC_PACKAGE_LIFECYCLE_NATIVE")) return 2;
    char path[] = "/run/fic-empty-password-test.XXXXXX";
    if (!mkdtemp(path)) return 3;
    try {
        exercise(path);
        fs::remove_all(path);
        std::cout << "D13 empty-password ownership tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        fs::remove_all(path);
        std::cerr << error.what() << '\n';
        return 1;
    }
}
