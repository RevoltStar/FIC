#include "modules/identity_access/sssd/SssdConfiguration.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace fs = std::filesystem;
namespace s = fic::identity::sssd;
static void check(bool ok, const std::string& why) { if (!ok) throw std::runtime_error(why); }
static void write(const fs::path& path, const std::string& text) {
    std::ofstream out(path); out << text; out.close(); check(bool(out), "write fixture");
    check(::chmod(path.c_str(), 0600) == 0, "chmod fixture");
}
static std::string read(const fs::path& path) {
    std::ifstream in(path); return {std::istreambuf_iterator<char>(in), {}};
}
static void resetHooks() {
    s::setManagedSnippetRemovalRaceHookForTests({});
    s::setManagedSnippetStagedRaceHookForTests({});
    s::setManagedSnippetRemovalCheckpointForTests({});
}
int main() {
    if (::geteuid() != 0) return 77;
    char name[] = "/run/fic-i5-removal-XXXXXX";
    check(::mkdtemp(name), "mkdtemp"); const fs::path dir(name);
    struct Cleanup { fs::path dir; ~Cleanup() { resetHooks(); std::error_code ec; fs::remove_all(dir, ec); } } cleanup{dir};
    try {
        fic::identity::SecureConfigurationFileOptions options;
        options.path = dir / "zzzz-fic.conf"; options.exactMode = 0600;
        fic::identity::SecureConfigurationDirectoryOptions directory;
        const fs::path stage = options.path.string() + ".fic-removing-i5-1-2";
        const std::string content = "[pam]\noffline_credentials_expiration = 10\n\n";
        const auto prepare = [&] {
            resetHooks(); fs::remove_all(options.path); fs::remove_all(stage);
            write(options.path, content); AtomicTargetState expected; std::string error;
            check(AtomicFileWriter::captureTargetState(options.path.string(), expected, &error), error); return expected;
        };
        const auto remove = [&](const AtomicTargetState& expected) {
            return s::removeProvenManagedSnippet(options, directory, expected, stage);
        };
        auto expected = prepare(); auto result = remove(expected);
        check(result.staged && result.removed && result.durable && !result.conflict &&
              !fs::exists(options.path) && !fs::exists(stage), "exact durable removal");
        result = remove(expected); check(!result.removed && !result.durable, "missing artifact is not success");
        expected = prepare();
        // Retain original inode to exclude accidental allocator reuse.
        fs::rename(options.path, dir / "old-inode"); write(options.path, content);
        result = remove(expected); check(result.conflict && !result.staged && read(options.path) == content, "same bytes new inode refused");
        expected = prepare(); write(options.path, "changed");
        result = remove(expected); check(result.conflict && !result.staged && read(options.path) == "changed", "body drift refused");
        expected = prepare(); ::chmod(options.path.c_str(), 0640);
        result = remove(expected); check(result.conflict && !result.staged, "metadata drift refused");
        expected = prepare(); write(stage, "occupied"); result = remove(expected);
        check(!result.staged && !result.removed && read(stage) == "occupied" && read(options.path) == content, "staging collision preserves both");
        expected = prepare();
        s::setManagedSnippetRemovalRaceHookForTests([&] {
            fs::rename(options.path, dir / "owned-before-race"); write(options.path, "foreign");
        });
        result = remove(expected);
        check(result.conflict && !result.removed && read(options.path) == "foreign" && !fs::exists(stage), "foreign rename replacement restored without deletion");
        expected = prepare();
        s::setManagedSnippetStagedRaceHookForTests([&](const fs::path& path) { write(path, "foreign in-place edit"); });
        result = remove(expected);
        check(result.conflict && !result.removed && read(options.path) == "foreign in-place edit", "staged same-inode body drift reproof");
        expected = prepare();
        s::setManagedSnippetStagedRaceHookForTests([&](const fs::path& path) {
            fs::rename(path, dir / "original-staged"); write(path, "foreign staged"); write(options.path, "third version");
        });
        result = remove(expected);
        check(result.conflict && !result.removed && read(options.path) == "third version" && read(stage) == "foreign staged", "no-replace restoration preserves third version and foreign staging");
        expected = prepare();
        auto invalid = s::removeProvenManagedSnippet(options, directory, expected, dir / "other");
        check(!invalid.staged && read(options.path) == content, "non-journal namespace refused");
        for (const std::string phase : {"before_rename_away", "rename_away", "before_staged_reproof", "staged_reproved", "staged_unlink", "before_removal_directory_fsync", "removal_directory_fsync"}) {
            expected = prepare(); const auto child = ::fork(); check(child >= 0, "fork");
            if (child == 0) {
                s::setManagedSnippetRemovalCheckpointForTests([&](const std::string& now) { if (now == phase) ::_exit(74); });
                remove(expected); ::_exit(1);
            }
            int status = 0; check(::waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 74, "real crash at " + phase);
            const bool before = phase == "before_rename_away";
            const bool staged = phase == "rename_away" || phase == "before_staged_reproof" || phase == "staged_reproved";
            check(fs::exists(options.path) == before && fs::exists(stage) == staged, "post-crash paths at " + phase);
            if (before) check(read(options.path) == content, "unarmed original bytes");
            if (staged) {
                AtomicTargetState actual; std::string error;
                check(AtomicFileWriter::captureTargetState(stage.string(), actual, &error) && actual.content == content &&
                      actual.identity.inode == expected.identity.inode && actual.identity.device == expected.identity.device,
                      "post-crash staged identity at " + phase);
            }
            // Physical absence at late seams is deliberately NOT a journal
            // completion or power-loss durability claim.
        }
        std::cout << "PASS: proof-bound removal, foreign preservation and seven real termination seams\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
