#include "modules/oss/grub/Grub.h"
#include "modules/oss/grub/policies/OSS_grub_cmdline_linux.h"
#include "modules/oss/grub/policies/OSS_grub_disable_recovery.h"
#include "modules/oss/grub/policies/OSS_grub_timeout.h"
#include "modules/oss/grub/GrubConfiguration.h"
#include "modules/oss/grub/GrubManagedBlock.h"
#include "modules/oss/grub/GrubManagedConfig.h"

#include <fic/core/integrity/CommandHashStore.h>
#include <fic/core/runtime/FicRuntimePaths.h>
#include <rollback/DaemonMutationJournal.h>

#include <filesystem>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

namespace {

namespace fs = std::filesystem;

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void writeFile(const fs::path& path,
               const std::string& content,
               mode_t mode = 0644) {
    fs::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    require(output.is_open(), "could not write " + path.string());
    output << content;
    output.close();
    require(::chmod(path.c_str(), mode) == 0,
            "could not chmod " + path.string());
}

std::string readFile(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    require(input.is_open(), "could not read " + path.string());
    return std::string(
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>());
}

struct stat fileStatus(const fs::path& path) {
    struct stat status {};
    require(::lstat(path.c_str(), &status) == 0,
            "could not stat " + path.string());
    return status;
}

void initializeRuntimePaths(const fs::path& root) {
    auto paths = fic::core::FicProductPaths::production();
    paths.privateBinDir = root / "bin";
    paths.configDir = root / "config";
    paths.languageDir = root / "lang";
    paths.logDir = root / "log";
    paths.notifyDir = root / "notify";
    paths.dataDir = root / "data";
    paths.shareDir = root / "share";
    paths.imageDir = root / "image";
    paths.runtimeDir = root / "run";
    paths.lockStatusFile = root / "lockstatus";
    paths.commandHashFile = root / "data/commandhash.txt";
    paths.deviceDatabaseFile = root / "data/devices.db";
    paths.deviceDatabaseLockFile = root / "log/devices.lock";
    paths.lockDebugLogFile = root / "log/db-lock.log";

    fs::create_directories(paths.configDir);
    fs::create_directories(paths.logDir);
    fs::create_directories(paths.dataDir);
    writeFile(
        paths.configDir / "AUDIT.conf",
        "_schema_version=1\n"
        "log_level.status=ENABLE\n"
        "log_level.value=ERROR\n");

    std::string error;
    require(fic::core::FicRuntimePaths::initialize(paths, error), error);

    // Deterministic mutation journal location for the GRUB apply journaling
    // performed by the built-in policies' apply().
    fic::rollback::DaemonMutationJournal::instance().setOverridePath(
        root / "data" / "mutation-journal.json");
}

fic::platform::PlatformExecutableResolver makeResolver(
    const fs::path& executable) {
    fic::platform::PlatformExecutables executables;
    executables.entries.push_back(
        {fic::platform::ExecutableId::UpdateGrub, {executable}});
    fic::platform::PlatformExecutableResolverOptions options;
    options.enforceTrustedOwnership = false;
    return fic::platform::PlatformExecutableResolver(
        std::move(executables), options);
}

ProcessResult successfulProcess() {
    ProcessResult result;
    result.started = true;
    result.exitCode = 0;
    return result;
}

ProcessResult failedProcess(const std::string& error = "injected failure") {
    ProcessResult result;
    result.started = true;
    result.exitCode = 1;
    result.standardError = error;
    return result;
}

class RecordingGrubPolicy final : public Grub {
public:
    explicit RecordingGrubPolicy(
        const fic::platform::PlatformExecutableResolver& executables)
        : Grub(
              fic::platform::GrubPlatformConfig{
                  fic::platform::GrubConfigTopology::SharedDefaultsFile,
                  "/etc/default/grub", {}, {}, {}},
              executables) {
        this->policyName = "grub_test_policy";
        this->policyTypeValue =
            std::make_unique<PossibleListPolicyTypeValue>(
                std::vector<std::string>{"expected"});
    }

    bool called = false;
    std::string observedValue;

private:
    bool applyGrub(const std::string& expectedValue) override {
        called = true;
        observedValue = expectedValue;
        return true;
    }
};

class ApplyingGrubPolicy final : public Grub {
public:
    ApplyingGrubPolicy(
        fic::platform::GrubPlatformConfig platformConfig,
        const fic::platform::PlatformExecutableResolver& executables)
        : Grub(std::move(platformConfig), executables, false) {
        this->policyName = "grub_apply_test_policy";
        this->policyTypeValue =
            std::make_unique<PossibleListPolicyTypeValue>(
                std::vector<std::string>{"expected"});
    }

private:
    bool applyGrub(const std::string& expectedValue) override {
        return applyGrubValue("GRUB_TEST_VALUE", expectedValue);
    }
};

GrubConfigurationOptions testOptions(const fs::path& defaults) {
    GrubConfigurationOptions options;
    options.defaultsPath = defaults;
    options.rebuildExecutable = "/test/grub-rebuild";
    options.rebuildArguments = {"--output", "/test/grub.cfg"};
    options.enforceOwnership = false;
    return options;
}

GrubManagedConfigurationOptions managedTestOptions(
    const fs::path& managed,
    const fs::path& baseDefaults = {}) {
    GrubManagedConfigurationOptions options;
    options.managedPath = managed;
    options.rebuildExecutable = "/test/grub-rebuild";
    options.rebuildArguments = {"--output", "/test/grub.cfg"};
    options.enforceOwnership = false;
    options.baseDefaultsPath = baseDefaults;
    return options;
}

GrubCommandRunner countingRebuildRunner(size_t& calls) {
    return [&calls](const std::string&, const std::vector<std::string>&,
                    const ProcessOptions&) {
        ++calls;
        return successfulProcess();
    };
}

// Pure parser tests of the strict FIC managed block grammar (fail closed).
void testGrubManagedBlockParser() {
    // No block: not present, content unchanged.
    {
        const GrubBlockParseResult parse = parseGrubManagedBlock(
            "GRUB_TIMEOUT=5\n# comment\n");
        require(parse.ok && !parse.view.present,
                "foreign content must not be reported as a FIC block");
        require(parse.view.placement ==
                    GrubManagedBlockPlacement::Absent,
                "missing block must be reported as Absent");
    }
    // Valid one-key block.
    {
        const std::string content =
            "GRUB_TIMEOUT=5\n"
            "# FIC_GRUB_BLOCK_BEGIN version=1\n"
            "GRUB_TIMEOUT=\"0\"\n"
            "# FIC_GRUB_BLOCK_END\n";
        const GrubBlockParseResult parse = parseGrubManagedBlock(content);
        require(parse.ok && parse.view.present &&
                    parse.view.entries.size() == 1 &&
                    parse.view.entries[0].first == "GRUB_TIMEOUT" &&
                    parse.view.entries[0].second == "0",
                "valid one-key FIC block was not parsed");
        require(parse.view.placement ==
                    GrubManagedBlockPlacement::AtEof,
                "block without foreign tail must be reported as AtEof");
    }
    // A valid block with a foreign tail stays PARSE-VALID: it is an
    // ownership proof, only its effective placement degrades to NotAtEof.
    {
        const std::string content =
            "# FIC_GRUB_BLOCK_BEGIN version=1\n"
            "GRUB_TIMEOUT=\"0\"\n"
            "# FIC_GRUB_BLOCK_END\n"
            "GRUB_TIMEOUT=5\n";
        const GrubBlockParseResult parse = parseGrubManagedBlock(content);
        require(parse.ok && parse.view.present &&
                    parse.view.entries.size() == 1 &&
                    parse.view.entries[0].second == "0",
                "valid block with a foreign tail must stay parse-valid");
        require(parse.view.placement ==
                    GrubManagedBlockPlacement::NotAtEof,
                "block with a foreign tail must be reported as NotAtEof");
    }
    // Ambiguous placement is never AtEof: even a lone blank line after the
    // END marker (let alone a foreign assignment after it) makes the block
    // NotAtEof.
    {
        const GrubBlockParseResult parse = parseGrubManagedBlock(
            std::string(kGrubBlockBeginMarker) +
            "\nGRUB_TIMEOUT=\"0\"\n" + kGrubBlockEndMarker +
            "\n\nGRUB_TIMEOUT=5\n");
        require(parse.ok && parse.view.present &&
                    parse.view.placement ==
                        GrubManagedBlockPlacement::NotAtEof,
                "blank line plus foreign assignment must be NotAtEof");
    }
    // Valid multi-key block in any order -> canonical view.
    {
        const std::string content =
            "# FIC_GRUB_BLOCK_BEGIN version=1\n"
            "GRUB_TIMEOUT=\"0\"\n"
            "GRUB_DISABLE_RECOVERY=\"true\"\n"
            "GRUB_CMDLINE_LINUX=\"quiet\"\n"
            "# FIC_GRUB_BLOCK_END\n";
        const GrubBlockParseResult parse = parseGrubManagedBlock(content);
        require(parse.ok && parse.view.entries.size() == 3 &&
                    parse.view.entries[0].first == "GRUB_CMDLINE_LINUX" &&
                    parse.view.entries[1].first == "GRUB_DISABLE_RECOVERY",
                "FIC block entries are not canonicalized");
    }
    // Malformed cases: all fail closed.
    const std::string begin = std::string(kGrubBlockBeginMarker) + "\n";
    const std::string end = std::string(kGrubBlockEndMarker) + "\n";
    struct MalformedCase { const char* name; std::string content; };
    const std::vector<MalformedCase> malformed = {
        {"duplicate block",
         begin + "GRUB_TIMEOUT=\"0\"\n" + end +
             "foreign\n" + begin + "GRUB_TIMEOUT=\"1\"\n" + end},
        {"missing END", begin + "GRUB_TIMEOUT=\"0\"\n"},
        {"missing BEGIN", "foreign\n" + end},
        {"nested BEGIN", begin + begin + end},
        {"unknown key", begin + "GRUB_DEFAULT=\"0\"\n" + end},
        {"duplicate key",
         begin + "GRUB_TIMEOUT=\"0\"\nGRUB_TIMEOUT=\"1\"\n" + end},
        {"malformed quoted value", begin + "GRUB_TIMEOUT=0\n" + end},
        {"shell expression", begin + "GRUB_TIMEOUT=$(reboot)\n" + end},
        {"comment inside block", begin + "# note\n" + end},
        {"empty line inside block", begin + "\n" + end},
        {"whitespace around equals",
             begin + "GRUB_TIMEOUT = \"0\"\n" + end},
        {"leading whitespace in block",
             begin + "  GRUB_TIMEOUT=\"0\"\n" + end},
        {"trailing whitespace after value",
             begin + "GRUB_TIMEOUT=\"0\"  \n" + end},
        {"inline comment after value",
             begin + "GRUB_TIMEOUT=\"0\" # note\n" + end},
        {"foreign FIC-like malformed marker",
             "#FIC_GRUB_BLOCK_BEGIN version=1\n"},
        {"foreign FIC-like END", "x # FIC_GRUB_BLOCK_END\n"},
    };
    for (const MalformedCase& testCase : malformed) {
        const GrubBlockParseResult parse =
            parseGrubManagedBlock(testCase.content);
        require(!parse.ok,
                std::string("malformed block must fail closed: ") +
                testCase.name);
    }
    // set/remove round trip.
    {
        const GrubBlockMutationResult set = setGrubManagedBlockValue(
            "GRUB_TIMEOUT=5\n", "GRUB_TIMEOUT", "0");
        require(set.ok,
                "managed block set failed");
        require(set.content ==
                    "GRUB_TIMEOUT=5\n"
                    "\n"
                    "# FIC_GRUB_BLOCK_BEGIN version=1\n"
                    "GRUB_TIMEOUT=\"0\"\n"
                    "# FIC_GRUB_BLOCK_END\n",
                "managed block was not rendered canonically at EOF");
        const GrubBlockMutationResult remove =
            removeGrubManagedBlockValue(set.content, "GRUB_TIMEOUT");
        require(remove.ok && remove.content == "GRUB_TIMEOUT=5\n",
                "last key removal must drop the whole block byte-exact");
    }
    // Canonical round trip: the rendered block reparses to the same entries
    // and a canonical rewrite stays byte-stable (strict grammar accepts
    // exactly what FIC renders).
    {
        const GrubBlockMutationResult set = setGrubManagedBlockValue(
            "FOO=bar\n", "GRUB_CMDLINE_LINUX", "quiet \"x\" $y `z` \\q");
        require(set.ok, "escaped canonical set failed");
        const GrubBlockParseResult parse = parseGrubManagedBlock(set.content);
        require(parse.ok && parse.view.present &&
                    parse.view.entries.size() == 1 &&
                    parse.view.entries[0].first == "GRUB_CMDLINE_LINUX" &&
                    parse.view.entries[0].second ==
                        "quiet \"x\" $y `z` \\q",
                "escaped value did not survive render->parse round trip");
        const GrubBlockMutationResult set2 =
            setGrubManagedBlockValue(set.content, "GRUB_TIMEOUT", "0");
        require(set2.ok, "second canonical set failed");
        const GrubBlockParseResult parse2 =
            parseGrubManagedBlock(set2.content);
        require(parse2.ok && parse2.view.entries.size() == 2 &&
                    parse2.view.entries[1].first == "GRUB_TIMEOUT",
                "canonical rewrite must stay parseable");
        const GrubBlockMutationResult set3 = setGrubManagedBlockValue(
            set2.content, "GRUB_TIMEOUT", "0");
        require(set3.ok && set3.content == set2.content,
                "idempotent canonical set must be byte-stable");
    }
    // Byte-exact foreign round trips around the FIC-owned boundary separator:
    // foreign content without a trailing newline gains exactly one FIC-owned
    // separator newline and is restored byte-exact on removal; a foreign
    // trailing newline survives apply and removal unchanged.
    {
        const GrubBlockMutationResult set = setGrubManagedBlockValue(
            "FOO=bar", "GRUB_TIMEOUT", "0");
        require(set.ok, "no-final-newline managed block set failed");
        require(set.content ==
                    "FOO=bar\n"
                    "# FIC_GRUB_BLOCK_BEGIN version=1\n"
                    "GRUB_TIMEOUT=\"0\"\n"
                    "# FIC_GRUB_BLOCK_END\n",
                "no-final-newline foreign content must gain exactly the "
                "FIC-owned separator newline");
        const GrubBlockMutationResult remove =
            removeGrubManagedBlockValue(set.content, "GRUB_TIMEOUT");
        require(remove.ok && remove.content == "FOO=bar",
                "removal must restore foreign EOF bytes byte-exact");
    }
    {
        const GrubBlockMutationResult set = setGrubManagedBlockValue(
            "FOO=bar\n", "GRUB_TIMEOUT", "0");
        require(set.ok, "trailing-newline managed block set failed");
        require(set.content ==
                    "FOO=bar\n"
                    "\n"
                    "# FIC_GRUB_BLOCK_BEGIN version=1\n"
                    "GRUB_TIMEOUT=\"0\"\n"
                    "# FIC_GRUB_BLOCK_END\n",
                "foreign trailing newline must be preserved");
        const GrubBlockMutationResult remove =
            removeGrubManagedBlockValue(set.content, "GRUB_TIMEOUT");
        require(remove.ok && remove.content == "FOO=bar\n",
                "removal must preserve the foreign trailing newline");
    }
}

// ALT shared defaults editor: the FIC EOF managed block model.
void testGrubConfigurationEditor(const fs::path& root) {
    const fs::path defaults = root / "editor/etc/sysconfig/grub2";
    writeFile(
        defaults,
        "GRUB_TIMEOUT=5\n"
        "GRUB_CMDLINE_LINUX=\"quiet splash\"\n");

    size_t rebuildCalls = 0;
    const GrubCommandRunner runner =
        [&rebuildCalls](const std::string& executable,
                        const std::vector<std::string>& arguments,
                        const ProcessOptions& options) {
            ++rebuildCalls;
            require(executable == "/test/grub-rebuild",
                    "wrong rebuild executable");
            require(options.clearEnvironment,
                    "GRUB rebuild must clear the environment");
            return successfulProcess();
        };

    GrubConfiguration configuration(testOptions(defaults), runner);
    std::string error;
    require(configuration.load(error), error);

    const GrubOperationResult changed =
        configuration.ensureManagedValue("GRUB_TIMEOUT", "10");
    require(changed.ok && changed.changed, changed.message);
    require(rebuildCalls == 1, "changed value must rebuild once");
    require(
        readFile(defaults) ==
            "GRUB_TIMEOUT=5\n"
            "GRUB_CMDLINE_LINUX=\"quiet splash\"\n"
            "\n"
            "# FIC_GRUB_BLOCK_BEGIN version=1\n"
            "GRUB_TIMEOUT=\"10\"\n"
            "# FIC_GRUB_BLOCK_END\n",
        "ALT apply must append a canonical FIC block and keep foreign bytes");

    // Idempotent apply: no source change, but rebuild still happens.
    GrubConfiguration verification(testOptions(defaults), runner);
    require(verification.load(error), error);
    const GrubOperationResult unchanged =
        verification.ensureManagedValue("GRUB_TIMEOUT", "10");
    require(unchanged.ok && !unchanged.changed, unchanged.message);
    require(rebuildCalls == 2,
            "matching managed value must still rebuild a stale grub.cfg");

    // Value update rewrites only the managed block.
    GrubConfiguration update(testOptions(defaults), runner);
    require(update.load(error), error);
    const GrubOperationResult updated =
        update.ensureManagedValue("GRUB_CMDLINE_LINUX", "quiet audit=1");
    require(updated.ok && updated.changed, updated.message);
    const std::string content = readFile(defaults);
    require(
        content.find("GRUB_CMDLINE_LINUX=\"quiet audit=1\"") !=
                std::string::npos &&
            content.find("foreign") == std::string::npos,
        "managed block update failed");
    const GrubBlockParseResult parse = parseGrubManagedBlock(content);
    require(parse.ok && parse.view.entries.size() == 2,
            "FIC block must keep both managed keys");
}

// Foreign bytes survive apply, update and rollback byte-exact; a block that
// is no longer at EOF is relocated to EOF without moving foreign lines.
void testAltForeignPreservationAndRelocation(const fs::path& root) {
    const std::string foreign =
        "# custom admin comment\n"
        "\n"
        "GRUB_TIMEOUT=5\n"
        "FOO='strange value'\n"
        "\n"
        "if test -n \"$SOMETHING\"; then\n"
        "    BAR=baz\n"
        "fi\n";
    const fs::path defaults = root / "foreign/etc/sysconfig/grub2";
    writeFile(defaults, foreign);

    const GrubCommandRunner runner =
        [](const std::string&, const std::vector<std::string>&,
           const ProcessOptions&) { return successfulProcess(); };
    GrubConfiguration configuration(testOptions(defaults), runner);
    std::string error;
    require(configuration.load(error), error);
    require(configuration.ensureManagedValue("GRUB_TIMEOUT", "0").ok,
            "foreign preservation apply failed");
    require(readFile(defaults).substr(0, foreign.size()) == foreign,
            "foreign bytes were not preserved byte-exact after apply");
    require(
        readFile(defaults).find(kGrubBlockBeginMarker) > foreign.size() - 1,
        "FIC block must be at EOF");

    // Relocation: foreign content appended after the block.
    const fs::path relocated = root / "foreign-relocated/etc/sysconfig/grub2";
    writeFile(
        relocated,
        "foreign A\n"
        "# FIC_GRUB_BLOCK_BEGIN version=1\n"
        "GRUB_TIMEOUT=\"5\"\n"
        "# FIC_GRUB_BLOCK_END\n"
        "foreign B\n");
    GrubConfiguration relocatedConfiguration(testOptions(relocated), runner);
    require(relocatedConfiguration.load(error), error);
    require(relocatedConfiguration.ensureManagedValue("GRUB_TIMEOUT", "0").ok,
            "block relocation apply failed");
    const std::string relocatedContent = readFile(relocated);
    require(relocatedContent ==
                "foreign A\n"
                "foreign B\n"
                // FIC-owned serialization separator: the byte-exact foreign
                // area is recoverable by stripping exactly this newline.
                "\n"
                "# FIC_GRUB_BLOCK_BEGIN version=1\n"
                "GRUB_TIMEOUT=\"0\"\n"
                "# FIC_GRUB_BLOCK_END\n",
            "block relocation must keep foreign order byte-exact and place "
            "the block at EOF");

    // Byte-exact removal round trip: foreign content without a trailing
    // newline is restored exactly after the last FIC key is removed — the
    // boundary newline introduced by FIC is FIC-owned serialization.
    const fs::path noNewline = root / "foreign-no-newline/etc/sysconfig/grub2";
    const std::string noNewlineForeign = "GRUB_TIMEOUT=5\nFOO=bar";
    writeFile(noNewline, noNewlineForeign);
    GrubConfiguration noNewlineConfiguration(testOptions(noNewline), runner);
    require(noNewlineConfiguration.load(error), error);
    require(
        noNewlineConfiguration.ensureManagedValue("GRUB_TIMEOUT", "0").ok,
        "no-final-newline apply failed");
    const GrubBlockMutationResult removal = removeGrubManagedBlockValue(
        readFile(noNewline), "GRUB_TIMEOUT");
    require(removal.ok && removal.content == noNewlineForeign,
            "no-final-newline foreign bytes must survive apply and removal "
            "byte-exact");
}

void testAmbiguousAndDynamicAssignmentsFailClosed(const fs::path& root) {
    const fs::path defaults = root / "ambiguous/etc/sysconfig/grub2";
    // Foreign duplicate assignments are NOT an ownership conflict anymore:
    // the final FIC block override wins.
    const std::string duplicates =
        "GRUB_TIMEOUT=5\n"
        "GRUB_TIMEOUT=10\n";
    writeFile(defaults, duplicates);
    size_t calls = 0;
    const GrubCommandRunner runner =
        [&calls](const std::string&, const std::vector<std::string>&,
                 const ProcessOptions&) {
            ++calls;
            return successfulProcess();
        };

    GrubConfiguration duplicateConfiguration(testOptions(defaults), runner);
    std::string error;
    require(duplicateConfiguration.load(error), error);
    require(duplicateConfiguration.ensureManagedValue("GRUB_TIMEOUT", "15").ok,
            "foreign duplicate assignments must not block the FIC block");
    require(calls == 1, "apply must rebuild exactly once");

    // A malformed FIC block is a fail-closed conflict: no write, no rebuild.
    const std::string malformedBlock =
        "GRUB_TIMEOUT=5\n"
        "# FIC_GRUB_BLOCK_BEGIN version=1\n"
        "GRUB_TIMEOUT=$(reboot)\n";
    writeFile(defaults, malformedBlock);
    calls = 0;
    GrubConfiguration malformedConfiguration(testOptions(defaults), runner);
    require(malformedConfiguration.load(error), error);
    const GrubOperationResult malformedResult =
        malformedConfiguration.ensureManagedValue("GRUB_TIMEOUT", "15");
    require(!malformedResult.ok,
            "malformed FIC block must fail closed");
    require(calls == 0 && readFile(defaults) == malformedBlock,
            "malformed FIC block changed the file or ran a rebuild");
}

void testRebuildFailureCompensates(const fs::path& root) {
    const fs::path defaults = root / "rollback/etc/sysconfig/grub2";
    const std::string original =
        "GRUB_TIMEOUT=5\n"
        "# admin tail\n";
    writeFile(defaults, original);

    size_t calls = 0;
    const GrubCommandRunner runner =
        [&calls](const std::string&, const std::vector<std::string>&,
                 const ProcessOptions&) {
            ++calls;
            return calls == 1
                ? failedProcess("new configuration rejected")
                : successfulProcess();
        };
    GrubConfiguration configuration(testOptions(defaults), runner);
    std::string error;
    require(configuration.load(error), error);
    const GrubOperationResult result =
        configuration.ensureManagedValue("GRUB_TIMEOUT", "10");
    require(!result.ok, "failed rebuild must fail policy application");
    require(result.sourceState == GrubSourceMutationState::Compensated,
            "proven compensation must be reported as Compensated");
    require(calls == 2,
            "failed rebuild must regenerate grub.cfg after restoring defaults");
    require(readFile(defaults) == original,
            "shared defaults file was not restored after rebuild failure");
}

// ALT double rebuild failure: the source is proven restored (compensation
// succeeded) but the COMPENSATING rebuild failed too — the derived grub.cfg
// state is unresolved, so the outcome is the typed
// CompensatedPendingRebuild, never a fully Compensated transaction.
void testAltDoubleRebuildFailurePendingRebuild(const fs::path& root) {
    const fs::path defaults = root / "alt-pending/etc/sysconfig/grub2";
    const std::string original =
        "GRUB_TIMEOUT=5\n"
        "# admin tail\n";
    writeFile(defaults, original);

    size_t calls = 0;
    const GrubCommandRunner runner =
        [&calls](const std::string&, const std::vector<std::string>&,
                 const ProcessOptions&) {
            ++calls;
            return failedProcess("injected rebuild failure");
        };
    GrubConfiguration configuration(testOptions(defaults), runner);
    std::string error;
    require(configuration.load(error), error);
    const GrubOperationResult result =
        configuration.ensureManagedValue("GRUB_TIMEOUT", "10");
    require(!result.ok, "double rebuild failure must fail the apply");
    require(result.sourceState ==
                GrubSourceMutationState::CompensatedPendingRebuild,
            "source restored + failed compensating rebuild must be "
            "CompensatedPendingRebuild");
    require(calls == 2,
            "compensating rebuild must be attempted exactly once");
    require(readFile(defaults) == original,
            "double failure must still restore the source byte-exact");
    require(!result.diagnostics.empty(),
            "incomplete compensation must be diagnosed");
}

// ALT ownership vs compliance: a valid block with the recorded value but a
// foreign tail after the END marker is proven OWNERSHIP (inspect finds the
// value, rollback may release it) but NOT compliance (proof != Matches,
// journal classification Ineffective, grubManagedValueCompliant false).
void testAltPlacementComplianceSemantics(const fs::path& root) {
    const fs::path shared = root / "placement/etc/sysconfig/grub2";
    GrubManagedConfigurationOptions options;
    options.sharedDefaultsPath = shared;
    options.rebuildExecutable = "/test/grub-rebuild";
    options.enforceOwnership = false;

    const std::string blockOnly =
        "# FIC_GRUB_BLOCK_BEGIN version=1\n"
        "GRUB_TIMEOUT=\"0\"\n"
        "# FIC_GRUB_BLOCK_END\n";
    // Compliant state: block at EOF.
    writeFile(shared, blockOnly);
    const GrubValueObservation compliant =
        inspectGrubManagedValue(options, "GRUB_TIMEOUT");
    require(compliant.valid && compliant.found &&
                compliant.value == "0" && compliant.managedLayerEffective,
            "EOF block must be observed as the effective layer");
    require(grubManagedValueCompliant(compliant, "0"),
            "EOF block with the expected value must be compliant");
    std::string proofError;
    require(proveExpectedGrubManagedValue(
                options, "GRUB_TIMEOUT", "0", proofError) ==
                GrubManagedValueProof::Matches,
            proofError.empty() ? "EOF block proof failed" : proofError);
    require(classifyGrubManagedJournalState(
                options, "GRUB_TIMEOUT", "0") ==
                GrubManagedJournalState::After,
            "EOF block must classify as After");

    // Same valid block + foreign tail: ownership proven, compliance lost.
    const std::string displaced = blockOnly + "GRUB_TIMEOUT=5\n";
    writeFile(shared, displaced);
    const GrubValueObservation ineffective =
        inspectGrubManagedValue(options, "GRUB_TIMEOUT");
    require(ineffective.valid && ineffective.found &&
                ineffective.value == "0",
            "displaced valid block must still prove ownership");
    require(!ineffective.managedLayerEffective,
            "foreign tail must mark the managed layer ineffective");
    require(!grubManagedValueCompliant(ineffective, "0"),
            "displaced block must not be compliant");
    proofError.clear();
    require(proveExpectedGrubManagedValue(
                options, "GRUB_TIMEOUT", "0", proofError) ==
                GrubManagedValueProof::Ineffective,
            "displaced block proof must be Ineffective: " + proofError);
    require(classifyGrubManagedJournalState(
                options, "GRUB_TIMEOUT", "0") ==
                GrubManagedJournalState::Ineffective,
            "displaced block must classify as Ineffective");
    // A different recorded value is a value mismatch first: Drift takes
    // precedence over the placement defect (the recorded key is NOT owned
    // with that value).
    require(classifyGrubManagedJournalState(
                options, "GRUB_TIMEOUT", "5") ==
                GrubManagedJournalState::Drift,
            "recorded value mismatch must classify as Drift");
}
void testUnsafeInputAndPathsFailClosed(const fs::path& root) {
    const fs::path defaults = root / "unsafe/etc/default/grub";
    writeFile(defaults, "GRUB_TIMEOUT=5\n");
    size_t calls = 0;
    const GrubCommandRunner runner =
        [&calls](const std::string&, const std::vector<std::string>&,
                 const ProcessOptions&) {
            ++calls;
            return successfulProcess();
        };

    GrubConfiguration configuration(testOptions(defaults), runner);
    std::string error;
    require(configuration.load(error), error);
    require(
        !configuration.ensureManagedValue(
             "GRUB_TIMEOUT", "10\nMALICIOUS=1").ok,
        "multiline value must be rejected");
    require(calls == 0 && readFile(defaults) == "GRUB_TIMEOUT=5\n",
            "unsafe value changed configuration or ran rebuild");

    const fs::path target = root / "unsafe/target";
    const fs::path link = root / "unsafe/grub-link";
    writeFile(target, "GRUB_TIMEOUT=5\n");
    fs::create_symlink(target, link);
    GrubConfiguration symlinkConfiguration(testOptions(link), runner);
    require(!symlinkConfiguration.load(error),
            "GRUB defaults symlink must be rejected");

    GrubConfiguration missingConfiguration(
        testOptions(root / "unsafe/missing"), runner);
    require(!missingConfiguration.load(error),
            "missing GRUB defaults must not be created implicitly");
}

void testAltSharedTopologyStaysShared(const fs::path& root) {
    const fs::path defaults = root / "alt/etc/sysconfig/grub2";
    const fs::path managed =
        root / "alt/etc/default/grub.d/zzzz-fic.cfg";
    writeFile(defaults, "GRUB_TIMEOUT=5\n");
    std::size_t rebuildCalls = 0;
    GrubConfigurationOptions options = testOptions(defaults);
    options.rebuildArguments = {"-o", "/etc/grub.cfg"};
    GrubConfiguration configuration(
        options,
        [&rebuildCalls](const std::string&,
                        const std::vector<std::string>& arguments,
                        const ProcessOptions&) {
            ++rebuildCalls;
            require(arguments == std::vector<std::string>{
                        "-o", "/etc/grub.cfg"},
                    "ALT rebuild arguments changed");
            return successfulProcess();
        });
    std::string error;
    require(configuration.load(error), error);
    const GrubOperationResult result =
        configuration.ensureManagedValue("GRUB_TIMEOUT", "10");
    require(result.ok && result.changed && rebuildCalls == 1 &&
                readFile(defaults).find("GRUB_TIMEOUT=\"10\"") !=
                    std::string::npos &&
                !fs::exists(managed),
            "ALT shared topology used a managed Debian drop-in");
}

void testManagedDropInEditingAndIdempotence(const fs::path& root) {
    const fs::path directory = root / "managed-edit/etc/default/grub.d";
    const fs::path managed = directory / "zzzz-fic.cfg";
    const fs::path shared = root / "managed-edit/etc/default/grub";
    fs::create_directories(directory);
    writeFile(shared, "GRUB_TIMEOUT=3\n");
    writeFile(directory / "50-vendor.cfg", "GRUB_DEFAULT=0\n");

    std::size_t rebuildCalls = 0;
    const GrubCommandRunner runner =
        [&rebuildCalls](const std::string& executable,
                        const std::vector<std::string>& arguments,
                        const ProcessOptions& processOptions) {
            ++rebuildCalls;
            require(executable == "/test/grub-rebuild" &&
                        arguments == std::vector<std::string>{
                            "--output", "/test/grub.cfg"} &&
                        processOptions.clearEnvironment,
                    "managed GRUB rebuild contract changed");
            return successfulProcess();
        };

    GrubOperationResult result = ensureManagedGrubDropInValue(
        managedTestOptions(managed), "GRUB_TIMEOUT", "10", runner);
    require(result.ok && result.changed && rebuildCalls == 1,
            "missing managed GRUB file was not created and rebuilt");
    require(readFile(shared) == "GRUB_TIMEOUT=3\n",
            "Debian owned topology modified /etc/default/grub");
    require(readFile(managed) ==
                "# Managed by FIC. Do not edit.\n\nGRUB_TIMEOUT=\"10\"\n",
            "managed GRUB file was not canonically generated");
    require((fileStatus(managed).st_mode & 07777) == 0644,
            "managed GRUB file mode is unsafe");

    const std::string cmdline =
        "quiet \"quoted\" \\path $literal `literal` ;&";
    result = ensureManagedGrubDropInValue(
        managedTestOptions(managed), "GRUB_CMDLINE_LINUX", cmdline, runner);
    require(result.ok && result.changed && rebuildCalls == 2,
            "second managed GRUB key was not added");
    GrubManagedConfig verification({managed, false});
    require(verification.loadConfig() &&
                verification.getValue("GRUB_TIMEOUT") == "10" &&
                verification.getValue("GRUB_CMDLINE_LINUX") == cmdline,
            "managed GRUB escaping did not round-trip logical values");
    const std::string escaped = readFile(managed);
    require(escaped.find("\\\"quoted\\\"") != std::string::npos &&
                escaped.find("\\\\path") != std::string::npos &&
                escaped.find("\\$literal") != std::string::npos &&
                escaped.find("\\`literal\\`") != std::string::npos,
            "managed GRUB shell-special characters were not escaped");

    result = ensureManagedGrubDropInValue(
        managedTestOptions(managed), "GRUB_TIMEOUT", "20", runner);
    require(result.ok && result.changed && rebuildCalls == 3,
            "existing managed GRUB value was not changed");
    const ino_t inodeBefore = fileStatus(managed).st_ino;
    const std::string contentBefore = readFile(managed);
    result = ensureManagedGrubDropInValue(
        managedTestOptions(managed), "GRUB_TIMEOUT", "20", runner);
    require(result.ok && !result.changed && rebuildCalls == 4 &&
                fileStatus(managed).st_ino == inodeBefore &&
                readFile(managed) == contentBefore,
            "idempotent managed apply rewrote the file or skipped rebuild");
}

void testManagedTopologyAndStrictFormat(const fs::path& root) {
    const fs::path directory = root / "managed-strict/etc/default/grub.d";
    fs::create_directories(directory);

    const std::vector<std::string> invalidDocuments = {
        "GRUB_TIMEOUT=\"10\"\n",
        "# Managed by FIC. Do not edit.\nUNKNOWN=\"x\"\n",
        "# Managed by FIC. Do not edit.\nGRUB_TIMEOUT=\"5\"\nGRUB_TIMEOUT=\"10\"\n",
        "# Managed by FIC. Do not edit.\nGRUB_TIMEOUT=10\n",
        "# Managed by FIC. Do not edit.\nGRUB_TIMEOUT=\"1\"0\"\n",
        "# Managed by FIC. Do not edit.\nGRUB_CMDLINE_LINUX=\"quiet $(id)\"\n",
        "# Managed by FIC. Do not edit.\nsource /tmp/other\n"
    };
    for (std::size_t index = 0; index < invalidDocuments.size(); ++index) {
        const fs::path caseDirectory = directory / std::to_string(index);
        const fs::path path = caseDirectory / "zzzz-fic.cfg";
        fs::create_directories(caseDirectory);
        writeFile(path, invalidDocuments[index]);
        GrubManagedConfig configuration({path, false});
        require(!configuration.loadConfig(),
                "invalid managed GRUB document was accepted: " +
                    std::to_string(index));
    }

    const fs::path inputDirectory = directory / "input";
    const fs::path inputPath = inputDirectory / "zzzz-fic.cfg";
    fs::create_directories(inputDirectory);
    GrubManagedConfig input({inputPath, false});
    require(input.loadConfig(), input.lastError());
    require(!input.setValue("GRUB_TIMEOUT", "10\r") &&
                !input.setValue("GRUB_TIMEOUT", "10\n") &&
                !input.setValue("GRUB_TIMEOUT", std::string("10\0x", 4)),
            "CR, LF, or NUL managed GRUB values were accepted");
    require(!fs::exists(inputPath),
            "rejected managed values created the managed file");

    const fs::path symlinkDirectory = directory / "symlink";
    const fs::path symlinkPath = symlinkDirectory / "zzzz-fic.cfg";
    fs::create_directories(symlinkDirectory);
    writeFile(symlinkDirectory / "target", "# Managed by FIC. Do not edit.\n");
    fs::create_symlink("target", symlinkPath);
    GrubManagedConfig symlinkConfig({symlinkPath, false});
    require(!symlinkConfig.loadConfig(),
            "managed GRUB symlink was accepted");

    const fs::path unsafeDirectory = directory / "unsafe";
    const fs::path unsafePath = unsafeDirectory / "zzzz-fic.cfg";
    fs::create_directories(unsafeDirectory);
    writeFile(unsafePath, "# Managed by FIC. Do not edit.\n", 0666);
    GrubManagedConfig unsafeConfig({unsafePath, true});
    require(!unsafeConfig.loadConfig(),
            "unsafe managed GRUB ownership or mode was accepted");
}

void testManagedDropInOrdering(const fs::path& root) {
    const fs::path earlyDirectory = root / "ordering-early/etc/default/grub.d";
    const fs::path earlyManaged = earlyDirectory / "zzzz-fic.cfg";
    fs::create_directories(earlyDirectory);
    writeFile(earlyDirectory / "00-vendor.cfg", "GRUB_DEFAULT=0\n");
    writeFile(earlyDirectory / ".zzzzz-hidden.cfg", "GRUB_TIMEOUT=99\n");
    std::size_t earlyCalls = 0;
    GrubOperationResult early = ensureManagedGrubDropInValue(
        managedTestOptions(earlyManaged), "GRUB_TIMEOUT", "10",
        [&earlyCalls](const std::string&, const std::vector<std::string>&,
                      const ProcessOptions&) {
            ++earlyCalls;
            return successfulProcess();
        });
    require(early.ok && earlyCalls == 1,
            "earlier GRUB drop-in incorrectly blocked apply");

    const fs::path lateDirectory = root / "ordering-late/etc/default/grub.d";
    const fs::path lateManaged = lateDirectory / "zzzz-fic.cfg";
    fs::create_directories(lateDirectory);
    const std::string original =
        "# Managed by FIC. Do not edit.\n\nGRUB_TIMEOUT=\"5\"\n";
    writeFile(lateManaged, original);
    writeFile(lateDirectory / "zzzzz-local.cfg", "GRUB_TIMEOUT=99\n");
    std::size_t lateCalls = 0;
    GrubOperationResult late = ensureManagedGrubDropInValue(
        managedTestOptions(lateManaged), "GRUB_TIMEOUT", "10",
        [&lateCalls](const std::string&, const std::vector<std::string>&,
                     const ProcessOptions&) {
            ++lateCalls;
            return successfulProcess();
        });
    require(!late.ok && lateCalls == 0 && readFile(lateManaged) == original,
            "later GRUB drop-in did not fail before mutation and rebuild");
}

void testManagedRebuildFailureCompensation(const fs::path& root) {
    const auto runCase = [&](const std::string& name,
                             bool initiallyExists,
                             bool compensationSucceeds) {
        const fs::path directory =
            root / ("managed-compensation-" + name) / "etc/default/grub.d";
        const fs::path managed = directory / "zzzz-fic.cfg";
        fs::create_directories(directory);
        const std::string original =
            "# Managed by FIC. Do not edit.\n\nGRUB_TIMEOUT=\"5\"\n";
        if (initiallyExists) writeFile(managed, original);
        std::size_t calls = 0;
        GrubOperationResult result = ensureManagedGrubDropInValue(
            managedTestOptions(managed), "GRUB_TIMEOUT", "10",
            [&calls, compensationSucceeds](
                const std::string&, const std::vector<std::string>&,
                const ProcessOptions&) {
                ++calls;
                return calls == 2 && compensationSucceeds
                    ? successfulProcess()
                    : failedProcess("injected rebuild failure");
            });
        require(!result.ok && calls == 2,
                "managed rebuild failure did not run compensation rebuild");
        // Compensation is proven in BOTH cases: an existing pre-apply
        // drop-in is restored exactly; a newly created drop-in is NEVER
        // unlinked — it is compensated with the canonical header-only
        // FIC-owned artifact, which proves the policy key is absent.
        require(fs::exists(managed),
                "managed drop-in disappeared after compensation");
        require(initiallyExists
                    ? readFile(managed) == original
                    : readFile(managed) ==
                          GrubManagedConfig::canonicalEmptyContent(),
                "managed source was not restored after rebuild failure");
        // Full compensation (source restored AND compensating rebuild
        // succeeded) is Compensated; a failed compensating rebuild leaves
        // the derived grub.cfg state unresolved — CompensatedPendingRebuild,
        // for BOTH compensation topologies (existing drop-in and the
        // canonical header-only initially-missing compensation alike).
        require(
            result.sourceState ==
                (compensationSucceeds
                     ? GrubSourceMutationState::Compensated
                     : GrubSourceMutationState::CompensatedPendingRebuild),
            "unexpected source state after rebuild failure compensation");
        require(compensationSucceeds || !result.diagnostics.empty(),
                "compensating rebuild failure was not diagnosed");
    };
    runCase("existing", true, true);
    runCase("created", false, true);
    runCase("double-failure", true, false);
    runCase("created-double-failure", false, false);
}

void testBaseDefaultsValidation(const fs::path& root) {
    const std::string managedContent =
        "# Managed by FIC. Do not edit.\n\nGRUB_TIMEOUT=\"10\"\n";
    for (const char* name :
         {"base-missing", "base-safe", "base-symlink", "base-mode",
          "base-unsafedir", "base-idempotent"}) {
        fs::create_directories(root / name / "etc/default/grub.d");
    }

    // Missing base defaults: owned apply is allowed.
    {
        const fs::path base = root / "base-missing/etc/default/grub";
        const fs::path managed =
            root / "base-missing/etc/default/grub.d/zzzz-fic.cfg";
        size_t calls = 0;
        const GrubOperationResult result = ensureManagedGrubDropInValue(
            managedTestOptions(managed, base), "GRUB_TIMEOUT", "10",
            countingRebuildRunner(calls));
        require(result.ok && calls == 1 && !fs::exists(base) &&
                    readFile(managed) == managedContent,
                "missing base GRUB defaults must not block the owned apply");
    }

    // Safe regular base defaults: apply allowed, base file untouched.
    {
        const fs::path base = root / "base-safe/etc/default/grub";
        const fs::path managed =
            root / "base-safe/etc/default/grub.d/zzzz-fic.cfg";
        writeFile(base, "GRUB_TIMEOUT=3\n");
        size_t calls = 0;
        const GrubOperationResult result = ensureManagedGrubDropInValue(
            managedTestOptions(managed, base), "GRUB_TIMEOUT", "10",
            countingRebuildRunner(calls));
        require(result.ok && calls == 1 &&
                    readFile(base) == "GRUB_TIMEOUT=3\n" &&
                    readFile(managed) == managedContent,
                "safe base GRUB defaults must not block the owned apply");
    }

    // Symlinked base defaults: fail before any mutation or rebuild.
    {
        const fs::path defaultDirectory = root / "base-symlink/etc/default";
        fs::create_directories(defaultDirectory / "real");
        const fs::path base = defaultDirectory / "grub";
        fs::create_symlink(defaultDirectory / "real/other", base);
        const fs::path managed =
            root / "base-symlink/etc/default/grub.d/zzzz-fic.cfg";
        size_t calls = 0;
        const GrubOperationResult result = ensureManagedGrubDropInValue(
            managedTestOptions(managed, base), "GRUB_TIMEOUT", "10",
            countingRebuildRunner(calls));
        require(!result.ok && calls == 0 && !fs::exists(managed),
                "symlinked base GRUB defaults must fail before mutation");
    }

    // Group/world writable base defaults: fail before any mutation.
    {
        const fs::path base = root / "base-mode/etc/default/grub";
        const fs::path managed =
            root / "base-mode/etc/default/grub.d/zzzz-fic.cfg";
        writeFile(base, "GRUB_TIMEOUT=3\n", 0666);
        size_t calls = 0;
        const GrubOperationResult result = ensureManagedGrubDropInValue(
            managedTestOptions(managed, base), "GRUB_TIMEOUT", "10",
            countingRebuildRunner(calls));
        require(!result.ok && calls == 0 && !fs::exists(managed),
                "group/world writable base GRUB defaults must fail closed");
    }

    // Unsafe parent directory of the base defaults: fail before mutation.
    {
        const fs::path defaultDirectory = root / "base-unsafedir/etc/default";
        const fs::path base = defaultDirectory / "grub";
        writeFile(base, "GRUB_TIMEOUT=3\n");
        require(::chmod(defaultDirectory.c_str(), 0777) == 0,
                "could not chmod base defaults parent directory");
        const fs::path managed =
            root / "base-unsafedir/etc/default/grub.d/zzzz-fic.cfg";
        size_t calls = 0;
        const GrubOperationResult result = ensureManagedGrubDropInValue(
            managedTestOptions(managed, base), "GRUB_TIMEOUT", "10",
            countingRebuildRunner(calls));
        require(::chmod(defaultDirectory.c_str(), 0755) == 0,
                "could not restore base defaults parent directory mode");
        require(!result.ok && calls == 0 && !fs::exists(managed),
                "unsafe base GRUB defaults parent must fail before mutation");
    }

    // Idempotent managed value with unsafe base defaults: no rebuild,
    // no managed mutation.
    {
        const fs::path base = root / "base-idempotent/etc/default/grub";
        const fs::path managed =
            root / "base-idempotent/etc/default/grub.d/zzzz-fic.cfg";
        writeFile(base, "GRUB_TIMEOUT=3\n", 0666);
        writeFile(managed, managedContent);
        size_t calls = 0;
        const GrubOperationResult result = ensureManagedGrubDropInValue(
            managedTestOptions(managed, base), "GRUB_TIMEOUT", "10",
            countingRebuildRunner(calls));
        require(!result.ok && calls == 0 &&
                    readFile(managed) == managedContent,
                "unsafe base defaults must block even an idempotent apply");
    }

    // Fix #1 regression: the whole grub.d topology is proven before the
    // rebuild — a foreign *.cfg sorted after zzzz-fic.cfg would override FIC
    // values in update-grub's lexicographic sourcing order.
    {
        const fs::path directory = root / "base-topology/etc/default/grub.d";
        fs::create_directories(directory);
        const fs::path base = root / "base-topology/etc/default/grub";
        const fs::path managed = directory / "zzzz-fic.cfg";
        writeFile(base, "GRUB_TIMEOUT=3\n");
        writeFile(directory / "zzzzz-late.cfg", "GRUB_TIMEOUT=99\n");
        size_t calls = 0;
        const GrubOperationResult result = ensureManagedGrubDropInValue(
            managedTestOptions(managed, base), "GRUB_TIMEOUT", "10",
            countingRebuildRunner(calls));
        require(!result.ok && calls == 0 && !fs::exists(managed),
                "a late foreign drop-in must block the owned apply rebuild");
    }

    // A symlinked foreign drop-in in grub.d must fail the rebuild inputs.
    {
        const fs::path directory = root / "base-topo-link/etc/default/grub.d";
        fs::create_directories(directory);
        const fs::path base = root / "base-topo-link/etc/default/grub";
        const fs::path managed = directory / "zzzz-fic.cfg";
        writeFile(base, "GRUB_TIMEOUT=3\n");
        writeFile(root / "base-topo-link/target.cfg", "GRUB_DEFAULT=0\n");
        fs::create_symlink(root / "base-topo-link/target.cfg",
                           directory / "40-foreign.cfg");
        size_t calls = 0;
        const GrubOperationResult result = ensureManagedGrubDropInValue(
            managedTestOptions(managed, base), "GRUB_TIMEOUT", "10",
            countingRebuildRunner(calls));
        require(!result.ok && calls == 0 && !fs::exists(managed),
                "a symlinked foreign drop-in must fail the rebuild inputs");
    }

    // A missing FIC drop-in stays legitimate: only the directory chain and
    // foreign drop-ins are proven; the owned apply then creates the artifact.
    {
        const fs::path directory = root / "base-topo-missing/etc/default/grub.d";
        fs::create_directories(directory);
        const fs::path base = root / "base-topo-missing/etc/default/grub";
        writeFile(directory / "10-vendor.cfg", "GRUB_DEFAULT=0\n");
        const fs::path managed = directory / "zzzz-fic.cfg";
        writeFile(base, "GRUB_TIMEOUT=3\n");
        size_t calls = 0;
        const GrubOperationResult result = ensureManagedGrubDropInValue(
            managedTestOptions(managed, base), "GRUB_TIMEOUT", "10",
            countingRebuildRunner(calls));
        require(result.ok && calls == 1 &&
                    readFile(managed) == managedContent,
                "a missing managed drop-in must not block the owned apply");
    }
}

// Fix #4 regression: the ALT idempotent apply must re-prove the loaded
// snapshot before the mandatory rebuild; a concurrent external replacement
// after load() fails closed with the external bytes preserved.
void testAltIdempotentReproofRace(const fs::path& root) {
    const fs::path directory = root / "alt-reproof/etc/sysconfig";
    fs::create_directories(directory);
    const fs::path defaults = directory / "grub2";
    writeFile(
        defaults,
        "GRUB_TIMEOUT=5\n"
        "\n"
        "# FIC_GRUB_BLOCK_BEGIN version=1\n"
        "GRUB_TIMEOUT=\"10\"\n"
        "# FIC_GRUB_BLOCK_END\n");
    const std::string external = "EXTERNAL=1\n";
    setGrubPostLoadMutationHookForTests(
        [&defaults, &external](const std::string&) {
            writeFile(defaults, external);
        });
    std::size_t rebuildCalls = 0;
    const GrubCommandRunner runner =
        [&rebuildCalls](const std::string&, const std::vector<std::string>&,
                        const ProcessOptions&) {
            ++rebuildCalls;
            return successfulProcess();
        };
    GrubConfiguration configuration(testOptions(defaults), runner);
    std::string error;
    require(configuration.load(error), error);
    const GrubOperationResult result =
        configuration.ensureManagedValue("GRUB_TIMEOUT", "10");
    require(!result.ok && rebuildCalls == 0,
            "a stale idempotent ALT snapshot must fail before the rebuild");
    require(readFile(defaults) == external,
            "external bytes must survive the failed idempotent apply");
}

void testManagedConcurrentDriftCompensation(const fs::path& root) {
    // Existing managed file changed externally during the failed rebuild:
    // FIC must keep the external state, refuse to restore the original,
    // and skip the compensating rebuild.
    {
        const fs::path directory =
            root / "managed-drift-existing/etc/default/grub.d";
        const fs::path managed = directory / "zzzz-fic.cfg";
        fs::create_directories(directory);
        writeFile(
            managed, "# Managed by FIC. Do not edit.\n\nGRUB_TIMEOUT=\"5\"\n");
        const std::string external =
            "# Managed by FIC. Do not edit.\n\nGRUB_TIMEOUT=\"20\"\n";
        size_t calls = 0;
        const GrubOperationResult result = ensureManagedGrubDropInValue(
            managedTestOptions(managed), "GRUB_TIMEOUT", "10",
            [&calls, &managed, external](
                const std::string&, const std::vector<std::string>&,
                const ProcessOptions&) {
                ++calls;
                if (calls == 1) {
                    // Privileged external writer mutates the FIC-installed
                    // file in place right before the rebuild fails.
                    writeFile(managed, external);
                    return failedProcess("injected rebuild failure");
                }
                return successfulProcess();
            });
        require(!result.ok && calls == 1,
                "concurrent drift must not trigger a compensating rebuild");
        require(readFile(managed) == external,
                "external concurrent change was overwritten by compensation");
        require(std::any_of(
                    result.diagnostics.begin(),
                    result.diagnostics.end(),
                    [](const std::string& diagnostic) {
                        return diagnostic.find("внешнее изменение") !=
                                std::string::npos ||
                            diagnostic.find("concurrent") !=
                                std::string::npos;
                    }),
                "concurrent drift was not diagnosed");
    }

    // Newly created managed file replaced externally (new inode) during the
    // failed rebuild: FIC must keep the external state, refuse to restore
    // or remove anything, and skip the compensating rebuild. This is the
    // TOCTOU case the old check-then-unlink compensation would have lost.
    {
        const fs::path directory =
            root / "managed-drift-created/etc/default/grub.d";
        const fs::path managed = directory / "zzzz-fic.cfg";
        fs::create_directories(directory);
        const std::string external =
            "# Managed by FIC. Do not edit.\n\nGRUB_TIMEOUT=\"20\"\n";
        size_t calls = 0;
        const GrubOperationResult result = ensureManagedGrubDropInValue(
            managedTestOptions(managed), "GRUB_TIMEOUT", "10",
            [&calls, &managed, external](
                const std::string&, const std::vector<std::string>&,
                const ProcessOptions&) {
                ++calls;
                if (calls == 1) {
                    // Privileged external writer REPLACES the FIC-created
                    // file with a new inode right before the rebuild fails.
                    const fs::path replacement =
                        fs::path(managed.string() + ".external");
                    writeFile(replacement, external);
                    fs::rename(replacement, managed);
                    return failedProcess("injected rebuild failure");
                }
                return successfulProcess();
            });
        require(!result.ok && calls == 1,
                "concurrent drift on a created file must not run "
                "a compensating rebuild");
        require(result.sourceState ==
                    GrubSourceMutationState::Indeterminate,
                "concurrent drift on a created file must be Indeterminate");
        require(fs::exists(managed) && readFile(managed) == external,
                "FIC removed or overwrote an externally mutated created file");
        require(std::any_of(
                    result.diagnostics.begin(),
                    result.diagnostics.end(),
                    [](const std::string& diagnostic) {
                        return diagnostic.find("внешнее изменение") !=
                                std::string::npos ||
                            diagnostic.find("concurrent") !=
                                std::string::npos;
                    }),
                "concurrent drift on a created file was not diagnosed");
    }
}

void testConcretePolicyContracts(
    const fic::platform::PlatformExecutableResolver& executables) {
    const fic::platform::GrubPlatformConfig platform{
        fic::platform::GrubConfigTopology::OwnedDefaultsDropIn,
        {}, "/etc/default/grub.d/zzzz-fic.cfg", {}, {}};
    OSS_grub_timeout timeout(platform, executables);
    require(timeout.moduleName == "OSS" && timeout.submoduleName == "Grub" &&
                timeout.policyName == "grub_timeout",
            "timeout policy metadata is incorrect");
    require(timeout.validate("0") && timeout.validate("60") &&
                !timeout.validate("61"),
            "timeout policy bounds are incorrect");

    OSS_grub_cmdline_linux cmdline(platform, executables);
    require(cmdline.policyName == "grub_cmdline_linux" &&
                cmdline.getDefaultValue() == "" &&
                cmdline.validate(cmdline.getDefaultValue()) &&
                cmdline.validate("") && !cmdline.validate("bad\nvalue") &&
                cmdline.postprocessingValue("") == "[]" &&
                cmdline.reverse_postprocessingValue("[]") == "" &&
                cmdline.postprocessingValue("quiet isolcpus=1-3,5") ==
                    "[\"quiet isolcpus=1-3,5\"]" &&
                cmdline.reverse_postprocessingValue(
                    "[\"quiet isolcpus=1-3,5\"]") ==
                    "quiet isolcpus=1-3,5",
            "kernel command-line policy contract is incorrect");

    OSS_grub_disable_recovery recovery(platform, executables);
    require(recovery.policyName == "grub_disable_recovery" &&
                recovery.validate("ENABLE") && recovery.validate("DISABLE") &&
                !recovery.validate("true"),
            "recovery policy contract is incorrect");
}

} // namespace

int main() {
    static_assert(std::is_abstract_v<Grub>,
                  "Grub must remain abstract");

    const fs::path root = fs::temp_directory_path() /
        ("fic-grub-policy-test-" + std::to_string(::getpid()));
    fs::remove_all(root);

    try {
        initializeRuntimePaths(root);
        const fs::path fakeExecutable = root / "bin/grub-rebuild";
        writeFile(fakeExecutable, "test", 0755);
        auto resolver = makeResolver(fakeExecutable);

        writeFile(
            root / "config/OSS.conf",
            "_schema_version=1\n"
            "grub_test_policy.status=ENABLE\n"
            "grub_test_policy.value=expected\n"
            "grub_apply_test_policy.status=ENABLE\n"
            "grub_apply_test_policy.value=expected\n"
            "grub_timeout.status=DISABLE\n"
            "grub_timeout.value=5\n"
            "grub_cmdline_linux.status=DISABLE\n"
            "grub_cmdline_linux.value=[]\n"
            "grub_disable_recovery.status=DISABLE\n"
            "grub_disable_recovery.value=ENABLE\n");

        RecordingGrubPolicy policy(resolver);
        require(policy.moduleName == "OSS" && policy.submoduleName == "Grub",
                "Grub wrapper metadata is incorrect");
        require(policy.apply(), "Grub apply wrapper failed");
        require(policy.called && policy.observedValue == "expected",
                "Grub hook did not receive configured value");

        const fs::path applyDefaults = root / "apply/etc/sysconfig/grub2";
        const std::string foreignApply = "GRUB_TEST_VALUE=expected\n";
        writeFile(applyDefaults, foreignApply);
        writeFile(fakeExecutable, "#!/bin/sh\nexit 1\n", 0755);
        writeFile(
            root / "data/commandhash.txt",
            fakeExecutable.string() +
                "=275239824e00e61b0a220e61a41791c7e9b4bd726f8b0c27077a338f8131c9dc\n");
        ApplyingGrubPolicy applyingPolicy(
            {fic::platform::GrubConfigTopology::SharedDefaultsFile,
             applyDefaults, {}, {}, {}}, resolver);
        // ALT apply with a failing rebuild: the installed FIC block is
        // conditionally compensated, the Prepared provenance is discarded
        // (failure + Compensated -> no journal record).
        require(!applyingPolicy.apply(),
                "failing rebuild must fail the GRUB policy apply");
        require(readFile(applyDefaults) == foreignApply,
                "failed ALT apply must restore the foreign file byte-exact");
        {
            std::string journalError;
            auto* journal = fic::rollback::DaemonMutationJournal::instance()
                                .tryGet(journalError);
            require(journal != nullptr, journalError);
            require(journal->records().empty(),
                "failed compensated ALT apply must not leave journal records");
        }

        writeFile(
            root / "config/OSS.conf",
            "_schema_version=1\n"
            "grub_test_policy.status=ENABLE\n"
            "grub_test_policy.value=invalid\n"
            "grub_cmdline_linux.status=ENABLE\n"
            "grub_cmdline_linux.value=not-json\n");
        RecordingGrubPolicy invalidPolicy(resolver);
        require(!invalidPolicy.apply() && !invalidPolicy.called,
                "invalid value must fail before Grub hook");
        OSS_grub_cmdline_linux malformedCmdline(
            {fic::platform::GrubConfigTopology::SharedDefaultsFile,
             applyDefaults, {}, {}, {}}, resolver);
        require(!malformedCmdline.apply(),
                "malformed stored GRUB value must fail without escaping apply");

        testGrubManagedBlockParser();
        testGrubConfigurationEditor(root);
        testAltForeignPreservationAndRelocation(root);
        testAmbiguousAndDynamicAssignmentsFailClosed(root);
        testRebuildFailureCompensates(root);
        testAltDoubleRebuildFailurePendingRebuild(root);
        testAltPlacementComplianceSemantics(root);
        testUnsafeInputAndPathsFailClosed(root);
        testAltSharedTopologyStaysShared(root);
        testManagedDropInEditingAndIdempotence(root);
        testManagedTopologyAndStrictFormat(root);
        testManagedDropInOrdering(root);
        testManagedRebuildFailureCompensation(root);
        testBaseDefaultsValidation(root);
        testAltIdempotentReproofRace(root);
        testManagedConcurrentDriftCompensation(root);
        testConcretePolicyContracts(resolver);
    } catch (const std::exception& error) {
        std::cerr << "GrubPolicyTests failed: " << error.what() << '\n';
        fs::remove_all(root);
        return 1;
    }

    fs::remove_all(root);
    std::cout << "GrubPolicyTests passed\n";
    return 0;
}
