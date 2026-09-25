#include "modules/identity_access/pam/PamPasswordTopologyState.h"

#include "modules/identity_access/pam/PamManagedPasswordSlotWriter.h"

#include <algorithm>
#include <fstream>
#include <iterator>
#include <optional>
#include <sstream>
#include <utility>
#include <vector>

namespace fic::identity::pam {
namespace {

// Canonical journal identity of the two password domains (exact payload
// contract of PamManagedPasswordSlotWriter: policy ref, PAM backend,
// "capability/<policy>" resource and the role-specific activation
// identifier). The behavioral sync between this read-only matcher and the
// writer is covered by the executor contract tests (a slot activated by
// the writer MUST be proven owned here).
const char* passwordDomainPolicyName(ManagedPasswordCapability capability) {
    return capability == ManagedPasswordCapability::PasswordQuality
        ? "enable_password_quality"
        : "enable_password_history";
}

const char* slotProfileIdentifier(ManagedPasswordSlotRole role) {
    switch (role) {
    case ManagedPasswordSlotRole::Quality:
        return kFicPasswordQualityHookProfileId;
    case ManagedPasswordSlotRole::HistoryNormal:
        return kFicPasswordHistoryHookProfileId;
    case ManagedPasswordSlotRole::HistoryInitial:
        return kFicPasswordHistoryInitialHookProfileId;
    }
    return kFicPasswordQualityHookProfileId;
}

std::string trimTrailingWhitespace(const std::string& text) {
    std::size_t end = text.size();
    while (end > 0 &&
           (text[end - 1] == ' ' || text[end - 1] == '\t' ||
            text[end - 1] == '\r')) {
        --end;
    }
    return text.substr(0, end);
}

std::vector<std::string> splitWhitespaceTokens(const std::string& line) {
    std::vector<std::string> tokens;
    std::istringstream stream(line);
    std::string token;
    while (stream >> token) {
        tokens.push_back(token);
    }
    return tokens;
}

bool readFileIfPresent(
    const std::filesystem::path& path, bool& present, std::string& content,
    std::string& error) {
    present = false;
    content.clear();
    std::error_code statusError;
    const std::filesystem::file_status status =
        std::filesystem::symlink_status(path, statusError);
    if (statusError) {
        if (statusError ==
            std::make_error_code(std::errc::no_such_file_or_directory)) {
            return true;
        }
        error = "could not stat " + path.string() + ": " +
            statusError.message();
        return false;
    }
    if (!std::filesystem::is_regular_file(status)) {
        error = "expected regular file at " + path.string();
        return false;
    }
    std::ifstream stream(path, std::ios::binary);
    if (!stream.good()) {
        error = "could not read " + path.string();
        return false;
    }
    content.assign(
        std::istreambuf_iterator<char>(stream),
        std::istreambuf_iterator<char>());
    present = true;
    return true;
}

// One parsed password line of the generated stack.
struct GeneratedStackLine {
    std::size_t position = 0;
    // "include" for include lines, "module" for module lines, "" for
    // non-password lines.
    std::string kind;
    std::string target;   // include target or module name
};

std::vector<GeneratedStackLine> parseGeneratedPasswordStack(
    const std::string& content) {
    std::vector<GeneratedStackLine> lines;
    std::istringstream stream(content);
    std::string raw;
    std::size_t position = 0;
    while (std::getline(stream, raw)) {
        const std::string line = trimTrailingWhitespace(raw);
        const std::vector<std::string> tokens =
            splitWhitespaceTokens(line);
        if (!tokens.empty() && tokens.front() == "password" &&
            tokens.size() >= 3) {
            GeneratedStackLine parsed;
            parsed.position = position;
            // Include forms: "password [control...] include <target>".
            // Substack/@include forms are deliberately NOT treated as
            // managed-slot includes (same strictness as the attach
            // validator).
            for (std::size_t index = 1; index + 1 < tokens.size();
                 ++index) {
                if (tokens[index] == "include") {
                    parsed.kind = "include";
                    parsed.target = tokens[index + 1];
                    break;
                }
            }
            if (parsed.kind.empty()) {
                for (std::size_t index = 1; index < tokens.size();
                     ++index) {
                    const std::string& token = tokens[index];
                    if (token.size() > 3 &&
                        token.compare(token.size() - 3, 3, ".so") == 0) {
                        parsed.kind = "module";
                        parsed.target = token;
                        break;
                    }
                }
            }
            if (!parsed.kind.empty()) {
                lines.push_back(std::move(parsed));
            }
        }
        ++position;
    }
    return lines;
}

const ManagedPasswordSlotSpec* slotForFileName(const std::string& name) {
    for (const ManagedPasswordSlotSpec& spec :
         PamManagedPasswordSlots::slots()) {
        if (name == spec.fileName) {
            return &spec;
        }
    }
    return nullptr;
}

} // namespace

// Coherence, ownership, semantic model and classification tail of the
// snapshot assembly (defined after the public entry point).
bool inspectPamPasswordTopologyTail(
    const PamPasswordStateInspectionOptions& options,
    fic::rollback::MutationJournal& journal,
    PamPasswordTopologySnapshot& snapshot, std::string& error);
bool inspectPamPasswordTopologyOwnershipTail(
    fic::rollback::MutationJournal& journal,
    PamPasswordTopologySnapshot& snapshot, std::string& error);

bool inspectPamPasswordTopology(
    const PamPasswordStateInspectionOptions& options,
    fic::rollback::MutationJournal& journal,
    PamPasswordTopologySnapshot& snapshot, std::string& error) {
    snapshot = {};
    const std::filesystem::path configDirectory =
        options.configDirectory.empty()
        ? std::filesystem::path("/etc/pam.d")
        : options.configDirectory;
    const std::filesystem::path stateDirectory =
        options.stateDirectory.empty()
        ? std::filesystem::path("/var/lib/pam")
        : options.stateDirectory;
    const std::string stateFileName =
        options.passwordStateFileName.empty()
        ? std::string("password")
        : options.passwordStateFileName;
    const std::string stackFileName =
        options.generatedPasswordStackFile.empty()
        ? std::string("common-password")
        : options.generatedPasswordStackFile;

    // 1. Password state database: exact FIC selections + foreign profile.
    bool present = false;
    std::string content;
    if (!readFileIfPresent(
            stateDirectory / stateFileName, present, content, error)) {
        return false;
    }
    if (present) {
        std::istringstream stream(content);
        std::string line;
        while (std::getline(stream, line)) {
            const std::string trimmed = trimTrailingWhitespace(line);
            const std::string prefix = "Module: ";
            if (trimmed.compare(0, prefix.size(), prefix) != 0) {
                continue;
            }
            const std::string identifier = trimmed.substr(prefix.size());
            if (identifier == kFicPasswordQualityHookProfileId) {
                snapshot.selections.ficQualitySelected = true;
            } else if (identifier == kFicPasswordHistoryHookProfileId) {
                snapshot.selections.ficHistorySelected = true;
            } else if (identifier ==
                kFicPasswordHistoryInitialHookProfileId) {
                snapshot.selections.ficHistoryInitialSelected = true;
            } else if (identifier == kStockPwqualityProfileId) {
                snapshot.foreignPwqualityProfileSelected = true;
            }
        }
    }

    // 2. Managed slot states (canonical grammar).
    struct SlotProbe {
        const ManagedPasswordSlotSpec& spec;
        ManagedPasswordSlotState* state;
        std::uint64_t* mutationId;
    };
    const SlotProbe probes[] = {
        {PamManagedPasswordSlots::qualitySlot(),
         &snapshot.qualitySlotState, &snapshot.qualitySlotMutationId},
        {PamManagedPasswordSlots::historyNormalSlot(),
         &snapshot.historySlotState, &snapshot.historySlotMutationId},
        {PamManagedPasswordSlots::historyInitialSlot(),
         &snapshot.historyInitialSlotState,
         &snapshot.historyInitialSlotMutationId},
    };
    for (const SlotProbe& probe : probes) {
        const std::filesystem::path path =
            PamManagedPasswordSlots::slotFilePath(
                probe.spec, configDirectory);
        bool slotPresent = false;
        std::string slotContent;
        if (!readFileIfPresent(
                path, slotPresent, slotContent, error)) {
            return false;
        }
        ManagedPasswordSlotInspection inspection;
        if (!PamManagedPasswordSlots::inspectContent(
                probe.spec,
                slotPresent
                    ? std::optional<std::string>(slotContent)
                    : std::nullopt,
                inspection, error)) {
            error = "managed password slot inspection failed for " +
                path.string() + ": " + error;
            return false;
        }
        *probe.state = inspection.state;
        *probe.mutationId = inspection.mutationId;
    }

    // 3. Generated stack evidence (trailing-whitespace-tolerant grammar).
    if (!readFileIfPresent(
            configDirectory / stackFileName, present, content, error)) {
        return false;
    }
    if (!present) {
        error = "the generated password stack is missing: " +
            (configDirectory / stackFileName).string();
        return false;
    }
    for (const GeneratedStackLine& parsed :
         parseGeneratedPasswordStack(content)) {
        if (parsed.kind == "include") {
            if (const ManagedPasswordSlotSpec* slot =
                    slotForFileName(parsed.target)) {
                switch (slot->role) {
                case ManagedPasswordSlotRole::Quality:
                    snapshot.generated.qualityInclude = true;
                    snapshot.generated.qualityIncludePosition =
                        parsed.position;
                    break;
                case ManagedPasswordSlotRole::HistoryNormal:
                    snapshot.generated.historyInclude = true;
                    snapshot.generated.historyIncludePosition =
                        parsed.position;
                    break;
                case ManagedPasswordSlotRole::HistoryInitial:
                    snapshot.generated.historyInitialInclude = true;
                    snapshot.generated.historyInitialIncludePosition =
                        parsed.position;
                    break;
                }
            }
        } else if (parsed.kind == "module") {
            if (parsed.target == "pam_unix.so" &&
                snapshot.generated.pamUnixPosition ==
                    kPamPasswordStackAbsent) {
                snapshot.generated.pamUnixPosition = parsed.position;
            } else if (parsed.target == "pam_pwquality.so") {
                snapshot.generated.foreignPwqualityDirectRule = true;
                snapshot.generated.foreignPwqualityPosition =
                    parsed.position;
            }
        }
    }
    return inspectPamPasswordTopologyTail(
        options, journal, snapshot, error);
}

bool inspectPamPasswordTopologyTail(
    const PamPasswordStateInspectionOptions& options,
    fic::rollback::MutationJournal& journal,
    PamPasswordTopologySnapshot& snapshot, std::string& error) {
    (void)options;

    // 4. Foreign producer discovery (Rule I): the stock profile selection
    // and a direct pam_pwquality.so rule must agree.
    snapshot.foreignQualityProducer =
        snapshot.foreignPwqualityProfileSelected &&
        snapshot.generated.foreignPwqualityDirectRule;
    if (snapshot.foreignPwqualityProfileSelected !=
        snapshot.generated.foreignPwqualityDirectRule) {
        snapshot.coherenceError =
            snapshot.foreignPwqualityProfileSelected
            ? "distro pwquality is selected in the pam-auth-update "
              "password state but the generated stack has no direct "
              "pam_pwquality.so provider (Rule I violation)"
            : "the generated stack carries a direct pam_pwquality.so rule "
              "but no distro pwquality profile is selected (Rule I "
              "violation)";
    }

    // 5. Include/selection coherence: a generated include of a managed
    // slot exists exactly when the profile is selected.
    if (snapshot.coherenceError.empty() &&
        snapshot.generated.qualityInclude !=
            snapshot.selections.ficQualitySelected) {
        snapshot.coherenceError =
            "the FIC quality selection and its generated include disagree "
            "(regeneration is incomplete or the state was modified "
            "externally)";
    }
    if (snapshot.coherenceError.empty() &&
        snapshot.generated.historyInclude !=
            snapshot.selections.ficHistorySelected) {
        snapshot.coherenceError =
            "the FIC history selection and its generated include disagree "
            "(regeneration is incomplete or the state was modified "
            "externally)";
    }
    if (snapshot.coherenceError.empty() &&
        snapshot.generated.historyInitialInclude !=
            snapshot.selections.ficHistoryInitialSelected) {
        snapshot.coherenceError =
            "the FIC history-initial selection and its generated include "
            "disagree (regeneration is incomplete or the state was "
            "modified externally)";
    }
    return inspectPamPasswordTopologyOwnershipTail(
        journal, snapshot, error);
}

bool inspectPamPasswordTopologyOwnershipTail(
    fic::rollback::MutationJournal& journal,
    PamPasswordTopologySnapshot& snapshot, std::string& error) {
    // 6. Journal ownership per identity. A virgin journal (neither the
    // journal nor its witness exists) is provenance-empty, not an error;
    // an existing journal that cannot be proven read-only fails closed.
    const auto witness = journal.witnessPath();
    auto journalPath = witness;
    journalPath.replace_extension();
    const auto absent = [](const std::filesystem::path& path) {
        std::error_code ec;
        const auto status = std::filesystem::symlink_status(path, ec);
        return status.type() == std::filesystem::file_type::not_found &&
            (!ec || ec == std::errc::no_such_file_or_directory);
    };
    if (!journal.loaded() && absent(journalPath) && absent(witness)) {
        // VirginUnbound: no ownership anywhere; skip the record match.
    } else if (!journal.usable() || !journal.lifecycleInitialized()) {
        std::string journalError;
        if (!journal.validatePersistentStateReadOnly(journalError)) {
            error = "managed password journal persistent state is not "
                    "proven (fail closed): " +
                journalError;
            return false;
        }
        if (!journal.usable() || !journal.lifecycleInitialized()) {
            error = "managed password journal failed its read-only gate";
            return false;
        }
    }
    if (journal.usable()) {
        const auto capabilityOf = [](ManagedPasswordSlotRole role) {
            return role == ManagedPasswordSlotRole::Quality
                ? ManagedPasswordCapability::PasswordQuality
                : ManagedPasswordCapability::PasswordHistory;
        };
        const auto owned = [&](ManagedPasswordSlotRole role,
                               ManagedPasswordSlotState state,
                               std::uint64_t markerId) {
            if (state != ManagedPasswordSlotState::Active ||
                markerId == 0) {
                return false;
            }
            for (const fic::rollback::MutationRecord& candidate :
                 journal.records()) {
                if (candidate.id != markerId) {
                    continue;
                }
                // Exact payload contract of PamManagedPasswordSlotWriter.
                const auto* payload = std::get_if<
                    fic::rollback::UndoDisablePamCapability>(
                    &candidate.undo.payload);
                const std::string policyName =
                    passwordDomainPolicyName(capabilityOf(role));
                if (candidate.policy.moduleName != "IDENTITY_ACCESS" ||
                    candidate.policy.submoduleName != "PAM" ||
                    candidate.policy.policyName != policyName ||
                    candidate.undo.backend !=
                        fic::rollback::MutationBackend::Pam ||
                    candidate.resource !=
                        std::string("capability/") + policyName ||
                    payload == nullptr ||
                    payload->topology !=
                        fic::rollback::PamTopologyKind::PamAuthUpdate ||
                    payload->capability != policyName) {
                    return false;
                }
                return candidate.status ==
                           fic::rollback::MutationStatus::Applied &&
                    payload->activationIdentifiers ==
                        std::vector<std::string>{
                            slotProfileIdentifier(role)};
            }
            return false;
        };
        snapshot.ownership.ficQualityOwned = owned(
            ManagedPasswordSlotRole::Quality,
            snapshot.qualitySlotState, snapshot.qualitySlotMutationId);
        snapshot.ownership.ficHistoryOwned = owned(
            ManagedPasswordSlotRole::HistoryNormal,
            snapshot.historySlotState, snapshot.historySlotMutationId);
        snapshot.ownership.ficHistoryInitialOwned = owned(
            ManagedPasswordSlotRole::HistoryInitial,
            snapshot.historyInitialSlotState,
            snapshot.historyInitialSlotMutationId);
    }

    // 7. Semantic model, classification and C2 structural safety.
    PamPasswordTopology& topology = snapshot.topology;
    topology.selections = snapshot.selections;
    topology.foreignQualityProducer = snapshot.foreignQualityProducer;
    topology.producer =
        snapshot.selections.ficQualitySelected
        ? PamPasswordProducerKind::FicQuality
        : (snapshot.selections.ficHistoryInitialSelected
               ? PamPasswordProducerKind::FicHistoryInitial
               : (snapshot.foreignQualityProducer
                      ? PamPasswordProducerKind::ForeignQuality
                      : PamPasswordProducerKind::None));
    topology.history =
        snapshot.selections.ficHistorySelected
        ? PamPasswordHistoryKind::FicConsumer
        : PamPasswordHistoryKind::None;
    snapshot.classification = classifyPamPasswordTopology(topology);
    PamPasswordC2SlotStates slots;
    slots.quality = snapshot.qualitySlotState;
    slots.history = snapshot.historySlotState;
    slots.historyInitial = snapshot.historyInitialSlotState;
    snapshot.safety = evaluatePamPasswordC2SelectionSafety(
        snapshot.selections, slots, snapshot.foreignQualityProducer);
    error.clear();
    return true;
}

bool provePamPasswordTopologySemantics(
    const PamPasswordTopologySnapshot& snapshot, std::string& error) {
    const PamPasswordGeneratedStackEvidence& generated =
        snapshot.generated;
    const PamPasswordSelections& selections = snapshot.selections;
    const std::size_t absent = kPamPasswordStackAbsent;
    const auto requireInclude = [&](bool include, std::size_t position,
                                    const char* name,
                                    std::size_t& out) {
        if (!include || position == absent) {
            error = std::string("the generated include of the managed ") +
                name + " slot is missing while the profile is selected";
            return false;
        }
        out = position;
        return true;
    };

    if (generated.pamUnixPosition == absent) {
        error =
            "the generated password stack carries no pam_unix.so rule "
            "(the stock unix profile is not selected or the stack is "
            "malformed)";
        return false;
    }

    std::size_t producerPosition = absent;
    if (selections.ficQualitySelected) {
        if (!requireInclude(
                generated.qualityInclude, generated.qualityIncludePosition,
                "quality", producerPosition)) {
            return false;
        }
        if (producerPosition >= generated.pamUnixPosition) {
            error =
                "the FIC quality include is not before the pam_unix rule "
                "in the generated stack (effective ordering proof "
                "failed)";
            return false;
        }
    }
    if (selections.ficHistoryInitialSelected) {
        if (selections.ficHistorySelected) {
            error =
                "both FIC history variants are selected (consumer and "
                "initial producer) — mutual exclusion violated";
            return false;
        }
        std::size_t initialPosition = absent;
        if (!requireInclude(
                generated.historyInitialInclude,
                generated.historyInitialIncludePosition,
                "history-initial", initialPosition)) {
            return false;
        }
        if (generated.historyInclude) {
            error =
                "the FIC history consumer include exists while the "
                "history-initial producer profile is selected";
            return false;
        }
        if (initialPosition >= generated.pamUnixPosition) {
            error =
                "the FIC history-initial include is not before the "
                "pam_unix rule in the generated stack (effective "
                "ordering proof failed)";
            return false;
        }
        if (snapshot.foreignQualityProducer) {
            error =
                "a foreign quality producer coexists with the selected "
                "FIC history-initial producer";
            return false;
        }
    }
    if (selections.ficHistorySelected) {
        std::size_t historyPosition = absent;
        if (!requireInclude(
                generated.historyInclude, generated.historyIncludePosition,
                "history", historyPosition)) {
            return false;
        }
        if (generated.historyInitialInclude) {
            error =
                "the FIC history-initial include exists while the "
                "history consumer profile is selected";
            return false;
        }
        if (historyPosition >= generated.pamUnixPosition) {
            error =
                "the FIC history include is not before the pam_unix rule "
                "in the generated stack (effective ordering proof "
                "failed)";
            return false;
        }
        // The producer must exist and precede the consumer.
        if (selections.ficQualitySelected) {
            if (producerPosition == absent ||
                producerPosition >= historyPosition) {
                error =
                    "the FIC quality producer include is not before the "
                    "FIC history consumer include (effective ordering "
                    "proof failed)";
                return false;
            }
        } else if (snapshot.foreignQualityProducer) {
            if (generated.foreignPwqualityPosition == absent ||
                generated.foreignPwqualityPosition >= historyPosition) {
                error =
                    "the foreign pwquality producer is not before the "
                    "FIC history consumer include (effective ordering "
                    "proof failed)";
                return false;
            }
        } else {
            error =
                "the FIC history consumer is selected but no token "
                "producer exists (Rule G violation)";
            return false;
        }
    }
    // Unselected identities must not have generated includes.
    if (!selections.ficQualitySelected && generated.qualityInclude) {
        error = "the FIC quality include exists while the profile is not "
                "selected";
        return false;
    }
    if (!selections.ficHistorySelected && generated.historyInclude) {
        error = "the FIC history include exists while the profile is not "
                "selected";
        return false;
    }
    if (!selections.ficHistoryInitialSelected &&
        generated.historyInitialInclude) {
        error = "the FIC history-initial include exists while the profile "
                "is not selected";
        return false;
    }
    error.clear();
    return true;
}

} // namespace fic::identity::pam
