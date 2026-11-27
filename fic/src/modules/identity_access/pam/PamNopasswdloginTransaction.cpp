#include "modules/identity_access/pam/PamNopasswdloginTransaction.h"
#include "modules/identity_access/pam/PamNopasswdloginFragment.h"
#include "modules/identity_access/pam/PamControlFlowAnalyzer.h"
#include <fic/core/fs/TrustedFileReader.h>

#include <algorithm>
#include <cerrno>
#include <mutex>
#include <unistd.h>

namespace fic::identity::pam {
namespace {

using namespace fic::rollback;
const PolicyRef policy{"IDENTITY_ACCESS", "PAM", "disable_nopasswdlogin"};
std::mutex transactionMutex;

struct Snapshot {
    std::filesystem::path path;
    std::optional<AtomicTargetState> state;
};

bool read(const std::filesystem::path& path, Snapshot& snapshot, std::string& error) {
    fic::core::TrustedFileReadOptions options;
    options.expectedOwner = ::geteuid();
    options.forbiddenMode = 0022;
    options.requireSingleLink = true;
    fic::core::TrustedFileMetadata metadata;
    std::string bytes;
    int code = 0;
    snapshot = {path, std::nullopt};
    if (!fic::core::readTrustedFile(path, options, bytes, error, &metadata, {}, &code)) {
        if (code != ENOENT) return false;
        error.clear();
        return true;
    }
    AtomicTargetState state;
    state.identity.device = metadata.device;
    state.identity.inode = metadata.inode;
    state.content = std::move(bytes);
    state.owner = metadata.owner;
    state.group = metadata.group;
    state.mode = metadata.mode & 07777;
    snapshot.state = std::move(state);
    return true;
}

bool durable(const Snapshot& snapshot, std::string& error) {
    if (snapshot.state) {
        return AtomicFileWriter::ensureTargetDurableIfCurrentState(
            snapshot.path, *snapshot.state, &error);
    }
    return AtomicFileWriter::ensureTargetAbsentDurableIfCurrentState(snapshot.path, &error);
}

bool write(const PamNopasswdloginOptions& options, const Snapshot& before,
           const std::string& candidate, Snapshot& published, std::string& error) {
    if (!before.state) {
        error = "Missing PAM service cannot be created by suppression";
        return false;
    }
    AtomicWriteOptions writeOptions;
    writeOptions.createIfMissing = false;
    writeOptions.rejectSymlink = true;
    writeOptions.metadataPolicy = FileMetadataPolicy::PreserveExisting;
    writeOptions.expectedTargetState = *before.state;
    const bool success = options.writer(before.path.string(), candidate, writeOptions, &error);
    std::string verifyError;
    if (!read(before.path, published, verifyError) || !published.state ||
        published.state->content != candidate ||
        published.state->owner != before.state->owner ||
        published.state->group != before.state->group ||
        published.state->mode != before.state->mode || !durable(published, verifyError)) {
        if (!verifyError.empty()) error += "; " + verifyError;
        return false;
    }
    return success;
}

bool hasBypass(PamConfiguration& configuration, const std::string& service,
               std::string& error, const std::filesystem::path& permittedMarkerSource = {}) {
    std::string selected;
    if (!configuration.existingServiceOrOther(service, selected, error)) return true;
    if (selected.empty()) return false;
    std::vector<PamRule> rules;
    std::set<std::filesystem::path> sources;
    if (!configuration.collectRules(selected, PamManagementGroup::Auth, rules, error, &sources)) return true;
    for (const auto& source : sources) {
        if (source == permittedMarkerSource) continue;
        Snapshot current;
        if (!read(source, current, error)) return true;
        if (!current.state) {
            error = "PAM dependency disappeared during suppression proof";
            return true;
        }
        if (current.state->content.find("FIC_PAM_NOPASSWDLOGIN") != std::string::npos) {
            error = "Unsupported suppression witness in an included or fallback PAM source";
            return true;
        }
    }
    return std::any_of(rules.begin(), rules.end(), referencesNopasswdlogin);
}

bool prove(const PamNopasswdloginOptions& options, const std::string& service,
           const std::string& original, const std::string& suppressed,
           const PamRule& target, std::string& error) {
    PamConfiguration before(options.platform), after(options.platform);
    PamEffectiveStack originalStack, suppressedStack;
    if (!before.projectService(service, original, error) ||
        !after.projectService(service, suppressed, error) ||
        !before.buildEffectiveStack(service, PamManagementGroup::Auth, originalStack, error) ||
        !after.buildEffectiveStack(service, PamManagementGroup::Auth, suppressedStack, error) ||
        !provePamRuleSuppression(originalStack, suppressedStack, target, error)) return false;
    if (hasBypass(after, service, error, target.source)) {
        if (error.empty()) error = "Unsupported nopasswdlogin path remains in effective PAM stack";
        return false;
    }
    return true;
}

const MutationRecord* active(const MutationJournal& journal, const std::string& service) {
    for (const auto& record : journal.records()) {
        if (record.isActive() && record.policy == policy &&
            record.undo.backend == MutationBackend::PamSuppression &&
            record.resource == service) return &record;
    }
    return nullptr;
}

std::filesystem::path pathFor(const PamNopasswdloginOptions& options,
                              const std::string& service) {
    return options.platform.configDirectories.front() / service;
}

// Losing the active witness never grants authority to restore historical bytes.
bool retireReplaced(const PamNopasswdloginOptions& options, MutationJournal& journal,
                    const MutationRecord& record, const Snapshot& current,
                    std::string& error) {
    if (current.state) {
        if (current.state->content.find("FIC_PAM_NOPASSWDLOGIN") != std::string::npos ||
            !options.proveStock ||
            !options.proveStock(current.path, current.state->content, error)) {
            if (error.empty()) error = "Lost PAM suppression ownership";
            return false;
        }
    } else {
        PamConfiguration configuration(options.platform);
        if (hasBypass(configuration, record.resource, error)) {
            if (error.empty()) error = "Missing primary PAM file exposes a passwordless fallback";
            return false;
        }
    }
    error.clear();
    return durable(current, error) &&
        journal.setStatus(record.id, MutationStatus::RolledBack, error);
}

bool releaseOne(const PamNopasswdloginOptions& options, MutationJournal& journal,
                MutationRecord record, std::string& error) {
    const auto* proof = std::get_if<UndoRestorePamSuppression>(&record.undo.payload);
    if (!proof || record.policy != policy || record.resource != proof->service ||
        record.undo.backend != MutationBackend::PamSuppression ||
        std::find(options.services.begin(), options.services.end(), proof->service) ==
            options.services.end()) {
        error = "Invalid PAM suppression release route";
        return false;
    }
    Snapshot current;
    if (!read(pathFor(options, proof->service), current, error)) return false;
    std::string restored;
    PamRule target;
    if (!current.state ||
        !restoreNopasswdloginFragment(current.path, current.state->content,
                                     record.id, *proof, restored, target, error)) {
        // A releasing Prepared record can already have published its scoped release.
        if (current.state && record.status == MutationStatus::Prepared) {
            std::optional<UndoRestorePamSuppression> observed;
            std::string ignored;
            if (planNopasswdloginSuppression(current.path, proof->service,
                    current.state->content, observed, target, ignored) && observed &&
                observed->original == proof->original &&
                observed->previousAnchor == proof->previousAnchor &&
                observed->nextAnchor == proof->nextAnchor) {
                error.clear();
                return durable(current, error) &&
                    journal.setStatus(record.id, MutationStatus::RolledBack, error);
            }
        }
        return retireReplaced(options, journal, record, current, error);
    }
    if (!prove(options, proof->service, restored, current.state->content, target, error)) return false;
    std::get<UndoRestorePamSuppression>(record.undo.payload).releasing = true;
    record.status = MutationStatus::Prepared;
    MutationId id = 0;
    if (!journal.prepareMutation(record, id, error)) return false;
    Snapshot published;
    if (!write(options, current, restored, published, error) ||
        !prove(options, proof->service, restored, current.state->content, target, error) ||
        !durable(published, error)) return false;
    return journal.setStatus(id, MutationStatus::RolledBack, error);
}

} // namespace

PamNopasswdloginTransaction::PamNopasswdloginTransaction(
    PamNopasswdloginOptions options, MutationJournal& journal)
    : options_(std::move(options)), journal_(journal) {}

bool PamNopasswdloginTransaction::release(const MutationRecord& record, std::string& error) {
    const std::lock_guard<std::mutex> lock(transactionMutex);
    if (!journal_.usable() || options_.platform.configDirectories.empty()) {
        error = "PAM suppression journal or platform unavailable";
        return false;
    }
    const auto found = std::find_if(journal_.records().begin(), journal_.records().end(),
        [&](const auto& current) { return current.id == record.id; });
    if (found == journal_.records().end() || found->policy != policy ||
        found->undo.backend != MutationBackend::PamSuppression) {
        error = "PAM suppression release requires the current journal record";
        return false;
    }
    error.clear();
    if (!found->isActive()) return true;
    return releaseOne(options_, journal_, *found, error);
}

bool PamNopasswdloginTransaction::apply(std::string& error) {
    const std::lock_guard<std::mutex> lock(transactionMutex);
    if (!journal_.usable() || options_.platform.configDirectories.empty()) {
        error = "PAM suppression journal or platform unavailable";
        return false;
    }
    for (const auto& record : journal_.records()) {
        if (record.isActive() && record.policy == policy &&
            std::find(options_.services.begin(), options_.services.end(), record.resource) ==
                options_.services.end()) {
            error = "Active PAM suppression resource is outside the platform contract";
            return false;
        }
    }
    // Keep only new effects from this call for compensation. Existing ownership
    // survives a failure of a different service.
    error.clear();
    struct Publication {
        MutationRecord record;
        std::string original;
        std::string candidate;
    };
    std::vector<Publication> created;
    for (const auto& service : options_.services) {
        Snapshot current;
        if (!read(pathFor(options_, service), current, error)) break;
        if (const auto* found = active(journal_, service)) {
            const auto record = *found;
            const auto& proof = std::get<UndoRestorePamSuppression>(record.undo.payload);
            std::string restored;
            PamRule target;
            if (!proof.releasing && current.state &&
                restoreNopasswdloginFragment(current.path, current.state->content,
                    record.id, proof, restored, target, error)) {
                if (!prove(options_, service, restored, current.state->content, target, error) ||
                    !durable(current, error) ||
                    !journal_.setStatus(record.id, MutationStatus::Applied, error)) break;
                continue;
            }
            if (record.status == MutationStatus::Prepared || proof.releasing) {
                if (!releaseOne(options_, journal_, record, error)) break;
            } else if (!retireReplaced(options_, journal_, record, current, error)) break;
            if (!read(current.path, current, error)) break;
        }
        if (!current.state) {
            PamConfiguration configuration(options_.platform);
            if (hasBypass(configuration, service, error)) {
                if (error.empty()) error = "Unsupported passwordless PAM fallback";
                break;
            }
            if (!durable(current, error)) break;
            continue;
        }
        std::optional<UndoRestorePamSuppression> proof;
        PamRule target;
        if (!planNopasswdloginSuppression(current.path, service, current.state->content,
                                          proof, target, error)) break;
        if (!proof) {
            PamConfiguration configuration(options_.platform);
            if (hasBypass(configuration, service, error)) {
                if (error.empty()) error = "Unsupported included passwordless PAM rule";
                break;
            }
            continue;
        }
        MutationRecord record;
        record.policy = policy;
        record.resource = service;
        record.undo.backend = MutationBackend::PamSuppression;
        record.undo.payload = *proof;
        std::string candidate;
        // A provisional nonzero id suffices for graph proof, before any journal write.
        if (!suppressNopasswdloginFragment(current.path, current.state->content, 1,
                                          *proof, candidate, error) ||
            !prove(options_, service, current.state->content, candidate, target, error)) break;
        MutationId id = 0;
        if (!journal_.prepareMutation(record, id, error)) break;
        record.id = id;
        if (!suppressNopasswdloginFragment(current.path, current.state->content, id,
                                          *proof, candidate, error)) break;
        created.push_back({record, current.state->content, candidate});
        Snapshot published;
        if (!write(options_, current, candidate, published, error) ||
            !prove(options_, service, current.state->content, candidate, target, error) ||
            !durable(published, error) ||
            !journal_.setStatus(id, MutationStatus::Applied, error)) break;
        created.back().record.status = MutationStatus::Applied;
    }
    if (error.empty()) return true;
    const auto failure = error;
    for (auto publication = created.rbegin(); publication != created.rend(); ++publication) {
        std::string releaseError;
        Snapshot current;
        const auto& record = publication->record;
        const bool unchanged = read(pathFor(options_, record.resource), current, releaseError) &&
            current.state && (current.state->content == publication->candidate ||
                              current.state->content == publication->original);
        if (!unchanged || !releaseOne(options_, journal_, record, releaseError)) {
            error = failure + "; suppression compensation unresolved: " + releaseError;
            return false;
        }
    }
    error = failure;
    return false;
}

} // namespace fic::identity::pam
