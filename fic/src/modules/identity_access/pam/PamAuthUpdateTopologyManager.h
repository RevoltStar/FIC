#ifndef FIC_IDENTITY_ACCESS_PAM_AUTH_UPDATE_TOPOLOGY_MANAGER_H
#define FIC_IDENTITY_ACCESS_PAM_AUTH_UPDATE_TOPOLOGY_MANAGER_H

#include "modules/identity_access/pam/PamTopologyManager.h"
#include "platform/PlatformExecutableResolver.h"

#include <fic/core/process/ProcessExecutor.h>

#include <filesystem>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace fic::identity::pam {

class PamConfiguration;

struct PamAuthUpdateTopologyManagerOptions {
    std::function<ProcessResult(
        const std::string&, const std::vector<std::string>&,
        const ProcessOptions&)> runner;
    // pam-auth-update profile selection state directory. Empty means the
    // platform default (/var/lib/pam).
    std::filesystem::path stateDirectory;
    // Directory of the generated common-* PAM configuration files.
    // Empty means the platform default (/etc/pam.d).
    std::filesystem::path configDirectory;
    // Files snapshotted before a topology mutation and restored whenever
    // any post-mutation step fails. Empty means the pam-auth-update state
    // database and the generated common-* configs of the directories
    // above.
    std::vector<std::filesystem::path> statePaths;
};

class PamAuthUpdateTopologyManager final : public PamTopologyManager {
public:
    PamAuthUpdateTopologyManager(
        fic::platform::PamPlatformConfig platformConfig,
        fic::platform::PamCapabilityConfig capability,
        std::vector<std::string> services,
        const fic::platform::PlatformExecutableResolver& executables,
        PamAuthUpdateTopologyManagerOptions options = {});

    bool inspect(PamTopologyStatus& status, std::string& error) override;
    bool canEnable(std::string& error) const override;
    bool enable(std::string& error) override;
    bool disable(std::string& error) override;
    bool confirmDurable(std::string& error) const override;

    bool canEnableStrategy(
        fic::platform::PamFaillockStrategy strategy,
        std::string& error) const override;
    bool enableStrategy(
        fic::platform::PamFaillockStrategy strategy,
        std::string& error) override;

private:
    // FIC profile selection as observed in the pam-auth-update state
    // database. NoFicProfiles means no FIC profile is selected; whether
    // that is an external topology or a clean disabled state depends on
    // the presence of faillock rules in the effective stacks.
    enum class Ownership {
        FicOwned,
        NoFicProfiles,
        InvalidSelection
    };

    enum class ExternalFaillockGraphState {
        Clear,
        Present,
        Error
    };

    // Snapshot of one file: nullopt content means the file did not exist.
    using StateSnapshot =
        std::map<std::filesystem::path, std::optional<std::string>>;

    fic::platform::PamPlatformConfig platformConfig_;
    fic::platform::PamCapabilityConfig capability_;
    std::vector<std::string> services_;
    const fic::platform::PlatformExecutableResolver& executables_;
    PamAuthUpdateTopologyManagerOptions options_;

    std::filesystem::path stateDirectory() const;
    std::filesystem::path configDirectory() const;
    std::vector<std::filesystem::path> transactionPaths() const;

    // All faillock activation identifiers declared by this platform, across
    // every supported strategy. Used to reset the profile selection before
    // enabling the requested strategy.
    std::vector<std::string> knownActivationIdentifiers() const;
    const std::vector<std::string>* strategyActivationIdentifiers(
        fic::platform::PamFaillockStrategy strategy,
        std::string& error) const;

    // Identifiers of the enabled profiles recorded in the pam-auth-update
    // state database (per-type "Module:" entries). FIC-owned topologies
    // are recognized through this database; a faillock topology without
    // FIC profile selection is treated as external and is not mutated.
    bool enabledStateIdentifiers(std::set<std::string>& identifiers,
                                 std::string& error) const;
    bool detectOwnership(Ownership& ownership, std::string& error) const;
    bool existingVerificationServices(
        PamConfiguration& configuration,
        std::vector<std::string>& existing,
        std::string& error) const;
    ExternalFaillockGraphState externalFaillockGraphState(
        std::string& error) const;

    // Detects the pam_faillock strategy independently for every configured
    // PAM service. All services must agree on one strategy; conflicting
    // strategies leave the topology unmanageable (fail closed).
    bool detectUniformStrategy(
        std::optional<fic::platform::PamFaillockStrategy>& strategy,
        std::string& error) const;

    bool runPamAuthUpdate(const std::vector<std::string>& arguments,
                          std::string& error);
    bool resolveExecutable(std::filesystem::path& executable,
                           std::string& error) const;

    // Simple capability activation is owned by exact FIC profile identifiers.
    // Compensation and rollback remove only those identifiers through
    // pam-auth-update; they never restore a whole state snapshot over foreign
    // selections that may have changed concurrently.
    bool releaseSelectedIdentifiers(
        const std::vector<std::string>& identifiers,
        std::string& error);
    bool failWithActivationCompensation(
        const std::vector<std::string>& identifiers,
        const std::string& failure,
        std::string& error);

    // Strategy-transition support: snapshot the pam-auth-update state database and
    // the generated common-* configs, apply the mutation with a single
    // pam-auth-update invocation, re-read and verify the exact requested
    // strategy, and restore the snapshot on any failure. A rollback that
    // itself fails or fails verification is reported as CRITICAL.
    bool snapshotState(StateSnapshot& snapshot, std::string& error) const;
    bool restoreState(const StateSnapshot& snapshot, std::string& error) const;
    bool rollback(const StateSnapshot& snapshot,
                  const std::optional<fic::platform::PamFaillockStrategy>&
                      priorStrategy,
                  const std::string& failure,
                  std::string& error);
    bool verifyPostcondition(
        fic::platform::PamFaillockStrategy strategy,
        std::string& error);
};

} // namespace fic::identity::pam

#endif
