#ifndef FIC_IDENTITY_ACCESS_SSSD_CONFIGURATION_H
#define FIC_IDENTITY_ACCESS_SSSD_CONFIGURATION_H

#include "modules/identity_access/shared/configuration/PreparedFileChange.h"
#include "modules/identity_access/composite/ConfigurationParticipant.h"

#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace fic::identity::sssd {

void setManagedSnippetRemovalRaceHookForTests(
    std::function<void()> hook);
void setManagedSnippetBeforeStageHookForTests(
    std::function<void(const std::filesystem::path&)> hook);
void setManagedSnippetStagedRaceHookForTests(
    std::function<void(const std::filesystem::path&)> hook);

struct SssdConfigurationOptions {
    SecureConfigurationFileOptions mainFile;
    std::vector<std::filesystem::path> snippetDirectories;
    // The FIC-owned drop-in file. FIC never edits the foreign main
    // sssd.conf; all FIC-owned settings of the SSSD module live in this
    // single managed snippet (root-owned, mode 0600, atomic writes).
    std::filesystem::path managedSnippetFile;

    static SssdConfigurationOptions production();
};

// Fail-closed guard for active rollback provenance with an absent source.
// A staged object may be a foreign replacement stranded by an interrupted
// proof-bound removal, and must not be mistaken for completed release.
bool hasManagedSnippetStagingArtifacts(
    const SssdConfigurationOptions& options,
    bool& found,
    std::string& error);

struct SssdSetting {
    std::string section;
    std::string option;
    std::string value;
};

// Topology observation of the FIC-owned managed drop-in and its effective
// semantics. Used by the SSSD policy apply path and the rollback backend to
// classify the current state (AFTER / BEFORE / DRIFT) without mutating
// anything.
struct SssdManagedSnippetObservation {
    enum class DropInState {
        Missing,   // the managed snippet does not exist (legitimate)
        Ok,        // parsed successfully
        Unsafe,    // symlink / non-regular / insecure metadata
        Malformed  // exists but cannot be parsed as an SSSD configuration
    };

    DropInState dropInState = DropInState::Missing;
    // The target option inside the FIC-owned drop-in (if Ok).
    bool optionPresent = false;
    std::string optionValue;
    // Foreign snippets that sort AFTER the managed drop-in AND define the
    // target (section, option): FIC could not become effective. Apply must
    // fail closed; foreign files are never modified.
    std::vector<std::filesystem::path> laterConflictingSnippets;
    // Effective (section, option) value across the main file and all
    // snippets in resolution order (last definition wins); nullopt when
    // nothing defines it.
    std::optional<std::string> effectiveValue;
};

class SssdConfiguration {
public:
    explicit SssdConfiguration(SssdConfigurationOptions options);

    bool tryGetEffectiveValue(
        const std::string& section,
        const std::string& option,
        std::optional<std::string>& value,
        std::string& error) const;

    // Read-only topology/semantics inspection of the FIC-owned drop-in.
    // Never modifies anything. Fails (returns false) when the foreign main
    // configuration or a foreign snippet cannot be read safely: effective
    // semantics would be undefined.
    bool inspectManagedSnippet(
        const std::string& section,
        const std::string& option,
        SssdManagedSnippetObservation& observation,
        std::string& error) const;

    // Prepares an atomic FIC-owned drop-in change that makes
    // (section, option) == value the unambiguous effective source. Fails
    // closed on any conflicting later foreign snippet, an unsafe or
    // malformed managed drop-in, or an unsafe topology — foreign files are
    // never modified. The managed snippet is created when missing.
    ConfigurationPreparationResult prepareManagedSnippetValue(
        const std::string& section,
        const std::string& option,
        const std::string& value) const;

    // Prepares removal of ONLY the target option from the FIC-owned
    // drop-in. When the drop-in becomes semantically empty (no assignments
    // left) the FIC-owned file is removed entirely. Never touches the
    // foreign main configuration or foreign snippets.
    ConfigurationPreparationResult prepareManagedSnippetRemoval(
        const std::string& section,
        const std::string& option) const;

    ConfigurationPreparationResult prepareSetValue(
        const std::string& section,
        const std::string& option,
        const std::string& value) const;

    // Test-only deterministic seam: injects an external atomic replacement
    // of the FIC-owned drop-in exactly between the removal proof and the
    // rename-away removal step. Production code must never call this.
    static void setRemovalRaceHookForTests(
        std::function<void()> hook) {
        setManagedSnippetRemovalRaceHookForTests(std::move(hook));
    }

    ConfigurationPreparationResult prepareSetValues(
        const std::vector<SssdSetting>& settings) const;

    bool setValue(const std::string& section,
                  const std::string& option,
                  const std::string& value,
                  std::string& error) const;

    bool setValues(const std::vector<SssdSetting>& settings,
                   std::string& error) const;

private:
    SssdConfigurationOptions options_;
};

} // namespace fic::identity::sssd

#endif // FIC_IDENTITY_ACCESS_SSSD_CONFIGURATION_H
