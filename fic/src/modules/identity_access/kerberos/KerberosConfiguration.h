#ifndef FIC_IDENTITY_ACCESS_KERBEROS_CONFIGURATION_H
#define FIC_IDENTITY_ACCESS_KERBEROS_CONFIGURATION_H

#include "modules/identity_access/shared/configuration/PreparedFileChange.h"
#include "modules/identity_access/composite/ConfigurationParticipant.h"

#include <optional>
#include <string>
#include <vector>

namespace fic::identity::kerberos {

struct KerberosConfigurationOptions {
    SecureConfigurationFileOptions mainFile;
    std::size_t maximumIncludeDepth = 16;
    std::size_t maximumFiles = 256;

    static KerberosConfigurationOptions production();
};

struct KerberosScalarSetting {
    std::string section;
    std::string relation;
    std::string value;
};

// Read-only observation of the target scalar in the ROOT /etc/krb5.conf
// relative to the full include graph. Used by the Kerberos policy apply path
// and the rollback backend to classify the current state
// (AFTER / BEFORE / DRIFT) without mutating anything.
struct KerberosRootScalarObservation {
    // The relation is ALSO defined in some include/includedir file: FIC must
    // never edit foreign include files and the target could not be owned
    // unambiguously — fail closed.
    bool externallyDefined = false;
    // The section header exists in the root document.
    bool sectionExistsInRoot = false;
    // Exactly one occurrence of the relation in the root document.
    bool relationInRoot = false;
    // More than one occurrence in the root document — ambiguous, fail closed.
    bool duplicateInRoot = false;
    // Exact raw line content of the (first) root occurrence, including the
    // original indentation and key/value '*' markers.
    std::string rawLine;
    // Semantic value of the (first) root occurrence.
    std::string value;
};

// Parameters of a reversible structured edit of the ROOT /etc/krb5.conf
// target relation: either restore the exact pre-FIC raw line, or remove the
// relation (and, provably, a FIC-created section header that became empty).
struct KerberosRootScalarMutation {
    std::string section;
    std::string relation;
    // Non-empty: the root relation line is replaced with this exact content.
    // Empty: the root relation line is removed.
    std::string replacementRawLine;
    // Only for removal: additionally remove the section header when it is
    // provably empty after the relation removal (used only when the journal
    // proves FIC created the section).
    bool removeEmptyCreatedSection = false;
};

class KerberosConfiguration {
public:
    explicit KerberosConfiguration(KerberosConfigurationOptions options);

    bool tryGetScalarValue(
        const std::string& section,
        const std::string& relation,
        std::optional<std::string>& value,
        std::string& error) const;

    // Read-only inspection of the target scalar against the full profile
    // graph. Never modifies anything. Fails (returns false) when any file
    // of the graph cannot be read safely or parsed.
    bool inspectRootScalar(
        const std::string& section,
        const std::string& relation,
        KerberosRootScalarObservation& observation,
        std::string& error) const;

    // Prepares an atomic CAS structured edit of the ROOT /etc/krb5.conf that
    // restores/removes the exact target relation. The full profile graph is
    // re-parsed as the postcondition; foreign include files are never
    // modified and an external definition of the target fails closed.
    ConfigurationPreparationResult prepareRootScalarMutation(
        const KerberosRootScalarMutation& mutation) const;

    ConfigurationPreparationResult prepareSetScalar(
        const std::string& section,
        const std::string& relation,
        const std::string& value) const;

    ConfigurationPreparationResult prepareSetScalars(
        const std::vector<KerberosScalarSetting>& settings) const;

    bool setScalar(const std::string& section,
                   const std::string& relation,
                   const std::string& value,
                   std::string& error) const;

    bool setScalars(const std::vector<KerberosScalarSetting>& settings,
                    std::string& error) const;

private:
    KerberosConfigurationOptions options_;
};

} // namespace fic::identity::kerberos

#endif // FIC_IDENTITY_ACCESS_KERBEROS_CONFIGURATION_H
