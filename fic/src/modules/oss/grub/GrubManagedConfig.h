#ifndef FIC_OSS_GRUB_MANAGED_CONFIG_H
#define FIC_OSS_GRUB_MANAGED_CONFIG_H

#include <fic/core/config/ConfigFileHandler.h>

#include <filesystem>
#include <optional>
#include <string>

struct GrubManagedConfigOptions {
    std::filesystem::path path;
    bool enforceOwnership = true;
};

class GrubManagedConfig final : public ConfigFileHandler {
public:
    explicit GrubManagedConfig(GrubManagedConfigOptions options);

    static bool validateTopology(const GrubManagedConfigOptions& options,
                                 std::string& error);

    bool loadConfig() override;
    bool setValue(const std::string& parameter,
                  const std::string& value) override;
    bool removeValue(const std::string& parameter) override;

    bool saveConfig(std::string& error, bool& installed);
    bool snapshotUnchanged(std::string& error) const;
    // Compensating restore after a failed rebuild. Allowed ONLY while the
    // target still IS exactly the state FIC installed (see installedState()):
    // external drift is reported as a conflict (concurrentDrift = true) and
    // never silently overwritten or removed.
    //
    // A drop-in that did NOT exist before the apply is NEVER compensated by
    // removing the file (check-then-unlink is race-prone and may delete a
    // concurrent replacement). The neutral compensated state is the
    // canonical header-only FIC-owned artifact (canonicalEmptyContent())
    // written through a CAS against the installed state: the policy key is
    // provably absent afterwards, which is all ownership-release requires.
    bool restoreOriginal(std::string& error, bool& concurrentDrift) const;
    bool verifyOriginal(std::string& error) const;

    bool existedAtLoad() const;
    // True when loadConfig() captured an existing regular file; stateOut
    // receives the EXACT snapshot loaded at that time (identity, content,
    // mode, owner, group). This is the single authoritative pre-mutation
    // state: CAS writes use it as their precondition and compensation uses it
    // as its content source — no fresh re-read may ever substitute for it.
    bool originalStateAtLoad(AtomicTargetState& stateOut) const;
    // Exact post-write state FIC installed through its last atomic
    // create/replace (identity, content, mode, owner, group). Captured from
    // the AtomicWriteResult of saveConfig(), not from a post-write re-read:
    // it is the install snapshot compensation is proven against.
    const std::optional<AtomicTargetState>& installedState() const;
    // Byte-exact canonical representation of an empty FIC-owned managed
    // drop-in: the header line followed by one blank line. Identical to
    // canonicalContent() of an empty configuration and used as the neutral
    // compensated state when the drop-in did not exist before the apply.
    static std::string canonicalEmptyContent();
    const std::string& lastError() const;

private:
    struct Snapshot {
        bool exists = false;
        AtomicTargetState state;
    };

    GrubManagedConfigOptions managedOptions_;
    Snapshot original_;
    std::optional<AtomicTargetState> installed_;
    std::string lastError_;
    bool loaded_ = false;

    bool readSnapshot(bool allowMissing,
                      Snapshot& snapshot,
                      std::string& error) const;
    bool parse(const std::string& content, std::string& error);
    void canonicalize();
    std::string canonicalContent() const;
};

#endif // FIC_OSS_GRUB_MANAGED_CONFIG_H
