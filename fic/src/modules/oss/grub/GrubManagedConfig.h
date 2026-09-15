#ifndef FIC_OSS_GRUB_MANAGED_CONFIG_H
#define FIC_OSS_GRUB_MANAGED_CONFIG_H

#include <fic/core/config/ConfigFileHandler.h>

#include <filesystem>
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
    bool restoreOriginal(std::string& error) const;
    bool verifyOriginal(std::string& error) const;

    bool existedAtLoad() const;
    const std::string& lastError() const;

private:
    struct Snapshot {
        bool exists = false;
        AtomicTargetState state;
    };

    GrubManagedConfigOptions managedOptions_;
    Snapshot original_;
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
