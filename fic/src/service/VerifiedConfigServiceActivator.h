#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <map>
#include <string>
#include <vector>

namespace fic::service {

enum class ControlledPathKind { File, Directory };
// Canonical relative file names and lowercase SHA-256; directories are inferred
// from file ancestors. Unexpected empty subdirectories are not supported.
using FileManifest = std::map<std::string, std::string>;
struct ControlledPath {
    std::filesystem::path path;
    ControlledPathKind kind = ControlledPathKind::File;
    std::string sha256;       // File only
    FileManifest manifest;   // Directory only
};
struct ActivationRequest {
    std::vector<ControlledPath> paths;
    std::string unit;
    std::chrono::milliseconds timeout{10000};
    std::uint64_t maxSnapshotBytes = 8 * 1024 * 1024;
};
enum class ActivationStatus {
    Success, ChecksumMismatch, UnsupportedConfiguration, SnapshotFailed,
    MountFailed, InterferenceDetected, RestartFailed, ReadinessUnconfirmed,
    TimedOut, CleanupFailed, ResidualMounts
};
struct ActivationResult {
    ActivationStatus status = ActivationStatus::UnsupportedConfiguration;
    // Captured before cleanup; preserved even when status becomes CleanupFailed.
    ActivationStatus primaryStatus = ActivationStatus::UnsupportedConfiguration;
    std::string diagnostic;
    std::vector<std::string> cleanupErrors;
    std::vector<std::string> residualPaths;
    bool readinessConfirmed = false;
    bool success() const { return status == ActivationStatus::Success; }
};

// One controlled activation, NOT persistent protection. Not integrated into any
// production policy. Supports already running notify/main services without a
// mount sandbox, in the same mount namespace as the system manager.
class VerifiedConfigServiceActivator {
public:
    static ActivationResult activate(const ActivationRequest& request);
};
const char* activationStatusName(ActivationStatus status);

} // namespace fic::service
