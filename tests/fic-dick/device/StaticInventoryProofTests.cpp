// Contract tests for the per-boot static inventory proof.
//
// The proof is the ONLY evidence the device daemon accepts before it derives
// static hardware violations, so its failure modes matter: missing, malformed,
// foreign-boot or unsafely-permissioned state must never read as "proven".
#include "device/StaticInventoryProof.h"

#include <fic/core/runtime/FicRuntimePaths.h>

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace {

namespace fs = std::filesystem;

void require(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "FAILED: " << message << "\n";
        std::exit(1);
    }
}

} // namespace

int main() {
    using namespace fic::device_control;

    const fs::path root = fs::temp_directory_path() /
        ("fic-static-inventory-proof-test-" + std::to_string(::getpid()));
    fs::remove_all(root);
    fs::create_directories(root / "run");
    fs::create_directories(root / "log");
    fs::create_directories(root / "data");

    auto productPaths = fic::core::FicProductPaths::production();
    productPaths.privateBinDir = root / "bin";
    productPaths.configDir = root / "config";
    productPaths.languageDir = root / "lang";
    productPaths.logDir = root / "log";
    productPaths.notifyDir = root / "notify";
    productPaths.dataDir = root / "data";
    productPaths.shareDir = root / "share";
    productPaths.imageDir = root / "image";
    productPaths.runtimeDir = root / "run";
    productPaths.lockStatusFile = root / "lockstatus";
    productPaths.commandHashFile = root / "data/commandhash.txt";
    productPaths.deviceDatabaseFile = root / "data/devices.db";
    productPaths.deviceDatabaseLockFile = root / "log/devices.lock";
    productPaths.lockDebugLogFile = root / "log/db-lock.log";
    std::string error;
    require(productPaths.validate(error), error);
    require(fic::core::FicRuntimePaths::initialize(productPaths, error), error);

    const fs::path proofPath = static_inventory_proof_path();
    require(proofPath == root / "run/static-inventory.state",
            "the proof must live in the runtime directory");

    // Absent proof: never proven.
    {
        std::string diagnostic;
        require(!read_static_inventory_proof(diagnostic).has_value(),
                "an absent proof must not be proven");
        require(!diagnostic.empty(), "an absent proof must be diagnosed");
    }

    // Round trip.
    StaticInventoryProof written;
    written.bootId = "boot-a";
    written.cpu = true;
    written.board = false;
    written.memory = true;
    require(write_static_inventory_proof(written, error),
            "proof write failed: " + error);
    const auto read = read_static_inventory_proof(error);
    require(read.has_value(), "the written proof must be readable: " + error);
    require(read->bootId == "boot-a" && read->cpu && !read->board && read->memory,
            "the proof must round-trip every subsystem flag");
    require(read->proven("cpu", "boot-a"), "cpu must be proven for its boot");
    require(!read->proven("board", "boot-a"),
            "an unproven subsystem must stay unproven");
    require(!read->proven("cpu", "boot-b"),
            "a proof of another boot must not prove anything");

    // Corrupt content: never proven, never a malformed-success.
    {
        std::ofstream output(proofPath, std::ios::trunc);
        output << "not a proof";
    }
    require(::chmod(proofPath.c_str(), 0600) == 0, "chmod failed");
    {
        std::string diagnostic;
        require(!read_static_inventory_proof(diagnostic).has_value(),
                "a malformed proof must not be proven");
    }

    // Unsafe permissions: an unreadable-authority proof is not proven.
    require(write_static_inventory_proof(written, error), error);
    require(::chmod(proofPath.c_str(), 0644) == 0, "chmod failed");
    {
        std::string diagnostic;
        require(!read_static_inventory_proof(diagnostic).has_value(),
                "a world-readable proof must not be trusted");
    }

    // Writing without a boot id is rejected: the proof is always per-boot.
    {
        StaticInventoryProof incomplete;
        incomplete.cpu = true;
        require(!write_static_inventory_proof(incomplete, error),
                "a proof without a boot id must be rejected");
    }

    fs::remove_all(root);
    std::cout << "Static inventory proof contract proven\n";
    return 0;
}
