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
#include <optional>
#include <string>
#include <utility>
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

    // The publication identity changes with the stamp, so a repeated inventory
    // run with the same subsystem flags is still a NEW publication. The key of
    // an absent or foreign-boot proof is "unproven".
    {
        StaticInventoryProof first;
        first.bootId = "boot-a";
        first.cpu = true;
        first.publishedAtNs = 1000;
        const std::string firstKey =
            static_inventory_proof_key(first, "boot-a");
        StaticInventoryProof second = first;
        second.publishedAtNs = 2000;
        require(firstKey != static_inventory_proof_key(second, "boot-a"),
                "two publications with the same flags must differ");
        require(static_inventory_proof_key(first, "boot-b") == "unproven",
                "a proof of another boot must be unproven");
        require(static_inventory_proof_key(std::nullopt, "boot-a") ==
                    "unproven",
                "an absent proof must be unproven");
        require(firstKey.rfind("boot-a|", 0) == 0,
                "the key must be bound to the boot id");
    }

    // A write stamps the publication when the caller did not.
    {
        StaticInventoryProof stamped;
        stamped.bootId = "boot-a";
        stamped.cpu = true;
        require(write_static_inventory_proof(stamped, error),
                "stamped write failed: " + error);
        require(stamped.publishedAtNs > 0,
                "the writer must record a publication stamp");
        const auto readStamped = read_static_inventory_proof(error);
        require(readStamped.has_value() && readStamped->publishedAtNs ==
                                              stamped.publishedAtNs,
                "the stamp must round-trip");
    }

    // Wrong field TYPES are a damaged proof, not a proven one, and must never
    // throw out of the reader.
    {
        const std::pair<std::string, std::string> corrupt[] = {
            {"{\"boot_id\": 42, \"cpu\": true}", "non-string boot id"},
            {"{\"boot_id\": \"boot-a\", \"cpu\": \"yes\"}", "string flag"},
            {"{\"boot_id\": \"boot-a\", \"cpu\": 1}", "numeric flag"},
            {"{\"boot_id\": \"boot-a\", \"memory\": null}", "null flag"},
            {"{\"boot_id\": \"boot-a\", \"published_at_ns\": \"now\"}",
             "string stamp"},
            {"{\"boot_id\": \"boot-a\", \"published_at_ns\": -5}",
             "negative stamp"},
            {"{\"boot_id\": \"\", \"cpu\": true}", "empty boot id"},
            {"[]", "non-object payload"}
        };
        for (const auto& [content, description] : corrupt) {
            {
                std::ofstream output(proofPath, std::ios::trunc);
                output << content;
            }
            require(::chmod(proofPath.c_str(), 0600) == 0, "chmod failed");
            std::string diagnostic;
            bool threw = false;
            try {
                require(!read_static_inventory_proof(diagnostic).has_value(),
                        std::string("a proof with a wrong field type must not "
                                    "be proven: ") + description);
            } catch (const std::exception& unexpected) {
                threw = true;
                std::cerr << "unexpected exception: " << unexpected.what()
                          << "\n";
            }
            require(!threw, "the reader must not throw: " + description);
            require(!diagnostic.empty(),
                    "a damaged proof must be diagnosed: " + description);
        }
    }

    // Missing optional flags stay unproven instead of breaking the reader.
    {
        {
            std::ofstream output(proofPath, std::ios::trunc);
            output << "{\"boot_id\":\"boot-a\",\"cpu\":true}";
        }
        require(::chmod(proofPath.c_str(), 0600) == 0, "chmod failed");
        std::string diagnostic;
        const auto partial = read_static_inventory_proof(diagnostic);
        require(partial.has_value(),
                "absent optional flags must be readable: " + diagnostic);
        require(partial->cpu && !partial->board && !partial->memory,
                "absent optional flags must read as unproven");
        require(partial->proven("cpu", "boot-a"),
                "the reported flag must stay proven");
    }

    // Invalidation removes the publication, so a failed inventory run cannot
    // leave a stale proof standing in for its own result.
    {
        StaticInventoryProof stale;
        stale.bootId = "boot-a";
        stale.cpu = true;
        require(write_static_inventory_proof(stale, error), error);
        require(remove_static_inventory_proof(error),
                "invalidating the proof failed: " + error);
        std::string diagnostic;
        require(!read_static_inventory_proof(diagnostic).has_value(),
                "an invalidated proof must not be readable");
        require(remove_static_inventory_proof(error),
                "invalidating an absent proof must be idempotent: " + error);
    }

    fs::remove_all(root);
    std::cout << "Static inventory proof contract proven\n";
    return 0;
}
