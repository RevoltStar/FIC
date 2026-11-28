#ifndef FIC_DEVICE_STATIC_INVENTORY_PROOF_H
#define FIC_DEVICE_STATIC_INVENTORY_PROOF_H

#include <filesystem>
#include <optional>
#include <string>

namespace fic::device_control {

// The per-boot proof that the STATIC hardware inventory (cpu/board/memory) was
// completed reliably.
//
// The proof is deliberately narrow: it proves only that the collector obtained
// trustworthy identities for a subsystem during THIS boot. A placeholder
// record (a failed lscpu/dmidecode call or the /proc/meminfo fallback) keeps
// the subsystem unproven, so it can never be used as evidence that a concrete
// device is present or absent. Successful process exit alone proves nothing.
//
// The file lives in the runtime directory and is therefore discarded on
// reboot; the boot id inside it additionally invalidates a stale copy.
struct StaticInventoryProof {
    std::string bootId;
    bool cpu = false;
    bool board = false;
    bool memory = false;

    // True only when the subsystem is proven for `currentBootId`.
    bool proven(const std::string& subsystem,
                const std::string& currentBootId) const;
};

std::filesystem::path static_inventory_proof_path();

// Atomic replacement (temporary file + rename), root/euid-owned and mode 0600
// with O_NOFOLLOW semantics.
bool write_static_inventory_proof(const StaticInventoryProof& proof,
                                  std::string& error);

// Missing, unsafe, malformed or foreign-boot state is reported as nullopt with
// a diagnostic: an unreadable proof is never treated as proven.
std::optional<StaticInventoryProof> read_static_inventory_proof(
    std::string& error);

} // namespace fic::device_control

#endif // FIC_DEVICE_STATIC_INVENTORY_PROOF_H
