#pragma once
#include "service/VerifiedConfigMountSupport.h"
#include "service/ssh/SshVerifiedActivationAdapter.h"

namespace fic::service::ssh::detail {
// Operation-local evidence, never an authorized reference or ownership record.
struct PersistentMetadata {
    std::map<std::string, fic::service::detail::Identity> roots;
    std::map<std::string, std::map<std::string, struct stat>> attributes;
};
inline void requireStableMetadata(const PersistentMetadata& before, const PersistentMetadata& after) {
    const auto drift = [] { throw fic::service::detail::Failure(ActivationStatus::InterferenceDetected,
                                                               "SSH persistent identity/metadata changed"); };
    if (before.roots.size() != after.roots.size() || before.attributes.size() != after.attributes.size()) drift();
    for (const auto& [path, a] : before.roots) {
        const auto it = after.roots.find(path);
        if (it == after.roots.end() || a.mount != it->second.mount ||
            !fic::service::detail::sameObject(a, it->second)) drift();
    }
    for (const auto& [path, entries] : before.attributes) {
        const auto root = after.attributes.find(path);
        if (root == after.attributes.end() || entries.size() != root->second.size()) drift();
        for (const auto& [name, a] : entries) {
            const auto it = root->second.find(name);
            if (it == root->second.end()) drift();
            const auto& b = it->second;
            // atime can change simply by proving the input; it is not evidence of drift.
            if (a.st_dev != b.st_dev || a.st_ino != b.st_ino || a.st_mode != b.st_mode ||
                a.st_uid != b.st_uid || a.st_gid != b.st_gid || a.st_nlink != b.st_nlink || a.st_size != b.st_size ||
                a.st_mtim.tv_sec != b.st_mtim.tv_sec || a.st_mtim.tv_nsec != b.st_mtim.tv_nsec ||
                a.st_ctim.tv_sec != b.st_ctim.tv_sec || a.st_ctim.tv_nsec != b.st_ctim.tv_nsec) drift();
        }
    }
}
// Acquisition errors are uncertainty; only a successfully observed mismatch is drift.
template<class Read, class Validate>
ProofState persistentProof(const PersistentMetadata& baseline, Read read, Validate validate) {
    try {
        const auto current = read();
        try {
            requireStableMetadata(baseline, current);
            validate(current);
            return ProofState::Proven;
        } catch (const fic::service::detail::Failure& e) {
            return e.status == ActivationStatus::ChecksumMismatch || e.status == ActivationStatus::InterferenceDetected
                ? ProofState::NonCompliant : ProofState::NotProven;
        }
    } catch (...) { return ProofState::NotProven; }
}
inline void requireSafePrivateHostKey(const struct stat& st) {
    if (!S_ISREG(st.st_mode) || st.st_uid != 0 ||
        ((st.st_mode & 07777) != 0600 && (st.st_mode & 07777) != 0400))
        throw fic::service::detail::Failure(ActivationStatus::UnsupportedConfiguration,
                                           "SSH private HostKey requires root-owned regular 0600/0400 input");
}
} // namespace fic::service::ssh::detail
