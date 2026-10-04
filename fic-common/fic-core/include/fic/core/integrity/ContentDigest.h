#ifndef FIC_CORE_CONTENTDIGEST_H
#define FIC_CORE_CONTENTDIGEST_H

#include <string>

namespace fic::core {

// Compact, stable fingerprint of an exact byte sequence (SHA-256, lowercase
// hex). Used wherever FIC must PROVE ownership of a fragment it created
// without storing that fragment as a backup: the persistent record keeps only
// this fingerprint, so a later change to the physical content is detected as
// drift instead of being silently released.
//
// Deliberately free of any backend-specific semantics. Deterministic across
// processes and runs by construction (no salt, no process or time input).
class ContentDigest {
public:
    // Returns the lowercase hex SHA-256 of `content`. Returns an empty string
    // on failure so callers can treat "no digest" as fail closed instead of
    // comparing against garbage.
    static std::string sha256Hex(const std::string& content);

    // True when `digest` has the exact shape produced by sha256Hex(): 64
    // lowercase hex characters. Used to reject malformed persisted payloads
    // at load time rather than during rollback.
    static bool isCanonicalSha256Hex(const std::string& digest);
};

} // namespace fic::core

#endif // FIC_CORE_CONTENTDIGEST_H