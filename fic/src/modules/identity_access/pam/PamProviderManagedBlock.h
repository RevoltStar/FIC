#ifndef FIC_IDENTITY_ACCESS_PAM_PROVIDER_MANAGED_BLOCK_H
#define FIC_IDENTITY_ACCESS_PAM_PROVIDER_MANAGED_BLOCK_H

#include <cctype>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// Step 7A: FIC-owned managed block for SHARED PAM provider configuration
// files (/etc/security/*.conf class). Unlike the FIC-owned/backends handled
// by PamOptionFile (full overwrite semantics are correct there), a provider
// primary configuration is shared with the administrator and the PAM
// modules: FIC owns ONLY its own explicitly marked override entries inside
// one managed block. FIC never stores or restores historical administrator
// values: rollback (Step 7B-7F) proves exact FIC ownership and releases the
// FIC entry; foreign content outside the FIC serialization survives every
// mutation byte-exact.
//
// This is the PAM-specific strict mini-language. It intentionally does NOT
// reuse or modify GrubManagedBlock (different grammar, per-entry physical
// provenance, BOF/EOF placement contracts).

// ---------------------------------------------------------------------------
// Canonical grammar (version 1), fail-closed.
//
//   # FIC_PAM_PROVIDER_BLOCK_BEGIN version=1 provider=<provider> lead=<none|newline>
//   # FIC_PAM_ENTRY_BEGIN version=1 policy=<policy> mutation=<id>
//   <key> = <value>
//   # FIC_PAM_ENTRY_END
//   # FIC_PAM_PROVIDER_BLOCK_END
//
// * markers must start at column 0; only trailing CR/LF and trailing
//   spaces/tabs are tolerated before exact comparison;
// * <provider>/<policy> are identity tokens ([a-z0-9_-]+);
// * <id> is a canonical decimal mutation id (> 0, no leading zeros, no
//   sign; the physical mutation id MUST equal the journal MutationRecord.id
//   of the mutation that wrote the entry — ABA protection);
// * the entry body is EXACTLY "<key> = <value>" (single line);
// * the canonical structural portion admits NOTHING else: no blank lines,
//   no comments, no unknown FIC-like markers;
// * any line anywhere in the file mentioning the reserved "FIC_PAM_"-marker
//   namespace in a non-canonical form is a conflict, never an ordinary
//   foreign comment.
//
// STRUCTURAL SEPARATOR BOUNDARY OWNERSHIP (lead contract): the BEGIN marker
// carries an explicit `lead=` field declaring whether the single LF byte
// immediately before the BEGIN marker belongs to the FIC-owned serialization:
//   * lead=none    — the block span starts at the BEGIN marker byte itself;
//                    no FIC byte exists before it (block at BOF, or the file
//                    had no foreign bytes);
//   * lead=newline — the EXACTLY ONE LF immediately before BEGIN was inserted
//                    by FIC as the foreign/block separator (block appended at
//                    EOF after non-empty foreign bytes). Decoding strips
//                    exactly that one LF, so foreign bytes without a trailing
//                    newline survive byte-exact; the parser fails closed when
//                    lead=newline is declared but the byte before BEGIN is
//                    not LF (or BEGIN sits at offset 0).
// This makes `foreign → FIC block → append foreign X → relocate → remove`
// restore `foreign + X` byte-exactly by construction — no heuristics.
//
// The foreign part of the file is opaque bytes and is never interpreted.
// ---------------------------------------------------------------------------

constexpr const char* kPamProviderBlockBeginMarkerPrefix =
    "# FIC_PAM_PROVIDER_BLOCK_BEGIN version=1 provider=";
constexpr const char* kPamProviderBlockEndMarker =
    "# FIC_PAM_PROVIDER_BLOCK_END";
constexpr const char* kPamProviderEntryBeginMarkerPrefix =
    "# FIC_PAM_ENTRY_BEGIN version=1 policy=";
constexpr const char* kPamProviderEntryEndMarker = "# FIC_PAM_ENTRY_END";

// Reserved marker namespace: ANY occurrence of this substring outside the
// exactly canonical marker forms is fail-closed conflict.
constexpr const char* kPamProviderReservedMarkerNamespace = "FIC_PAM_";

constexpr const char* kPamProviderBlockLeadField = " lead=";
constexpr const char* kPamProviderBlockLeadNone = "none";
constexpr const char* kPamProviderBlockLeadOwnedNewline = "newline";

inline std::string pamProviderBlockBeginMarker(const std::string& provider,
                                               bool leadOwnedNewline) {
    return std::string(kPamProviderBlockBeginMarkerPrefix) + provider +
        kPamProviderBlockLeadField +
        (leadOwnedNewline ? kPamProviderBlockLeadOwnedNewline
                          : kPamProviderBlockLeadNone);
}

inline std::string pamProviderEntryBeginMarker(const std::string& policy,
                                               std::uint64_t mutationId) {
    return std::string(kPamProviderEntryBeginMarkerPrefix) + policy +
        " mutation=" + std::to_string(mutationId);
}

// Identity tokens (provider names, FIC policy names): lowercase identifier
// characters only, non-empty. Uppercase/spaces would make the physical
// markers ambiguous.
inline bool isValidPamProviderIdentityToken(const std::string& token) {
    if (token.empty()) {
        return false;
    }
    for (const char character : token) {
        const unsigned char c = static_cast<unsigned char>(character);
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
              c == '_' || c == '-')) {
            return false;
        }
    }
    return true;
}

// Managed keys inside an entry body.
inline bool isValidPamProviderManagedKey(const std::string& key) {
    if (key.empty()) {
        return false;
    }
    for (const char character : key) {
        const unsigned char c = static_cast<unsigned char>(character);
        if (!(std::isalnum(c) != 0 || c == '_' || c == '-')) {
            return false;
        }
    }
    return true;
}

inline bool pamProviderValueFreeOfControls(const std::string& value) {
    return value.find_first_of("\r\n") == std::string::npos &&
        value.find('\0') == std::string::npos;
}

// Canonical entry body: "<key> = <value>". The single shared canonical
// validator of the body grammar: used by the physical parser, the mutation
// spec validation, the journal undo-payload validation and the ownership
// expectations, so that no path can accept a body any other path would
// reject. The value must be non-empty, trimmed and free of '#', CR, LF and
// NUL ('#' truncates PAM key-value parsing: such a value could never be
// proven effective).
inline std::string pamProviderEntryBody(const std::string& key,
                                        const std::string& value) {
    return key + " = " + value;
}

inline bool isValidPamProviderEntryValue(const std::string& value) {
    if (value.empty() || !pamProviderValueFreeOfControls(value) ||
        value.find('#') != std::string::npos) {
        return false;
    }
    const unsigned char first = static_cast<unsigned char>(value.front());
    const unsigned char last = static_cast<unsigned char>(value.back());
    return std::isspace(first) == 0 && std::isspace(last) == 0;
}

inline bool parseCanonicalPamProviderEntryBody(const std::string& body,
                                               std::string& key,
                                               std::string& value) {
    const std::size_t separator = body.find(" = ");
    if (separator == std::string::npos) {
        return false;
    }
    key = body.substr(0, separator);
    value = body.substr(separator + 3);
    return isValidPamProviderManagedKey(key) &&
        isValidPamProviderEntryValue(value);
}

inline bool isCanonicalPamProviderEntryBody(const std::string& body) {
    std::string key;
    std::string value;
    return parseCanonicalPamProviderEntryBody(body, key, value);
}

// ---------------------------------------------------------------------------
// Step 7E additions: set-only PAM flags (even_deny_root / enforce_for_root).
//
// These provider directives are PRESENCE flags upstream: the value text of a
// recognized key never expresses `false`. FIC therefore owns two additional
// canonical forms:
//
//   * ENABLED flag entry  — the bare managed key as the entry body:
//         # FIC_PAM_ENTRY_BEGIN version=1 policy=<policy> mutation=<id>
//         even_deny_root
//         # FIC_PAM_ENTRY_END
//   * DISABLED flag entry — a FIC-owned inert sentinel body (the provider
//     ignores comments, but the entry stays a physical ownership anchor so
//     desired=false always has durable journal↔physical provenance, even
//     with zero foreign occurrences):
//         # FIC_PAM_ENTRY_BEGIN version=1 policy=<policy> mutation=<id>
//         # FIC_PAM_FLAG_DISABLED version=1 key=<key>
//         # FIC_PAM_ENTRY_END
//
// FALSE STATE AND SUPPRESSION WRAPPERS: because `false` has no native
// representation, every FOREIGN ACTIVE occurrence of the managed key in the
// primary file must be temporarily neutralized. FIC never deletes foreign
// lines and never stores them in the journal: the foreign line is wrapped
// IN PLACE into a FIC-owned comment (the provider sees a comment; the exact
// original bytes survive inside the file):
//
//   # FIC_PAM_SUPPRESS version=1 provider=<p> policy=<p> key=<k> \
//     mutation=<id> suppression=<sid> raw=<EXACT ORIGINAL PHYSICAL LINE>
//
// `raw=` is the LAST field delimiter; everything after it is the opaque
// original physical line (indentation, inline comments, casing, separators
// included). Unwrapping restores the embedded bytes exactly; the wrapper
// occupies the physical position of the original line. The journal stores
// ONLY the provenance id (suppression=<sid>) — never the foreign line.
// ---------------------------------------------------------------------------

constexpr const char* kPamProviderSuppressMarkerPrefix =
    "# FIC_PAM_SUPPRESS version=1 provider=";
constexpr const char* kPamProviderFlagDisabledSentinelPrefix =
    "# FIC_PAM_FLAG_DISABLED version=1 key=";

// One physically proven FIC suppression wrapper (outside the provider
// block). rawLine is the EXACT embedded original physical line content
// (without its CR/LF terminator). lineIndex is the physical line index in
// the parsed content (the wrapper position).
struct PamProviderSuppressedLine {
    std::string provider;
    std::string policy;
    std::string managedKey;
    std::uint64_t mutationId = 0;
    std::string suppressionId;
    std::string rawLine;
    std::size_t lineIndex = 0;
};

inline std::string pamProviderFlagDisabledBody(const std::string& key) {
    return std::string(kPamProviderFlagDisabledSentinelPrefix) + key;
}

// Strict canonical parse of a disabled-flag sentinel body: the WHOLE body
// must be the exact marker with a valid managed key (no extra fields, no
// trailing whitespace, exact casing).
inline bool parseCanonicalPamProviderFlagDisabledBody(
    const std::string& body, std::string& key) {
    const std::string prefix = kPamProviderFlagDisabledSentinelPrefix;
    if (body.size() <= prefix.size() ||
        body.compare(0, prefix.size(), prefix) != 0) {
        return false;
    }
    key = body.substr(prefix.size());
    return isValidPamProviderManagedKey(key);
}

inline bool isCanonicalPamProviderFlagDisabledBody(const std::string& body) {
    std::string key;
    return parseCanonicalPamProviderFlagDisabledBody(body, key);
}

// Typed managed-entry body kind. The (policy, key) ownership tuple is kind-
// agnostic: one entry per tuple, whatever its body kind.
enum class PamProviderManagedEntryKind {
    Assignment,   // canonical "<key> = <value>"
    FlagEnabled,  // exact bare managed key
    FlagDisabled  // canonical "# FIC_PAM_FLAG_DISABLED version=1 key=<key>"
};

// Classifies a physical entry body against a known managed key. nullopt =
// non-canonical body (fail closed by the parser). For FlagEnabled the whole
// body must BE the key.
inline std::optional<PamProviderManagedEntryKind>
pamProviderManagedEntryKindForBody(const std::string& body,
                                   const std::string& key) {
    if (!isValidPamProviderManagedKey(key)) {
        return std::nullopt;
    }
    std::string parsedKey;
    std::string parsedValue;
    if (parseCanonicalPamProviderEntryBody(body, parsedKey, parsedValue)) {
        return parsedKey == key
            ? std::optional(PamProviderManagedEntryKind::Assignment)
            : std::nullopt;
    }
    if (body == key) {
        return PamProviderManagedEntryKind::FlagEnabled;
    }
    std::string sentinelKey;
    if (parseCanonicalPamProviderFlagDisabledBody(body, sentinelKey)) {
        return sentinelKey == key
            ? std::optional(PamProviderManagedEntryKind::FlagDisabled)
            : std::nullopt;
    }
    return std::nullopt;
}

inline std::string pamProviderFlagEntryBody(
    PamProviderManagedEntryKind kind, const std::string& key) {
    return kind == PamProviderManagedEntryKind::FlagDisabled
        ? pamProviderFlagDisabledBody(key)
        : key;
}

namespace fic::identity::pam {

// One physically proven FIC-owned entry inside the managed block.
struct PamProviderManagedEntry {
    std::string policy;      // FIC policy identity token
    std::string managedKey;  // managed key (also the body prefix)
    std::string body;        // exact canonical body line "<key> = <value>"
    std::uint64_t mutationId = 0; // physical mutation id == journal record id
    // Step 7E: typed body kind of the entry (assignment / enabled flag /
    // disabled flag sentinel). The ownership tuple (policy, key) is
    // kind-agnostic.
    PamProviderManagedEntryKind kind =
        PamProviderManagedEntryKind::Assignment;
};

// Provider-specific managed-flag key comparison semantics (Step 7E §18).
// Upstream evidence:
//   * pam_faillock (faillock_config.c): strcmp(name, "even_deny_root")
//     — CASE-SENSITIVE;
//   * libpwquality (settings.c) and pam_pwhistory
//     (pam_modutil_search_key): ASCII case-insensitive key matching.
// Unknown providers default to the strict case-sensitive comparison.
bool pamProviderFlagKeyMatchIgnoreCase(const std::string& provider);

// Typed provider-specific active-occurrence scanner for a set-only flag
// key. A physical line is an ACTIVE occurrence of the managed key when:
//   * the text before the first '#' (inline comment truncation, upstream
//     semantics of all three providers) is non-blank after leading
//     whitespace skip;
//   * the first key token (delimited by space, tab or '=') equals the
//     managed key under the provider-specific comparison semantics above.
// Comments ("# even_deny_root"), FIC marker lines and blank lines are NEVER
// active. The textual value of a recognized key is irrelevant (presence
// semantics): "enforce_for_root = 0" IS an active occurrence.
bool pamProviderFlagLineIsActiveOccurrence(const std::string& provider,
                                           const std::string& physicalLine,
                                           const std::string& managedKey);

// Canonical suppression wrapper line for one foreign active occurrence.
// rawLine must be the exact original physical line content WITHOUT its
// CR/LF terminator (LF and NUL are forbidden inside it).
std::string pamProviderSuppressionWrapperLine(const std::string& provider,
                                              const std::string& policy,
                                              const std::string& managedKey,
                                              std::uint64_t mutationId,
                                              const std::string& suppressionId,
                                              const std::string& rawLine);

// Strict canonical parse of ONE physical suppression wrapper line (CR/LF
// terminator already stripped or not — both accepted; the terminator never
// belongs to the embedded raw line). Fail closed on: non-canonical field
// order, invalid identity/key/suppression tokens, malformed mutation id,
// empty raw line, LF/NUL inside the raw line, and an embedded raw line that
// is NOT an active occurrence of the wrapper's managed key under the
// provider-specific key semantics (a drifted embedded line is never proven
// suppressed state — Step 7E §11).
bool parsePamProviderSuppressionWrapper(const std::string& physicalLine,
                                        PamProviderSuppressedLine& wrapper,
                                        std::string& error);

// Canonical suppression id token: same charset as identity tokens
// (lowercase alnum, '-', '_').
inline bool isValidPamProviderSuppressionId(const std::string& token) {
    return isValidPamProviderIdentityToken(token);
}

// Returns the next canonical suppression id "s<N>" (N = 1, 2, ...) that is
// not present in existingIds: N is one more than the largest numeric suffix
// already used, so existing wrapper ids stay stable across refreshes while
// every new id is unique within the file's wrapper namespace.
std::string nextPamProviderSuppressionId(
    const std::vector<std::string>& existingIds);

// Typed placement of the block. A valid FIC block NEVER stops being
// FIC-owned because of displacement: ownership proof and effective
// placement proof are different things. Both booleans are reported
// independently (a lone block satisfies both BOF and EOF contracts);
// effectivePlacement is the single-valued diagnostic view (BOF wins).
enum class PamProviderBlockPlacement {
    Absent,
    AtBeginning,
    AtEnd,
    Misplaced
};

// Requested placement contract of the provider configuration (Step 7B-7D:
// faillock/pwquality EOF, pwhistory BOF). This is the caller-side contract,
// separate from the observed effective placement.
enum class PamProviderBlockPlacementRequest {
    Beginning,
    End
};

struct PamProviderBlockView {
    bool present = false;
    // No bytes before the block (BEGIN marker at offset 0).
    bool atBeginning = false;
    // No bytes after the block beyond the FIC-owned terminator newline.
    bool atEnd = false;
    // Structural separator boundary provenance: true when the single LF
    // byte immediately before the BEGIN marker is FIC-owned serialization
    // (stripped on decode). See the lead contract in the grammar comment.
    bool leadOwnedNewline = false;
    PamProviderBlockPlacement effectivePlacement =
        PamProviderBlockPlacement::Absent;
    std::string provider; // proven provider identity of the block
    // Entries in canonical order (policy, then key) — deterministic and
    // independent of the policy apply order.
    std::vector<PamProviderManagedEntry> entries;
    // Step 7E: canonical suppression wrappers found OUTSIDE the provider
    // block, in physical line order (lineIndex ascending). Every mention of
    // the reserved namespace outside the block must be an exactly canonical
    // wrapper; wrappers inside the block are a parse failure.
    std::vector<PamProviderSuppressedLine> suppressions;

    bool satisfiesPlacement(
        PamProviderBlockPlacementRequest request) const {
        if (!present) {
            return true; // absent container satisfies any contract
        }
        return request == PamProviderBlockPlacementRequest::Beginning
            ? atBeginning
            : atEnd;
    }
};

struct PamProviderBlockParseResult {
    bool ok = false;
    PamProviderBlockView view;
    std::string error;
};

// Strict parser of the FIC managed block inside a shared PAM provider
// configuration file. Fail closed on: more than one block, nested block,
// duplicate/missing BEGIN or END, END without BEGIN, BEGIN without END,
// malformed or unknown FIC-like markers (any non-canonical mention of the
// reserved marker namespace), duplicate entries, duplicate physical
// mutation ids, non-canonical entry bodies, invalid policy/provider/key
// metadata, malformed mutation ids, and any unexpected line inside the
// canonical structural portion.
PamProviderBlockParseResult parsePamProviderManagedBlock(
    const std::string& content);

// Ownership expectation derived from a journal record: policy identity,
// managed key, the canonical applied body (drift fingerprint) and the
// journal mutation id, which the physical entry must carry verbatim.
// Step 7E: the body may be a canonical ASSIGNMENT body ("<key> = <value>"),
// an ENABLED flag body (the exact bare managed key) or a DISABLED flag
// sentinel body ("# FIC_PAM_FLAG_DISABLED version=1 key=<key>"); in every
// case the body's key must be exactly the expectation's managed key.
// previousBody carries the durable previous→target FIC-owned transition of
// an in-place refresh (crash-safe ownership recovery): empty means the
// record is a fresh create (no previous FIC-owned body exists); non-empty
// must be the exact previous canonical body of the SAME managed key (any
// canonical kind) and is used to classify Prepared crash states (previous
// present → continue the transition; target present → adopt; neither →
// fail closed).
struct PamProviderOwnershipExpectation {
    std::string provider;    // provider identity token of the block
    std::string policy;      // FIC policy identity token
    std::string managedKey;  // managed key
    std::string body;        // canonical applied body "<key> = <value>"
    std::string previousBody; // canonical previous body; empty = fresh create
    std::uint64_t mutationId = 0; // journal MutationRecord.id
};

// Typed per-entry ownership proof. Key/value equality alone is NEVER
// ownership: the exact physical mutation id and policy identity are
// required (ABA protection).
enum class PamProviderEntryProof {
    Owned,            // exact (policy, key, body, physical mutation id)
    Absent,           // no FIC entry for (policy, key)
    Lookalike,        // (policy, key) present with a DIFFERENT mutation id
    Drifted,          // exact mutation id but manually edited body
    ForeignProvider,  // proven block belongs to a different provider
    MalformedState    // the file failed the strict parse
};

struct PamProviderEntryProofResult {
    bool proven = false; // true iff proof == Owned
    PamProviderEntryProof proof = PamProviderEntryProof::MalformedState;
    std::string error;
};

PamProviderEntryProofResult provePamProviderEntryOwnership(
    const PamProviderBlockParseResult& parse,
    const PamProviderOwnershipExpectation& expectation);

// Journal mutation lifecycle subset relevant to the primitive. The caller
// maps fic::rollback::MutationStatus onto it (the primitive does not depend
// on the rollback layer).
enum class PamProviderJournalMutationStatus {
    Prepared,
    Applied
};

// Prepared crash semantics with the durable previous→target FIC-owned
// transition (the journal payload carries previousBody; empty = fresh
// create). Recovery matrix:
//   fresh (no previousBody):
//     absent physical entry            → PreparedFreshAbsent
//         (mutation not yet happened: safe to (re)write the target, the
//          record keeps its id);
//     exact target body present        → PreparedFreshTargetPresent
//         (crash after the physical write, before journal completion:
//          ADOPT the entry, complete the record as Applied — no new
//          mutation id, no rewrite);
//     anything else (other body with the same id, lookalike id, drift,
//     foreign provider)               → PreparedConflict (fail closed).
//   update (previousBody present):
//     exact previous body present      → PreparedUpdatePreviousPresent
//         (continue the transition: write the target body under the SAME
//          record id);
//     exact target body present        → PreparedUpdateTargetPresent
//         (crash after the physical write: complete the record as Applied);
//     anything else                    → PreparedConflict (fail closed).
//   Applied:
//     AppliedExact  — normal owned state (physical == target);
//     AppliedMissing— the owned entry disappeared: ownership cannot be
//                     reconstructed from the journal alone;
//     AppliedDrifted— the physical entry was modified or belongs to another
//                     identity: conflict, never rewrite or remove blindly.
enum class PamProviderJournalBindingState {
    PreparedFreshAbsent,
    PreparedFreshTargetPresent,
    PreparedUpdatePreviousPresent,
    PreparedUpdateTargetPresent,
    PreparedConflict,
    AppliedExact,
    AppliedMissing,
    AppliedDrifted
};

struct PamProviderJournalBindingResult {
    bool ok = false;
    PamProviderJournalBindingState state;
    std::string error;
};

PamProviderJournalBindingResult classifyPamProviderJournalBinding(
    PamProviderJournalMutationStatus status,
    const PamProviderBlockParseResult& parse,
    const PamProviderOwnershipExpectation& expectation);

// ---------------------------------------------------------------------------
// Mutations (pure string-level transforms; foreign bytes preserved
// byte-exact)
// ---------------------------------------------------------------------------

struct PamProviderEntrySpec {
    std::string provider;   // provider identity token
    std::string policy;     // FIC policy identity token
    std::string managedKey; // managed key
    std::string value;      // logical value (canonical body derived)
    std::uint64_t mutationId = 0; // physical == journal mutation id
};

struct PamProviderMutationResult {
    bool ok = false;
    enum class Outcome {
        Committed, // content changed (including pure relocation)
        NoOp       // exact state already present at the requested placement
    } outcome = Outcome::Committed;
    std::string content;
    std::string error;
};

// Adds or updates exactly ONE FIC-owned entry. The block is (re)placed at
// the requested placement; foreign bytes survive byte-exact; entries of
// OTHER policies keep their bodies AND their physical mutation ids.
// Refuses (fail closed) when the (policy, key) entry exists physically but
// carries a DIFFERENT mutation id: the caller must prove/release that
// identity first — silently rewriting it would orphan another journal
// transaction's provenance.
PamProviderMutationResult setPamProviderManagedEntry(
    const std::string& content,
    const PamProviderEntrySpec& spec,
    PamProviderBlockPlacementRequest request);

// Removes exactly ONE FIC-owned entry, only when the exact ownership
// expectation (policy, key, body, physical mutation id) is proven. A
// missing entry is an idempotent no-op (already released); a lookalike
// entry (same key/value shape, different mutation id) or a drifted body is
// a typed refusal — never removed. When the last entry is removed the
// whole block is removed and the pre-FIC foreign bytes are restored
// byte-exact (including a missing trailing newline).
struct PamProviderRemovalResult {
    bool ok = false;
    enum class Outcome {
        Removed,      // entry removed; block still holds other entries
        BlockRemoved, // last entry removed: whole block gone
        AlreadyAbsent // no FIC entry for (policy, key): nothing to release
    } outcome = Outcome::Removed;
    std::string content;
    std::string error;
};

PamProviderRemovalResult removePamProviderManagedEntry(
    const std::string& content,
    const PamProviderOwnershipExpectation& expectation,
    PamProviderBlockPlacementRequest request);

// ---------------------------------------------------------------------------
// Step 7E: set-only flag mutations.
// ---------------------------------------------------------------------------

// Typed spec of ONE set-only managed flag transition. The transition is a
// SINGLE atomic content transform combining the managed entry change and
// the suppression wrapper changes, so the provider block entry and the
// wrapped foreign lines are always installed by ONE physical file
// replacement (never two independent filesystem mutations).
struct PamProviderFlagSpec {
    std::string provider;   // provider identity token
    std::string policy;     // FIC policy identity token
    std::string managedKey; // managed set-only key
    bool enabled = false;   // target flag state
    std::uint64_t mutationId = 0; // physical == journal mutation id
    // Disabled target: suppression ids of EXISTING wrappers of this record
    // that must be kept as-is (proven provenance carried over). Wrappers of
    // this record carrying any OTHER id are a typed refusal (never released
    // or kept silently).
    std::vector<std::string> keepSuppressionIds;
    // Disabled target: canonical suppression ids to assign to the newly
    // wrapped active occurrences, in physical line order. Must be empty for
    // an enabled target; must contain exactly one id per active unsuppressed
    // occurrence (a shortage is a typed refusal — the caller proves the
    // exact target provenance set).
    std::vector<std::string> createSuppressionIds;
};

struct PamProviderFlagMutationResult {
    bool ok = false;
    enum class Outcome {
        Committed, // content changed (entry, wrappers or placement)
        NoOp       // exact target state already present at the placement
    } outcome = Outcome::Committed;
    std::string content;
    std::string error;
};

// Applies ONE flag transition to the content:
//   * enabled target: the (policy, key) entry becomes the bare managed key
//     and EVERY suppression wrapper of this record is unwrapped in place
//     (the embedded raw line returns byte-exact to its physical position);
//     foreign active occurrences are NEVER touched (true is effective
//     regardless of foreign lines);
//   * disabled target: the entry becomes the disabled sentinel, wrappers in
//     keepSuppressionIds stay, and every active unsuppressed occurrence of
//     the managed key in the foreign area is wrapped in place with the next
//     id from createSuppressionIds;
//   * the block is (re)placed at the requested placement; foreign bytes and
//     foreign wrapper positions survive byte-exact; entries of OTHER
//     policies keep their bodies AND their physical mutation ids;
//   * fail closed when: the strict parse fails, the (policy, key) entry
//     exists with a different mutation id, an owned wrapper carries an id
//     outside keep ∪ create, create ids are insufficient/invalid, or a
//     released wrapper's embedded line would collide with the reserved
//     namespace proof rules enforced by the parser.
PamProviderFlagMutationResult setPamProviderManagedFlagTransition(
    const std::string& content,
    const PamProviderFlagSpec& spec,
    PamProviderBlockPlacementRequest request);




} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_PROVIDER_MANAGED_BLOCK_H
