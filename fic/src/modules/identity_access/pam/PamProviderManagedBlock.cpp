#include "modules/identity_access/pam/PamProviderManagedBlock.h"

#include <algorithm>
#include <charconv>
#include <cstring>
#include <system_error>
#include <utility>

namespace fic::identity::pam {
namespace {

// Strips CR/LF line endings and trailing spaces/tabs (never leading ones:
// marker grammar requires the marker at the start of the line).
std::string lineContent(const std::string& physicalLine) {
    std::string line = physicalLine;
    while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
        line.pop_back();
    }
    while (!line.empty() && (line.back() == ' ' || line.back() == '\t')) {
        line.pop_back();
    }
    return line;
}

// Strips only the physical CR/LF line boundary: canonical-strict grammar of
// the entry body must see any trailing whitespace and fail closed.
std::string physicalLineContent(const std::string& physicalLine) {
    std::string line = physicalLine;
    while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
        line.pop_back();
    }
    return line;
}

std::vector<std::string> physicalLines(const std::string& content) {
    std::vector<std::string> lines;
    std::size_t start = 0;
    while (start < content.size()) {
        const std::size_t newline = content.find('\n', start);
        if (newline == std::string::npos) {
            lines.push_back(content.substr(start));
            return lines;
        }
        lines.push_back(content.substr(start, newline - start + 1));
        start = newline + 1;
    }
    return lines;
}

bool mentionsReservedNamespace(const std::string& line) {
    return line.find(kPamProviderReservedMarkerNamespace) !=
        std::string::npos;
}

// Strict canonical decimal mutation id: > 0, digits only, no leading
// zeros, no sign, must fit uint64. MutationId 0 is invalid (journal ids
// start at 1).
bool parsePhysicalMutationId(const std::string& text,
                             std::uint64_t& id,
                             std::string& error) {
    if (text.empty() || text.size() > 20 ||
        !std::all_of(text.begin(), text.end(), [](unsigned char c) {
            return std::isdigit(c) != 0;
        })) {
        error = "malformed physical mutation id inside FIC PAM provider "
                "block: " + text;
        return false;
    }
    if (text.front() == '0' || text == "0") {
        error = "physical mutation id must be canonical decimal > 0: " + text;
        return false;
    }
    const auto result =
        std::from_chars(text.data(), text.data() + text.size(), id);
    if (result.ec != std::errc() || result.ptr != text.data() + text.size() ||
        id == 0) {
        error = "physical mutation id out of range: " + text;
        return false;
    }
    return true;
}

// Extracts the strict "<policy> mutation=<id>" suffix of a canonical entry
// BEGIN marker.
bool parseEntryBeginMarker(const std::string& line,
                           std::string& policy,
                           std::uint64_t& mutationId,
                           std::string& error) {
    const std::string prefix = kPamProviderEntryBeginMarkerPrefix;
    if (line.size() <= prefix.size() ||
        line.compare(0, prefix.size(), prefix) != 0) {
        return false;
    }
    const std::string rest = line.substr(prefix.size());
    const std::size_t mutation = rest.find(" mutation=");
    if (mutation == std::string::npos) {
        error = "foreign FIC-подобный malformed ENTRY BEGIN marker: " + line;
        return false;
    }
    policy = rest.substr(0, mutation);
    const std::string idText = rest.substr(mutation + 10);
    if (!isValidPamProviderIdentityToken(policy)) {
        error = "invalid policy identity inside FIC PAM provider block: " +
            policy;
        return false;
    }
    return parsePhysicalMutationId(idText, mutationId, error);
}

// Extracts the strict "<provider> lead=<none|newline>" suffix of a canonical
// block BEGIN marker and reports the structural separator boundary
// provenance (lead contract). A BEGIN marker without the lead field or with
// an unknown lead value is a non-canonical FIC-like marker: fail closed.
bool parseBlockBeginMarker(const std::string& line,
                           std::string& provider,
                           bool& leadOwnedNewline,
                           std::string& error) {
    const std::string prefix = kPamProviderBlockBeginMarkerPrefix;
    if (line.size() <= prefix.size() ||
        line.compare(0, prefix.size(), prefix) != 0) {
        return false;
    }
    const std::string rest = line.substr(prefix.size());
    const std::size_t lead = rest.find(kPamProviderBlockLeadField);
    if (lead == std::string::npos ||
        rest.find(kPamProviderBlockLeadField, lead + 1) !=
            std::string::npos) {
        error = "foreign FIC-подобный block BEGIN marker без однозначного "
                "поля lead=: " +
            line;
        return false;
    }
    provider = rest.substr(0, lead);
    const std::string leadValue = rest.substr(
        lead + std::strlen(kPamProviderBlockLeadField));
    if (leadValue == kPamProviderBlockLeadNone) {
        leadOwnedNewline = false;
    } else if (leadValue == kPamProviderBlockLeadOwnedNewline) {
        leadOwnedNewline = true;
    } else {
        error = "неизвестное значение lead= внутри FIC PAM provider block "
                "BEGIN: " +
            leadValue;
        return false;
    }
    if (!isValidPamProviderIdentityToken(provider)) {
        error = "invalid provider identity inside FIC PAM provider block: " +
            provider;
        return false;
    }
    return true;
}

// Canonical entry body parse via the SINGLE shared canonical validator
// (exact "<key> = <value>" with a valid key and a trimmed value free of
// '#', CR, LF and NUL). Anything deviating from the canonical serialization
// FIC renders fails closed.
bool parseEntryBody(const std::string& line,
                    std::string& key,
                    std::string& body,
                    std::string& error) {
    std::string value;
    if (!parseCanonicalPamProviderEntryBody(line, key, value)) {
        error = "строка внутри FIC PAM provider entry не является canonical "
                "assignment: " + line;
        return false;
    }
    body = line;
    return true;
}

// Foreign bytes = everything except the proven block, in the original
// order. Ownership of the FIC-owned serialization boundaries:
//   * block at BOF: the block render ALWAYS ends with '\n' after the END
//     marker; that terminator belongs to the block span, so foreign bytes
//     are exactly everything after it — restored byte-exact on removal;
//   * block at EOF: the newline immediately before the BEGIN marker is the
//     FIC-owned separator (assembleAtEnd always appends exactly one for a
//     non-empty foreign area), so exactly one is stripped on decode —
//     foreign bytes without a trailing newline survive byte-exact;
//   * misplaced block: the separator position is no longer identifiable,
//     so nothing is stripped and foreign bytes are kept verbatim.
// Foreign bytes = everything except the proven block, in the original
// order. Ownership of the FIC-owned serialization boundaries is STRUCTURAL
// (the lead contract), never heuristic:
//   * block at BOF: the block span starts at byte 0 and the block render
//     ALWAYS ends with '\n' after the END marker; that terminator belongs
//     to the block span, so foreign bytes are exactly everything after it —
//     restored byte-exact on removal;
//   * lead=newline: the EXACTLY ONE LF immediately before the BEGIN marker
//     was inserted by FIC as the foreign/block separator, so decode strips
//     exactly that one byte — foreign bytes without a trailing newline
//     survive byte-exact (the parser has already proven the byte IS an LF);
//   * lead=none with foreign bytes before BEGIN: nothing before BEGIN is
//     FIC-owned, so nothing is ever stripped;
//   * displaced block: foreign bytes on both sides are kept verbatim, and
//     the lead side still follows the lead contract.
std::string foreignBytes(const std::string& content,
                         std::size_t beginIndex,
                         std::size_t endIndex,
                         bool atBeginning,
                         bool leadOwnedNewline) {
    const std::vector<std::string> lines = physicalLines(content);
    if (atBeginning) {
        // Block span: bytes 0 through the END marker line's newline
        // inclusive (the canonical renderer always emits it).
        std::size_t afterBlock = 0;
        for (std::size_t index = 0; index <= endIndex; ++index) {
            afterBlock += lines[index].size();
        }
        return content.substr(afterBlock);
    }
    std::string before;
    for (std::size_t index = 0; index < beginIndex; ++index) {
        before += lines[index];
    }
    if (leadOwnedNewline && !before.empty() && before.back() == '\n') {
        before.pop_back();
    }
    std::string after;
    for (std::size_t index = endIndex + 1; index < lines.size(); ++index) {
        after += lines[index];
    }
    return before + after;
}

// Joins foreign bytes with the block at BOF. The block render ends with its
// own FIC-owned terminator newline, which separates it from the foreign
// area — no extra separator is added.
std::string assembleAtBeginning(const std::string& foreign,
                                const std::string& block) {
    return block + foreign;
}

// Joins foreign bytes with the block at EOF. The newline separating the
// foreign area from the block is FIC-owned serialization: it is ALWAYS
// appended for a non-empty foreign area (even when the foreign content
// already ends with a newline), so the exact pre-apply foreign bytes are
// recoverable on decode by stripping exactly that one separator newline.
std::string assembleAtEnd(const std::string& foreign,
                          const std::string& block) {
    std::string content = foreign;
    if (!content.empty()) {
        content.push_back('\n');
    }
    content += block;
    return content;
}

std::string renderBlock(const std::string& provider,
                        const std::vector<PamProviderManagedEntry>& entries,
                        bool leadOwnedNewline) {
    std::string block =
        pamProviderBlockBeginMarker(provider, leadOwnedNewline);
    block.push_back('\n');
    for (const PamProviderManagedEntry& entry : entries) {
        block += pamProviderEntryBeginMarker(entry.policy, entry.mutationId);
        block.push_back('\n');
        block += entry.body;
        block.push_back('\n');
        block += kPamProviderEntryEndMarker;
        block.push_back('\n');
    }
    block += kPamProviderBlockEndMarker;
    block.push_back('\n');
    return block;
}

// Deterministic canonical entry order: (policy, then key), independent of
// the policy apply order.
void canonicalSort(std::vector<PamProviderManagedEntry>& entries) {
    std::stable_sort(
        entries.begin(), entries.end(),
        [](const PamProviderManagedEntry& left,
           const PamProviderManagedEntry& right) {
            if (left.policy != right.policy) {
                return left.policy < right.policy;
            }
            return left.managedKey < right.managedKey;
        });
}

const PamProviderManagedEntry* findEntry(
    const std::vector<PamProviderManagedEntry>& entries,
    const std::string& policy,
    const std::string& managedKey) {
    for (const PamProviderManagedEntry& entry : entries) {
        if (entry.policy == policy && entry.managedKey == managedKey) {
            return &entry;
        }
    }
    return nullptr;
}

// Shared spec validation for setPamProviderManagedEntry.
bool validateEntrySpec(const PamProviderEntrySpec& spec,
                       std::string& error) {
    if (!isValidPamProviderIdentityToken(spec.provider)) {
        error = "invalid provider identity for FIC PAM managed entry";
        return false;
    }
    if (!isValidPamProviderIdentityToken(spec.policy)) {
        error = "invalid policy identity for FIC PAM managed entry";
        return false;
    }
    if (!isValidPamProviderManagedKey(spec.managedKey)) {
        error = "invalid managed key for FIC PAM managed entry: " +
            spec.managedKey;
        return false;
    }
    if (spec.mutationId == 0) {
        error = "FIC PAM managed entry requires a non-zero mutation id";
        return false;
    }
    // Shared canonical value rule (same validator the physical parser and
    // the journal payload validation use).
    if (!isValidPamProviderEntryValue(spec.value)) {
        error = "invalid managed value for FIC PAM managed entry " +
            spec.managedKey;
        return false;
    }
    return true;
}

// Re-derives the block line indices of an already strict-validated content
// (the marker scan is unambiguous after a successful parse).
void findBlockLineIndices(const std::string& content,
                          std::size_t& beginIndex,
                          std::size_t& endIndex) {
    beginIndex = std::string::npos;
    endIndex = std::string::npos;
    const std::vector<std::string> lines = physicalLines(content);
    for (std::size_t index = 0; index < lines.size(); ++index) {
        const std::string line = lineContent(lines[index]);
        if (line == kPamProviderBlockEndMarker) {
            endIndex = index;
        } else if (line.compare(0, std::strlen(kPamProviderBlockBeginMarkerPrefix),
                                kPamProviderBlockBeginMarkerPrefix) == 0) {
            beginIndex = index;
        }
    }
}

// MARKER_ANCHOR_VALIDATE
namespace {

// Shared canonical body validator of the ownership expectation: accepts the
// canonical ASSIGNMENT body, the ENABLED flag body (exact bare managed key)
// and the DISABLED flag sentinel body — in every case with EXACTLY the
// expectation's managed key (never a prefix compare).
bool ownershipBodyMatchesKey(const std::string& body,
                             const std::string& managedKey) {
    if (!isValidPamProviderManagedKey(managedKey)) {
        return false;
    }
    std::string parsedKey;
    std::string parsedValue;
    if (parseCanonicalPamProviderEntryBody(body, parsedKey, parsedValue)) {
        return parsedKey == managedKey;
    }
    if (body == managedKey) {
        return true;
    }
    std::string sentinelKey;
    if (parseCanonicalPamProviderFlagDisabledBody(body, sentinelKey)) {
        return sentinelKey == managedKey;
    }
    return false;
}

} // namespace

bool validateOwnershipExpectation(
    const PamProviderOwnershipExpectation& expectation,
    std::string& error) {
    if (!isValidPamProviderIdentityToken(expectation.provider) ||
        !isValidPamProviderIdentityToken(expectation.policy) ||
        !isValidPamProviderManagedKey(expectation.managedKey) ||
        expectation.mutationId == 0) {
        error = "invalid FIC PAM ownership expectation";
        return false;
    }
    // EXACT key match via the shared canonical body validator — never a
    // prefix compare: "deny_extra = 5" must never validate against
    // managedKey "deny".
    if (!ownershipBodyMatchesKey(expectation.body,
                                 expectation.managedKey)) {
        error = "FIC PAM ownership expectation requires a canonical "
                "applied body of exactly the managed key";
        return false;
    }
    if (!expectation.previousBody.empty()) {
        if (!ownershipBodyMatchesKey(expectation.previousBody,
                                     expectation.managedKey) ||
            expectation.previousBody == expectation.body) {
            error = "FIC PAM ownership expectation requires a canonical "
                    "previous body of the same managed key, different from "
                    "the applied body";
            return false;
        }
    }
    return true;
}


} // namespace

// ---------------------------------------------------------------------------
// Step 7E: provider-specific set-only flag primitives.
// ---------------------------------------------------------------------------

bool pamProviderFlagKeyMatchIgnoreCase(const std::string& provider) {
    // Upstream evidence (Step 7E §18):
    //   * libpwquality src/settings.c: recognized keys are matched after
    //     lowercasing (ASCII case-insensitive);
    //   * pam_pwhistory: pam_modutil_search_key uses strcasecmp;
    //   * pam_faillock faillock_config.c: strcmp — CASE-SENSITIVE.
    return provider == "pam_pwquality" || provider == "pam_pwhistory";
}

bool pamProviderFlagLineIsActiveOccurrence(const std::string& provider,
                                           const std::string& physicalLine,
                                           const std::string& managedKey) {
    if (!isValidPamProviderManagedKey(managedKey)) {
        return false;
    }
    std::string line = physicalLine;
    // Upstream: '#' truncates the rest of the line (all three providers).
    const std::size_t comment = line.find('#');
    if (comment != std::string::npos) {
        line.erase(comment);
    }
    std::size_t start = 0;
    while (start < line.size() &&
           std::isspace(static_cast<unsigned char>(line[start])) != 0) {
        ++start;
    }
    if (start == line.size()) {
        return false; // blank or comment-only line: never active
    }
    std::size_t keyEnd = start;
    while (keyEnd < line.size() &&
           std::isspace(static_cast<unsigned char>(line[keyEnd])) == 0 &&
           line[keyEnd] != '=') {
        ++keyEnd;
    }
    const std::string key = line.substr(start, keyEnd - start);
    if (key.size() != managedKey.size()) {
        return false;
    }
    const bool ignoreCase = pamProviderFlagKeyMatchIgnoreCase(provider);
    for (std::size_t index = 0; index < key.size(); ++index) {
        const unsigned char a = static_cast<unsigned char>(key[index]);
        const unsigned char b = static_cast<unsigned char>(managedKey[index]);
        if (a == b) {
            continue;
        }
        if (!ignoreCase) {
            return false;
        }
        const unsigned char lowerA = a >= 'A' && a <= 'Z' ? a - 'A' + 'a' : a;
        const unsigned char lowerB = b >= 'A' && b <= 'Z' ? b - 'A' + 'a' : b;
        if (lowerA != lowerB) {
            return false;
        }
    }
    return true;
}

std::string pamProviderSuppressionWrapperLine(
    const std::string& provider, const std::string& policy,
    const std::string& managedKey, std::uint64_t mutationId,
    const std::string& suppressionId, const std::string& rawLine) {
    return std::string(kPamProviderSuppressMarkerPrefix) + provider +
        " policy=" + policy + " key=" + managedKey +
        " mutation=" + std::to_string(mutationId) +
        " suppression=" + suppressionId + " raw=" + rawLine;
}

bool parsePamProviderSuppressionWrapper(const std::string& physicalLine,
                                        PamProviderSuppressedLine& wrapper,
                                        std::string& error) {
    const std::string prefix = kPamProviderSuppressMarkerPrefix;
    if (physicalLine.size() <= prefix.size() ||
        physicalLine.compare(0, prefix.size(), prefix) != 0) {
        error = "line is not a canonical FIC PAM suppression wrapper";
        return false;
    }
    // Sequential canonical field order after the marker prefix:
    // <provider>, policy=, key=, mutation=, suppression=, raw= (LAST field
    // delimiter: everything after it is the opaque original physical line).
    std::string rest = physicalLine.substr(prefix.size());
    const std::size_t providerEnd = rest.find(' ');
    if (providerEnd == std::string::npos) {
        error = "FIC PAM suppression wrapper: missing provider field";
        return false;
    }
    const std::string provider = rest.substr(0, providerEnd);
    rest.erase(0, providerEnd + 1);
    if (!isValidPamProviderIdentityToken(provider)) {
        error = "FIC PAM suppression wrapper: invalid provider identity";
        return false;
    }
    const auto readTokenField = [&](const char* name,
                                    std::string& value) -> bool {
        const std::string field = std::string(name) + "=";
        if (rest.compare(0, field.size(), field) != 0) {
            error = std::string("FIC PAM suppression wrapper: expected ") +
                name + "= field";
            return false;
        }
        rest.erase(0, field.size());
        const std::size_t space = rest.find(' ');
        if (space == std::string::npos) {
            error = std::string("FIC PAM suppression wrapper: missing ") +
                name + "= field terminator";
            return false;
        }
        value = rest.substr(0, space);
        rest.erase(0, space + 1);
        return true;
    };
    std::string policy;
    std::string key;
    std::string mutation;
    std::string suppression;
    if (!readTokenField("policy", policy) || !readTokenField("key", key) ||
        !readTokenField("mutation", mutation) ||
        !readTokenField("suppression", suppression)) {
        return false;
    }
    if (rest.compare(0, 4, "raw=") != 0) {
        error = "FIC PAM suppression wrapper: raw= must be the last field "
                "delimiter";
        return false;
    }
    const std::string raw = rest.substr(4);
    wrapper = PamProviderSuppressedLine{};
    wrapper.provider = provider;
    wrapper.policy = policy;
    wrapper.managedKey = key;
    wrapper.suppressionId = suppression;
    wrapper.rawLine = raw;
    if (!isValidPamProviderIdentityToken(policy)) {
        error = "FIC PAM suppression wrapper: invalid policy identity";
        return false;
    }
    if (!isValidPamProviderManagedKey(key)) {
        error = "FIC PAM suppression wrapper: invalid managed key";
        return false;
    }
    std::string mutationError;
    if (!parsePhysicalMutationId(mutation, wrapper.mutationId,
                                 mutationError)) {
        error = "FIC PAM suppression wrapper: " + mutationError;
        return false;
    }
    if (!isValidPamProviderSuppressionId(suppression)) {
        error = "FIC PAM suppression wrapper: invalid suppression id";
        return false;
    }
    if (raw.empty() || raw.find('\n') != std::string::npos ||
        raw.find('\0') != std::string::npos) {
        error = "FIC PAM suppression wrapper: embedded raw line must be a "
                "single non-empty physical line";
        return false;
    }
    // Strict wrapper proof (Step 7E §11): the embedded raw line must be an
    // ACTIVE occurrence of the same managed key under the provider-specific
    // key semantics. A manually edited embedded line is never proven
    // suppressed state.
    if (!pamProviderFlagLineIsActiveOccurrence(wrapper.provider, raw, key)) {
        error = "FIC PAM suppression wrapper: embedded raw line is not an "
                "active occurrence of the managed key " +
            key + " (fail closed)";
        return false;
    }
    return true;
}

std::string nextPamProviderSuppressionId(
    const std::vector<std::string>& existingIds) {
    std::uint64_t maxSuffix = 0;
    for (const std::string& id : existingIds) {
        if (id.size() < 2 || id.front() != 's') {
            continue;
        }
        const std::string suffix = id.substr(1);
        if (!std::all_of(suffix.begin(), suffix.end(), [](unsigned char c) {
                return std::isdigit(c) != 0;
            }) || suffix.front() == '0') {
            continue;
        }
        std::uint64_t value = 0;
        const auto result =
            std::from_chars(suffix.data(), suffix.data() + suffix.size(),
                            value);
        if (result.ec == std::errc() &&
            result.ptr == suffix.data() + suffix.size()) {
            maxSuffix = std::max(maxSuffix, value);
        }
    }
    return "s" + std::to_string(maxSuffix + 1);
}

PamProviderBlockParseResult parsePamProviderManagedBlock(
    const std::string& content) {
    PamProviderBlockParseResult result;
    const std::vector<std::string> lines = physicalLines(content);

    std::size_t beginIndex = std::string::npos;
    std::size_t endIndex = std::string::npos;
    bool insideEntry = false;
    bool entryBodySeen = false;
    std::size_t entryCount = 0;
    std::string provider;
    bool leadOwnedNewline = false;
    std::vector<PamProviderManagedEntry> entries;
    std::vector<PamProviderSuppressedLine> suppressions;
    PamProviderManagedEntry current;

    for (std::size_t index = 0; index < lines.size(); ++index) {
        const std::string line = lineContent(lines[index]);
        const bool insideBlock =
            beginIndex != std::string::npos && endIndex == std::string::npos;
        if (mentionsReservedNamespace(line)) {
            // Every mention of the reserved marker namespace must be an
            // EXACTLY canonical marker in a valid structural position.
            // Anything else is a foreign FIC-like malformed marker.
            //
            // Step 7E: the canonical suppression wrapper is accepted ONLY
            // outside the provider block (inside the block it is a
            // misplaced FIC structure — fail closed).
            const std::string physical = physicalLineContent(lines[index]);
            if (physical.compare(
                    0, std::strlen(kPamProviderSuppressMarkerPrefix),
                    kPamProviderSuppressMarkerPrefix) == 0) {
                if (insideBlock) {
                    result.error =
                        "FIC PAM suppression wrapper внутри provider block "
                        "(fail closed): " +
                        line;
                    return result;
                }
                PamProviderSuppressedLine wrapper;
                std::string wrapperError;
                if (!parsePamProviderSuppressionWrapper(
                        physical, wrapper, wrapperError)) {
                    result.error = "foreign FIC-подобный malformed SUPPRESS "
                                   "marker: " +
                        wrapperError;
                    return result;
                }
                for (const PamProviderSuppressedLine& existing :
                     suppressions) {
                    if (existing.suppressionId == wrapper.suppressionId) {
                        result.error =
                            "дублированный suppression id внутри shared "
                            "PAM provider configuration: " +
                            wrapper.suppressionId;
                        return result;
                    }
                }
                wrapper.lineIndex = index;
                suppressions.push_back(std::move(wrapper));
                continue;
            }
            if (line == kPamProviderBlockEndMarker) {
                if (!insideBlock || insideEntry) {
                    result.error =
                        "FIC PAM provider block END без BEGIN или внутри "
                        "entry";
                    return result;
                }
                if (entryCount == 0) {
                    result.error = "пустой FIC PAM provider block";
                    return result;
                }
                endIndex = index;
                continue;
            }
            std::string markerPolicy;
            std::uint64_t markerMutation = 0;
            std::string markerProvider;
            bool markerLeadOwnedNewline = false;
            if (parseBlockBeginMarker(line, markerProvider,
                                      markerLeadOwnedNewline,
                                      result.error)) {
                if (insideBlock) {
                    result.error =
                        "дублированный или вложенный FIC PAM provider "
                        "block BEGIN";
                    return result;
                }
                if (beginIndex != std::string::npos) {
                    result.error = "дублированный FIC PAM provider block";
                    return result;
                }
                beginIndex = index;
                provider = markerProvider;
                leadOwnedNewline = markerLeadOwnedNewline;
                continue;
            }
            if (parseEntryBeginMarker(
                    line, markerPolicy, markerMutation, result.error)) {
                if (!insideBlock || insideEntry) {
                    result.error =
                        "FIC PAM entry BEGIN вне блока или внутри другого "
                        "entry";
                    return result;
                }
                insideEntry = true;
                entryBodySeen = false;
                current = PamProviderManagedEntry{};
                current.policy = markerPolicy;
                current.mutationId = markerMutation;
                continue;
            }
            if (line == kPamProviderEntryEndMarker) {
                if (!insideBlock || !insideEntry || !entryBodySeen) {
                    result.error =
                        "FIC PAM entry END без BEGIN, без body или "
                        "дублированный";
                    return result;
                }
                for (const PamProviderManagedEntry& existing : entries) {
                    if (existing.policy == current.policy &&
                        existing.managedKey == current.managedKey) {
                        result.error =
                            "дублированный entry (ownership tuple) внутри "
                            "FIC PAM provider block: " +
                            current.policy + "/" + current.managedKey;
                        return result;
                    }
                    if (existing.mutationId == current.mutationId) {
                        result.error =
                            "дублированный physical mutation id внутри FIC "
                            "PAM provider block: один journal record не "
                            "может доказывать два entry";
                        return result;
                    }
                }
                entries.push_back(current);
                insideEntry = false;
                ++entryCount;
                continue;
            }
            // Step 7E: the canonical disabled-flag sentinel is accepted ONLY
            // as the body line of an entry inside the block (it is the
            // FIC-owned inert disabled-state anchor).
            std::string sentinelKey;
            if (insideBlock && insideEntry && !entryBodySeen &&
                parseCanonicalPamProviderFlagDisabledBody(
                    physicalLineContent(lines[index]), sentinelKey)) {
                current.managedKey = sentinelKey;
                current.body = physicalLineContent(lines[index]);
                current.kind = PamProviderManagedEntryKind::FlagDisabled;
                entryBodySeen = true;
                continue;
            }
            result.error = "foreign FIC-подобный malformed marker в shared "
                           "PAM provider configuration: " + line;
            return result;
        }
        if (!insideBlock) {
            continue; // foreign content: opaque bytes
        }
        if (insideEntry) {
            if (entryBodySeen) {
                result.error = "FIC PAM entry содержит более одной строки "
                               "значения";
                return result;
            }
            const std::string bodyLine = physicalLineContent(lines[index]);
            if (bodyLine.empty()) {
                result.error = "пустая строка внутри FIC PAM provider entry";
                return result;
            }
            std::string parsedKey;
            std::string parsedBody;
            // Step 7E typed body union: canonical assignment (unchanged
            // Step 7A grammar), exact bare managed key (enabled flag) — the
            // disabled sentinel was handled in the reserved-namespace
            // branch above.
            if (parseEntryBody(bodyLine, parsedKey, parsedBody,
                               result.error)) {
                current.managedKey = parsedKey;
                current.body = parsedBody;
                current.kind = PamProviderManagedEntryKind::Assignment;
                entryBodySeen = true;
                continue;
            }
            if (isValidPamProviderManagedKey(bodyLine)) {
                current.managedKey = bodyLine;
                current.body = bodyLine;
                current.kind = PamProviderManagedEntryKind::FlagEnabled;
                entryBodySeen = true;
                continue;
            }
            result.error = "строка внутри FIC PAM provider entry не является "
                           "canonical assignment, bare flag key или disabled "
                           "sentinel: " +
                bodyLine;
            return result;
        }
        // Inside the block, outside an entry: the canonical structural
        // portion admits nothing.
        result.error = "неожиданная строка внутри FIC PAM provider block: " +
            line;
        return result;
    }

    if (insideEntry) {
        result.error = "FIC PAM entry не закрыт маркером END";
        return result;
    }
    if (beginIndex != std::string::npos && endIndex == std::string::npos) {
        result.error = "FIC PAM provider block не закрыт маркером END";
        return result;
    }

    if (beginIndex != std::string::npos) {
        PamProviderBlockView& view = result.view;
        view.present = true;
        view.provider = provider;
        // Structural separator boundary provenance: lead=newline declares
        // the LF byte immediately before the BEGIN marker as FIC-owned
        // serialization. An impossible declaration (BEGIN at offset 0, or
        // the preceding byte is not LF) is a parse failure: the decoder
        // must never silently strip a byte it does not provably own.
        std::size_t beginOffset = 0;
        for (std::size_t index = 0; index < beginIndex; ++index) {
            beginOffset += lines[index].size();
        }
        if (leadOwnedNewline &&
            (beginOffset == 0 || content[beginOffset - 1] != '\n')) {
            result.error = "FIC PAM provider block объявляет lead=newline, "
                           "но байт непосредственно перед BEGIN не LF "
                           "(fail closed)";
            return result;
        }
        view.leadOwnedNewline = leadOwnedNewline;
        // Typed placement: atBeginning means NO bytes before the BEGIN
        // marker; atEnd means NO foreign physical lines after the END
        // marker (the canonical renderer emits exactly one FIC-owned
        // terminator newline, which stays part of the block span). A
        // trailing foreign byte — an assignment, a comment, even a blank
        // line — makes the block misplaced for the EOF contract. This is
        // placement information only: a valid block with a foreign tail
        // stays parse-valid (ownership is provable; the next apply
        // relocates it to the requested placement).
        view.atBeginning = beginIndex == 0;
        view.atEnd = endIndex + 1 == lines.size();
        view.effectivePlacement = view.atBeginning
            ? PamProviderBlockPlacement::AtBeginning
            : (view.atEnd ? PamProviderBlockPlacement::AtEnd
                          : PamProviderBlockPlacement::Misplaced);
        canonicalSort(entries);
        view.entries = std::move(entries);
        view.suppressions = std::move(suppressions);
    }

    result.ok = true;
    return result;
}

PamProviderEntryProofResult provePamProviderEntryOwnership(
    const PamProviderBlockParseResult& parse,
    const PamProviderOwnershipExpectation& expectation) {
    PamProviderEntryProofResult result;
    std::string validationError;
    if (!validateOwnershipExpectation(expectation, validationError)) {
        result.error = validationError;
        return result;
    }
    if (!parse.ok) {
        result.proof = PamProviderEntryProof::MalformedState;
        result.error = parse.error;
        return result;
    }
    if (parse.view.present &&
        parse.view.provider != expectation.provider) {
        result.proof = PamProviderEntryProof::ForeignProvider;
        result.error = "FIC PAM provider block принадлежит другому "
                       "provider: " + parse.view.provider;
        return result;
    }
    const PamProviderManagedEntry* entry = parse.view.present
        ? findEntry(parse.view.entries, expectation.policy,
                    expectation.managedKey)
        : nullptr;
    if (entry == nullptr) {
        result.proof = PamProviderEntryProof::Absent;
        return result;
    }
    // ABA protection: the physical entry must carry the EXACT journal
    // mutation id. A key/value lookalike with a different id is foreign
    // state, never an owned artifact.
    if (entry->mutationId != expectation.mutationId) {
        result.proof = PamProviderEntryProof::Lookalike;
        result.error = "FIC PAM entry (policy, key) совпадает, но physical "
                       "mutation id отличается: " +
            std::to_string(entry->mutationId) + " != " +
            std::to_string(expectation.mutationId);
        return result;
    }
    if (entry->body != expectation.body) {
        result.proof = PamProviderEntryProof::Drifted;
        result.error =
            "FIC PAM entry был изменён вручную (body drift)";
        return result;
    }
    result.proven = true;
    result.proof = PamProviderEntryProof::Owned;
    return result;
}

PamProviderJournalBindingResult classifyPamProviderJournalBinding(
    PamProviderJournalMutationStatus status,
    const PamProviderBlockParseResult& parse,
    const PamProviderOwnershipExpectation& expectation) {
    PamProviderJournalBindingResult result;
    std::string validationError;
    if (!validateOwnershipExpectation(expectation, validationError)) {
        result.error = validationError;
        return result;
    }
    if (!parse.ok) {
        result.error = parse.error;
        return result;
    }
    const bool prepared =
        status == PamProviderJournalMutationStatus::Prepared;
    const bool fresh = expectation.previousBody.empty();
    if (parse.view.present &&
        parse.view.provider != expectation.provider) {
        result.ok = true;
        result.state = prepared
            ? PamProviderJournalBindingState::PreparedConflict
            : PamProviderJournalBindingState::AppliedDrifted;
        return result;
    }
    const PamProviderManagedEntry* entry = parse.view.present
        ? findEntry(parse.view.entries, expectation.policy,
                    expectation.managedKey)
        : nullptr;
    result.ok = true;
    if (entry == nullptr) {
        // fresh + absent → the mutation has not happened yet; update +
        // absent → the previous FIC-owned body vanished: neither the
        // previous nor the target state is provable — fail closed.
        result.state = prepared
            ? (fresh ? PamProviderJournalBindingState::PreparedFreshAbsent
                     : PamProviderJournalBindingState::PreparedConflict)
            : PamProviderJournalBindingState::AppliedMissing;
        return result;
    }
    if (entry->mutationId != expectation.mutationId) {
        // ABA protection: (policy, key) present with a different physical
        // mutation id — never adopt, never rewrite.
        result.state = prepared
            ? PamProviderJournalBindingState::PreparedConflict
            : PamProviderJournalBindingState::AppliedDrifted;
        return result;
    }
    if (entry->body == expectation.body) {
        // Crash after the physical write, before journal completion: the
        // exact target body is present under the SAME record id — adopt.
        result.state = prepared
            ? (fresh
                   ? PamProviderJournalBindingState::PreparedFreshTargetPresent
                   : PamProviderJournalBindingState::
                         PreparedUpdateTargetPresent)
            : PamProviderJournalBindingState::AppliedExact;
        return result;
    }
    if (!fresh && entry->body == expectation.previousBody) {
        // Crash after recording the previous→target transition but before
        // writing the target: the previous FIC-owned body is still
        // physically present — continue the transition.
        result.state =
            PamProviderJournalBindingState::PreparedUpdatePreviousPresent;
        return result;
    }
    // Exact id, but the body is neither the target nor the previous body:
    // manual drift — conflict, never rewrite or remove blindly.
    result.state = prepared
        ? PamProviderJournalBindingState::PreparedConflict
        : PamProviderJournalBindingState::AppliedDrifted;
    return result;
}

PamProviderMutationResult setPamProviderManagedEntry(
    const std::string& content,
    const PamProviderEntrySpec& spec,
    PamProviderBlockPlacementRequest request) {
    PamProviderMutationResult result;
    std::string error;
    if (!validateEntrySpec(spec, error)) {
        result.error = error;
        return result;
    }
    const PamProviderBlockParseResult parse =
        parsePamProviderManagedBlock(content);
    if (!parse.ok) {
        result.error = parse.error;
        return result;
    }
    if (parse.view.present && parse.view.provider != spec.provider) {
        result.error = "FIC PAM provider block принадлежит другому "
                       "provider: " + parse.view.provider;
        return result;
    }

    std::vector<PamProviderManagedEntry> entries = parse.view.entries;
    const std::string newBody =
        pamProviderEntryBody(spec.managedKey, spec.value);
    PamProviderManagedEntry* existing = nullptr;
    for (PamProviderManagedEntry& entry : entries) {
        if (entry.policy == spec.policy &&
            entry.managedKey == spec.managedKey) {
            existing = &entry;
            break;
        }
    }
    if (existing != nullptr) {
        // Fail closed: a physically present entry carrying a DIFFERENT
        // mutation id belongs to another journal transaction identity.
        if (existing->mutationId != spec.mutationId) {
            result.error = "FIC PAM entry (policy, key) уже существует с "
                           "другим physical mutation id: " +
                std::to_string(existing->mutationId) + " != " +
                std::to_string(spec.mutationId);
            return result;
        }
        if (existing->body == newBody &&
            parse.view.satisfiesPlacement(request)) {
            result.outcome = PamProviderMutationResult::Outcome::NoOp;
            result.content = content;
            result.ok = true;
            return result;
        }
        existing->body = newBody;
    } else {
        PamProviderManagedEntry added;
        added.policy = spec.policy;
        added.managedKey = spec.managedKey;
        added.body = newBody;
        added.mutationId = spec.mutationId;
        entries.push_back(std::move(added));
        canonicalSort(entries);
    }

    std::string foreign;
    if (parse.view.present) {
        std::size_t beginIndex = std::string::npos;
        std::size_t endIndex = std::string::npos;
        findBlockLineIndices(content, beginIndex, endIndex);
        foreign = foreignBytes(content, beginIndex, endIndex,
                               parse.view.atBeginning,
                               parse.view.leadOwnedNewline);
    } else {
        foreign = content;
    }
    // Structural lead contract: an EOF placement after non-empty foreign
    // bytes owns exactly one separator LF (lead=newline); a BOF placement
    // and a block with no foreign bytes at all own nothing before BEGIN
    // (lead=none).
    const bool leadOwnedNewline =
        request == PamProviderBlockPlacementRequest::End && !foreign.empty();
    const std::string block = renderBlock(spec.provider, entries,
                                          leadOwnedNewline);
    result.content =
        request == PamProviderBlockPlacementRequest::Beginning
        ? assembleAtBeginning(foreign, block)
        : assembleAtEnd(foreign, block);
    result.outcome = PamProviderMutationResult::Outcome::Committed;
    result.ok = true;
    return result;
}

PamProviderRemovalResult removePamProviderManagedEntry(
    const std::string& content,
    const PamProviderOwnershipExpectation& expectation,
    PamProviderBlockPlacementRequest request) {
    PamProviderRemovalResult result;
    std::string error;
    if (!validateOwnershipExpectation(expectation, error)) {
        result.error = error;
        return result;
    }
    const PamProviderBlockParseResult parse =
        parsePamProviderManagedBlock(content);
    if (!parse.ok) {
        result.error = parse.error;
        return result;
    }
    if (!parse.view.present) {
        // No FIC block: ownership already released, content unchanged. A
        // foreign key/value lookalike outside any FIC block is foreign
        // state and is NEVER touched (ABA protection).
        result.outcome = PamProviderRemovalResult::Outcome::AlreadyAbsent;
        result.content = content;
        result.ok = true;
        return result;
    }
    if (parse.view.provider != expectation.provider) {
        result.error = "FIC PAM provider block принадлежит другому "
                       "provider: " + parse.view.provider;
        return result;
    }
    const PamProviderManagedEntry* entry =
        findEntry(parse.view.entries, expectation.policy,
                  expectation.managedKey);
    if (entry == nullptr) {
        // No FIC entry for this (policy, key): already released. Foreign
        // directives with the same key shape stay untouched.
        result.outcome = PamProviderRemovalResult::Outcome::AlreadyAbsent;
        result.content = content;
        result.ok = true;
        return result;
    }
    // Exact ownership proof before any removal: the physical entry must
    // carry the journal mutation id AND the exact applied body. A
    // lookalike entry (different mutation id) or a manually edited body
    // (drift) is a typed refusal — never removed blindly.
    if (entry->mutationId != expectation.mutationId) {
        result.error = "FIC PAM entry (policy, key) совпадает, но physical "
                       "mutation id отличается: удаление запрещено (ABA): " +
            std::to_string(entry->mutationId) + " != " +
            std::to_string(expectation.mutationId);
        return result;
    }
    if (entry->body != expectation.body) {
        result.error = "FIC PAM entry был изменён вручную (body drift): "
                       "удаление запрещено";
        return result;
    }

    std::vector<PamProviderManagedEntry> remaining;
    for (const PamProviderManagedEntry& candidate : parse.view.entries) {
        if (candidate.policy == expectation.policy &&
            candidate.managedKey == expectation.managedKey) {
            continue;
        }
        remaining.push_back(candidate);
    }

    std::size_t beginIndex = std::string::npos;
    std::size_t endIndex = std::string::npos;
    findBlockLineIndices(content, beginIndex, endIndex);
    const std::string foreign =
        foreignBytes(content, beginIndex, endIndex,
                     parse.view.atBeginning, parse.view.leadOwnedNewline);

    if (remaining.empty()) {
        // Remove the whole block: never leave an empty BEGIN/END artifact.
        // The foreign bytes are restored byte-exact (including the absence
        // of a trailing newline).
        result.outcome = PamProviderRemovalResult::Outcome::BlockRemoved;
        result.content = foreign;
        result.ok = true;
        return result;
    }
    const bool leadOwnedNewline =
        request == PamProviderBlockPlacementRequest::End && !foreign.empty();
    const std::string block = renderBlock(expectation.provider, remaining,
                                          leadOwnedNewline);
    result.content =
        request == PamProviderBlockPlacementRequest::Beginning
        ? assembleAtBeginning(foreign, block)
        : assembleAtEnd(foreign, block);
    result.outcome = PamProviderRemovalResult::Outcome::Removed;
    result.ok = true;
    return result;
}

// ---------------------------------------------------------------------------
// Step 7E: set-only flag transition primitive.
// ---------------------------------------------------------------------------

namespace {

// Splits ONE physical line into its content (no CR/LF terminator) and its
// exact terminator ("" for a last line without a newline; "\n"; "\r\n").
// The split is what makes the suppression wrapper byte-exact round-trip
// safe: the embedded raw line never contains the terminator, and the
// terminator of the wrapper line is the terminator of the original line.
std::pair<std::string, std::string> splitPhysicalLine(
    const std::string& physical) {
    std::string text = physical;
    std::string terminator;
    if (!text.empty() && text.back() == '\n') {
        text.pop_back();
        if (!text.empty() && text.back() == '\r') {
            terminator = "\r\n";
            text.pop_back();
        } else {
            terminator = "\n";
        }
    } else if (!text.empty() && text.back() == '\r') {
        // Degenerate lone-CR terminator: preserved byte-exact.
        terminator = "\r";
        text.pop_back();
    }
    return {std::move(text), std::move(terminator)};
}

PamProviderManagedEntry* findMutableEntry(
    std::vector<PamProviderManagedEntry>& entries, const std::string& policy,
    const std::string& managedKey) {
    for (PamProviderManagedEntry& entry : entries) {
        if (entry.policy == policy && entry.managedKey == managedKey) {
            return &entry;
        }
    }
    return nullptr;
}

bool containsId(const std::vector<std::string>& ids,
                const std::string& value) {
    return std::find(ids.begin(), ids.end(), value) != ids.end();
}

bool validateFlagSpec(const PamProviderFlagSpec& spec, std::string& error) {
    if (!isValidPamProviderIdentityToken(spec.provider) ||
        !isValidPamProviderIdentityToken(spec.policy)) {
        error = "invalid provider/policy identity for FIC PAM managed flag";
        return false;
    }
    if (!isValidPamProviderManagedKey(spec.managedKey)) {
        error = "invalid managed key for FIC PAM managed flag: " +
            spec.managedKey;
        return false;
    }
    if (spec.mutationId == 0) {
        error = "FIC PAM managed flag requires a non-zero mutation id";
        return false;
    }
    if (spec.enabled) {
        if (!spec.keepSuppressionIds.empty() ||
            !spec.createSuppressionIds.empty()) {
            error = "enabled FIC PAM flag target must not own suppression "
                    "wrappers";
            return false;
        }
        return true;
    }
    for (const std::string& id : spec.keepSuppressionIds) {
        if (!isValidPamProviderSuppressionId(id)) {
            error = "invalid kept suppression id for FIC PAM managed flag: " +
                id;
            return false;
        }
    }
    for (const std::string& id : spec.createSuppressionIds) {
        if (!isValidPamProviderSuppressionId(id)) {
            error = "invalid new suppression id for FIC PAM managed flag: " +
                id;
            return false;
        }
        if (containsId(spec.keepSuppressionIds, id)) {
            error = "suppression id is both kept and newly created: " + id;
            return false;
        }
    }
    for (std::size_t outer = 0; outer < spec.createSuppressionIds.size();
         ++outer) {
        for (std::size_t inner = outer + 1;
             inner < spec.createSuppressionIds.size(); ++inner) {
            if (spec.createSuppressionIds[outer] ==
                spec.createSuppressionIds[inner]) {
                error = "duplicate new suppression id: " +
                    spec.createSuppressionIds[outer];
                return false;
            }
        }
    }
    return true;
}

} // namespace

PamProviderFlagMutationResult setPamProviderManagedFlagTransition(
    const std::string& content,
    const PamProviderFlagSpec& spec,
    PamProviderBlockPlacementRequest request) {
    PamProviderFlagMutationResult result;
    std::string error;
    if (!validateFlagSpec(spec, error)) {
        result.error = error;
        return result;
    }
    const PamProviderBlockParseResult parse =
        parsePamProviderManagedBlock(content);
    if (!parse.ok) {
        result.error = parse.error;
        return result;
    }
    if (parse.view.present && parse.view.provider != spec.provider) {
        result.error = "FIC PAM provider block принадлежит другому "
                       "provider: " +
            parse.view.provider;
        return result;
    }

    // --- managed entry (policy, key): bare key or disabled sentinel ---
    std::vector<PamProviderManagedEntry> entries = parse.view.entries;
    const std::string targetBody =
        spec.enabled ? spec.managedKey
                     : pamProviderFlagDisabledBody(spec.managedKey);
    const PamProviderManagedEntryKind targetKind =
        spec.enabled ? PamProviderManagedEntryKind::FlagEnabled
                     : PamProviderManagedEntryKind::FlagDisabled;
    bool changed = false;
    if (PamProviderManagedEntry* existing =
            findMutableEntry(entries, spec.policy, spec.managedKey)) {
        // Fail closed: an entry carrying a DIFFERENT mutation id belongs to
        // another journal transaction identity (ABA protection).
        if (existing->mutationId != spec.mutationId) {
            result.error = "FIC PAM entry (policy, key) уже существует с "
                           "другим physical mutation id: " +
                std::to_string(existing->mutationId) + " != " +
                std::to_string(spec.mutationId);
            return result;
        }
        if (existing->body != targetBody) {
            existing->body = targetBody;
            existing->kind = targetKind;
            changed = true;
        }
    } else {
        PamProviderManagedEntry added;
        added.policy = spec.policy;
        added.managedKey = spec.managedKey;
        added.body = targetBody;
        added.kind = targetKind;
        added.mutationId = spec.mutationId;
        entries.push_back(std::move(added));
        canonicalSort(entries);
        changed = true;
    }

    // --- suppression wrappers + foreign active occurrences ---
    // Wrappers and foreign lines live OUTSIDE the block span; every edit is
    // done IN PLACE so the physical position of each foreign byte relative
    // to the others never changes (Step 7E §63).
    const std::vector<std::string> lines = physicalLines(content);
    std::size_t beginIndex = std::string::npos;
    std::size_t endIndex = std::string::npos;
    findBlockLineIndices(content, beginIndex, endIndex);
    std::vector<std::string> rebuilt;
    rebuilt.reserve(lines.size());
    std::size_t createCursor = 0;
    for (std::size_t index = 0; index < lines.size(); ++index) {
        const bool insideBlockSpan =
            beginIndex != std::string::npos && index >= beginIndex &&
            index <= endIndex;
        if (insideBlockSpan) {
            rebuilt.push_back(lines[index]);
            continue;
        }
        // Canonical wrapper line (the strict parse already proved the
        // canonical form and raw-line proof of every wrapper).
        const PamProviderSuppressedLine* wrapper = nullptr;
        for (const PamProviderSuppressedLine& candidate :
             parse.view.suppressions) {
            if (candidate.lineIndex == index) {
                wrapper = &candidate;
                break;
            }
        }
        if (wrapper != nullptr) {
            const bool owned = wrapper->provider == spec.provider &&
                wrapper->policy == spec.policy &&
                wrapper->managedKey == spec.managedKey &&
                wrapper->mutationId == spec.mutationId;
            if (!owned) {
                // Another record's provenance is foreign state here —
                // never touched.
                rebuilt.push_back(lines[index]);
                continue;
            }
            if (spec.enabled) {
                // Release: the embedded raw line returns byte-exact to the
                // wrapper's physical position (Step 7E §42).
                const std::string terminator =
                    splitPhysicalLine(lines[index]).second;
                rebuilt.push_back(wrapper->rawLine + terminator);
                changed = true;
                continue;
            }
            if (!containsId(spec.keepSuppressionIds,
                            wrapper->suppressionId)) {
                result.error = "FIC PAM suppression wrapper of this record "
                               "carries an id outside keep∪create (fail "
                               "closed): " +
                    wrapper->suppressionId;
                return result;
            }
            rebuilt.push_back(lines[index]);
            continue;
        }
        // Foreign line: wrap when the target state is disabled and the line
        // is an ACTIVE occurrence of the managed key (comments, FIC markers
        // and blank lines are never active — the scanner proves it).
        if (!spec.enabled) {
            const auto [text, terminator] = splitPhysicalLine(lines[index]);
            if (pamProviderFlagLineIsActiveOccurrence(
                    spec.provider, text, spec.managedKey)) {
                if (createCursor >= spec.createSuppressionIds.size()) {
                    result.error = "FIC PAM flag transition ran out of new "
                                   "suppression ids: an active occurrence "
                                   "cannot be wrapped (fail closed)";
                    return result;
                }
                rebuilt.push_back(pamProviderSuppressionWrapperLine(
                    spec.provider, spec.policy, spec.managedKey,
                    spec.mutationId, spec.createSuppressionIds[createCursor],
                    text) + terminator);
                ++createCursor;
                changed = true;
                continue;
            }
        }
        rebuilt.push_back(lines[index]);
    }
    if (!spec.enabled && createCursor != spec.createSuppressionIds.size()) {
        result.error = "FIC PAM flag transition received more new "
                       "suppression ids than there are active occurrences "
                       "(fail closed)";
        return result;
    }

    // --- reassembly: foreign bytes + block at the requested placement ---
    std::string foreign;
    if (parse.view.present) {
        if (parse.view.atBeginning) {
            for (std::size_t index = endIndex + 1; index < rebuilt.size();
                 ++index) {
                foreign += rebuilt[index];
            }
        } else {
            std::string before;
            for (std::size_t index = 0; index < beginIndex; ++index) {
                before += rebuilt[index];
            }
            // lead=newline: the EXACTLY ONE LF immediately before BEGIN is
            // FIC-owned serialization — stripped here, re-added by the
            // renderer (mirrors foreignBytes/assembleAtEnd).
            if (parse.view.leadOwnedNewline && !before.empty() &&
                before.back() == '\n') {
                before.pop_back();
            }
            std::string after;
            for (std::size_t index = endIndex + 1; index < rebuilt.size();
                 ++index) {
                after += rebuilt[index];
            }
            foreign = before + after;
        }
    } else {
        for (const std::string& line : rebuilt) {
            foreign += line;
        }
    }
    if (!changed && parse.view.satisfiesPlacement(request)) {
        result.outcome = PamProviderFlagMutationResult::Outcome::NoOp;
        result.content = content;
        result.ok = true;
        return result;
    }
    // Structural lead contract (identical to setPamProviderManagedEntry).
    const bool leadOwnedNewline =
        request == PamProviderBlockPlacementRequest::End && !foreign.empty();
    const std::string block = renderBlock(spec.provider, entries,
                                          leadOwnedNewline);
    result.content =
        request == PamProviderBlockPlacementRequest::Beginning
        ? assembleAtBeginning(foreign, block)
        : assembleAtEnd(foreign, block);
    result.outcome = PamProviderFlagMutationResult::Outcome::Committed;
    result.ok = true;
    return result;
}

} // namespace fic::identity::pam
