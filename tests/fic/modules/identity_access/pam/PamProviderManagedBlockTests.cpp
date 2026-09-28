#include "modules/identity_access/pam/PamProviderManagedBlock.h"

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace fic::identity::pam;

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

const char* kProvider = "pam_faillock";
const char* kPolicyA = "failed_authentication_attempts";
const char* kPolicyB = "failed_authentication_counting_period";

std::string renderEntry(const std::string& policy,
                        std::uint64_t mutationId,
                        const std::string& body) {
    return pamProviderEntryBeginMarker(policy, mutationId) + "\n" + body +
        "\n" + kPamProviderEntryEndMarker + "\n";
}

std::string renderBlock(const std::string& entries,
                        bool leadOwnedNewline = false) {
    return pamProviderBlockBeginMarker(kProvider, leadOwnedNewline) + "\n" +
        entries + kPamProviderBlockEndMarker + "\n";
}

PamProviderEntrySpec specA(std::uint64_t id, const std::string& value) {
    PamProviderEntrySpec spec;
    spec.provider = kProvider;
    spec.policy = kPolicyA;
    spec.managedKey = "deny";
    spec.value = value;
    spec.mutationId = id;
    return spec;
}

PamProviderEntrySpec specB(std::uint64_t id, const std::string& value) {
    PamProviderEntrySpec spec;
    spec.provider = kProvider;
    spec.policy = kPolicyB;
    spec.managedKey = "fail_interval";
    spec.value = value;
    spec.mutationId = id;
    return spec;
}

PamProviderOwnershipExpectation expectationA(std::uint64_t id,
                                             const std::string& body) {
    PamProviderOwnershipExpectation expectation;
    expectation.provider = kProvider;
    expectation.policy = kPolicyA;
    expectation.managedKey = "deny";
    expectation.body = body;
    expectation.mutationId = id;
    return expectation;
}

void runAllParsingTests() {
    // 1. absent block: foreign-only content parses, nothing present.
    {
        const auto parse = parsePamProviderManagedBlock("a = 1\n# c\n");
        require(parse.ok, "foreign-only parse failed");
        require(!parse.view.present, "absent block reported present");
        require(parse.view.effectivePlacement ==
                    PamProviderBlockPlacement::Absent,
                "absent placement mismatch");
        require(parse.view.satisfiesPlacement(
                    PamProviderBlockPlacementRequest::Beginning) &&
                    parse.view.satisfiesPlacement(
                        PamProviderBlockPlacementRequest::End),
                "absent container must satisfy any placement contract");
    }

    // 2. canonical BOF block (two entries, canonical order).
    const std::string bofBlock =
        renderBlock(renderEntry(kPolicyA, 42, "deny = 5") +
                    renderEntry(kPolicyB, 7, "fail_interval = 900"));
    {
        const auto parse =
            parsePamProviderManagedBlock(bofBlock + "a = 1\n");
        require(parse.ok, "BOF block parse failed");
        require(parse.view.present, "BOF block not present");
        require(parse.view.atBeginning && !parse.view.atEnd,
                "BOF placement flags wrong");
        require(parse.view.effectivePlacement ==
                    PamProviderBlockPlacement::AtBeginning,
                "BOF effective placement wrong");
        require(parse.view.provider == kProvider, "provider not proven");
        require(parse.view.entries.size() == 2, "entry count wrong");
        require(parse.view.entries[0].policy == kPolicyA &&
                    parse.view.entries[0].managedKey == "deny" &&
                    parse.view.entries[0].body == "deny = 5" &&
                    parse.view.entries[0].mutationId == 42,
                "entry A not proven");
        require(parse.view.entries[1].policy == kPolicyB &&
                    parse.view.entries[1].mutationId == 7,
                "entry B not proven");
        // Trailing whitespace after markers is tolerated (CR/LF and
        // trailing spaces/tabs only).
        const auto tolerant = parsePamProviderManagedBlock(
            pamProviderBlockBeginMarker(kProvider, false) + "   \r\n" +
            renderEntry(kPolicyA, 42, "deny = 5") +
            kPamProviderBlockEndMarker + "\t\r\n");
        require(tolerant.ok && tolerant.view.present,
                "marker trailing whitespace must be tolerated");
    }

    // 3. canonical EOF block.
    {
        const auto parse =
            parsePamProviderManagedBlock("a = 1\n" + bofBlock);
        require(parse.ok && parse.view.present, "EOF block parse failed");
        require(!parse.view.atBeginning && parse.view.atEnd,
                "EOF placement flags wrong");
        require(parse.view.effectivePlacement ==
                    PamProviderBlockPlacement::AtEnd,
                "EOF effective placement wrong");
    }

    // 4. valid but misplaced block stays parse-valid and OWNED.
    {
        const std::string content =
            "foreign A\n" + bofBlock + "foreign B\n";
        const auto parse = parsePamProviderManagedBlock(content);
        require(parse.ok && parse.view.present, "misplaced parse failed");
        require(!parse.view.atBeginning && !parse.view.atEnd,
                "misplaced placement flags wrong");
        require(parse.view.effectivePlacement ==
                    PamProviderBlockPlacement::Misplaced,
                "misplaced effective placement wrong");
        const auto proof = provePamProviderEntryOwnership(
            parse, expectationA(42, "deny = 5"));
        require(proof.proven &&
                    proof.proof == PamProviderEntryProof::Owned,
                "displacement must not break ownership proof");
    }
}

void runAllParsingNegativeTests() {
    const std::string singleEntryBlock =
        renderBlock(renderEntry(kPolicyA, 42, "deny = 5"));
    // 5. duplicate block fails.
    require(!parsePamProviderManagedBlock(singleEntryBlock + singleEntryBlock)
                 .ok,
            "duplicate block accepted");
    // 6. nested block fails.
    require(!parsePamProviderManagedBlock(
                renderBlock(renderEntry(kPolicyA, 42, "deny = 5") +
                            pamProviderBlockBeginMarker(kProvider, false) + "\n"))
                .ok,
            "nested block accepted");
    // 7. missing END fails.
    require(!parsePamProviderManagedBlock(
                pamProviderBlockBeginMarker(kProvider, false) + "\n" +
                renderEntry(kPolicyA, 42, "deny = 5"))
                .ok,
            "block without END accepted");
    // 8. END without BEGIN fails.
    require(!parsePamProviderManagedBlock(
                "a = 1\n" + std::string(kPamProviderBlockEndMarker) + "\n")
                .ok,
            "END without BEGIN accepted");
    // 9. malformed FIC-like BEGIN fails.
    require(!parsePamProviderManagedBlock(
                std::string("# FIC_PAM_PROVIDER_BLOCK_BEGIN version=1") +
                "\n")
                .ok,
            "BEGIN without provider accepted");
    require(!parsePamProviderManagedBlock(
                pamProviderBlockBeginMarker("pam faillock", false) + "\n")
                .ok,
            "provider token with space accepted");
    // 9b. STRUCTURAL lead contract: the BEGIN marker must declare the
    // separator boundary provenance; impossible declarations fail closed.
    require(!parsePamProviderManagedBlock(
                pamProviderBlockBeginMarker(kProvider, true) + "\n")
                .ok,
            "lead=newline without any preceding byte accepted");
    require(parsePamProviderManagedBlock(
                "a = 1\n" + pamProviderBlockBeginMarker(kProvider, true) +
                    "\n" + renderEntry(kPolicyA, 42, "deny = 5") +
                    kPamProviderBlockEndMarker + "\n")
                .ok,
            "lead=newline with a preceding LF must parse");
    require(!parsePamProviderManagedBlock(
                "a = 1" + pamProviderBlockBeginMarker(kProvider, true) +
                    "\n" + renderEntry(kPolicyA, 42, "deny = 5") +
                    kPamProviderBlockEndMarker + "\n")
                .ok,
            "lead=newline with a non-LF byte before BEGIN accepted");
    require(!parsePamProviderManagedBlock(
                std::string(kPamProviderBlockBeginMarkerPrefix) + kProvider +
                " lead=space\n")
                .ok,
            "unknown lead= value accepted");
    require(!parsePamProviderManagedBlock(
                std::string(kPamProviderBlockBeginMarkerPrefix) + kProvider +
                " lead=\n")
                .ok,
            "empty lead= value accepted");
    require(!parsePamProviderManagedBlock(
                std::string(
                    "# FIC_PAM_PROVIDER_BLOCK_BEGIN version=2 provider=") +
                kProvider + "\n")
                .ok,
            "unknown block version accepted");
    // 10. malformed FIC-like END fails.
    require(!parsePamProviderManagedBlock(
                singleEntryBlock + std::string(kPamProviderBlockEndMarker) +
                " junk\n")
                .ok,
            "END with trailing junk accepted");
    // 11. unknown FIC reserved marker is a conflict, not a comment.
    require(!parsePamProviderManagedBlock(
                "# FIC_PAM_FUTURE_MARKER something\n")
                .ok,
            "unknown reserved marker treated as ordinary comment");
    require(!parsePamProviderManagedBlock(
                " # FIC_PAM_PROVIDER_BLOCK_END\n")
                .ok,
            "indented reserved marker accepted");
    require(parsePamProviderManagedBlock(
                "# fic_pam_provider_block_end\n")
                .ok,
            "lowercase non-marker text must stay an ordinary foreign "
            "comment (the reserved namespace is case-sensitive, mirroring "
            "the GRUB managed block)");
    // 12. duplicate entry fails.
    require(!parsePamProviderManagedBlock(
                renderBlock(renderEntry(kPolicyA, 42, "deny = 5") +
                            renderEntry(kPolicyA, 43, "deny = 9")))
                .ok,
            "duplicate ownership tuple accepted");
    // 13. malformed entry BEGIN/END fails.
    require(!parsePamProviderManagedBlock(
                renderBlock(std::string(
                    kPamProviderEntryBeginMarkerPrefix) +
                    "failed_authentication_attempts\n" + "deny = 5\n" +
                    kPamProviderEntryEndMarker + "\n"))
                .ok,
            "entry BEGIN without mutation accepted");
    require(!parsePamProviderManagedBlock(
                renderBlock(std::string(
                    kPamProviderEntryBeginMarkerPrefix) +
                    "failed_authentication_attempts mutation=42 "
                    "extra=1\ndeny = 5\n" +
                    kPamProviderEntryEndMarker + "\n"))
                .ok,
            "entry BEGIN with extra field accepted");
    require(!parsePamProviderManagedBlock(
                renderBlock(std::string(
                    kPamProviderEntryBeginMarkerPrefix) +
                    "failed_authentication_attempts mutation=42\ndeny = 5\n" +
                    kPamProviderEntryEndMarker + " x\n"))
                .ok,
            "entry END with trailing junk accepted");
    // 14. invalid mutation ids fail.
    for (const char* id : {"0", "042", "-5", "abc", "42x",
                           "99999999999999999999999"}) {
        const std::string marker =
            std::string(kPamProviderEntryBeginMarkerPrefix) + kPolicyA +
            " mutation=" + id;
        require(!parsePamProviderManagedBlock(
                    renderBlock(marker + "\ndeny = 5\n" +
                                kPamProviderEntryEndMarker + "\n"))
                    .ok,
                std::string("invalid mutation id accepted: ") + id);
    }
    // 15. duplicate physical mutation id is ambiguity: fail closed.
    require(!parsePamProviderManagedBlock(
                renderBlock(renderEntry(kPolicyA, 42, "deny = 5") +
                            renderEntry(kPolicyB, 42,
                                        "fail_interval = 900")))
                .ok,
            "duplicate physical mutation id accepted");
    // 16. invalid policy/key metadata fails.
    require(!parsePamProviderManagedBlock(
                renderBlock(renderEntry("Failed_Auth", 42, "deny = 5")))
                .ok,
            "uppercase policy token accepted");
    require(!parsePamProviderManagedBlock(
                renderBlock(renderEntry(kPolicyA, 42, "deny x = 5")))
                .ok,
            "malformed body accepted");
    // 17. manually edited entry body breaks ownership proof.
    {
        const auto parse = parsePamProviderManagedBlock(
            renderBlock(renderEntry(kPolicyA, 42, "deny = 7")));
        require(parse.ok, "edited body parse failed");
        const auto proof = provePamProviderEntryOwnership(
            parse, expectationA(42, "deny = 5"));
        require(!proof.proven &&
                    proof.proof == PamProviderEntryProof::Drifted,
                "edited body must not prove ownership");
    }
}

void runAllBofTests() {
    // 18. empty file -> BOF block.
    {
        const auto mutation = setPamProviderManagedEntry(
            "", specA(42, "5"), PamProviderBlockPlacementRequest::Beginning);
        require(mutation.ok, "empty-file BOF mutation failed");
        require(mutation.content == renderBlock(renderEntry(kPolicyA, 42,
                                                            "deny = 5")),
                "empty-file BOF content wrong");
        const auto parse =
            parsePamProviderManagedBlock(mutation.content);
        require(parse.ok && parse.view.atBeginning,
                "empty-file block not at BOF");
    }

    // 19. foreign file -> block before foreign bytes, byte-exact.
    const std::string foreign = "a = 1\n# administrator comment\n";
    {
        const auto mutation = setPamProviderManagedEntry(
            foreign, specA(42, "5"),
            PamProviderBlockPlacementRequest::Beginning);
        require(mutation.ok, "foreign BOF mutation failed");
        require(mutation.content ==
                    renderBlock(renderEntry(kPolicyA, 42, "deny = 5")) +
                        foreign,
                "BOF block must precede foreign bytes");
    }

    // 20. add second entry.
    std::string content;
    {
        const auto first = setPamProviderManagedEntry(
            foreign, specA(42, "5"),
            PamProviderBlockPlacementRequest::Beginning);
        require(first.ok, "first BOF add failed");
        const auto second = setPamProviderManagedEntry(
            first.content, specB(7, "900"),
            PamProviderBlockPlacementRequest::Beginning);
        require(second.ok, "second BOF add failed");
        require(second.content ==
                    renderBlock(renderEntry(kPolicyA, 42, "deny = 5") +
                                renderEntry(kPolicyB, 7,
                                            "fail_interval = 900")) +
                        foreign,
                "second BOF entry content wrong");
        content = second.content;
    }

    // 21. update one entry while preserving the other entry provenance.
    {
        const std::string entryB = renderEntry(kPolicyB, 7,
                                               "fail_interval = 900");
        require(content.find(entryB) != std::string::npos,
                "entry B bytes missing before update");
        const auto update = setPamProviderManagedEntry(
            content, specA(42, "9"),
            PamProviderBlockPlacementRequest::Beginning);
        require(update.ok, "BOF update failed");
        require(update.content.find(entryB) != std::string::npos,
                "entry B provenance broken by entry A update");
        require(update.content.find("deny = 9") != std::string::npos,
                "entry A body not updated");
        require(update.content.substr(update.content.size() -
                                      foreign.size()) == foreign,
                "foreign bytes not byte-exact after update");
    }
}

void runAllBofTests2() {
    const std::string foreign = "a = 1\n# administrator comment\n";
    const std::string content =
        renderBlock(renderEntry(kPolicyA, 42, "deny = 5") +
                    renderEntry(kPolicyB, 7, "fail_interval = 900")) +
        foreign;

    // 22. remove one entry.
    {
        const auto removal = removePamProviderManagedEntry(
            content, expectationA(42, "deny = 5"),
            PamProviderBlockPlacementRequest::Beginning);
        require(removal.ok &&
                    removal.outcome ==
                        PamProviderRemovalResult::Outcome::Removed,
                "BOF entry removal failed");
        require(removal.content.find("deny") == std::string::npos,
                "removed entry still present");
        require(removal.content.find(renderEntry(kPolicyB, 7,
                                                 "fail_interval = 900")) !=
                    std::string::npos,
                "entry B lost after removing entry A");
        require(removal.content.substr(removal.content.size() -
                                       foreign.size()) == foreign,
                "foreign bytes not byte-exact after removal");
    }

    // 23. remove last entry -> whole block removed, foreign restored.
    {
        const auto removal = removePamProviderManagedEntry(
            renderBlock(renderEntry(kPolicyA, 42, "deny = 5")) + foreign,
            expectationA(42, "deny = 5"),
            PamProviderBlockPlacementRequest::Beginning);
        require(removal.ok &&
                    removal.outcome ==
                        PamProviderRemovalResult::Outcome::BlockRemoved,
                "last-entry removal outcome wrong");
        require(removal.content == foreign,
                "block removal did not restore foreign bytes byte-exact");
    }

    // 24. relocate a misplaced valid block back to BOF.
    {
        const std::string misplaced =
            "foreign A\n" +
            renderBlock(renderEntry(kPolicyA, 42, "deny = 5")) +
            "foreign B\n";
        const auto mutation = setPamProviderManagedEntry(
            misplaced, specA(42, "5"),
            PamProviderBlockPlacementRequest::Beginning);
        require(mutation.ok, "BOF relocation failed");
        const auto parse = parsePamProviderManagedBlock(mutation.content);
        require(parse.ok && parse.view.atBeginning,
                "relocated block not at BOF");
        require(mutation.content.size() >=
                    std::string("foreign A\nforeign B\n").size() &&
                mutation.content.substr(
                    mutation.content.size() -
                    std::string("foreign A\nforeign B\n").size()) ==
                    "foreign A\nforeign B\n",
                "relocation lost foreign bytes or their order");
    }

    // 25. aggregate byte-exactness: foreign survives add/update/remove.
    {
        const std::string pre = "max = 72\n  indented = 1\n";
        const auto add = setPamProviderManagedEntry(
            pre, specA(42, "5"), PamProviderBlockPlacementRequest::End);
        require(add.ok, "EOF add failed");
        const auto update = setPamProviderManagedEntry(
            add.content, specA(42, "6"),
            PamProviderBlockPlacementRequest::End);
        require(update.ok, "EOF update failed");
        const auto remove = removePamProviderManagedEntry(
            update.content, expectationA(42, "deny = 6"),
            PamProviderBlockPlacementRequest::End);
        require(remove.ok, "EOF remove failed");
        require(remove.content == pre,
                "pre-FIC foreign bytes not restored byte-exact");
    }
}

void runAllEofTests() {
    // 26. foreign file WITHOUT trailing newline -> EOF block.
    const std::string foreignNoNewline = "a = 1";
    const auto add = setPamProviderManagedEntry(
        foreignNoNewline, specA(42, "5"),
        PamProviderBlockPlacementRequest::End);
    require(add.ok, "EOF add (no trailing newline) failed");
    require(add.content ==
                foreignNoNewline + "\n" +
                    renderBlock(renderEntry(kPolicyA, 42, "deny = 5"), true),
            "EOF add must append exactly one FIC-owned separator newline");
    {
        const auto parse = parsePamProviderManagedBlock(add.content);
        require(parse.ok && parse.view.atEnd, "EOF block not at EOF");
    }

    // 27. remove final block restores exact no-trailing-newline content.
    {
        const auto removal = removePamProviderManagedEntry(
            add.content, expectationA(42, "deny = 5"),
            PamProviderBlockPlacementRequest::End);
        require(removal.ok &&
                    removal.outcome ==
                        PamProviderRemovalResult::Outcome::BlockRemoved,
                "EOF final removal outcome wrong");
        require(removal.content == foreignNoNewline,
                "removal did not restore the missing trailing newline "
                "byte-exact");
    }

    // 28. CRLF foreign content survives add/update/remove byte-exact.
    {
        const std::string crlf = "a = 1\r\n# comment\r\n";
        const auto addCrlf = setPamProviderManagedEntry(
            crlf, specA(42, "5"), PamProviderBlockPlacementRequest::End);
        require(addCrlf.ok, "CRLF EOF add failed");
        require(addCrlf.content.substr(0, crlf.size()) == crlf,
                "CRLF foreign bytes damaged by add");
        const auto update = setPamProviderManagedEntry(
            addCrlf.content, specA(42, "6"),
            PamProviderBlockPlacementRequest::End);
        require(update.ok, "CRLF EOF update failed");
        require(update.content.substr(0, crlf.size()) == crlf,
                "CRLF foreign bytes damaged by update");
        const auto removal = removePamProviderManagedEntry(
            update.content, expectationA(42, "deny = 6"),
            PamProviderBlockPlacementRequest::End);
        require(removal.ok, "CRLF EOF removal failed");
        require(removal.content == crlf,
                "CRLF foreign bytes not restored byte-exact");
    }

    // 29. foreign content appended after a FIC EOF block -> the block
    // stays parse-valid and OWNED but no longer satisfies the EOF
    // contract; foreign content on BOTH sides is Misplaced.
    {
        const std::string appended =
            renderBlock(renderEntry(kPolicyA, 42, "deny = 5")) +
            "extra = 1\n";
        const auto parse = parsePamProviderManagedBlock(appended);
        require(parse.ok && parse.view.present,
                "appended-tail block must stay parse-valid");
        require(!parse.view.atEnd,
                "block with foreign tail must not be classified AtEnd");
        require(!parse.view.satisfiesPlacement(
                    PamProviderBlockPlacementRequest::End),
                "appended tail must break the EOF placement contract");
        const auto proof = provePamProviderEntryOwnership(
            parse, expectationA(42, "deny = 5"));
        require(proof.proven, "misplaced block lost ownership proof");
        // Foreign bytes on both sides: neither BOF nor EOF -> Misplaced.
        const auto both = parsePamProviderManagedBlock(
            "before\n" + appended);
        require(both.ok && both.view.present &&
                    both.view.effectivePlacement ==
                        PamProviderBlockPlacement::Misplaced,
                "two-sided foreign tail must be Misplaced");
    }

    // 30. relocation to EOF preserves the appended foreign bytes exactly.
    {
        const std::string appended =
            "before\n" +
            renderBlock(renderEntry(kPolicyA, 42, "deny = 5")) +
            "extra = 1\n";
        const auto mutation = setPamProviderManagedEntry(
            appended, specA(42, "5"),
            PamProviderBlockPlacementRequest::End);
        require(mutation.ok, "EOF relocation failed");
        // assembleAtEnd always adds exactly ONE FIC-owned separator
        // newline; the appended foreign bytes keep their exact order.
        require(mutation.content ==
                    "before\nextra = 1\n" + std::string("\n") +
                        renderBlock(renderEntry(kPolicyA, 42, "deny = 5"),
                                    true),
                "EOF relocation must keep foreign bytes in order");
        const auto parse = parsePamProviderManagedBlock(mutation.content);
        require(parse.ok && parse.view.atEnd,
                "relocated block not at EOF");
        const auto removal = removePamProviderManagedEntry(
            mutation.content, expectationA(42, "deny = 5"),
            PamProviderBlockPlacementRequest::End);
        require(removal.ok && removal.content == "before\nextra = 1\n",
                "EOF relocation removal did not restore foreign bytes");
    }
}

void runAllSeparatorBoundaryTests() {
    // 29b. EXACT displacement round-trip: foreign -> FIC EOF block ->
    // append foreign X -> relocate -> remove == foreign + X, byte-exact by
    // CONSTRUCTION (structural lead ownership), no heuristics.
    {
        const std::string foreign = "a = 1\n# c\n";
        const std::string appended = "extra = 1\n";
        const auto add = setPamProviderManagedEntry(
            foreign, specA(42, "5"), PamProviderBlockPlacementRequest::End);
        require(add.ok, "round-trip add failed");
        const auto afterAppend = add.content + appended;
        const auto relocate = setPamProviderManagedEntry(
            afterAppend, specA(42, "5"),
            PamProviderBlockPlacementRequest::End);
        require(relocate.ok, "round-trip relocation failed");
        require(relocate.content ==
                    foreign + appended + "\n" +
                        renderBlock(renderEntry(kPolicyA, 42, "deny = 5"),
                                    true),
                "relocation must restore foreign+X exactly, in order");
        const auto removal = removePamProviderManagedEntry(
            relocate.content, expectationA(42, "deny = 5"),
            PamProviderBlockPlacementRequest::End);
        require(removal.ok &&
                    removal.outcome ==
                        PamProviderRemovalResult::Outcome::BlockRemoved,
                "round-trip removal outcome wrong");
        require(removal.content == foreign + appended,
                "displacement round-trip must restore foreign+X byte-exact");
    }
    // 29c. Same round-trip with foreign bytes WITHOUT a trailing newline:
    // the FIC-owned separator LF must be reconstructed exactly once and
    // stripped exactly once.
    {
        const std::string foreign = "a = 1";
        const auto add = setPamProviderManagedEntry(
            foreign, specA(42, "5"), PamProviderBlockPlacementRequest::End);
        require(add.ok &&
                    add.content ==
                        foreign + "\n" +
                            renderBlock(renderEntry(kPolicyA, 42, "deny = 5"),
                                        true),
                "EOF add must own exactly one separator LF (lead=newline)");
        const auto displaced = add.content + "extra = 1";
        const auto relocate = setPamProviderManagedEntry(
            displaced, specA(42, "5"), PamProviderBlockPlacementRequest::End);
        require(relocate.ok, "no-trailing-newline relocation failed");
        const auto removal = removePamProviderManagedEntry(
            relocate.content, expectationA(42, "deny = 5"),
            PamProviderBlockPlacementRequest::End);
        require(removal.ok && removal.content == foreign + "extra = 1",
                "no-trailing-newline foreign bytes must survive byte-exact");
    }
    // 29d. BOF block followed by an appended foreign tail: relocation to
    // BOF keeps the tail byte-exact.
    {
        const std::string foreign = "a = 1\n";
        const auto add = setPamProviderManagedEntry(
            foreign, specA(42, "5"),
            PamProviderBlockPlacementRequest::Beginning);
        require(add.ok, "BOF round-trip add failed");
        const auto displaced = add.content + "extra = 1\n";
        const auto relocate = setPamProviderManagedEntry(
            displaced, specA(42, "5"),
            PamProviderBlockPlacementRequest::Beginning);
        require(relocate.ok, "BOF relocation failed");
        const auto removal = removePamProviderManagedEntry(
            relocate.content, expectationA(42, "deny = 5"),
            PamProviderBlockPlacementRequest::Beginning);
        require(removal.ok &&
                    removal.content == foreign + "extra = 1\n",
                "BOF displacement round-trip must restore foreign+X "
                "byte-exact");
    }
    // 29e. CRLF displacement round-trip.
    {
        const std::string foreign = "a = 1\r\n# c\r\n";
        const auto add = setPamProviderManagedEntry(
            foreign, specA(42, "5"), PamProviderBlockPlacementRequest::End);
        require(add.ok, "CRLF round-trip add failed");
        const auto displaced = add.content + "extra = 1\r\n";
        const auto relocate = setPamProviderManagedEntry(
            displaced, specA(42, "5"), PamProviderBlockPlacementRequest::End);
        require(relocate.ok, "CRLF relocation failed");
        require(relocate.content.substr(0, foreign.size()) == foreign &&
                    relocate.content.find("extra = 1\r\n") ==
                        foreign.size(),
                "CRLF foreign bytes damaged by relocation");
        const auto removal = removePamProviderManagedEntry(
            relocate.content, expectationA(42, "deny = 5"),
            PamProviderBlockPlacementRequest::End);
        require(removal.ok &&
                    removal.content == foreign + "extra = 1\r\n",
                "CRLF displacement round-trip must restore foreign+X "
                "byte-exact");
    }
}

void runAllOwnershipTests() {
    const std::string content =
        renderBlock(renderEntry(kPolicyA, 42, "deny = 5"));

    // 31. journal id == physical id -> exact ownership.
    {
        const auto parse = parsePamProviderManagedBlock(content);
        const auto proof =
            provePamProviderEntryOwnership(parse, expectationA(42, "deny = 5"));
        require(proof.proven && proof.proof == PamProviderEntryProof::Owned,
                "exact physical id must prove ownership");
    }

    // 32. same key/value but different physical mutation id -> NOT owned.
    {
        const auto lookalike =
            renderBlock(renderEntry(kPolicyA, 99, "deny = 5"));
        const auto parse = parsePamProviderManagedBlock(lookalike);
        const auto proof =
            provePamProviderEntryOwnership(parse, expectationA(42, "deny = 5"));
        require(!proof.proven &&
                    proof.proof == PamProviderEntryProof::Lookalike,
                "lookalike id must not prove ownership");
        const auto removal = removePamProviderManagedEntry(
            lookalike, expectationA(42, "deny = 5"),
            PamProviderBlockPlacementRequest::End);
        require(!removal.ok && !removal.error.empty(),
                "lookalike removal must be refused");
        require(removal.content.empty(),
                "refused removal must not produce content");
    }

    // 33. same mutation id but different policy -> NOT owned by A.
    {
        const auto contentB =
            renderBlock(renderEntry(kPolicyB, 42, "fail_interval = 900"));
        const auto parse = parsePamProviderManagedBlock(contentB);
        const auto proof =
            provePamProviderEntryOwnership(parse, expectationA(42, "deny = 5"));
        require(!proof.proven && proof.proof == PamProviderEntryProof::Absent,
                "foreign policy entry must not prove A ownership");
    }

    // 34. same mutation id/policy but edited value -> conflict.
    {
        const auto drifted =
            renderBlock(renderEntry(kPolicyA, 42, "deny = 7"));
        const auto parse = parsePamProviderManagedBlock(drifted);
        const auto proof =
            provePamProviderEntryOwnership(parse, expectationA(42, "deny = 5"));
        require(!proof.proven && proof.proof == PamProviderEntryProof::Drifted,
                "drifted body must be a typed conflict");
        const auto removal = removePamProviderManagedEntry(
            drifted, expectationA(42, "deny = 5"),
            PamProviderBlockPlacementRequest::End);
        require(!removal.ok, "drifted entry removal must be refused");
    }

    // 35. delete + externally recreate lookalike: stale journal must not
    // authorize removal of foreign content.
    {
        // (a) plain foreign directive without any FIC marker.
        const std::string plain = "deny = 5\n";
        const auto removal = removePamProviderManagedEntry(
            plain, expectationA(42, "deny = 5"),
            PamProviderBlockPlacementRequest::End);
        require(removal.ok &&
                    removal.outcome ==
                        PamProviderRemovalResult::Outcome::AlreadyAbsent,
                "plain lookalike must be AlreadyAbsent");
        require(removal.content == plain,
                "foreign lookalike directive must stay untouched");
        // (b) FIC-looking entry with a WRONG physical mutation id.
        const std::string wrongId =
            renderBlock(renderEntry(kPolicyA, 77, "deny = 5"));
        const auto refused = removePamProviderManagedEntry(
            wrongId, expectationA(42, "deny = 5"),
            PamProviderBlockPlacementRequest::End);
        require(!refused.ok, "wrong-id lookalike removal must be refused");
        // (c) setPamProviderManagedEntry must not silently adopt a
        // different physical mutation id either.
        const auto update = setPamProviderManagedEntry(
            wrongId, specA(42, "6"), PamProviderBlockPlacementRequest::End);
        require(!update.ok,
                "set must refuse an entry owned by another mutation id");
    }

    // Mutation guards: zero mutation id and injection-safe value checks.
    {
        const auto zeroId = setPamProviderManagedEntry(
            "", specA(0, "5"), PamProviderBlockPlacementRequest::End);
        require(!zeroId.ok, "zero mutation id accepted");
        auto comment = specA(42, "5 # comment");
        const auto commentValue = setPamProviderManagedEntry(
            "", comment, PamProviderBlockPlacementRequest::End);
        require(!commentValue.ok, "value with '#' accepted");
        auto padded = specA(42, " 5");
        const auto paddedValue = setPamProviderManagedEntry(
            "", padded, PamProviderBlockPlacementRequest::End);
        require(!paddedValue.ok, "padded value accepted");
        auto empty = specA(42, "");
        const auto emptyValue = setPamProviderManagedEntry(
            "", empty, PamProviderBlockPlacementRequest::End);
        require(!emptyValue.ok, "empty value accepted");
    }

    // Refresh semantics: same journal id, new body (the journal refreshes
    // the SAME record id on repeated apply) is a legal in-place update.
    {
        const auto refresh = setPamProviderManagedEntry(
            content, specA(42, "9"), PamProviderBlockPlacementRequest::End);
        require(refresh.ok &&
                    refresh.content.find("deny = 9") != std::string::npos,
                "same-id body refresh must be a legal update");
    }
}

void runAllMultiPolicyTests() {
    const std::string foreign = "a = 1\n";

    // 36. A + B coexist in one physical block.
    std::string content;
    {
        const auto a = setPamProviderManagedEntry(
            foreign, specA(42, "5"), PamProviderBlockPlacementRequest::End);
        require(a.ok, "A add failed");
        const auto b = setPamProviderManagedEntry(
            a.content, specB(7, "900"), PamProviderBlockPlacementRequest::End);
        require(b.ok, "B add failed");
        require(b.content.find("deny = 5") != std::string::npos &&
                    b.content.find("fail_interval = 900") !=
                        std::string::npos,
                "A and B must coexist");
        require(b.content.substr(0, foreign.size()) == foreign,
                "foreign bytes damaged by multi-policy add");
        content = b.content;
    }

    // 37. update A leaves B byte- and provenance-identical.
    {
        const std::string entryB =
            renderEntry(kPolicyB, 7, "fail_interval = 900");
        const auto update = setPamProviderManagedEntry(
            content, specA(42, "9"), PamProviderBlockPlacementRequest::End);
        require(update.ok, "A update failed");
        require(update.content.find(entryB) != std::string::npos,
                "B entry bytes must survive the A update");
    }

    // 38. remove A leaves B.
    {
        const auto removal = removePamProviderManagedEntry(
            content, expectationA(42, "deny = 5"),
            PamProviderBlockPlacementRequest::End);
        require(removal.ok, "A removal failed");
        require(removal.content.find(renderEntry(kPolicyB, 7,
                                                 "fail_interval = 900")) !=
                    std::string::npos,
                "B must survive the A removal");
        require(removal.content.substr(0, foreign.size()) == foreign,
                "foreign bytes damaged by the A removal");

        // 39. removing B (the last FIC entry) removes the block.
        const PamProviderOwnershipExpectation expectationB{
            kProvider, kPolicyB, "fail_interval", "fail_interval = 900", "",
            7};
        const auto removalB = removePamProviderManagedEntry(
            removal.content, expectationB,
            PamProviderBlockPlacementRequest::End);
        require(removalB.ok &&
                    removalB.outcome ==
                        PamProviderRemovalResult::Outcome::BlockRemoved,
                "last-entry removal must remove the block");
        require(removalB.content == foreign,
                "final removal must restore foreign bytes exactly");
    }

    // 40. canonical order independent of the apply order.
    {
        auto a = setPamProviderManagedEntry(
            foreign, specA(42, "5"), PamProviderBlockPlacementRequest::End);
        require(a.ok, "order A add failed");
        auto b = setPamProviderManagedEntry(
            a.content, specB(7, "900"), PamProviderBlockPlacementRequest::End);
        require(b.ok, "order B add failed");
        auto bFirst = setPamProviderManagedEntry(
            foreign, specB(7, "900"), PamProviderBlockPlacementRequest::End);
        require(bFirst.ok, "reverse B add failed");
        auto aSecond = setPamProviderManagedEntry(
            bFirst.content, specA(42, "5"),
            PamProviderBlockPlacementRequest::End);
        require(aSecond.ok, "reverse A add failed");
        require(b.content == aSecond.content,
                "entry order must not depend on the apply order");
    }
}

void runAllJournalBindingTests() {
    const std::string owned =
        renderBlock(renderEntry(kPolicyA, 42, "deny = 5"));
    const std::string foreignOnly = "a = 1\n";
    const auto ownedParse = parsePamProviderManagedBlock(owned);
    const auto foreignParse = parsePamProviderManagedBlock(foreignOnly);

    // 41. Prepared + fresh + no physical entry: mutation not happened yet.
    {
        const auto binding = classifyPamProviderJournalBinding(
            PamProviderJournalMutationStatus::Prepared, foreignParse,
            expectationA(42, "deny = 5"));
        require(binding.ok &&
                    binding.state ==
                        PamProviderJournalBindingState::PreparedFreshAbsent,
                "fresh absent state misclassified");
    }
    // 42. Prepared + exact target body (fresh): crash after the physical
    // write, before journal completion — adopt.
    {
        const auto binding = classifyPamProviderJournalBinding(
            PamProviderJournalMutationStatus::Prepared, ownedParse,
            expectationA(42, "deny = 5"));
        require(binding.ok &&
                    binding.state ==
                        PamProviderJournalBindingState::
                            PreparedFreshTargetPresent,
                "fresh target-present state misclassified");
    }
    // 43. Prepared + update + exact previous body: continue the transition.
    {
        PamProviderOwnershipExpectation update = expectationA(42, "deny = 9");
        update.previousBody = "deny = 5";
        const auto binding = classifyPamProviderJournalBinding(
            PamProviderJournalMutationStatus::Prepared, ownedParse, update);
        require(binding.ok &&
                    binding.state ==
                        PamProviderJournalBindingState::
                            PreparedUpdatePreviousPresent,
                "update previous-present state misclassified");
    }
    // 44. Prepared + update + exact target body: complete as Applied.
    {
        PamProviderOwnershipExpectation update = expectationA(42, "deny = 9");
        update.previousBody = "deny = 5";
        const auto targetParse = parsePamProviderManagedBlock(
            renderBlock(renderEntry(kPolicyA, 42, "deny = 9")));
        const auto binding = classifyPamProviderJournalBinding(
            PamProviderJournalMutationStatus::Prepared, targetParse, update);
        require(binding.ok &&
                    binding.state ==
                        PamProviderJournalBindingState::
                            PreparedUpdateTargetPresent,
                "update target-present state misclassified");
    }
    // 45. Prepared + update + neither previous nor target: fail closed.
    {
        PamProviderOwnershipExpectation update = expectationA(42, "deny = 9");
        update.previousBody = "deny = 5";
        const auto binding = classifyPamProviderJournalBinding(
            PamProviderJournalMutationStatus::Prepared, foreignParse, update);
        require(binding.ok &&
                    binding.state ==
                        PamProviderJournalBindingState::PreparedConflict,
                "update absent state must be a conflict");
    }
    // 46. Prepared + wrong physical id: fail closed.
    {
        const auto driftedParse = parsePamProviderManagedBlock(
            renderBlock(renderEntry(kPolicyA, 99, "deny = 5")));
        const auto binding = classifyPamProviderJournalBinding(
            PamProviderJournalMutationStatus::Prepared, driftedParse,
            expectationA(42, "deny = 5"));
        require(binding.ok &&
                    binding.state ==
                        PamProviderJournalBindingState::PreparedConflict,
                "lookalike id must be a Prepared conflict");
    }
    // 47. Applied + exact target body.
    {
        const auto binding = classifyPamProviderJournalBinding(
            PamProviderJournalMutationStatus::Applied, ownedParse,
            expectationA(42, "deny = 5"));
        require(binding.ok &&
                    binding.state ==
                        PamProviderJournalBindingState::AppliedExact,
                "state D misclassified");
    }
    // 48. Applied + missing entry.
    {
        const auto binding = classifyPamProviderJournalBinding(
            PamProviderJournalMutationStatus::Applied, foreignParse,
            expectationA(42, "deny = 5"));
        require(binding.ok &&
                    binding.state ==
                        PamProviderJournalBindingState::AppliedMissing,
                "state E misclassified");
    }
    // 49. Applied + drifted body.
    {
        const auto driftedParse = parsePamProviderManagedBlock(
            renderBlock(renderEntry(kPolicyA, 42, "deny = 7")));
        const auto binding = classifyPamProviderJournalBinding(
            PamProviderJournalMutationStatus::Applied, driftedParse,
            expectationA(42, "deny = 5"));
        require(binding.ok &&
                    binding.state ==
                        PamProviderJournalBindingState::AppliedDrifted,
                "state F misclassified");
    }
    // Malformed physical state fails the classification entirely.
    {
        const auto binding = classifyPamProviderJournalBinding(
            PamProviderJournalMutationStatus::Applied,
            parsePamProviderManagedBlock("# FIC_PAM_WEIRD\n"),
            expectationA(42, "deny = 5"));
        require(!binding.ok && !binding.error.empty(),
                "malformed state must fail the classification");
    }
    // Provider mismatch is a typed conflict in both lifecycles.
    {
        PamProviderOwnershipExpectation otherProvider =
            expectationA(42, "deny = 5");
        otherProvider.provider = "pam_pwquality";
        const auto binding = classifyPamProviderJournalBinding(
            PamProviderJournalMutationStatus::Applied, ownedParse,
            otherProvider);
        require(binding.ok &&
                    binding.state ==
                        PamProviderJournalBindingState::AppliedDrifted,
                "foreign provider must be a conflict");
    }
    // An invalid expectation (previous body of another managed key) is
    // refused outright: EXACT key match, never a prefix compare.
    {
        PamProviderOwnershipExpectation badPrevious =
            expectationA(42, "deny = 5");
        badPrevious.previousBody = "deny_extra = 5";
        const auto binding = classifyPamProviderJournalBinding(
            PamProviderJournalMutationStatus::Prepared, foreignParse,
            badPrevious);
        require(!binding.ok,
                "previous body of another key must fail validation");
    }
}








} // namespace

int main() {
    try {
        runAllParsingTests();
        runAllParsingNegativeTests();
        runAllBofTests();
        runAllBofTests2();
        runAllEofTests();
        runAllSeparatorBoundaryTests();
        runAllOwnershipTests();
        runAllMultiPolicyTests();
        runAllJournalBindingTests();
    } catch (const std::exception& error) {
        std::cerr << "PamProviderManagedBlockTests failed: " << error.what()
                  << '\n';
        return 1;
    }
    std::cout << "PamProviderManagedBlockTests passed\n";
    return 0;
}
