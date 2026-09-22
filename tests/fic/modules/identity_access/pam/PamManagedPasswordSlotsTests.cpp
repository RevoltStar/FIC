#include "modules/identity_access/pam/PamManagedPasswordSlots.h"

#include <cstdint>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

using fic::identity::pam::ManagedHistoryPairInspection;
using fic::identity::pam::ManagedHistoryPairState;
using fic::identity::pam::ManagedPasswordCapability;
using fic::identity::pam::ManagedPasswordSlotInspection;
using fic::identity::pam::ManagedPasswordSlotRole;
using fic::identity::pam::ManagedPasswordSlotSpec;
using fic::identity::pam::ManagedPasswordSlotState;
using fic::identity::pam::ManagedPwhistorySlotOptions;
using fic::identity::pam::PamManagedPasswordSlots;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

const ManagedPasswordSlotSpec& qualitySpec() {
    return PamManagedPasswordSlots::qualitySlot();
}

const ManagedPasswordSlotSpec& normalSpec() {
    return PamManagedPasswordSlots::historyNormalSlot();
}

const ManagedPasswordSlotSpec& initialSpec() {
    return PamManagedPasswordSlots::historyInitialSlot();
}

ManagedPasswordSlotInspection inspect(
    const ManagedPasswordSlotSpec& spec,
    const std::optional<std::string>& content) {
    ManagedPasswordSlotInspection inspection;
    std::string error;
    PamManagedPasswordSlots::inspectContent(spec, content, inspection, error);
    return inspection;
}

// inspect() must fail (return false) with the expected state.
ManagedPasswordSlotInspection expectState(
    const ManagedPasswordSlotSpec& spec,
    const std::optional<std::string>& content,
    ManagedPasswordSlotState expected) {
    ManagedPasswordSlotInspection inspection;
    std::string error;
    const bool ok = PamManagedPasswordSlots::inspectContent(
        spec, content, inspection, error);
    if (expected == ManagedPasswordSlotState::Neutral ||
        expected == ManagedPasswordSlotState::Active) {
        require(ok, "inspect should succeed for " + std::string(spec.fileName));
    } else {
        require(!ok, "inspect should fail for " + std::string(spec.fileName));
    }
    require(inspection.state == expected,
        std::string(spec.fileName) + ": unexpected state " + error);
    return inspection;
}

std::string neutral() {
    return PamManagedPasswordSlots::neutralBody();
}

std::string activeNormal(
    std::uint64_t id,
    const ManagedPwhistorySlotOptions& options = {}) {
    return PamManagedPasswordSlots::renderActiveHistoryNormal(id, options);
}

std::string activeInitial(
    std::uint64_t id,
    const ManagedPwhistorySlotOptions& options = {}) {
    return PamManagedPasswordSlots::renderActiveHistoryInitial(id, options);
}

void testSpecsAndNeutralBytes() {
    const auto& slots = PamManagedPasswordSlots::slots();
    require(slots.size() == 3, "three managed password slots are expected");
    require(slots[0].fileName == std::string("fic-password-quality"),
        "quality slot file name");
    require(slots[1].fileName == std::string("fic-password-history"),
        "history normal slot file name");
    require(slots[2].fileName == std::string("fic-password-history-initial"),
        "history initial slot file name");
    require(slots[0].capability == ManagedPasswordCapability::PasswordQuality,
        "quality slot capability");
    require(slots[1].capability == ManagedPasswordCapability::PasswordHistory &&
        slots[2].capability == ManagedPasswordCapability::PasswordHistory,
        "history slots capability");
    require(PamManagedPasswordSlots::capabilityName(
                ManagedPasswordCapability::PasswordQuality) ==
            "enable_password_quality",
        "quality capability name");
    require(PamManagedPasswordSlots::capabilityName(
                ManagedPasswordCapability::PasswordHistory) ==
            "enable_password_history",
        "history capability name");
    require(PamManagedPasswordSlots::slotName(
                ManagedPasswordSlotRole::HistoryInitial) == "history-initial",
        "typed slot name");
    require(PamManagedPasswordSlots::slotFilePath(qualitySpec()) ==
            "/etc/pam.d/fic-password-quality",
        "default slot path");
    require(PamManagedPasswordSlots::neutralBody() ==
            "# FIC managed password slot: state=neutral\n",
        "exact canonical neutral bytes");
    require(PamManagedPasswordSlots::renderNeutral(initialSpec()) == neutral(),
        "neutral rendering is identical for all slots");
}

void testNeutralStates() {
    for (const auto& spec : PamManagedPasswordSlots::slots()) {
        // Exact canonical neutral bytes.
        expectState(spec, neutral(), ManagedPasswordSlotState::Neutral);
        // Missing input is NEVER Neutral (security regression from r3).
        const auto missing = expectState(
            spec, std::nullopt, ManagedPasswordSlotState::Unavailable);
        require(missing.mutationId == 0 && !missing.pwhistoryOptions.has_value(),
            "missing slot carries no active fields");
        // Degenerate bodies are Broken, even when operationally no-op.
        expectState(spec, std::string(""), ManagedPasswordSlotState::Broken);
        expectState(
            spec, std::string("\n"), ManagedPasswordSlotState::Broken);
        // Neutral without the canonical trailing newline.
        expectState(
            spec,
            std::string("# FIC managed password slot: state=neutral"),
            ManagedPasswordSlotState::Broken);
        // Extra whitespace / extra lines / extra comments.
        expectState(
            spec, neutral() + "\n", ManagedPasswordSlotState::Broken);
        expectState(
            spec, " # FIC managed password slot: state=neutral\n",
            ManagedPasswordSlotState::Broken);
        expectState(
            spec, "# FIC managed password slot: state=neutral \n",
            ManagedPasswordSlotState::Broken);
        expectState(
            spec,
            neutral() + "# FIC managed password slot: state=neutral\n",
            ManagedPasswordSlotState::Broken);
        // Any PAM rule disqualifies neutral state.
        expectState(
            spec, neutral() + "password required pam_deny.so\n",
            ManagedPasswordSlotState::Broken);
        expectState(
            spec,
            std::string("password required pam_deny.so\n"),
            ManagedPasswordSlotState::Broken);
        expectState(
            spec,
            std::string("password optional pam_permit.so\n"),
            ManagedPasswordSlotState::Broken);
    }
}

std::string replaceAll(
    std::string text,
    const std::string& from,
    const std::string& to) {
    std::size_t position = 0;
    while ((position = text.find(from, position)) != std::string::npos) {
        text.replace(position, from.size(), to);
        position += to.size();
    }
    return text;
}

std::string beginMarker(const ManagedPasswordSlotSpec& spec, int id = 1) {
    return "#@FIC_PAM_SLOT_BEGIN version=1 capability=" +
        PamManagedPasswordSlots::capabilityName(spec.capability) +
        " mutation=" + std::to_string(id) + " slot=" + spec.fileName + "\n";
}

std::string endMarker(const ManagedPasswordSlotSpec& spec, int id = 1) {
    return "#@FIC_PAM_SLOT_END capability=" +
        PamManagedPasswordSlots::capabilityName(spec.capability) +
        " mutation=" + std::to_string(id) + " slot=" + spec.fileName + "\n";
}

void testActiveMarkers() {
    // Canonical renders parse as Active for every role.
    const auto quality = expectState(
        qualitySpec(),
        PamManagedPasswordSlots::renderActiveQuality(1),
        ManagedPasswordSlotState::Active);
    require(quality.mutationId == 1, "quality mutation id");
    require(quality.observedRole == ManagedPasswordSlotRole::Quality,
        "quality observed role");
    require(!quality.pwhistoryOptions.has_value(),
        "quality slot has no pwhistory options");
    require(PamManagedPasswordSlots::renderActiveQuality(1) ==
        PamManagedPasswordSlots::renderActive(qualitySpec(), 1, {}),
        "quality generic render equals specialized render");

    const auto normal = expectState(
        normalSpec(), activeNormal(1), ManagedPasswordSlotState::Active);
    require(normal.mutationId == 1, "normal mutation id");
    require(normal.observedRole == ManagedPasswordSlotRole::HistoryNormal,
        "normal observed role");
    require(normal.pwhistoryOptions.has_value() &&
        *normal.pwhistoryOptions == ManagedPwhistorySlotOptions{},
        "normal empty options");

    const auto initial = expectState(
        initialSpec(), activeInitial(1), ManagedPasswordSlotState::Active);
    require(initial.mutationId == 1, "initial mutation id");
    require(initial.observedRole == ManagedPasswordSlotRole::HistoryInitial,
        "initial observed role");
    require(initial.pwhistoryOptions.has_value() &&
        *initial.pwhistoryOptions == ManagedPwhistorySlotOptions{},
        "initial empty options");

    // Large but valid mutation id (uint64 max).
    expectState(
        normalSpec(), activeNormal(18446744073709551615ULL),
        ManagedPasswordSlotState::Active);
    expectState(
        qualitySpec(),
        PamManagedPasswordSlots::renderActiveQuality(18446744073709551615ULL),
        ManagedPasswordSlotState::Active);

    // Mutation id failures (task section 30).
    for (const auto& spec : PamManagedPasswordSlots::slots()) {
        expectState(
            spec,
            PamManagedPasswordSlots::renderActive(spec, 0, {}),
            ManagedPasswordSlotState::Broken);
        expectState(
            spec,
            replaceAll(
                PamManagedPasswordSlots::renderActive(spec, 1, {}),
                "mutation=1", "mutation=-5"),
            ManagedPasswordSlotState::Broken);
        expectState(
            spec,
            replaceAll(
                PamManagedPasswordSlots::renderActive(spec, 1, {}),
                "mutation=1", "mutation=abc"),
            ManagedPasswordSlotState::Broken);
        expectState(
            spec,
            replaceAll(
                PamManagedPasswordSlots::renderActive(spec, 1, {}),
                "mutation=1", "mutation=99999999999999999999999"),
            ManagedPasswordSlotState::Broken);
        expectState(
            spec,
            replaceAll(
                PamManagedPasswordSlots::renderActive(spec, 12, {}),
                "mutation=12", "mutation=12x"),
            ManagedPasswordSlotState::Broken);
        expectState(
            spec,
            replaceAll(
                PamManagedPasswordSlots::renderActive(spec, 1, {}),
                "version=1", "version=2"),
            ManagedPasswordSlotState::Broken);
        // Wrong slot name in the markers.
        expectState(
            spec,
            replaceAll(
                PamManagedPasswordSlots::renderActive(spec, 1, {}),
                "slot=" + std::string(spec.fileName), "slot=fic-faillock-x"),
            ManagedPasswordSlotState::Broken);
        // Wrong capability in the markers.
        expectState(
            spec,
            replaceAll(
                PamManagedPasswordSlots::renderActive(spec, 1, {}),
                "capability=" +
                    PamManagedPasswordSlots::capabilityName(spec.capability),
                "capability=enable_authentication_lockout"),
            ManagedPasswordSlotState::Broken);
    }
}

void testActiveMarkerStructure() {
    // Missing BEGIN / missing END.
    for (const auto& spec : PamManagedPasswordSlots::slots()) {
        const std::string full =
            PamManagedPasswordSlots::renderActive(spec, 1, {});
        expectState(
            spec,
            full.substr(full.find('\n') + 1),
            ManagedPasswordSlotState::Broken);
        expectState(
            spec,
            full.substr(0, full.rfind('\n', full.size() - 2) + 1),
            ManagedPasswordSlotState::Broken);
        // Duplicate BEGIN / duplicate END.
        expectState(
            spec, beginMarker(spec) + full, ManagedPasswordSlotState::Broken);
        expectState(
            spec, full + endMarker(spec), ManagedPasswordSlotState::Broken);
        // BEGIN/END field mismatches.
        expectState(
            spec,
            beginMarker(spec) + full.substr(full.find('\n') + 1) +
                endMarker(spec, 2),
            ManagedPasswordSlotState::Broken);
        // Wrong END slot.
        expectState(
            spec,
            beginMarker(spec) + full.substr(
                full.find('\n') + 1,
                full.rfind('\n', full.size() - 2) - full.find('\n')) +
                replaceAll(
                    endMarker(spec),
                    "slot=" + std::string(spec.fileName),
                    "slot=fic-other"),
            ManagedPasswordSlotState::Broken);
        // Extra prefix / suffix lines and an extra PAM rule.
        expectState(
            spec, "# comment\n" + full, ManagedPasswordSlotState::Broken);
        expectState(spec, full + "# tail\n", ManagedPasswordSlotState::Broken);
        expectState(
            spec,
            beginMarker(spec) + "password requisite pam_permit.so\n" +
                "password requisite pam_permit.so\n" + endMarker(spec),
            ManagedPasswordSlotState::Broken);
        // Non-canonical separators (double spaces) in the marker line.
        expectState(
            spec,
            replaceAll(full, "version=1 capability=", "version=1  capability="),
            ManagedPasswordSlotState::Broken);
        // No trailing newline.
        expectState(spec, full.substr(0, full.size() - 1),
            ManagedPasswordSlotState::Broken);
        // CRLF line ending is not canonical bytes.
        expectState(
            spec, replaceAll(full, "\n", "\r\n"),
            ManagedPasswordSlotState::Broken);
    }
}

void testQualityBody() {
    const std::string prefix = beginMarker(qualitySpec());
    const std::string suffix = endMarker(qualitySpec());
    const auto body = [&](const std::string& rule) {
        expectState(
            qualitySpec(), prefix + rule + "\n" + suffix,
            ManagedPasswordSlotState::Broken);
    };
    // Canonical body passes (also covered by renderActiveQuality).
    expectState(
        qualitySpec(),
        prefix + "password requisite pam_pwquality.so retry=3\n" + suffix,
        ManagedPasswordSlotState::Active);
    // Failures (task section 31).
    body("password requisite pam_cracklib.so retry=3");
    body("password requisite pam_pwquality.so retry=3 use_authtok");
    body("password requisite pam_pwquality.so retry=4");
    body("password requisite pam_pwquality.so retry=3 debug");
    body("password requisite pam_pwquality.so retry=3 retry=3");
    body("password requisite pam_pwquality.so");
    body("password required pam_pwquality.so retry=3");
    body("password optional pam_pwquality.so retry=3");
    body("auth requisite pam_pwquality.so retry=3");
    body("account requisite pam_pwquality.so retry=3");
    body("password requisite pam_permit.so retry=3");
    body("");
    // Two full PAM rules.
    expectState(
        qualitySpec(),
        prefix + "password requisite pam_pwquality.so retry=3\n" +
            "password requisite pam_pwquality.so retry=3\n" + suffix,
        ManagedPasswordSlotState::Broken);
}

void testHistoryNormalBody() {
    const std::string prefix = beginMarker(normalSpec());
    const std::string suffix = endMarker(normalSpec());
    const auto active = [&](const std::string& rule) {
        return expectState(
            normalSpec(), prefix + rule + "\n" + suffix,
            ManagedPasswordSlotState::Active);
    };
    const auto broken = [&](const std::string& rule) {
        expectState(
            normalSpec(), prefix + rule + "\n" + suffix,
            ManagedPasswordSlotState::Broken);
    };
    // PASS cases (task section 32).
    auto inspection = active("password requisite pam_pwhistory.so use_authtok");
    require(*inspection.pwhistoryOptions == ManagedPwhistorySlotOptions{},
        "normal base options");
    inspection = active(
        "password requisite pam_pwhistory.so use_authtok remember=5");
    require(inspection.pwhistoryOptions->remember.value_or(0) == 5 &&
        !inspection.pwhistoryOptions->enforceForRoot,
        "normal remember=5");
    inspection = active(
        "password requisite pam_pwhistory.so use_authtok enforce_for_root");
    require(!inspection.pwhistoryOptions->remember.has_value() &&
        inspection.pwhistoryOptions->enforceForRoot,
        "normal enforce_for_root");
    inspection = active(
        "password requisite pam_pwhistory.so use_authtok remember=5 "
        "enforce_for_root");
    require(inspection.pwhistoryOptions->remember.value_or(0) == 5 &&
        inspection.pwhistoryOptions->enforceForRoot,
        "normal remember + enforce_for_root");
    // remember=0 is syntactically valid active state (task section 14);
    // semantic effectiveness is verified at a higher layer.
    inspection = active(
        "password requisite pam_pwhistory.so use_authtok remember=0");
    require(inspection.pwhistoryOptions->remember.value_or(1) == 0,
        "normal remember=0 is typed parsed");
    // FAIL cases.
    broken("password requisite pam_pwhistory.so");
    broken("password requisite pam_pwhistory.so remember=5");
    broken("password requisite pam_pwhistory.so use_authtok use_authtok");
    broken("password requisite pam_unix.so use_authtok");
    broken("password required pam_pwhistory.so use_authtok");
    broken("password optional pam_pwhistory.so use_authtok");
    broken("auth requisite pam_pwhistory.so use_authtok");
    broken("password requisite pam_pwhistory.so use_authtok remember=5 "
        "remember=6");
    broken("password requisite pam_pwhistory.so use_authtok remember=abc");
    broken("password requisite pam_pwhistory.so use_authtok remember=");
    broken("password requisite pam_pwhistory.so use_authtok "
        "remember=99999999999999999999");
    broken("password requisite pam_pwhistory.so use_authtok "
        "enforce_for_root enforce_for_root");
    broken("password requisite pam_pwhistory.so use_authtok debug");
    broken("password requisite pam_pwhistory.so use_authtok Enforce_For_Root");
    broken("password requisite pam_pwhistory.so use_authtok USE_AUTHTOK");
    // Reordered arguments are not canonical FIC ownership.
    broken("password requisite pam_pwhistory.so remember=5 use_authtok");
    broken("password requisite pam_pwhistory.so enforce_for_root use_authtok");
    // Wrong role: initial marker around a normal body (slot mismatch).
    expectState(
        initialSpec(), activeNormal(1), ManagedPasswordSlotState::Broken);
}

void testHistoryInitialBody() {
    const std::string prefix = beginMarker(initialSpec());
    const std::string suffix = endMarker(initialSpec());
    const auto active = [&](const std::string& rule) {
        return expectState(
            initialSpec(), prefix + rule + "\n" + suffix,
            ManagedPasswordSlotState::Active);
    };
    const auto broken = [&](const std::string& rule) {
        expectState(
            initialSpec(), prefix + rule + "\n" + suffix,
            ManagedPasswordSlotState::Broken);
    };
    // PASS cases (task section 33).
    auto inspection = active("password requisite pam_pwhistory.so");
    require(*inspection.pwhistoryOptions == ManagedPwhistorySlotOptions{},
        "initial base options");
    inspection = active("password requisite pam_pwhistory.so remember=5");
    require(inspection.pwhistoryOptions->remember.value_or(0) == 5 &&
        !inspection.pwhistoryOptions->enforceForRoot,
        "initial remember=5");
    inspection = active("password requisite pam_pwhistory.so enforce_for_root");
    require(!inspection.pwhistoryOptions->remember.has_value() &&
        inspection.pwhistoryOptions->enforceForRoot,
        "initial enforce_for_root");
    inspection = active(
        "password requisite pam_pwhistory.so remember=5 enforce_for_root");
    require(inspection.pwhistoryOptions->remember.value_or(0) == 5 &&
        inspection.pwhistoryOptions->enforceForRoot,
        "initial remember + enforce_for_root");
    // FAIL cases.
    broken("password requisite pam_pwhistory.so use_authtok");
    broken("password requisite pam_pwhistory.so remember=5 use_authtok");
    broken("password requisite pam_pwhistory.so use_authtok remember=5 "
        "enforce_for_root");
    broken("password required pam_pwhistory.so");
    broken("password optional pam_pwhistory.so");
    broken("auth requisite pam_pwhistory.so");
    broken("password requisite pam_unix.so");
    broken("password requisite pam_pwhistory.so remember=5 remember=5");
    broken("password requisite pam_pwhistory.so enforce_for_root "
        "enforce_for_root");
    broken("password requisite pam_pwhistory.so debug");
    broken("password requisite pam_pwhistory.so remember=5 debug");
    broken("password requisite pam_pwhistory.so remember=5 "
        "enforce_for_root use_authtok");
    // Wrong role: normal marker names another slot file.
    expectState(
        normalSpec(), activeInitial(1), ManagedPasswordSlotState::Broken);
}

void testQualityHistoryIndependence() {
    // Quality and history are independent capabilities: history active
    // with quality neutral is structurally representable at the
    // physical slot layer. The history-only "Unsupported" product rule
    // belongs to the Step 4 verifier, not to this parser.
    expectState(
        normalSpec(), activeNormal(1), ManagedPasswordSlotState::Active);
    expectState(
        initialSpec(), activeInitial(1), ManagedPasswordSlotState::Active);
    expectState(
        qualitySpec(), neutral(), ManagedPasswordSlotState::Neutral);
    // And the reverse: quality active with history neutral.
    expectState(
        qualitySpec(),
        PamManagedPasswordSlots::renderActiveQuality(7),
        ManagedPasswordSlotState::Active);
    expectState(
        normalSpec(), neutral(), ManagedPasswordSlotState::Neutral);
    expectState(
        initialSpec(), neutral(), ManagedPasswordSlotState::Neutral);
}

void testCrossSlotHistoryPair() {
    const auto pair = [](const ManagedPasswordSlotInspection& normal,
                          const ManagedPasswordSlotInspection& initial) {
        ManagedHistoryPairInspection result;
        std::string error;
        PamManagedPasswordSlots::inspectHistoryPair(
            normal, initial, result, error);
        return result;
    };
    const auto neutralNormal = inspect(normalSpec(), neutral());
    const auto neutralInitial = inspect(initialSpec(), neutral());

    // PASS: neutral + neutral.
    require(pair(neutralNormal, neutralInitial).state ==
            ManagedHistoryPairState::Neutral,
        "neutral pair is neutral");

    // PASS: consistent active pair.
    ManagedPwhistorySlotOptions options;
    options.remember = 5;
    options.enforceForRoot = true;
    const auto activeNormalInspection =
        inspect(normalSpec(), activeNormal(1, options));
    const auto activeInitialInspection =
        inspect(initialSpec(), activeInitial(1, options));
    const auto activeResult =
        pair(activeNormalInspection, activeInitialInspection);
    require(activeResult.state == ManagedHistoryPairState::Active,
        "consistent active pair");
    require(activeResult.mutationId == 1, "active pair mutation id");
    require(activeResult.options.has_value() &&
        *activeResult.options == options,
        "active pair options");

    // FAIL: mixed states are never a partially enabled topology.
    require(pair(activeNormalInspection, neutralInitial).state ==
            ManagedHistoryPairState::Broken,
        "active normal + neutral initial is broken");
    require(pair(neutralNormal, activeInitialInspection).state ==
            ManagedHistoryPairState::Broken,
        "neutral normal + active initial is broken");

    // FAIL: divergent mutation ids.
    require(pair(
                inspect(normalSpec(), activeNormal(1, options)),
                inspect(initialSpec(), activeInitial(2, options)))
                .state == ManagedHistoryPairState::Broken,
        "divergent mutation ids are broken");

    // FAIL: divergent options.
    ManagedPwhistorySlotOptions other = options;
    other.remember = 6;
    require(pair(
                activeNormalInspection,
                inspect(initialSpec(), activeInitial(1, other)))
                .state == ManagedHistoryPairState::Broken,
        "divergent remember is broken");
    other = options;
    other.enforceForRoot = false;
    require(pair(
                activeNormalInspection,
                inspect(initialSpec(), activeInitial(1, other)))
                .state == ManagedHistoryPairState::Broken,
        "divergent enforce_for_root is broken");

    // FAIL: wrong roles in both files.
    require(pair(
                inspect(normalSpec(), activeInitial(1, options)),
                inspect(initialSpec(), activeInitial(1, options)))
                .state == ManagedHistoryPairState::Broken,
        "normal role in both files is broken");
    require(pair(
                inspect(normalSpec(), activeNormal(1, options)),
                inspect(initialSpec(), activeNormal(1, options)))
                .state == ManagedHistoryPairState::Broken,
        "initial role in both files is broken");

    // FAIL: one file missing.
    const auto missingNormal = inspect(normalSpec(), std::nullopt);
    const auto missingInitial = inspect(initialSpec(), std::nullopt);
    const auto missingActive = pair(missingNormal, activeInitialInspection);
    require(missingActive.state == ManagedHistoryPairState::Broken &&
        missingActive.error.find("missing") != std::string::npos,
        "missing one file is broken and reported");
    require(pair(missingNormal, missingInitial).state ==
            ManagedHistoryPairState::Broken,
        "both files missing is broken");

    // FAIL: one file malformed.
    require(pair(
                inspect(normalSpec(), std::string("")),
                activeInitialInspection)
                .state == ManagedHistoryPairState::Broken,
        "malformed one file is broken");
}

void testRoundTrips() {
    ManagedPwhistorySlotOptions withRemember;
    withRemember.remember = 5;
    ManagedPwhistorySlotOptions withRoot;
    withRoot.enforceForRoot = true;
    ManagedPwhistorySlotOptions withBoth;
    withBoth.remember = 5;
    withBoth.enforceForRoot = true;

    // render -> inspect -> render returns exact original bytes.
    const auto check = [&](const ManagedPasswordSlotSpec& spec,
                            const std::string& content) {
        const auto inspection = expectState(
            spec, content, ManagedPasswordSlotState::Active);
        const auto reRendered = PamManagedPasswordSlots::renderActive(
            spec,
            inspection.mutationId,
            inspection.pwhistoryOptions.value_or(ManagedPwhistorySlotOptions{}));
        require(reRendered == content,
            "render(inspect(render(x))) == x for " +
                std::string(spec.fileName));
    };
    check(qualitySpec(), PamManagedPasswordSlots::renderActiveQuality(42));
    check(normalSpec(), activeNormal(42));
    check(normalSpec(), activeNormal(42, withRemember));
    check(normalSpec(), activeNormal(42, withRoot));
    check(normalSpec(), activeNormal(42, withBoth));
    check(initialSpec(), activeInitial(42));
    check(initialSpec(), activeInitial(42, withRemember));
    check(initialSpec(), activeInitial(42, withRoot));
    check(initialSpec(), activeInitial(42, withBoth));

    // inspect -> render for canonical neutral input returns exact
    // original bytes.
    require(PamManagedPasswordSlots::renderNeutral(qualitySpec()) ==
            PamManagedPasswordSlots::neutralBody(),
        "neutral render bytes");
    require(
        inspect(qualitySpec(), neutral()).state ==
            ManagedPasswordSlotState::Neutral,
        "neutral round trip");
    require(
        inspect(initialSpec(), PamManagedPasswordSlots::renderNeutral(initialSpec()))
            .state == ManagedPasswordSlotState::Neutral,
        "neutral round trip (initial)");

    // Cross-role bodies stay distinct.
    require(activeNormal(1, withBoth) != activeInitial(1, withBoth),
        "normal and initial bodies differ");
    require(PamManagedPasswordSlots::renderActiveQuality(1) !=
            PamManagedPasswordSlots::renderActive(normalSpec(), 1, {}),
        "quality and history bodies differ");
}

} // namespace

int main() {
    try {
        const std::pair<const char*, void (*)()> tests[] = {
            {"testSpecsAndNeutralBytes", testSpecsAndNeutralBytes},
            {"testNeutralStates", testNeutralStates},
            {"testActiveMarkers", testActiveMarkers},
            {"testActiveMarkerStructure", testActiveMarkerStructure},
            {"testQualityBody", testQualityBody},
            {"testHistoryNormalBody", testHistoryNormalBody},
            {"testHistoryInitialBody", testHistoryInitialBody},
            {"testCrossSlotHistoryPair", testCrossSlotHistoryPair},
            {"testQualityHistoryIndependence",
             testQualityHistoryIndependence},
            {"testRoundTrips", testRoundTrips}};
        for (const auto& test : tests) {
            test.second();
            std::cout << test.first << " passed\n";
        }
    } catch (const std::exception& exception) {
        std::cerr << "PamManagedPasswordSlotsTests failed: "
                  << exception.what() << '\n';
        return 1;
    }
    std::cout << "PamManagedPasswordSlotsTests passed\n";
    return 0;
}
