#include "modules/oss/desktop_environment/policies/OSS_disable_kde_lock_screen_media_controls.h"

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void require(bool value, const std::string& message) {
    if (!value) throw std::runtime_error(message);
}

// Fake KdeBackend-совместимый backend: записывает protocol operations и
// позволяет управлять результатом каждого шага. Методы const — helper
// принимает const Backend&, как реальный KdeBackend.
struct FakeBackend {
    mutable std::string fileValue = "false";
    // Если непусто — возвращается readConfig'ом после успешного configure
    // (эмуляция файла, не изменившегося после reload).
    std::string valueAfterConfigure;
    bool readOk = true;
    bool writeOk = true;
    bool configureOk = true;
    bool runtimeStable = true;

    mutable int readCalls = 0;
    mutable int writeCalls = 0;
    mutable int configureCalls = 0;
    mutable bool validated = false;
    mutable std::vector<std::string> operations;

    bool readConfig(const std::string&, const std::vector<std::string>&,
                    const std::string&, std::string& value,
                    std::string&) const {
        ++readCalls;
        operations.push_back("read");
        value = configureCalls > 0 && !valueAfterConfigure.empty()
                    ? valueAfterConfigure
                    : fileValue;
        return readOk;
    }
    bool writeConfig(const std::string&, const std::vector<std::string>&,
                     const std::string&, const std::string& value,
                     std::string&) const {
        ++writeCalls;
        operations.push_back("write");
        fileValue = value;
        return writeOk;
    }
    bool callDbusMethod(const std::string&, const std::string&,
                        const std::string&, const std::string& method,
                        std::string&) const {
        ++configureCalls;
        operations.push_back("configure");
        return configureOk;
    }
    bool validateRuntimeContext(std::string&) const {
        operations.push_back("validate");
        validated = true;
        return runtimeStable;
    }
};

// Обязательный test 1: already-compliant file всё равно проходит
// configure reload и не выполняет лишний write.
void testAlreadyCompliantFileStillConfigures() {
    FakeBackend backend;
    std::string error;
    require(kde_media_controls::reconcileMediaControls(backend, error),
            "already-compliant media-controls state failed reconciliation");
    require(backend.writeCalls == 0,
            "already-compliant file triggered a redundant write");
    require(backend.configureCalls == 1,
            "already-compliant file skipped runtime configure reload");
    require(backend.readCalls == 2,
            "final readback was not performed after configure");
    require(backend.validated, "runtime owner validation was skipped");
    require(backend.operations ==
                std::vector<std::string>{
                    "read", "configure", "read", "validate"},
            "reconciliation ordering is wrong for already-compliant file");
}

// Обязательный test 2: configure failure на already-compliant файле
// фатальна. На старом коде configure не вызывался вовсе — false success.
void testConfigureFailureOnCompliantFileIsFatal() {
    FakeBackend backend;
    backend.configureOk = false;
    std::string error;
    require(!kde_media_controls::reconcileMediaControls(backend, error),
            "configure failure on already-compliant file was accepted");
    require(error.rfind(
                "failed to reload KDE lock-screen media-control settings",
                0) == 0,
            "configure failure diagnostic is not distinguishable");
    require(backend.writeCalls == 0,
            "configure-failure path performed a write");
}

// Обязательный test 3: mismatch — ровно один write и ровно один configure.
void testMismatchWritesOnceAndConfiguresOnce() {
    FakeBackend backend;
    backend.fileValue = "true";
    std::string error;
    require(kde_media_controls::reconcileMediaControls(backend, error),
            "mismatch reconciliation failed");
    require(backend.writeCalls == 1,
            "mismatch did not perform exactly one write");
    require(backend.configureCalls == 1,
            "mismatch did not perform exactly one configure");
    require(backend.fileValue == "false",
            "written value is not the desired state");
    require(backend.operations ==
                std::vector<std::string>{
                    "read", "write", "configure", "read", "validate"},
            "reconciliation ordering is wrong for mismatch");
}

// Case D: write успешен, configure после write фатален.
void testConfigureFailureAfterWriteIsFatal() {
    FakeBackend backend;
    backend.fileValue = "true";
    backend.configureOk = false;
    std::string error;
    require(!kde_media_controls::reconcileMediaControls(backend, error),
            "configure failure after write was accepted");
    require(backend.writeCalls == 1,
            "write was skipped before configure failure");
    require(backend.configureCalls == 1,
            "configure was retried or skipped after failure");
    require(error.rfind(
                "failed to reload KDE lock-screen media-control settings",
                0) == 0,
            "post-write configure failure diagnostic is not distinguishable");
}

// Обязательный test 4: configure успешен, но final readback всё ещё
// mismatch — policy обязана вернуть failure.
void testPostConfigureMismatchFails() {
    FakeBackend backend;
    backend.fileValue = "true";
    backend.valueAfterConfigure = "true";
    std::string error;
    require(!kde_media_controls::reconcileMediaControls(backend, error),
            "post-configure mismatch was accepted");
    require(error ==
                "KDE lock-screen media controls did not reach the "
                "requested state",
            "final mismatch diagnostic changed");
}

// Обязательный test 5: validateRuntimeContext остаётся последней
// security boundary.
void testOwnerValidationRemainsRequired() {
    FakeBackend backend;
    backend.runtimeStable = false;
    std::string error;
    require(!kde_media_controls::reconcileMediaControls(backend, error),
            "owner race was accepted");
    require(error.rfind(
                "KDE screen locker changed during reconciliation: ", 0) == 0,
            "owner race diagnostic changed");
    require(backend.validated, "runtime validation was not invoked");
}

// __PART2__

} // namespace

int main() {
    try {
        testAlreadyCompliantFileStillConfigures();
        testConfigureFailureOnCompliantFileIsFatal();
        testMismatchWritesOnceAndConfiguresOnce();
        testConfigureFailureAfterWriteIsFatal();
        testPostConfigureMismatchFails();
        testOwnerValidationRemainsRequired();
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    std::cout << "kde media controls reconciler tests: OK\n";
    return 0;
}