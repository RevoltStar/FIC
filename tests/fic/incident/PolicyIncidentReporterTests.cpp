#include "incident/PolicyIncidentReporter.h"

#include <fic/core/fs/AtomicFileWriter.h>
#include <sys/stat.h>
#include <unistd.h>

#include <filesystem>
#include <fstream>
#include <stdexcept>

int main() {
    fic::incident::IncidentStateStore::setOwnershipExpectationForTests(
        ::geteuid(), ::geteuid());
    char pattern[] = "/tmp/fic-policy-incident-XXXXXX";
    char* directory = ::mkdtemp(pattern);
    if (directory == nullptr) throw std::runtime_error("mkdtemp failed");
    const std::filesystem::path path = std::filesystem::path(directory) / "lockstatus";
    {
        std::ofstream output(path);
        output << "HARD\n";
    }
    ::chmod(path.c_str(), 0640);
    fic::incident::IncidentController controller(
        fic::incident::IncidentStateStore(path), nullptr, nullptr);
    fic::incident::PolicyIncidentReporter reporter(controller);
    PolicyRegistry registry;
    PolicyApplySummary summary;
    const auto effective = reporter.report(registry, summary, "empty apply pass");
    std::filesystem::remove_all(directory);
    if (effective != fic::core::IncidentSeverity::Hard) {
        throw std::runtime_error("empty pass must report global HARD state");
    }
}
