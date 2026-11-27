#include "modules/identity_access/pam/PamNopasswdloginPackageProof.h"
#include "platform/PlatformProfile.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <unistd.h>

int main(int argc, char** argv) {
    if (argc < 3 || argc > 4) return 2;
    const std::string operation = argv[1];
    const auto profile = fic::platform::makeBuildPlatformProfile();
    auto options = fic::identity::pam::productionNopasswdloginOptions(profile.pam);
    if (argc == 4) options.services = {argv[3]};
    std::string error;
    fic::rollback::MutationJournal journal(argv[2]);
    if (!journal.initializeOrLoad(error)) {
        std::cerr << error << '\n';
        return 1;
    }
    if (operation == "crash-before" || operation == "crash-after") {
        options.writer = [&](const auto& path, const auto& bytes,
                             const AtomicWriteOptions& settings, std::string* message) {
            if (operation == "crash-before") ::_exit(71);
            if (!AtomicFileWriter::write(path, bytes, settings, message)) return false;
            ::_exit(72);
        };
    }
    fic::identity::pam::PamNopasswdloginTransaction transaction(options, journal);
    bool success = false;
    if (operation == "release") {
        success = true;
        const auto records = journal.records();
        for (const auto& record : records) {
            if (record.isActive() && record.undo.backend == fic::rollback::MutationBackend::PamSuppression &&
                (argc != 4 || record.resource == argv[3]) && !transaction.release(record, error)) {
                success = false;
                break;
            }
        }
    } else if (operation == "prove" && argc == 4) {
        const auto source = profile.pam.configDirectories.front() / argv[3];
        std::ifstream file(source, std::ios::binary);
        const std::string content(std::istreambuf_iterator<char>(file), {});
        success = file.is_open() && options.proveStock(source, content, error);
    } else if (operation == "apply" || operation == "crash-before" || operation == "crash-after") {
        success = transaction.apply(error);
    }
    std::cout << "platform=" << profile.id << " operation=" << operation
              << " ok=" << success << " records=" << journal.records().size() << '\n';
    if (!success) std::cerr << error << '\n';
    return success ? 0 : 1;
}
