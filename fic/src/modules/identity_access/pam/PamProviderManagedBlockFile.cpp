#include "modules/identity_access/pam/PamProviderManagedBlockFile.h"

#include <fic/core/fs/TrustedFileReader.h>

#include <unistd.h>

namespace fic::identity::pam {
namespace {

fic::core::TrustedFileReadOptions trustedReadOptions() {
    fic::core::TrustedFileReadOptions options;
    // requireRegularFile stays true (default): symlinks and other
    // non-regular objects are refused by the trusted-file primitive.
    return options;
}

AtomicWriteOptions writeOptions(bool containerWasAbsent) {
    AtomicWriteOptions options;
    options.createIfMissing = containerWasAbsent;
    options.rejectSymlink = true;
    if (containerWasAbsent) {
        // Atomically refuse creation if any object appeared at the target
        // between the proven ENOENT and the write.
        options.exclusiveCreate = true;
    }
    // The same metadata policy as the existing PAM option file writers:
    // an existing file keeps its uid/gid/mode, a FIC-created container is
    // 0644 with the current euid/egid (root:root for the daemon).
    options.metadataPolicy = FileMetadataPolicy::EnforceProvided;
    options.fileMode = 0644;
    options.fileOwner = ::geteuid();
    options.fileGroup = ::getegid();
    return options;
}

} // namespace

PamProviderContainerReadResult PamProviderManagedBlockFile::readForMutation(
    const std::filesystem::path& path,
    PamProviderAbsentContainerDecision absentDecision,
    std::string& error) {
    PamProviderContainerReadResult result;

    fic::core::TrustedFileMetadata metadata;
    int systemError = 0;
    if (!fic::core::inspectTrustedFile(
            path, trustedReadOptions(), &metadata, error, &systemError)) {
        if (systemError == ENOENT) {
            if (absentDecision !=
                PamProviderAbsentContainerDecision::CreateFicOwned) {
                error = "primary PAM provider configuration отсутствует: " +
                    path.string() +
                    "; создание контейнера не доказано (fail closed)";
                result.error = error;
                return result;
            }
            result.state = PamProviderContainerState::Absent;
            result.ok = true;
            return result;
        }
        error = "trusted read " + path.string() + " failed: " + error;
        result.error = error;
        return result;
    }

    std::string captureError;
    if (!AtomicFileWriter::captureTargetState(
            path.string(), result.snapshot, &captureError)) {
        error = "не удалось захватить snapshot " + path.string() + ": " +
            captureError;
        return result;
    }
    result.state = PamProviderContainerState::PreExisting;
    result.content = result.snapshot.content;
    result.ok = true;
    return result;
}

PamProviderContainerWriteResult PamProviderManagedBlockFile::writeMutation(
    const std::filesystem::path& path,
    bool containerWasAbsent,
    const AtomicTargetState& snapshot,
    const std::string& newContent,
    std::string& error) {
    PamProviderContainerWriteResult result;
    AtomicWriteOptions options = writeOptions(containerWasAbsent);
    if (!containerWasAbsent) {
        // Optimistic snapshot precondition: refuse replacement when the
        // file changed between the read and the write (TOCTOU/stale
        // replacement protection for shared configuration files).
        options.expectedTargetState = snapshot;
    }
    AtomicWriteResult writeResult;
    if (!AtomicFileWriter::writeWithResult(
            path.string(), newContent, options, &error, &writeResult)) {
        if (writeResult.preconditionFailed) {
            result.stale = true;
            error = "stale snapshot: " + path.string() +
                " изменился между чтением и записью; замена отклонена";
        }
        result.error = error;
        return result;
    }
    // installed == true; report success ONLY when the durability barrier
    // (parent directory fsync) was also confirmed. A durability failure
    // after rename means the mutation may already have taken effect —
    // never reported as a clean success.
    if (!writeResult.durabilityConfirmed) {
        error = "durability " + path.string() +
            " не подтверждена (rename опубликован, directory fsync не "
            "завершён)";
        result.error = error;
        return result;
    }
    result.containerCreated = containerWasAbsent;
    result.ok = true;
    return result;
}

PamProviderContainerReleaseDecision pamProviderContainerReleaseDecision(
    bool containerCreatedProven,
    const std::string& finalContentAfterBlockRemoval) {
    if (!containerCreatedProven) {
        // Container creation not proven (pre-existing file, or the
        // provenance record is gone): a pre-existing foreign primary file
        // is NEVER unlinked (fail closed).
        return PamProviderContainerReleaseDecision::RetainUnproven;
    }
    if (!finalContentAfterBlockRemoval.empty()) {
        // Foreign bytes exist: remove only the FIC block, keep the file.
        return PamProviderContainerReleaseDecision::RetainForeignContent;
    }
    return PamProviderContainerReleaseDecision::RemovableFicOwned;
}

} // namespace fic::identity::pam
