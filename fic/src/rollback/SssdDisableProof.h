#pragma once
#include "rollback/MutationRecord.h"
namespace fic::service::sssd { class SssdTransactionCoordinator; }
namespace fic::rollback {
// Constructed only after the coordinator's locked, live administrative proof.
// It never crosses IPC or persists as a substitute for revalidation.
class SssdDisableProof {
    friend class fic::service::sssd::SssdTransactionCoordinator;
    friend class MutationJournal;
    MutationId mutation_;
    std::uint64_t sequence_;
    std::string generation_;
    SssdDisableProof(MutationId mutation,std::uint64_t sequence,std::string generation)
        :mutation_(mutation),sequence_(sequence),generation_(std::move(generation)){}
};
}
