#ifndef FIC_PAM_NOPASSWDLOGIN_TRANSACTION_H
#define FIC_PAM_NOPASSWDLOGIN_TRANSACTION_H

#include "platform/PlatformProfile.h"
#include "rollback/MutationJournal.h"
#include <functional>

namespace fic::identity::pam {

struct PamNopasswdloginOptions {
    fic::platform::PamPlatformConfig platform;
    std::vector<std::string> services;
    using Writer = std::function<bool(const std::string&, const std::string&,
                                     const AtomicWriteOptions&, std::string*)>;
    Writer writer = AtomicFileWriter::write;
    // Called only when an active journal record has lost its physical witness.
    // Must prove installed package content against the captured bytes.
    std::function<bool(const std::filesystem::path&, const std::string&, std::string&)> proveStock;
};

class PamNopasswdloginTransaction {
public:
    PamNopasswdloginTransaction(PamNopasswdloginOptions options,
                               fic::rollback::MutationJournal& journal);
    bool apply(std::string& error);
    bool release(const fic::rollback::MutationRecord& record, std::string& error);

private:
    PamNopasswdloginOptions options_;
    fic::rollback::MutationJournal& journal_;
};

} // namespace fic::identity::pam
#endif
