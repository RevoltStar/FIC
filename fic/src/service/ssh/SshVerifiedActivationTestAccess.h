#pragma once
#ifdef FIC_ACTIVATOR_TESTING
#include "service/ssh/SshVerifiedActivationAdapter.h"
#include "service/VerifiedConfigServiceActivatorTestAccess.h"
namespace fic::service::ssh::detail {
struct AdapterTestHooks {
    std::function<void()> beforeActivation;
    std::function<void()> beforeFinalConfirmation;
    std::function<void()> admissionWait; // actual pending state observed, before bounded wait
    fic::service::detail::TestHooks activation;
};
SshVerifiedActivationResult activateAdapterForTests(const SshVerifiedActivationRequest&, const AdapterTestHooks&);
}
#endif
