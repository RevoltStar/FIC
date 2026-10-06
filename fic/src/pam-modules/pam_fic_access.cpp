#include "incident/IncidentAccessGateCore.h"

#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include <syslog.h>

extern "C" int pam_sm_acct_mgmt(pam_handle_t* pamh, int,
                                 int argc, const char** argv) {
    (void)argv;
    if (argc != 0) return PAM_SERVICE_ERR;
    const void* service = nullptr;
    if (pam_get_item(pamh, PAM_SERVICE, &service) != PAM_SUCCESS ||
        service == nullptr) {
        return PAM_PERM_DENIED;
    }
    try {
        const auto* serviceName = static_cast<const char*>(service);
        if (!fic::incident::isProductionControlledIncidentService(serviceName))
            return PAM_IGNORE;
        const char* user = nullptr;
        const void* remoteHost = nullptr;
        if (pam_get_user(pamh, &user, nullptr) != PAM_SUCCESS ||
            pam_get_item(pamh, PAM_RHOST, &remoteHost) != PAM_SUCCESS ||
            user == nullptr) {
            return PAM_PERM_DENIED;
        }
        const fic::incident::PamAccessContext context{
            user, serviceName,
            remoteHost == nullptr ? "" : static_cast<const char*>(remoteHost)};
        const auto decision = fic::incident::decideProductionIncidentAccess(context);
        if (decision.disposition == fic::incident::AccessGateDisposition::Neutral)
            return PAM_IGNORE;
        if (decision.disposition == fic::incident::AccessGateDisposition::Pass)
            return PAM_SUCCESS;
        pam_syslog(pamh, LOG_NOTICE, "incident access denied: %s",
                   decision.diagnostic.c_str());
        (void)pam_error(pamh, "Access is restricted by FIC security policy.");
        return PAM_PERM_DENIED;
    } catch (...) {
        return PAM_PERM_DENIED;
    }
}
