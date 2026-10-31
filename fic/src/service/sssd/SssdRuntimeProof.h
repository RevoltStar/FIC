#pragma once
#include "service/sssd/SssdVerifiedActivationAdapter.h"
namespace fic::service::sssd::detail_i3 {
struct NativeRuntimeContract {
  uid_t uid = 0;
  gid_t gid = 0;
  bool needsPam = false;
  bool needsBackendProtocol = false;
  std::map<std::string, std::string> code;
  std::string sourceContract;
  SssdLaunchReference launch;
};
NativeRuntimeContract nativePreflight(const SssdVerifiedActivationRequest &,
                                      const EffectiveConfiguration &, Deadline);
void verifyNativeCode(const NativeRuntimeContract &);
void proveRuntime(const SssdVerifiedActivationRequest &,
                  const EffectiveConfiguration &, const NativeRuntimeContract &,
                  const detail::ServiceState &, Deadline,
                  SssdVerifiedActivationResult &);
void confirmRuntime(const NativeRuntimeContract &,
                    const SssdVerifiedActivationResult &, Deadline);
// I5 read-only absence proof; never starts a service or manufactures B/C.
std::string proveStoppedConsumers(const SssdLaunchReference&, Deadline);
std::string backendBusName(const std::string &);
bool validBusOwner(const std::string &);
// Pure bounded parsers exercised by unit tests; no authority in their output.
using DbRecords = std::map<std::string, std::map<std::string, std::string>>;
DbRecords parseConfigDb(const std::string &);
std::string domainDn(const std::string &);
} // namespace fic::service::sssd::detail_i3
