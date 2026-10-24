#pragma once
#include <string>
namespace fic::service::ssh::detail {
enum class ServiceAdmission { Ready, Wait };
// Enablement/launch proof is separate. Only an already pending lifecycle can
// wait; this classifier never starts, enables or repairs a service.
ServiceAdmission classifyServiceAdmission(const std::string& active,
    const std::string& substate,const std::string& job);
}
