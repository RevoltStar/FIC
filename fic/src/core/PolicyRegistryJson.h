#ifndef POLICY_REGISTRY_JSON_H
#define POLICY_REGISTRY_JSON_H

#include <nlohmann/json_fwd.hpp>

#include "core/PolicyRegistry.h"

nlohmann::json moduleDescriptorsJson(const PolicyRegistry& registry);

#endif // POLICY_REGISTRY_JSON_H
