#pragma once
#include "platform/PlatformExecutableResolver.h"
#include <string>
bool sysctlLoaderAdmission(const fic::platform::PlatformExecutableResolver&,std::string&);
bool reapplySysctlPrefix(const fic::platform::PlatformExecutableResolver&,const std::string& key,std::string&);
std::string sysctlNativePrefix(const std::string& key);
