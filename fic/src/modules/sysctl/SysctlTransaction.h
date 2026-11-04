#pragma once
#include "modules/sysctl/SysctlConfiguration.h"
#include "modules/sysctl/SysctlRuntime.h"
#include "rollback/MutationJournal.h"
#include <functional>
struct SysctlContainerAuthority {bool created=false;fic::rollback::MutationId legacyOrigin=0;};
// Caller holds the shared SYSCTL mutex. Every physical assignment must have one
// exact active permission; no adoption by filename/header or matching value.
bool proveSysctlOwnership(fic::rollback::MutationJournal&,const SysctlConfiguration&,
    SysctlContainerAuthority&,std::string&,const std::string& releasingKey={});
SysctlOperationResult applySysctlOwned(fic::rollback::MutationJournal&,const PolicyRef&,
    const std::string& key,const std::string& value,SysctlConfigurationOptions,
    SysctlRuntimeOptions={},const std::function<bool(std::string&)>& admission={},
    const std::function<void()>& beforePublish={});
// Caller holds mutationMutex through physical release, terminal journal and
// bounded native reapply. Auxiliary failure is a warning after successful release.
SysctlOperationResult releaseSysctlOwned(fic::rollback::MutationJournal&,fic::rollback::MutationId,
    SysctlConfigurationOptions,const std::function<bool(const std::string&,std::string&)>& reapply);
