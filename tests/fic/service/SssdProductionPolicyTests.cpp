#include "modules/identity_access/sssd/policies/SssdOfflineCredentialsExpirationPolicy.h"
#include "modules/identity_access/sssd/policies/SssdCacheCredentialsPolicy.h"
#include "modules/identity_access/sssd/policies/SssdAccountCacheExpirationPolicy.h"
#include "policy/registry/PolicyRegistry.h"
#include "rollback/DaemonMutationJournal.h"
#include <fic/core/runtime/FicRuntimePaths.h>
#include <fstream>
#include <iostream>
#include <unistd.h>
#include <sys/stat.h>
namespace fs=std::filesystem;
namespace s=fic::service::sssd;
namespace r=fic::rollback;
static void check(bool value,const std::string& why){if(!value)throw std::runtime_error(why);}
int main() {
    char name[]="/tmp/fic-sssd-production-XXXXXX";
    const auto* temporary=::mkdtemp(name);if(!temporary)return 1;
    const fs::path root=temporary;
    try {
        auto paths=fic::core::FicProductPaths::production();
        paths.configDir=root/"config";paths.logDir=root/"log";paths.dataDir=root/"data";
        paths.languageDir=root/"lang";paths.notifyDir=root/"notify";
        for(const auto* dir:{"config","log","data","lang","notify"})fs::create_directories(root/dir);
        std::ofstream(root/"config/GLOBAL.conf")<<"_schema_version=1\nlang.status=ENABLE\nlang.value=en\n";
        std::ofstream(root/"config/AUDIT.conf")<<"_schema_version=1\nlog_level.status=ENABLE\nlog_level.value=5\n";
        std::string error;check(fic::core::FicRuntimePaths::initialize(paths,error),error);
        r::DaemonMutationJournal::instance().setOverridePath(root/"data/journal.json");
        auto* journal=r::DaemonMutationJournal::instance().tryGet(error);check(journal,error);
        const fic::platform::PlatformExecutableResolver executables(fic::platform::PlatformExecutables{});
        const auto write=[&](const std::string& status,const std::string& value) {
            std::ofstream out(root/"config/IDENTITY_ACCESS.conf");
            out<<"_schema_version=1\nsssd_offline_credentials_expiration.status="<<status<<"\nsssd_offline_credentials_expiration.value=30\n"
                "sssd_cache_credentials.status=DISABLE\nsssd_account_cache_expiration.status=DISABLE\n";
            if(!value.empty())out<<"sssd_account_cache_expiration.value="<<value<<'\n';
        };
        const auto registry=[&]() {
            PolicyRegistry result;
            check(result.addModule("IDENTITY_ACCESS",ModuleView::Standard,0,error),error);
            check(result.addPolicy(std::make_unique<SssdOfflineCredentialsExpirationPolicy>(executables),error),error);
            check(result.addPolicy(std::make_unique<SssdCacheCredentialsPolicy>(),error),error);
            check(result.addPolicy(std::make_unique<SssdAccountCacheExpirationPolicy>(),error),error);
            return result;
        };
        write("DISABLE","");auto current=registry();
        auto* offline=current.findPolicy(s::detail_i4::policyIdentity(s::SssdManagedParameter::OfflineCredentialsExpiration));
        auto* account=current.findPolicy(s::detail_i4::policyIdentity(s::SssdManagedParameter::AccountCacheExpiration));
        auto* cache=current.findPolicy(s::detail_i4::policyIdentity(s::SssdManagedParameter::CacheCredentials));
        check(offline&&account&&cache,"all three actual production policies registered");
        check(offline->getDefaultValue()=="30"&&offline->getValue()==std::optional<std::string>("30"),"offline default/value");
        for(const auto* value:{"-1","3651","30days","1.0","+1"})check(!offline->validate(value),"offline accepts only complete bounded integer");
        check(!account->getPolicyTypeValue().hasDefaultValue()&&!account->getValue(),"account has no synthetic default");
        check(cache->getValue()==std::optional<std::string>("true"),"cache fixed intrinsic true");
        check(offline->dependencies().size()==1&&offline->dependencies().front().strength==PolicyDependencyStrength::Recommended&&
            offline->dependencies().front().policy==cache->policyRef(),"only Recommended dependency");
        check(!offline->apply()&&journal->records().empty(),"disabled real Policy cannot reach OS mutation");
        write("ENABLE","60");
        check(!offline->apply()&&journal->records().empty(),"stale registry cannot apply after persistent generation change");
        for(const auto* value:{"0","60","3650"}) {
            write("ENABLE",value);current=registry();account=current.findPolicy(s::detail_i4::policyIdentity(s::SssdManagedParameter::AccountCacheExpiration));
            check(account->getValue()==std::optional<std::string>(value),"explicit account Days");
        }
        for(const auto* value:{"-1","3651","60days"}) {
            write("ENABLE",value);current=registry();account=current.findPolicy(s::detail_i4::policyIdentity(s::SssdManagedParameter::AccountCacheExpiration));
            check(!account->getValue(),"invalid account Days refused");
        }
        write("BROKEN","60");current=registry();offline=current.findPolicy(s::detail_i4::policyIdentity(s::SssdManagedParameter::OfflineCredentialsExpiration));
        check(!offline->apply()&&journal->records().empty(),"corrupt status cannot become ENABLE authority");
        write("ENABLE","60");::chmod((root/"config/IDENTITY_ACCESS.conf").c_str(),0666);
        current=registry();offline=current.findPolicy(s::detail_i4::policyIdentity(s::SssdManagedParameter::OfflineCredentialsExpiration));
        check(!offline->apply()&&journal->records().empty(),"untrusted writable configuration cannot authorize production mutation");
        ::chmod((root/"config/IDENTITY_ACCESS.conf").c_str(),0644);
        write("ENABLE","60");current=registry();offline=current.findPolicy(s::detail_i4::policyIdentity(s::SssdManagedParameter::OfflineCredentialsExpiration));
        for(const auto status:{r::MutationStatus::Applied,r::MutationStatus::Prepared,r::MutationStatus::RollbackFailed}) {
            r::MutationId id=0;
            check(r::recordPreparedMutation(offline->policyRef(),"pam/offline_credentials_expiration",
                {r::MutationBackend::Sssd,r::UndoRemoveSssdManagedSetting{"pam","offline_credentials_expiration","30"}},id,error),error);
            if(status!=r::MutationStatus::Prepared)check(journal->setStatus(id,status,error),error);
            const auto before=journal->records().size();
            check(!offline->apply()&&journal->records().size()==before,"legacy owner never adopted/promoted by real Policy");
            check(journal->setStatus(id,r::MutationStatus::RolledBack,error),error);
        }
        auto unknown=std::make_unique<SssdCacheCredentialsPolicy>();unknown->policyName="sssd_future_policy";
        check(current.addPolicy(std::move(unknown),error),error);
        const auto history=journal->records().size();
        check(!offline->apply()&&journal->records().size()==history&&journal->activeRecords(offline->policyRef()).empty(),
              "unknown registered SSSD member cannot be silently omitted from complete production intent");
        r::DaemonMutationJournal::instance().resetOverride();fs::remove_all(root);
        std::cout<<"SSSD production policy value/intent/legacy contracts PASS\n";return 0;
    } catch(const std::exception& e){std::cerr<<e.what()<<'\n';r::DaemonMutationJournal::instance().resetOverride();fs::remove_all(root);return 1;}
}
