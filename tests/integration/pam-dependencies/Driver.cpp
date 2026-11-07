#include "daemon/main_function.h"
#include "modules/identity_access/pam/PamProviderCatalog.h"
#include "modules/identity_access/pam/PamPlatformComposition.h"
#include "modules/identity_access/pam/PamProviderManagedEntryExecutor.h"
#include "modules/identity_access/pam/PamTopologyManagerFactory.h"
#include "policy/execution/PolicyDependencyGraph.h"
#include <fic/core/runtime/FicRuntimePaths.h>
#include <fic/core/process/ProcessExecutor.h>
#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <unistd.h>
using namespace fic::platform;
namespace p=fic::identity::pam;
namespace fs=std::filesystem;
using json=nlohmann::json;
void need(bool ok,const std::string& why){if(!ok)throw std::runtime_error(why);}
void write(const fs::path& path,const std::string& text){fs::create_directories(path.parent_path());std::ofstream out(path);out<<text;need(out.good(),"fixture write failed");}
std::string read(const fs::path& path){std::ifstream in(path);return {std::istreambuf_iterator<char>(in),{}};}
// Canonical policy identities under test. Capability mapping is the production
// pamPolicyCapability(feature), never a second feature-to-capability table.
struct Option {PamPolicyFeature feature;const char* name;};
const Option options[]={
#define OPTION(feature,name) {PamPolicyFeature::feature,name}
 OPTION(PasswordMinLength,"password_min_length"),OPTION(PasswordMinClasses,"password_min_classes"),
 OPTION(PasswordCheckUsername,"password_check_username"),OPTION(PasswordCheckGecos,"password_check_gecos"),
 OPTION(PasswordQualityEnforceForRoot,"password_quality_enforce_for_root"),OPTION(PasswordMinChangedCharacters,"password_min_changed_characters"),
 OPTION(PasswordMinLowercase,"password_min_lowercase"),OPTION(PasswordMinUppercase,"password_min_uppercase"),
 OPTION(PasswordMinDigits,"password_min_digits"),OPTION(PasswordMinOther,"password_min_other"),
 OPTION(PasswdqcStrengthThresholds,"passwdqc_strength_thresholds"),OPTION(PasswdqcPassphraseWords,"passwdqc_passphrase_words"),
 OPTION(PasswdqcMatchLength,"passwdqc_match_length"),OPTION(PasswdqcSimilarPassword,"passwdqc_similar_password"),
 OPTION(PasswdqcRetryCount,"passwdqc_retry_count"),OPTION(PasswordHistoryDepth,"password_history_depth"),
 OPTION(PasswordHistoryEnforceForRoot,"password_history_enforce_for_root"),OPTION(FailedAuthenticationAttempts,"failed_authentication_attempts"),
 OPTION(FailedAuthenticationCountingPeriod,"failed_authentication_counting_period"),OPTION(FailedAuthenticationEnforceForRoot,"failed_authentication_enforce_for_root"),
 OPTION(FailedAuthenticationUnlockTime,"failed_authentication_unlock_time")
#undef OPTION
};
const char* support(PamPolicySupport s){switch(s){case PamPolicySupport::Unsupported:return "Unsupported";case PamPolicySupport::Supported:return "Supported";case PamPolicySupport::ReadOnly:return "ReadOnly";case PamPolicySupport::RequiresTopologyActivation:return "RequiresTopologyActivation";}return "unknown";}
const char* topology(PamTopologyStrategyKind s){switch(s){case PamTopologyStrategyKind::StaticVerifyOnly:return "StaticVerifyOnly";case PamTopologyStrategyKind::PamAuthUpdate:return "PamAuthUpdate";case PamTopologyStrategyKind::AltTcbManaged:return "AltTcbManaged";}return "unknown";}
#include "Contracts.h"
int main(int argc,char** argv){
 fs::path root=fs::temp_directory_path()/("fic-pam-dependencies-"+std::to_string(getpid()));
 try {
  need(argc==3,"usage: driver --audit|--test|--alt-control OUTPUT");fs::create_directories(root);
  fic::core::FicProductPaths paths;
  paths.privateBinDir=root/"bin"; paths.configDir=root/"config"; paths.languageDir=root/"lang";
  paths.dataDir=root/"data"; paths.logDir=root/"log"; paths.runtimeDir=root/"run";
  paths.notifyDir=root/"notify"; paths.shareDir=root/"share"; paths.defaultConfigDir=root/"defaults"; paths.imageDir=root/"images";
  paths.lockStatusFile=root/"data/lockstatus"; paths.commandHashFile=root/"data/hashes";
  paths.deviceDatabaseFile=root/"data/devices.db"; paths.deviceDatabaseLockFile=root/"data/devices.lock";
  paths.lockDebugLogFile=root/"log/lock.log"; paths.mutationJournalFile=root/"data/mutation-journal.json";
  for(const auto& dir:{paths.configDir,paths.dataDir,paths.logDir,paths.runtimeDir})fs::create_directories(dir);
  if (fs::exists(FIC_PAM_DEPENDENCIES_STATIC_CONFIG_DIR))
   fs::copy(FIC_PAM_DEPENDENCIES_STATIC_CONFIG_DIR, paths.configDir, fs::copy_options::recursive|fs::copy_options::overwrite_existing);
  fs::copy(FIC_PAM_DEPENDENCIES_CONFIG_DIR,paths.configDir,fs::copy_options::recursive|fs::copy_options::overwrite_existing);
  std::string error;need(fic::core::FicRuntimePaths::initialize(paths,error),error);
  auto profile=makeBuildPlatformProfile();PlatformExecutableResolver executables(profile.executables);
  json result={{"platform",profile.id},{"mode",argv[1]}};
  if(std::string(argv[1])=="--test") {
   result["contracts"] = contracts(profile, root);
  } else if(std::string(argv[1])=="--audit") {
   PolicyRegistry registry;need(initPolicyRegistry(profile,executables,registry,error),error);need(validatePolicyDependencyGraph(registry,error),error);
   result["graph_valid"]=true;result["policies"]=json::array();
   for(const auto& option:options){
    const auto capability=p::pamPolicyCapability(option.feature);const auto* config=p::capabilityConfig(profile.pam,capability);
    const auto* policy=registry.findPolicy({"IDENTITY_ACCESS","PAM",option.name});
    json row={{"name",option.name},{"support",support(p::pamPolicySupport(profile.pam,option.feature))},{"registered",policy!=nullptr},
      {"activation",pamCapabilityActivationPolicyName(capability)},{"activation_registered",registry.findPolicy({"IDENTITY_ACCESS","PAM",pamCapabilityActivationPolicyName(capability)})!=nullptr}};
    if(config){
     row["provider"]=p::pamProviderDescriptor(config->provider).name;row["topology"]=topology(config->topology);
     row["configuration_mode"]=config->configurationMode==PamCapabilityConfigurationMode::ModuleArguments?"ModuleArguments":"ProviderConfigFile";
     const auto* binding=p::pamProviderPolicyBinding(config->provider,option.feature);
     if(binding)row["parameter_executor"]=p::usesPamProviderManagedEntry(p::pamProviderDescriptor(config->provider),*config,*binding,option.feature)?(binding->syntax==p::PamNativeOptionSyntax::Flag?"ManagedFlag":"ManagedEntry"):(config->configurationMode==PamCapabilityConfigurationMode::ModuleArguments?"C2ModuleArguments":"Other");
    }
    row["dependencies"]=json::array();if(policy)for(const auto& dep:policy->dependencies())row["dependencies"].push_back({{"name",dep.policy.policyName},{"strength",dep.strength==PolicyDependencyStrength::Required?"Required":"Recommended"}});
    result["policies"].push_back(row);
   }
  } else if(std::string(argv[1])=="--alt-control") {
   need(profile.id=="alt-p11"&&fs::exists("/.dockerenv"),"ALT disposable container required");
   // Scope is deliberately narrowed for this control experiment; this does
   // not claim the stock production scope passed structural verification.
   for(auto& scope:profile.pam.scopes)if(scope.scope==PamScope::EffectiveAuthenticationStack)scope.services={"system-auth"};
   const auto* capability=p::capabilityConfig(profile.pam,PamCapability::AuthenticationLockout);
   const auto* scope=p::scopeConfig(profile.pam,capability->scope);
   auto manager=p::createPamTopologyManager(profile.pam,*capability,scope->services,executables,error);need(bool(manager),error);
   p::PamTopologyStatus status;result["before_inspect"]=manager->inspect(status,error);result["before_detail"]=status.detail+error;
   error.clear();result["enable"]=manager->enableStrategy(PamFaillockStrategy::PreauthRequired,error);result["enable_detail"]=error;
   const std::string first="/etc/pam.d/system-auth-local-only",second="/etc/pam.d/system-auth-use_first_pass-local-only";
   const auto firstBytes=read(first),secondBytes=read(second);result["first_contains_managed"]=firstBytes.find("FIC pam_faillock")!=std::string::npos;
   result["modes"]=json::array();
   for(const auto* mode:{"multi","ldap","local"}){
    auto native=ProcessExecutor::execute("/usr/sbin/control",{"system-auth",mode});
    error.clear();const bool inspected=manager->inspect(status,error);
    result["modes"].push_back({{"mode",mode},{"control_exit",native.exitCode},{"system_auth_target",fs::read_symlink("/etc/pam.d/system-auth").string()},
       {"local_file_bytes_preserved",read(first)==firstBytes&&read(second)==secondBytes},{"inspect",inspected},{"state",static_cast<int>(status.state)},{"manageable",status.manageable},{"detail",status.detail+error}});
   }
  } else throw std::runtime_error("unknown mode");
  write(argv[2],result.dump(2)+"\n");fs::remove_all(root);return 0;
 }catch(const std::exception& e){std::cerr<<e.what()<<'\n';fs::remove_all(root);return 1;}
}
