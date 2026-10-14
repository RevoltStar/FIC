#include "modules/global/lock_settings/GLOBAL_lock_exempt_fic_members.h"
#include "incident/IncidentRecoveryConfigReader.h"
#include "policy/registry/PolicyRegistryInitialization.h"
#include "policy/registry/PolicyRegistryJson.h"
#include <fic/core/runtime/FicRuntimePaths.h>
#include <fic/core/config/ConfigAuthority.h>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <cstdlib>
#include <iostream>
#include <fic/core/runtime/FicPathDefaults.h>
#include <unistd.h>
#include <sys/stat.h>

namespace fs=std::filesystem;
void require(bool value,const std::string& error) {if(!value)throw std::runtime_error(error);}
int main(int argc,char** argv) {
    if(argc==2&&std::string(argv[1])=="--native") {
        require(geteuid()==0&&fs::exists("/.dockerenv")&&std::getenv("FIC_RECOVERY_NATIVE_GATE")&&
                std::string(std::getenv("FIC_RECOVERY_NATIVE_GATE"))=="container-only","native gate requires explicit disposable container");
        std::string error;require(fic::core::FicRuntimePaths::initialize(fic::core::FicProductPaths::production(),error),error);
        const auto file=fs::path(fic::core::path_defaults::CONFIG_DIR)/"GLOBAL.conf";
        for(bool enabled:{true,false,true}) {
            ModuleConfigFileHandler config("GLOBAL");require(config.loadConfig(),"production config load failed");
            require(config.setPolicyStatus("lock_exempt_fic_members",enabled?"ENABLE":"DISABLE")&&config.saveConfig(),"production status save failed");
            GLOBAL_lock_exempt_fic_members policy;
            require(policy.isEnabled()==enabled&&policy.apply(),"production policy/reader status mismatch");
            require(fic::incident::IncidentRecoveryConfigReader::ficMemberExemptionStatus(error)==std::optional<bool>(enabled),"standalone production reader disagrees");
        }
        {std::ofstream f(file);f<<"lock_exempt_fic_members.status=INVALID\n";}
        GLOBAL_lock_exempt_fic_members broken;require(!broken.apply(),"broken production config accepted");
        require(!fic::incident::IncidentRecoveryConfigReader::ficMemberExemptionStatus(error),"broken standalone reader became permissive");
        std::cout<<"native production recovery policy/secure reader/status mutations: PASS\n";
        return 0;
    }

    const auto root=fs::temp_directory_path()/("fic-recovery-policy-"+std::to_string(getpid()));
    fs::create_directories(root/"config");fs::create_directories(root/"log");
    ::chmod(root.c_str(),02750);::chmod((root/"config").c_str(),02750);
    auto paths=fic::core::FicProductPaths::production();paths.configDir=root/"config";paths.logDir=root/"log";
    std::string error;require(fic::core::FicRuntimePaths::initialize(paths,error),error);
    const auto file=root/"config/GLOBAL.conf";
    const auto write=[&](const std::string& text){std::ofstream(file)<<"_schema_version=1\n"<<text;::chmod(file.c_str(),0640);};
    auto expected=fic::core::configAuthorityExpectation({geteuid(),getegid()});
    const auto reader=[&](std::string& diagnostic){return fic::incident::IncidentRecoveryConfigReader::readStatus(file,expected,diagnostic);};
    try {
        write("lock_exempt_fic_members.status=ENABLE\n");
        PolicyList policies;policies.push_back(std::make_unique<GLOBAL_lock_exempt_fic_members>(reader));
        PolicyRegistry registry;require(buildPolicyRegistry(std::move(policies),registry,error),error);
        auto* policy=registry.findPolicy({"GLOBAL","lock_settings","lock_exempt_fic_members"});
        require(policy&&policy->dependencies().empty()&&policy->isEnabled()&&policy->apply(),"enabled policy registration/apply failed");
        const auto descriptor=policyToJson("GLOBAL","lock_settings","lock_exempt_fic_members",*policy);
        require(descriptor.at("editor")=="label"&&descriptor.at("default_value")=="ENABLE"&&!descriptor.at("set").get<bool>(),"status-only descriptor changed");
        write("lock_exempt_fic_members.status=DISABLE\n");require(!policy->apply(),"stale registry accepted changed intent");
        GLOBAL_lock_exempt_fic_members disabled(reader);require(!disabled.isEnabled()&&disabled.apply(),"valid disabled exemption failed verification");
        ModuleConfigFileHandler config("GLOBAL");require(config.loadConfig()&&config.enablePolicy("lock_exempt_fic_members")&&config.saveConfig(),"enable mutation failed");
        GLOBAL_lock_exempt_fic_members enabled(reader);require(enabled.isEnabled()&&enabled.apply(),"enabled mutation not effective");
        require(config.disablePolicy("lock_exempt_fic_members")&&config.saveConfig(),"disable mutation failed");
        GLOBAL_lock_exempt_fic_members off(reader);require(!off.isEnabled()&&off.apply(),"disabled mutation not effective");
        for(const auto& bad:{"", "lock_exempt_fic_members.status=INVALID\n", "lock_exempt_fic_members.status=ENABLE\nlock_exempt_fic_members.status=DISABLE\n"}) {
            write(bad);GLOBAL_lock_exempt_fic_members broken(reader);require(!broken.apply(),"untrusted/missing recovery status accepted");
        }
        write("lock_exempt_fic_members.status=ENABLE\n");GLOBAL_lock_exempt_fic_members unsafe(reader);
        ::chmod(file.c_str(),0666);require(!unsafe.apply(),"unsafe metadata accepted");::chmod(file.c_str(),0640);
        fs::rename(file,file.string()+".real");fs::create_symlink(file.string()+".real",file);
        require(!unsafe.apply(),"symlink config accepted");
    } catch(...) {fs::remove_all(root);throw;}
    fs::remove_all(root);
}
