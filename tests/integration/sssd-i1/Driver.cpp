#include "service/sssd/SssdVerifiedInputClosure.h"
#include <nlohmann/json.hpp>
#include <iostream>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>
using namespace fic::service;
namespace s=fic::service::sssd;
using J=nlohmann::json;
void write(const std::string& p,const std::string& b){std::ofstream f(p);f<<b;f.close();chmod(p.c_str(),0600);}
int main(int argc,char** argv) {
    J out;try {
        auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(30);
        const std::string action=argc>1?argv[1]:"capture";
        if(action=="launch")out["launch"]=detail::readSssdLaunchContract(deadline);
        else if(action=="admission") {auto r=s::admit(deadline);out["platform"]=r.profile.platform;out["launch"]=r.contract;out["activation_limit"]=r.activationLimit;}
        else if(action.rfind("admit-",0)==0) {
            s::detail_i1::admitForTests(deadline,[&](const s::SssdLaunchReference& r){
                out["checkpoint"]={{"process",r.processIdentity},{"environment",r.environmentFingerprint},{"lookup",r.unitLookupFingerprint}};
                if(action=="admit-control")return;
                if(action=="admit-unit") {
                    std::ofstream f(r.profile.fragment,std::ios::app);f<<"\n# I1 admission mutation; ExecStart unchanged\n";
                } else if(action=="admit-env-bytes"||action=="admit-env-create")write(r.profile.environment,"# admission changed\n");
                else if(action=="admit-env-inode") {
                    std::ifstream f(r.profile.environment);std::string bytes((std::istreambuf_iterator<char>(f)),{});
                    write(r.profile.environment+".i1-tmp",bytes);
                    if(rename((r.profile.environment+".i1-tmp").c_str(),r.profile.environment.c_str()))throw std::runtime_error("rename fixture failed");
                } else if(action=="admit-dropin") {
                    std::filesystem::create_directories("/etc/systemd/system/sssd.service.d");
                    write("/etc/systemd/system/sssd.service.d/i1-admission.conf","[Service]\nEnvironment=I1_TEST=1\n");
                } else throw std::runtime_error("unknown admission checkpoint");
                out["injected"]=true;
            });
        }
        else if(action=="source-change") {
            auto r=s::capture(deadline);write(r.launch.profile.environment,"# changed after reference\n");s::revalidate(r,deadline);
        }
        else if(action=="dropin-change") {
            auto r=s::capture(deadline);std::filesystem::create_directories("/etc/systemd/system/sssd.service.d");
            write("/etc/systemd/system/sssd.service.d/i1.conf","[Service]\nEnvironment=DEBUG_LOGGER=--logger=stderr\n");s::revalidate(r,deadline);
        }
        else if(action=="unit-change") {
            auto r=s::capture(deadline);write(r.launch.profile.fragment,"# changed native source\n");s::revalidate(r,deadline);
        }
        else if(action.rfind("race-",0)==0) {
            auto l=s::admit(deadline);
            const std::string p="/etc/sssd/conf.d/50-race.conf";
            auto r=s::detail_i1::captureForTests(l,"",deadline,[&]{
                if(action=="race-create")write("/etc/sssd/conf.d/51-new.conf","[pam]\ndebug_level=8\n");
                else if(action=="race-delete")unlink(p.c_str());
                else if(action=="race-inode") {write(p+".tmp","[pam]\ndebug_level=7\n");rename((p+".tmp").c_str(),p.c_str());}
                else if(action=="race-bytes")write(p,"[pam]\ndebug_level=8\n");
                else if(action=="race-metadata")chmod(p.c_str(),0400);
                else if(action=="race-restore") {write(p,"[pam]\ndebug_level=8\n");write(p,"[pam]\ndebug_level=7\n");}
                else throw std::runtime_error("unknown checkpoint");
            });(void)r;
        } else {
            auto r=s::capture(deadline);out["platform"]=r.launch.profile.platform;out["launch"]=r.launch.contract;
            out["fic_named_file_observed"]=r.sources.at("/etc/sssd").tree.files.count("conf.d/zzzz-fic.conf")!=0;
            out["order"]=r.order;out["absent"]=r.negativeDependencies;out["later"]=r.laterForeignSnippets;out["apply_conflict"]=r.applyConflict();
            out["engine_negative_gap"]=r.engineNeedsNegativeDependencySupport;out["activation_limit"]=r.launch.activationLimit;
            for(const auto& [sec,keys]:r.ini)for(const auto& [k,v]:keys)out["projection"][sec][k]=J{{"value",v.value},{"source",v.source}};
            for(const auto& [p,src]:r.sources)out["sources"][p]=J{{"present",src.present},{"mount",src.identity.mount},{"inode",src.identity.inode},{"files",src.tree.files.size()},{"objects",src.tree.attributes.size()}};
            s::revalidate(r,deadline);
        }
        out["status"]="CAPTURED";
    }catch(const detail::Failure& e) {out["status"]=activationStatusName(e.status);out["diagnostic"]=e.what();}
    catch(const std::exception& e){out["status"]="ERROR";out["diagnostic"]=e.what();}
    std::cout<<out.dump(2)<<std::endl;return 0;
}
