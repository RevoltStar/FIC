#include "daemon/UninstallOverride.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>
using namespace fic::daemon;
namespace fs=std::filesystem;
void require(bool ok,const std::string& text){if(!ok)throw std::runtime_error(text);}
int main(){
    if(::geteuid()!=0)return 77;
    char pattern[]="/run/fic-uninstall-override-XXXXXX";const auto* made=::mkdtemp(pattern);if(!made)return 1;
    const fs::path root=made,file=root/"override";
    struct Cleanup{fs::path root;~Cleanup(){std::error_code ec;fs::remove_all(root,ec);}} cleanup{root};
    try {
        std::string error;UninstallOverride result;
        require(readUninstallOverride(result,error,file)&&!result.present&&result.rollback==UninstallRollbackMode::Standard&&
            result.prepare==UninstallRequirement::Required&&result.stop==UninstallRequirement::Required,"strict absent defaults");
        const auto write=[&](const std::string& text){std::ofstream(file)<<text;::chmod(file.c_str(),0600);};
        for(const auto* mode:{"STANDARD","IGNORE_ERROR","SKIP"})for(const auto* prepare:{"TRUE","FALSE","SKIP"})for(const auto* stop:{"TRUE","FALSE","SKIP"}) {
            write(std::string("# safe data\nROLLBACK_TYPE=")+mode+"\nFIC_REQUIRED_UNINSTALL_STATUS="+prepare+"\nFIC_REQUIRED_STOP="+stop+"\n");
            require(readUninstallOverride(result,error,file)&&result.present,error);
            require((result.rollback==UninstallRollbackMode::Skip)==(std::string(mode)=="SKIP"),"rollback projection");
            require((result.prepare==UninstallRequirement::Skip)==(std::string(prepare)=="SKIP"),"prepare projection");
            require((result.stop==UninstallRequirement::BestEffort)==(std::string(stop)=="FALSE"),"stop projection");
        }
        for(const auto& invalid:std::vector<std::string>{std::string("ROLLBACK_TYPE=SKIP\nUNKNOWN=TRUE\n"),"ROLLBACK_TYPE=SKIP_ACTIVE\n", "ROLLBACK_TYPE=SKIP\nROLLBACK_TYPE=STANDARD\n",
            "ROLLBACK_TYPE='SKIP'\n", "FIC_REQUIRED_STOP=$(touch /tmp/fic-forbidden)\n", "export ROLLBACK_TYPE=SKIP\n", "ROLLBACK_TYPE=SKIP # inline\n",
            "FIC_REQUIRED_STOP=true\n", "missing separator\n", std::string(4097,'x'), std::string("ROLLBACK_TYPE=SKIP\0junk",23)}) {
            write(invalid);require(!readUninstallOverride(result,error,file)&&!result.present&&result.rollback==UninstallRollbackMode::Standard,"invalid/partial override admitted");
        }
        write("ROLLBACK_TYPE=SKIP\n");::chmod(file.c_str(),0660);require(!readUninstallOverride(result,error,file),"group-write accepted");
        ::chmod(file.c_str(),0600);::chown(file.c_str(),1,1);require(!readUninstallOverride(result,error,file),"foreign owner accepted");::chown(file.c_str(),0,0);
        fs::create_hard_link(file,root/"alias");require(!readUninstallOverride(result,error,file),"hard link accepted");fs::remove(root/"alias");
        fs::rename(file,root/"real");fs::create_symlink(root/"real",file);require(!readUninstallOverride(result,error,file),"symlink accepted");
        std::cout<<"PASS: strict defaults, all27 combinations, malformed/duplicate/unknown/injection/oversize, metadata/link trust\n";
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
