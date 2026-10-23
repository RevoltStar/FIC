#include "daemon/PackagePayloadManifest.h"
#include <fic/core/integrity/ContentDigest.h>
#include <fic/core/process/ProcessExecutor.h>
#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
using namespace fic::daemon;
namespace fs=std::filesystem;
using json=nlohmann::json;
void require(bool yes,const std::string& error){if(!yes)throw std::runtime_error(error);}
void write(const fs::path& path,const std::string& bytes){std::ofstream out(path);out<<bytes;out.close();require(bool(out),"fixture write");}
int main(int argc,char** argv) {
    if(::geteuid()!=0)return 77;
    char pattern[]="/var/lib/fic-payload-test-XXXXXX";const auto* made=::mkdtemp(pattern);if(!made)return 1;
    const fs::path root=made;
    struct Cleanup{fs::path root;~Cleanup(){std::error_code ec;fs::remove_all(root,ec);}} cleanup{root};
    try {
        const auto directory=root/"payload",file=directory/"binary",link=directory/"link",manifest=root/"manifest";
        fs::create_directory(directory);write(file,"original\n");::chmod(file.c_str(),0644);
        fs::create_symlink("binary",link);
        const json ordinary{{"path",file.string()},{"kind","file"},{"mode",0644u},{"group","root"},
            {"identity",fic::core::ContentDigest::sha256Hex("original\n")}};
        const json symbolic{{"path",link.string()},{"kind","symlink"},{"mode",0u},{"group","root"},{"identity","binary"}};
        const json valid{{"schema",1u},{"package","fic-runtime"},{"version","1:2.0-3"},{"files",json::array({ordinary,symbolic})}};
        const auto publish=[&](const json& value){write(manifest,value.dump()+"\n");::chmod(manifest.c_str(),0644);};
        const auto deadline=[] {return std::chrono::steady_clock::now()+std::chrono::seconds(5);};
        std::string error;PackagePayloadManifest proof;
        publish(valid);
        require(PackagePayloadManifest::load(manifest,"fic-runtime","1:2.0-3",proof,error),error);
        require(proof.proveInstalled(0,deadline(),error),error);
        require(!proof.proveRemoved(deadline(),error),"installed payload counted removed");
        write(file,"foreign\n");require(!proof.proveInstalled(0,deadline(),error),"foreign bytes accepted");write(file,"original\n");
        ::chmod(file.c_str(),0664);require(!proof.proveInstalled(0,deadline(),error),"writable payload accepted");::chmod(file.c_str(),0644);
        fs::create_hard_link(file,root/"hardlink");require(!proof.proveInstalled(0,deadline(),error),"hard-linked payload accepted");fs::remove(root/"hardlink");
        fs::remove(link);fs::create_symlink("elsewhere",link);require(!proof.proveInstalled(0,deadline(),error),"foreign symlink target accepted");
        fs::remove(link);fs::create_symlink("binary",link);
        fs::rename(directory,root/"moved");fs::create_directory_symlink(root/"moved",directory);
        require(!proof.proveInstalled(0,deadline(),error),"nested directory symlink accepted");
        fs::remove(directory);fs::rename(root/"moved",directory);
        require(!proof.proveInstalled(0,std::chrono::steady_clock::now(),error),"expired proof accepted");
        require(proof.proveInstalled(0,deadline(),error),error);
        require(!PackagePayloadManifest::load(manifest,"fic-runtime","2.0-3",proof,error)&&proof.entries().empty(),"epoch/version mismatch retained stale proof");
        for(const auto& invalid:{json{{"schema",2u},{"package","fic-runtime"},{"version","1:2.0-3"},{"files",json::array({ordinary})}},
            json{{"schema",1u},{"package","fic-runtime"},{"version","1:2.0-3"},{"files",json::array()}},
            json{{"schema",1u},{"package","fic-runtime"},{"version","1:2.0-3"},{"files",json::array({ordinary,ordinary})}}}) {
            publish(invalid);require(!PackagePayloadManifest::load(manifest,"fic-runtime","1:2.0-3",proof,error),"invalid schema/duplicate/empty manifest accepted");
        }
        auto bad=valid;bad["files"][0]["mode"]=0u;publish(bad);
        require(!PackagePayloadManifest::load(manifest,"fic-runtime","1:2.0-3",proof,error),"zero-mode disabled metadata proof");
        bad=valid;bad["files"][0]["path"]="/etc/pam.d/fic-password-quality";
        bad["files"][0]["kind"]="managed-pam-slot";bad["files"][0]["identity"]="";publish(bad);
        require(!PackagePayloadManifest::load(manifest,"fic-runtime","1:2.0-3",proof,error),"runtime manifest claimed mutable PAM slot");
        bad["package"]="fic";publish(bad);
        require(PackagePayloadManifest::load(manifest,"fic","1:2.0-3",proof,error),error);
        bad["files"][0]["path"]="/etc/pam.d/system-auth";publish(bad);
        require(!PackagePayloadManifest::load(manifest,"fic","1:2.0-3",proof,error),"arbitrary path escaped payload digest verification");
        publish(valid);::chmod(manifest.c_str(),0664);
        require(!PackagePayloadManifest::load(manifest,"fic-runtime","1:2.0-3",proof,error),"writable manifest trusted");
        publish(valid);auto duplicate=valid.dump();duplicate.insert(1,"\"schema\":1,");write(manifest,duplicate);
        require(!PackagePayloadManifest::load(manifest,"fic-runtime","1:2.0-3",proof,error),"duplicate manifest key accepted");
        publish(valid);require(PackagePayloadManifest::load(manifest,"fic-runtime","1:2.0-3",proof,error),error);
        fs::remove_all(directory);require(proof.proveRemoved(deadline(),error),error);
        fs::create_directory_symlink(root/"missing",directory);
        require(!proof.proveRemoved(deadline(),error),"dangling parent alias proved payload removed");
        // Alias checks run in a child chroot containing only test files. Never
        // replace the real host/container /lib or alter mount propagation.
        const auto isolated=root/"isolated";fs::create_directories(isolated/"usr/lib");
        write(isolated/"usr/lib/payload","payload\n");::chmod((isolated/"usr/lib/payload").c_str(),0644);
        auto aliases=valid;aliases["files"]=json::array({json{{"path","/lib/payload"},{"kind","file"},{"mode",0644u},
            {"group","root"},{"identity",fic::core::ContentDigest::sha256Hex("payload\n")}}});
        publish(aliases);require(PackagePayloadManifest::load(manifest,"fic-runtime","1:2.0-3",proof,error),error);
        const auto probeAlias=[&](bool expected) {
            const auto child=::fork();require(child>=0,"fork alias probe");
            if(child==0) {
                if(::chdir(isolated.c_str())||::chroot("."))::_exit(98);
                const bool proven=proof.proveInstalled(0,deadline(),error);::_exit(proven==expected?0:99);
            }
            int status=0;require(::waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0,"usr-merge alias proof mismatch/chroot unavailable");
        };
        fs::create_symlink("usr/lib",isolated/"lib");probeAlias(true);
        fs::remove(isolated/"lib");fs::create_symlink("/usr/lib",isolated/"lib");probeAlias(true);
        ::lchown((isolated/"lib").c_str(),0,1);probeAlias(false);::lchown((isolated/"lib").c_str(),0,0);
        fs::remove(isolated/"lib");fs::create_symlink("usr/elsewhere",isolated/"lib");probeAlias(false);
        fs::remove(isolated/"lib");fs::create_symlink("usr/lib",isolated/"lib");
        fs::rename(isolated/"usr/lib",isolated/"usr/real-lib");fs::create_directory_symlink("real-lib",isolated/"usr/lib");probeAlias(false);
        require(argc==3,"Python and staged manifest generator arguments required");
        const auto staged=root/"staged";fs::create_directory(staged);
        write(staged/"binary","original\n");::chmod((staged/"binary").c_str(),0644);fs::create_symlink("binary",staged/"link");
        ProcessOptions options;options.timeout=std::chrono::seconds(5);options.maxOutputBytes=8192;
        const auto generated=ProcessExecutor::execute(argv[1],{argv[2],staged.string(),"fic-runtime","1:2.0-3",manifest.string()},options);
        require(generated.success(),"staged manifest generator failed: "+generated.standardError);
        require(PackagePayloadManifest::load(manifest,"fic-runtime","1:2.0-3",proof,error),error);
        const auto child=::fork();require(child>=0,"fork generated payload proof");
        if(child==0) {
            if(::chdir(staged.c_str())||::chroot("."))::_exit(98);
            ::_exit(proof.proveInstalled(0,deadline(),error)?0:99);
        }
        int status=0;require(::waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0,"generated payload failed production reader/proof");
        const auto refused=ProcessExecutor::execute(argv[1],{argv[2],staged.string(),"fic-runtime","1",(staged/"recursive-manifest").string()},options);
        require(!refused.success()&&!fs::exists(staged/"recursive-manifest"),"generator included its own mutable output");
        std::cout<<"PASS: immutable payload bytes/metadata, exact identity, stale/duplicate/malformed refusal, separate PAM slot authority, trusted absence proof\n";
    }catch(const std::exception& exception){std::cerr<<exception.what()<<'\n';return 1;}
}
