#include "modules/identity_access/sssd/SssdConfiguration.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>
namespace fs=std::filesystem;
void require(bool ok,const std::string& message){if(!ok)throw std::runtime_error(message);}
int main(){
    if(::geteuid()!=0)return 77;
    char pattern[]="/run/fic-sssd-uninstall-XXXXXX";
    const auto made=::mkdtemp(pattern);if(!made)return 1;
    const fs::path root=made;
    struct Cleanup{fs::path root;~Cleanup(){std::error_code ec;fs::remove_all(root,ec);}} cleanup{root};
    try{
        auto options=fic::identity::sssd::SssdConfigurationOptions::production();
        const auto directory=root/"sssd/conf.d";options.managedSnippetFile=directory/"zzzz-fic.conf";
        bool absent=false;std::string error;
        const auto proof=[&]{return fic::identity::sssd::proveManagedSnippetAbsent(options,absent,error);};
        require(proof()&&absent,error);
        fs::create_directory(root/"sssd");require(proof()&&absent,error);
        fs::create_directory(directory);require(proof()&&absent,error);
        const auto staged=options.managedSnippetFile.string()+".fic-removing-test";
        std::ofstream(staged)<<"staged";require(!proof(),"staged removal treated as absence");fs::remove(staged);
        std::ofstream(options.managedSnippetFile)<<"[pam]\noffline_credentials_expiration=5\n";
        ::chmod(options.managedSnippetFile.c_str(),0600);
        require(proof()&&!absent,"existing snippet treated as absence");
        ::chmod(options.managedSnippetFile.c_str(),0666);require(!proof(),"unsafe snippet accepted");
        fs::remove(options.managedSnippetFile);fs::create_symlink("missing",options.managedSnippetFile);
        require(!proof(),"dangling managed symlink treated as absence");fs::remove(options.managedSnippetFile);
        fs::remove(directory);fs::remove(root/"sssd");fs::create_symlink(root/"missing",root/"sssd");
        require(!proof(),"aliased missing ancestor accepted");
        std::cout<<"PASS: missing SSSD ancestors, staging/orphan/metadata/alias guards; no effective-state assumptions\n";
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
