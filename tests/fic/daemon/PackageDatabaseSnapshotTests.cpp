#include "daemon/PackageDatabaseSnapshot.h"
#include <iostream>
#include <stdexcept>
using namespace fic::daemon;
using fic::platform::PackageManagerKind;
void require(bool yes,const std::string& error){if(!yes)throw std::runtime_error(error);}
int main() {
    try {
        PackageDatabaseSnapshot snapshot;std::string error;
        std::vector<std::filesystem::path> owned;
        require(parseFicPackageOwnedPaths("/.\n/usr\n/usr/libexec/fic/fic-runtime\n",owned,error)&&
            owned.size()==3&&owned.front()=="/","native dpkg root path not normalized");
        require(parseFicPackageOwnedPaths("/usr/share/fic/file with spaces\n",owned,error),error);
        for(const auto& text:{std::string(""),std::string("relative\n"),std::string("/a/../b\n"),
            std::string("/a//b\n"),std::string("/a/./b\n"),std::string("/a\n/a\n"),std::string("/.\n/\n"),
            std::string("/a"),std::string("/a\tbad\n"),std::string("/a\0b\n",5),std::string(1024*1024+1,'x')})
            require(!parseFicPackageOwnedPaths(text,owned,error)&&owned.empty(),"unproven file list retained/accepted");
        const auto parse=[&](PackageManagerKind kind,const std::string& text){return parseFicPackageDatabase(kind,text,snapshot,error);};
        require(parse(PackageManagerKind::Dpkg,"fic\tinstall ok installed\t1:2.0-3\tamd64\nfic-runtime\tinstall ok installed\t1:2.0-3\tamd64\n"),error);
        require(snapshot.packages.size()==2&&snapshot.packages.at("fic").state==PackageInstallState::Installed&&
            snapshot.packages.at("fic").version=="1:2.0-3","installed version identity lost");
        require(proveRuntimePackagePrerequisite(snapshot,"1:2.0-3",error),error);
        require(!proveRuntimePackagePrerequisite(snapshot,"2.0-3",error),"runtime epoch mismatch accepted");
        require(!proveRuntimePackagePrerequisite(snapshot,"",error),"missing compiled runtime identity accepted");
        for(const auto state:{PackageInstallState::Absent,PackageInstallState::ConfigFiles,PackageInstallState::Incomplete}) {
            snapshot.packages.at("fic-runtime").state=state;
            require(!proveRuntimePackagePrerequisite(snapshot,"1:2.0-3",error),"unconfigured runtime accepted");
        }
        for(const auto* status:{"install ok half-configured","install ok unpacked","install ok triggers-pending",
            "install ok triggers-awaited","install reinstreq installed","deinstall ok installed","purge ok half-installed"}) {
            require(parse(PackageManagerKind::Dpkg,std::string("fic\t")+status+"\t2\tamd64\n")&&
                snapshot.packages.at("fic").state==PackageInstallState::Incomplete,"incomplete dpkg state treated as installed");
        }
        require(parse(PackageManagerKind::Dpkg,"fic\tdeinstall ok config-files\t2\tamd64\n")&&
            snapshot.packages.at("fic").state==PackageInstallState::ConfigFiles,"config-files state lost");
        require(parse(PackageManagerKind::Dpkg,"fic\tpurge ok not-installed\t\t\n")&&
            snapshot.packages.at("fic").state==PackageInstallState::Absent,"not-installed observation lost");
        require(parse(PackageManagerKind::Rpm,"fic\t(none)\t2.0-alt1\tx86_64\nfic-runtime\t2\t2.0-alt1\tx86_64\n"),error);
        require(snapshot.packages.at("fic").version=="0:2.0-alt1"&&snapshot.packages.at("fic-runtime").version=="2:2.0-alt1","RPM epoch normalized incorrectly");
        require(proveRuntimePackagePrerequisite(snapshot,"2:2.0-alt1",error),error);
        require(!proveRuntimePackagePrerequisite(snapshot,"0:2.0-alt1",error)&&
            !proveRuntimePackagePrerequisite(snapshot,"2:2.0-alt2",error),"RPM runtime epoch/release mismatch accepted");
        require(!parse(PackageManagerKind::Rpm,"fic\t(none)\t1-alt1\tx86_64\nfic\t(none)\t2-alt1\tx86_64\n")&&
            snapshot.packages.empty(),"failed RPM upgrade duplicate versions collapsed");
        for(const auto* text:{"fic\tinstall ok mystery\t2\tamd64\n","fic\tinstall ok installed\t2\tamd64",
            "fic\tinstall ok installed\t2\t\n","fic\tinstall ok installed extra\t2\tamd64\n",
            "fic\tinstall ok installed\t2\tamd64\textra\n"})
            require(!parse(PackageManagerKind::Dpkg,text)&&snapshot.packages.empty(),"unproven dpkg output accepted");
        require(!parse(PackageManagerKind::Rpm,"fic\t01\t2-alt1\tx86_64\n"),"ambiguous epoch accepted");
        require(!parse(static_cast<PackageManagerKind>(123),""),"unknown package manager accepted");
        require(!parse(PackageManagerKind::Dpkg,std::string(1024*1024+1,'x')),"oversized output accepted");
        require(parse(PackageManagerKind::Rpm,"unrelated\t(none)\t1\tx86_64\n")&&snapshot.packages.empty(),"unrelated package claimed");
        require(!proveRuntimePackagePrerequisite(snapshot,"1",error),"missing runtime accepted");
        fic::platform::PlatformExecutableResolver noExecutables({});
        PackageDatabaseReader reader(noExecutables,PackageManagerKind::Dpkg);
        PackageManagerTransactionLock noLocks;
        std::size_t budget=1234;
        require(!reader.read(noLocks,std::chrono::steady_clock::now()+std::chrono::seconds(1),budget,snapshot,error)&&
            budget==1234&&snapshot.packages.empty()&&error.find("transaction locks")!=std::string::npos,
            "database query proceeded without matching transaction admission");
        owned={"/stale"};
        require(!reader.readOwnedPaths(noLocks,"fic",std::chrono::steady_clock::now()+std::chrono::seconds(1),budget,owned,error)&&
            owned.empty()&&budget==1234,"file list query bypassed package-manager admission");
        require(!reader.readOwnedPaths(noLocks,"foreign",std::chrono::steady_clock::now()+std::chrono::seconds(1),budget,owned,error)&&
            error.find("unknown payload package")!=std::string::npos,"unknown package query accepted");
        require(!reader.observeRuntimePrerequisite("",std::chrono::steady_clock::now()+std::chrono::seconds(1),budget,error)&&budget==1234,
            "prerequisite query proceeded without exact version");
        std::cout<<"PASS: dpkg incomplete/config-files/installed distinction, RPM EVR/duplicate refusal, bounded strict parser\n";
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
