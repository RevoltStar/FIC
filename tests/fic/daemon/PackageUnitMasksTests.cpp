#include "daemon/PackageUnitMasks.h"
#include "daemon/PackageWriterUnits.h"
#include <fic/core/fs/AtomicFileWriter.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>
using namespace fic::daemon;
namespace fs=std::filesystem;
void require(bool yes,const std::string& text){if(!yes)throw std::runtime_error(text);}
int main() {
    if(::geteuid()!=0)return 77;
    std::string pattern="/run/fic-masks-test-XXXXXX";char* created=::mkdtemp(pattern.data());if(!created)return 1;
    const fs::path root=created;
    struct Cleanup {fs::path root;~Cleanup(){std::error_code e;fs::remove_all(root,e);}} cleanup{root};
    try {
        const auto units=root/"units",state=root/"state";fs::create_directory(units);fs::create_directory(state);::chmod(state.c_str(),0700);
        DaemonInstanceLock guard,empty;std::string error;require(guard.tryAcquire(root/"runtime",error),error);
        PackageUnitMasks masks(state,units);const std::string id(32,'a');
        fs::create_symlink("/dev/null",units/"fic-notify.service");
        struct stat before{};require(::lstat((units/"fic-notify.service").c_str(),&before)==0,"foreign stat");
        require(!masks.prepare(empty,id,error),"unguarded plan");
        require(masks.prepare(guard,id,error),error);
        require(!masks.prepare(guard,id,error),"existing provenance adopted");
        require(!masks.provePublished(id,error),"absent masks accepted");
        require(masks.publish(guard,id,error),error);
        require(masks.provePublished(id,error),error);
        for(const auto* unit:PackageWriterUnits)require(fs::is_symlink(units/unit),std::string("unfenced writer: ")+unit);
        require(masks.publish(guard,id,error),"idempotent publish");
        PackageUnitMasks restarted(state,units);require(restarted.provePublished(id,error),"restart lost provenance");
        // Simulate crash halfway through publication: remaining mask is still
        // recognized by its immutable pre-mutation operation-owned artifact.
        fs::remove(units/"fic-device.service");require(restarted.publish(guard,id,error),error);
        require(!restarted.restore(empty,id,error),"unguarded restore");
        require(restarted.restore(guard,id,error),error);
        for(const auto* unit:PackageWriterUnits)if(std::string(unit)!="fic-notify.service")
            require(!fs::is_symlink(units/unit),std::string("own mask remained: ")+unit);
        require(!fs::exists(units/"fic.service")&&!fs::exists(units/"fic-device.service"),"own masks remained");
        struct stat after{};require(::lstat((units/"fic-notify.service").c_str(),&after)==0&&before.st_ino==after.st_ino,"foreign mask removed/replaced");
        require(restarted.restore(guard,id,error),"idempotent restore");
        require(masks.publish(guard,id,error),error);
        fs::remove(units/"fic.service");std::ofstream(units/"fic.service")<<"foreign override";
        require(!masks.restore(guard,id,error),"foreign override unlinked");
        std::ifstream input(units/"fic.service");std::string text;std::getline(input,text);require(text=="foreign override","foreign content changed");
        const std::string other(32,'b');require(!masks.prepare(guard,other,error)&&!fs::exists(state/other),"custom override admitted / preparation mutated before refusal");
        fs::remove(units/"fic.service");require(masks.publish(guard,id,error),error);
        // Provenance loss is never interpreted as an absent/no-op mask set.
        fs::rename(state/id/"masked-unit",state/id/"old-artifact");std::ofstream(state/id/"masked-unit");::chmod((state/id/"masked-unit").c_str(),0600);
        require(!masks.restore(guard,id,error)&&fs::is_symlink(units/"fic.service"),"artifact replacement accepted");
        const auto ledger=state/id/"masks.json";
        {std::ofstream corrupt(ledger);corrupt<<"unknown";}
        require(!masks.provePublished(id,error),"corrupt ledger accepted");
        fs::create_directory(root/"writable");::chmod((root/"writable").c_str(),0770);
        PackageUnitMasks unsafe(root/"writable",units);require(!unsafe.prepare(guard,other,error),"writable ancestor admitted");
        std::cout<<"PASS: immutable mask plan, restart/partial publish, ownership-safe restore and fail-closed provenance\n";
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
