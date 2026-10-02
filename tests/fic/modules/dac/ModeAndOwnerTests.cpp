#include "modules/dac/mode_and_owner/ModeAndOwnerProfilesPolicy.h"
#include <fic/core/runtime/FicRuntimePaths.h>
#include <filesystem>
#include <fstream>
#include <grp.h>
#include <pwd.h>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

namespace { namespace fs = std::filesystem;
using Dac = fic::platform::DacPlatformConfig;
void require(bool v, const std::string& m) { if (!v) throw std::runtime_error(m); }
std::string owner() { return ::getpwuid(::geteuid())->pw_name; }
std::string group() { return ::getgrgid(::getegid())->gr_name; }
void write(const fs::path& p, const std::string& s, mode_t m) {
    fs::create_directories(p.parent_path()); std::ofstream o(p); o << s; o.close();
    require(::chmod(p.c_str(), m) == 0, "chmod failed");
}
mode_t mode(const fs::path& p) { struct stat s {}; require(::lstat(p.c_str(), &s) == 0, "stat failed"); return s.st_mode & 07777; }
void setupPaths(const fs::path& r) {
    auto p = fic::core::FicProductPaths::production();
    p.configDir=r/"config"; p.defaultConfigDir=r/"defaults"; p.logDir=r/"log";
    p.notifyDir=r/"notify"; p.dataDir=r/"data"; p.runtimeDir=r/"run";
    fs::create_directories(p.configDir); fs::create_directories(p.logDir);
    fs::create_directories(p.notifyDir); std::string error;
    require(fic::core::FicRuntimePaths::initialize(p, error), error);
}
Dac::PathContract contract(mode_t m) { Dac::PathContract c; c.metadata={owner(),group(),m}; c.required=true; return c; }
Dac platform(const fs::path& a, const fs::path& b={}) {
    Dac d; Dac::StaticPathObject one{a,{{Dac::Profile::System,contract(0644)},{Dac::Profile::Strict,contract(0600)}}};
    d.modeAndOwnerObjects.push_back({"first",std::move(one)});
    if (!b.empty()) { Dac::StaticPathObject two{b,{{Dac::Profile::System,contract(0644)},{Dac::Profile::Strict,contract(0600)}}}; d.modeAndOwnerObjects.push_back({"second",std::move(two)}); }
    return d;
}
void configure(const fs::path& r, const std::string& json) {
    write(r/"config/DAC.conf", "_schema_version=1\nmode_and_owner_profiles.status=ENABLE\nmode_and_owner_profiles.value="+json+"\n",0640);
}
void testParser(const fs::path& r) {
    Dac d=platform(r/"one",r/"two"); ModeAndOwnerProfilesPolicyTypeValue t(d);
    require(t.validate(""),"empty rejected"); require(t.validate(" first = strict \n\nsecond=system "),"valid rejected");
    require(!t.validate("first=strict\nfirst=system"),"duplicate accepted"); require(!t.validate("unknown=system"),"unknown accepted");
    require(!t.validate("first=optimal"),"unavailable accepted"); require(!t.validate("first=strict=system"),"malformed accepted");
    const std::string stored=t.postProcessingValue("second=system\nfirst=strict");
    require(stored=="{\"first\":\"strict\",\"second\":\"system\"}","noncanonical JSON");
    require(t.reverse_postProcessingValue(stored)=="first=strict\nsecond=system","roundtrip failed");
}
void testDesiredStateAndRelease(const fs::path& r) {
    fs::path f=r/"managed"; write(f,"data",0666); Dac d=platform(f);
    configure(r,"{\"first\":\"strict\"}"); DAC_mode_and_owner_profiles strict(d); require(strict.apply(),"strict failed"); require(mode(f)==0600,"strict not applied");
    configure(r,"{\"first\":\"system\"}"); DAC_mode_and_owner_profiles system(d); require(system.apply(),"system failed"); require(mode(f)==0644,"system not applied");
    require(::chmod(f.c_str(),0600)==0,"test chmod failed"); configure(r,"{}"); DAC_mode_and_owner_profiles released(d); require(released.apply(),"empty failed"); require(mode(f)==0600,"omitted object mutated");
}
void testPreflightAndAggregation(const fs::path& r) {
    fs::path a=r/"a-first", b=r/"z-second"; write(a,"a",0666); write(b,"b",0666); Dac d=platform(a,b);
    ModeAndOwnerProfilesPolicyTypeValue t(d); require(!t.validate("first=strict\nsecond=optimal"),"late invalid accepted"); require(mode(a)==0666&&mode(b)==0666,"validation mutated");
    fs::remove(a); fs::create_directory(a); configure(r,"{\"first\":\"strict\",\"second\":\"strict\"}"); DAC_mode_and_owner_profiles p(d);
    require(!p.apply(),"aggregate failure succeeded"); require(mode(b)==0600,"runtime loop stopped early");
}
void testUserHomesDoesNotMutateRoot(const fs::path& r) {
    const fs::path homesRoot=r/"homes";
    const fs::path accountHome=homesRoot/owner();
    fs::create_directories(accountHome);
    require(::chmod(homesRoot.c_str(),0755)==0,"root chmod failed");
    require(::chmod(accountHome.c_str(),0755)==0,"home chmod failed");
    const fs::path passwd=r/"local-passwd";
    write(passwd,owner()+":x:"+std::to_string(::geteuid())+":"+
          std::to_string(::getegid())+"::"+accountHome.string()+":/bin/sh\n",0644);
    Dac d; Dac::UserHomesObject homes;
    homes.rootPath=homesRoot; homes.passwdPath=passwd;
    homes.directoryModes={{Dac::Profile::System,0755},{Dac::Profile::Strict,0700}};
    d.modeAndOwnerObjects.push_back({"user_homes",std::move(homes)});
    configure(r,"{\"user_homes\":\"strict\"}");
    DAC_mode_and_owner_profiles policy(d);
    require(policy.apply(),"user homes apply failed");
    require(mode(homesRoot)==0755,"user homes handler mutated /home root");
    require(mode(accountHome)==0700,"user home strict mode not applied");
}
void testCollectionAndProviderSafety(const fs::path& r) {
    const fs::path command=r/"command"; write(command,"binary",07755);
    Dac commands;
    Dac::PathContract system=contract(0755);
    Dac::PathContract strict=contract(0750);
    system.modeSemantics=Dac::ModeSemantics::MaximumAllowed;
    strict.modeSemantics=Dac::ModeSemantics::MaximumAllowed;
    Dac::CollectionMember member{command,{{Dac::Profile::System,system},{Dac::Profile::Strict,strict}}};
    Dac::PathCollectionObject collection; collection.members.push_back(std::move(member));
    commands.modeAndOwnerObjects.push_back({"df",std::move(collection)});
    configure(r,"{\"df\":\"strict\"}");
    DAC_mode_and_owner_profiles commandPolicy(commands);
    require(commandPolicy.apply(),"collection apply failed");
    require(mode(command)==0750,"MaximumAllowed did not remove excess/special bits");

    const fs::path target=r/"provider-resolv";
    const fs::path link=r/"resolv";
    write(target,"nameserver",0644);
    std::error_code ignored; fs::remove(link,ignored);
    fs::create_symlink(target,link);
    Dac resolv;
    Dac::PathContract resolvSystem=contract(0644);
    resolvSystem.providerTargets.push_back(
        {target,fic::platform::ManagedFileProvider::NetworkManager,
         {owner(),group(),0644}});
    Dac::StaticPathObject object{link,{{Dac::Profile::System,resolvSystem}}};
    resolv.modeAndOwnerObjects.push_back({"resolv",std::move(object)});
    configure(r,"{\"resolv\":\"system\"}");
    DAC_mode_and_owner_profiles providerOk(resolv);
    require(providerOk.apply(),"valid provider target rejected");
    require(::chmod(target.c_str(),0600)==0,"provider test chmod failed");
    DAC_mode_and_owner_profiles providerWrong(resolv);
    require(!providerWrong.apply(),"wrong provider metadata accepted");
    require(mode(target)==0600,"validate-only provider target was mutated");

    Dac forbidden;
    Dac::StaticPathObject forbiddenObject{
        link,{{Dac::Profile::System,contract(0644)}}};
    forbidden.modeAndOwnerObjects.push_back({"forbidden",std::move(forbiddenObject)});
    configure(r,"{\"forbidden\":\"system\"}");
    DAC_mode_and_owner_profiles forbiddenPolicy(forbidden);
    require(!forbiddenPolicy.apply(),"unlisted final symlink accepted");
    require(mode(target)==0600,"forbidden symlink target was mutated");
}
void testTcbTopology(const fs::path& r) {
    const fs::path root=r/"tcb";
    fic::platform::TcbCredentialStorageConfig c{
        root,owner(),group(),0710,0710,group(),02710,02710,
        {{"shadow",0640,0640,true},{"shadow-",0640,0640,false},
         {"shadow.lock",0600,0600,false}}};
    Dac d; Dac::TcbCredentialTreeObject tree;
    tree.profiles.emplace(Dac::Profile::System,c);
    d.modeAndOwnerObjects.push_back({"tcb_credentials",std::move(tree)});
    configure(r,"{\"tcb_credentials\":\"system\"}");
    DAC_mode_and_owner_profiles missing(d);
    require(!missing.apply(),"missing TCB root accepted");
    fs::create_directory(root); require(::chmod(root.c_str(),0700)==0,"tcb chmod failed");
    DAC_mode_and_owner_profiles empty(d); require(empty.apply(),"empty TCB rejected");
    require(mode(root)==0700,"TCB root mode was widened");
    const fs::path account=root/owner(); fs::create_directory(account);
    require(::chmod(account.c_str(),02777)==0,"account chmod failed");
    const fs::path shadow=account/"shadow"; write(shadow,"hash",0666);
    DAC_mode_and_owner_profiles repair(d); require(repair.apply(),"TCB repair failed");
    require(mode(account)==02710&&mode(shadow)==0640,"TCB metadata not repaired");
    fs::remove(shadow); DAC_mode_and_owner_profiles required(d);
    require(!required.apply(),"missing required TCB file accepted");
    write(shadow,"hash",0640);
    const fs::path external=r/"tcb-external"; write(external,"x",0644);
    fs::create_symlink(external,account/"shadow-");
    DAC_mode_and_owner_profiles symlink(d); require(!symlink.apply(),"TCB symlink accepted");
    require(mode(external)==0644,"TCB symlink target mutated");
    fs::remove(account/"shadow-"); fs::create_hard_link(external,account/"shadow-");
    DAC_mode_and_owner_profiles hardlink(d); require(!hardlink.apply(),"TCB hardlink accepted");
    require(mode(external)==0644,"TCB hardlink target mutated");
}
}
int main() { const fs::path r=fs::temp_directory_path()/("fic-mode-owner-profiles-"+std::to_string(::getpid())); fs::remove_all(r); fs::create_directories(r); setupPaths(r); testParser(r); testDesiredStateAndRelease(r); testPreflightAndAggregation(r); testUserHomesDoesNotMutateRoot(r); testCollectionAndProviderSafety(r); testTcbTopology(r); fs::remove_all(r); }
