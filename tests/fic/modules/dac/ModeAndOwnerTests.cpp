#include "modules/dac/mode_and_owner/ModeAndOwnerProfilesPolicy.h"
#include "policy/registry/PolicyRegistryJson.h"
#include <fic/core/runtime/FicRuntimePaths.h>
#include <nlohmann/json.hpp>
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
Dac::PathContract contract(mode_t m) { Dac::PathContract c; c.metadata={owner(),group(),m}; return c; }
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
    Dac d=platform(r/"one",r/"two");
    d.modeAndOwnerObjects[1].allowMissingVariant=true;
    auto& second=std::get<Dac::StaticPathObject>(
        d.modeAndOwnerObjects[1].target);
    second.profiles.emplace(Dac::Profile::Minimum,contract(0640));
    second.profiles.emplace(Dac::Profile::Optimal,contract(0620));
    ModeAndOwnerProfilesPolicyTypeValue t(d);
    require(t.validate(""),"empty rejected"); require(t.validate(" first = strict \n\nsecond=system "),"valid rejected");
    require(!t.validate("first=strict\nfirst=system"),"duplicate accepted"); require(!t.validate("unknown=system"),"unknown accepted");
    require(!t.validate("first=optimal"),"unavailable accepted"); require(!t.validate("first=strict=system"),"malformed accepted");
    require(t.validate("second=system_or_not_exists\nsecond=strict_or_not_exists")==false,
        "duplicate optional object accepted");
    require(t.validate("second=system_or_not_exists"),"system allow-missing rejected");
    require(t.validate("second=strict_or_not_exists"),"strict allow-missing rejected");
    require(t.validate("second=minimum_or_not_exists"),
        "minimum allow-missing rejected");
    require(t.validate("second=optimal_or_not_exists"),
        "optimal allow-missing rejected");
    require(!t.validate("first=system_or_not_exists"),"forbidden allow-missing accepted");
    require(!t.validate("first=minimum_or_not_exists"),"missing base profile accepted");
    for (const std::string& invalid : {"system_or_not_exist","_system_or_not_exists",
                                      "system_or_not_exists_extra"})
        require(!t.validate("second="+invalid),"malformed presence suffix accepted");
    const std::string stored=t.postProcessingValue("second=system\nfirst=strict");
    require(stored=="{\"first\":\"strict\",\"second\":\"system\"}","noncanonical JSON");
    require(t.reverse_postProcessingValue(stored)=="first=strict\nsecond=system","roundtrip failed");
    require(t.postProcessingValue("second=strict_or_not_exists")==
        "{\"second\":\"strict_or_not_exists\"}","optional JSON mismatch");
    require(t.reverse_postProcessingValue("{\"second\":\"strict_or_not_exists\"}")==
        "second=strict_or_not_exists","optional roundtrip mismatch");
    const std::string expectedDefault="first=system\nsecond=system_or_not_exists";
    require(t.getDefaultValue()==expectedDefault,"default is not logical all-system value");
    require(t.validate(t.getDefaultValue()),"default is invalid");
    require(t.postProcessingValue(t.getDefaultValue())==
        "{\"first\":\"system\",\"second\":\"system_or_not_exists\"}","default JSON mismatch");
    require(t.reverse_postProcessingValue("{\"first\":\"strict\"}")==
        "first=strict","saved explicit value was auto-filled");
    require(t.reverse_postProcessingValue("not-json")=="<invalid stored value>","malformed JSON accepted");
    require(t.reverse_postProcessingValue("{\"first\":1}")=="<invalid stored value>","non-string JSON accepted");
    DAC_mode_and_owner_profiles policy(d);
    const nlohmann::json descriptor=policyToJson(
        "DAC","Mode_and_Owner","mode_and_owner_profiles",policy);
    require(descriptor.at("default_value")==expectedDefault,
        "PolicyRegistryJson descriptor lost logical default");
    require(!descriptor.at("set").get<bool>() &&
            descriptor.at("value")==expectedDefault,
        "unconfigured descriptor did not expose generated default");
    write(r/"one","x",0777);
    DAC_mode_and_owner_profiles unconfigured(d);
    require(unconfigured.apply()&&mode(r/"one")==0644,
        "unconfigured policy did not apply generated default");
    require(!fs::exists(r/"two"),
        "allow-missing default unexpectedly created an object");
    configure(r,"{}");
    require(::chmod((r/"one").c_str(),0600)==0,"explicit empty setup failed");
    DAC_mode_and_owner_profiles explicitEmpty(d);
    require(explicitEmpty.apply()&&mode(r/"one")==0600,
        "explicit empty mapping was replaced with generated default");
}
void testExactTransitionsAndSpecialBits(const fs::path& r) {
    const fs::path f=r/"exact";
    Dac d; Dac::StaticPathObject object{f,{{Dac::Profile::System,contract(0755)},
        {Dac::Profile::Strict,contract(0750)}}};
    d.modeAndOwnerObjects.push_back({"command",std::move(object)});
    const auto apply=[&](mode_t initial,const char* profile,mode_t expected) {
        write(f,"x",initial); configure(r,std::string("{\"command\":\"")+profile+"\"}");
        DAC_mode_and_owner_profiles p(d); require(p.apply(),"exact transition failed");
        require(mode(f)==expected,"exact transition produced wrong mode");
    };
    apply(0755,"strict",0750); apply(0750,"system",0755);
    apply(0700,"strict",0750); apply(0777,"strict",0750);
    apply(04755,"system",0755); apply(06750,"strict",0750);
    apply(01777,"strict",0750);

    Dac special; Dac::StaticPathObject specialObject{f,
        {{Dac::Profile::System,contract(04755)}}};
    special.modeAndOwnerObjects.push_back({"special",std::move(specialObject)});
    write(f,"x",0755); configure(r,"{\"special\":\"system\"}");
    DAC_mode_and_owner_profiles setSpecial(special);
    require(setSpecial.apply()&&mode(f)==04755,"required SUID bit not set");

    Dac sgid; Dac::StaticPathObject sgidObject{f,
        {{Dac::Profile::System,contract(02750)}}};
    sgid.modeAndOwnerObjects.push_back({"special",std::move(sgidObject)});
    write(f,"x",0750); configure(r,"{\"special\":\"system\"}");
    DAC_mode_and_owner_profiles setSgid(sgid);
    require(setSgid.apply()&&mode(f)==02750,"required SGID bit not set");

    Dac sticky; Dac::StaticPathObject stickyObject{f,
        {{Dac::Profile::System,contract(01750)}}};
    sticky.modeAndOwnerObjects.push_back({"special",std::move(stickyObject)});
    write(f,"x",0750); configure(r,"{\"special\":\"system\"}");
    DAC_mode_and_owner_profiles setSticky(sticky);
    require(setSticky.apply()&&mode(f)==01750,"required sticky bit not set");

    if (::geteuid()==0) {
        const struct passwd* nobody=::getpwnam("nobody");
        const struct group* nobodyGroup=::getgrnam("nogroup");
        if (nobodyGroup==nullptr) nobodyGroup=::getgrnam("nobody");
        require(nobody!=nullptr&&nobodyGroup!=nullptr,
            "root special-bit test identity is unavailable");
        write(f,"x",04755);
        require(::chown(f.c_str(),nobody->pw_uid,nobodyGroup->gr_gid)==0,
            "could not prepare wrong ownership");
        require(::chmod(f.c_str(),04755)==0,"could not restore fixture SUID");
        Dac ownership; auto rootSpecial=contract(04755);
        rootSpecial.metadata.owner="root"; rootSpecial.metadata.group="root";
        ownership.modeAndOwnerObjects.push_back({"special",Dac::StaticPathObject{
            f,{{Dac::Profile::System,rootSpecial}}}});
        configure(r,"{\"special\":\"system\"}");
        DAC_mode_and_owner_profiles afterChown(ownership);
        require(afterChown.apply(),"ownership+SUID remediation failed");
        struct stat finalState {};
        require(::stat(f.c_str(),&finalState)==0&&finalState.st_uid==0&&
                finalState.st_gid==0&&(finalState.st_mode&07777)==04755,
            "fchown-cleared SUID was not restored exactly");
    }
}
void testRequiredOptionalAndIdentityFailure(const fs::path& r) {
    const fs::path required=r/"missing-required", optional=r/"missing-optional", good=r/"required-good";
    write(good,"x",0777); Dac d;
    auto req=contract(0600); auto opt=contract(0600);
    d.modeAndOwnerObjects.push_back({"required",Dac::StaticPathObject{required,{{Dac::Profile::System,req}}}});
    d.modeAndOwnerObjects.push_back({"optional",Dac::StaticPathObject{optional,
        {{Dac::Profile::System,opt},{Dac::Profile::Strict,contract(0500)}}},true});
    d.modeAndOwnerObjects.push_back({"good",Dac::StaticPathObject{good,{{Dac::Profile::System,req}}}});
    configure(r,"{\"good\":\"system\",\"optional\":\"system_or_not_exists\",\"required\":\"system\"}");
    DAC_mode_and_owner_profiles aggregate(d); require(!aggregate.apply(),"missing required accepted");
    require(mode(good)==0600,"aggregate loop stopped after missing required");
    configure(r,"{\"optional\":\"system\"}");
    DAC_mode_and_owner_profiles optionalMustExist(d);
    require(!optionalMustExist.apply(),"plain system allowed missing object");
    configure(r,"{\"optional\":\"system_or_not_exists\"}");
    DAC_mode_and_owner_profiles optionalMissing(d);
    require(optionalMissing.apply(),"allow-missing rejected ENOENT");
    write(optional,"x",0777);
    DAC_mode_and_owner_profiles optionalExisting(d);
    require(optionalExisting.apply()&&mode(optional)==0600,
        "allow-missing failed exact remediation for existing object");
    fs::remove(optional);
    configure(r,"{\"optional\":\"strict\"}");
    DAC_mode_and_owner_profiles strictMustExist(d);
    require(!strictMustExist.apply(),"plain strict allowed missing object");
    configure(r,"{\"optional\":\"strict_or_not_exists\"}");
    DAC_mode_and_owner_profiles strictMissing(d);
    require(strictMissing.apply(),"strict allow-missing rejected ENOENT");

    if (::geteuid()!=0) {
        const fs::path deniedParent=r/"inaccessible";
        const fs::path deniedPath=deniedParent/"object";
        write(deniedPath,"x",0600);
        Dac inaccessible;
        inaccessible.modeAndOwnerObjects.push_back({"inaccessible",
            Dac::StaticPathObject{deniedPath,
                {{Dac::Profile::System,contract(0600)}}},true});
        configure(r,"{\"inaccessible\":\"system_or_not_exists\"}");
        require(::chmod(deniedParent.c_str(),0000)==0,
            "could not prepare EACCES fixture");
        DAC_mode_and_owner_profiles inaccessiblePolicy(inaccessible);
        const bool accepted=inaccessiblePolicy.apply();
        require(::chmod(deniedParent.c_str(),0700)==0,
            "could not restore EACCES fixture");
        require(!accepted,"allow-missing suppressed EACCES");
    }

    write(good,"x",0644); Dac badIdentity;
    auto bad=contract(0600); bad.metadata.owner="fic-no-such-owner";
    badIdentity.modeAndOwnerObjects.push_back({"bad",Dac::StaticPathObject{good,{{Dac::Profile::System,bad}}}});
    configure(r,"{\"bad\":\"system\"}"); DAC_mode_and_owner_profiles identity(badIdentity);
    require(!identity.apply(),"unknown owner accepted"); require(mode(good)==0644,"identity failure partially mutated mode");

    write(good,"x",0644); Dac badGroup;
    auto invalidGroup=contract(0600); invalidGroup.metadata.group="fic-no-such-group";
    badGroup.modeAndOwnerObjects.push_back({"bad",Dac::StaticPathObject{
        good,{{Dac::Profile::System,invalidGroup}}}});
    configure(r,"{\"bad\":\"system\"}");
    DAC_mode_and_owner_profiles groupIdentity(badGroup);
    require(!groupIdentity.apply(),"unknown group accepted");
    require(mode(good)==0644,"unknown group partially mutated mode");

    if (::geteuid()!=0) {
        write(good,"x",0644); Dac denied;
        auto rootContract=contract(0600);
        rootContract.metadata.owner="root"; rootContract.metadata.group="root";
        denied.modeAndOwnerObjects.push_back({"denied",Dac::StaticPathObject{
            good,{{Dac::Profile::System,rootContract}}}});
        configure(r,"{\"denied\":\"system\"}");
        DAC_mode_and_owner_profiles chownFailure(denied);
        require(!chownFailure.apply(),"unprivileged chown unexpectedly succeeded");
        require(mode(good)==0644,"failed chown was followed by partial chmod");
    }
}
void testDesiredStateAndRelease(const fs::path& r) {
    fs::path f=r/"managed"; write(f,"data",0666); Dac d=platform(f);
    configure(r,"{\"first\":\"strict\"}"); DAC_mode_and_owner_profiles strict(d); require(strict.apply(),"strict failed"); require(mode(f)==0600,"strict not applied");
    configure(r,"{\"first\":\"system\"}"); DAC_mode_and_owner_profiles system(d); require(system.apply(),"system failed"); require(mode(f)==0644,"system not applied");
    require(::chmod(f.c_str(),0600)==0,"test chmod failed"); configure(r,"{}"); DAC_mode_and_owner_profiles released(d); require(released.apply(),"empty failed"); require(mode(f)==0600,"omitted object mutated");

    const fs::path second=r/"managed-second"; write(f,"data",0644); write(second,"data",0644);
    Dac multiple=platform(f,second);
    configure(r,"{\"first\":\"strict\",\"second\":\"strict\"}");
    DAC_mode_and_owner_profiles bothStrict(multiple);
    require(bothStrict.apply()&&mode(f)==0600&&mode(second)==0600,
        "multiple strict profiles not applied");
    configure(r,"{\"second\":\"system\"}");
    DAC_mode_and_owner_profiles releaseFirst(multiple);
    require(releaseFirst.apply(),"partial release failed");
    require(mode(f)==0600,"removed object was mutated");
    require(mode(second)==0644,"remaining object was not enforced");
}
void testPreflightAndAggregation(const fs::path& r) {
    fs::path a=r/"a-first", b=r/"z-second"; write(a,"a",0666); write(b,"b",0666); Dac d=platform(a,b);
    ModeAndOwnerProfilesPolicyTypeValue t(d); require(!t.validate("first=strict\nsecond=optimal"),"late invalid accepted"); require(mode(a)==0666&&mode(b)==0666,"validation mutated");
    fs::remove(a); fs::create_directory(a); configure(r,"{\"first\":\"strict\",\"second\":\"strict\"}"); DAC_mode_and_owner_profiles p(d);
    require(!p.apply(),"aggregate failure succeeded"); require(mode(b)==0600,"runtime loop stopped early");
    write(b,"b",0666); configure(r,"not-json"); DAC_mode_and_owner_profiles malformed(d);
    require(!malformed.apply(),"malformed stored JSON accepted"); require(mode(b)==0666,"malformed JSON mutated object");
    configure(r,"{\"second\":1}"); DAC_mode_and_owner_profiles nonString(d);
    require(!nonString.apply(),"non-string stored JSON accepted"); require(mode(b)==0666,"non-string JSON mutated object");
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
    Dac::CollectionMember member{command,{{Dac::Profile::System,system},{Dac::Profile::Strict,strict}}};
    Dac::PathCollectionObject collection; collection.members.push_back(std::move(member));
    commands.modeAndOwnerObjects.push_back({"df",std::move(collection)});
    configure(r,"{\"df\":\"strict\"}");
    DAC_mode_and_owner_profiles commandPolicy(commands);
    require(commandPolicy.apply(),"collection apply failed");
    require(mode(command)==0750,"exact profile did not set command mode");

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
    resolv.modeAndOwnerObjects.push_back({"resolv",std::move(object),true});
    configure(r,"{\"resolv\":\"system_or_not_exists\"}");
    DAC_mode_and_owner_profiles providerOk(resolv);
    require(providerOk.apply(),"valid provider target rejected");
    require(::chmod(target.c_str(),0600)==0,"provider test chmod failed");
    DAC_mode_and_owner_profiles providerWrong(resolv);
    require(!providerWrong.apply(),"wrong provider metadata accepted");
    require(mode(target)==0600,"validate-only provider target was mutated");

    fs::remove(link); fs::remove(target); fs::create_directory(target);
    require(::chmod(target.c_str(),0700)==0,"provider directory chmod failed");
    fs::create_symlink(target,link);
    DAC_mode_and_owner_profiles providerDirectory(resolv);
    require(!providerDirectory.apply(),"provider directory accepted as file");
    require(mode(target)==0700,"unexpected provider type was mutated");

    fs::remove(link); fs::remove_all(target); fs::create_symlink(target,link);
    DAC_mode_and_owner_profiles brokenProvider(resolv);
    require(!brokenProvider.apply(),
        "allow-missing accepted a broken provider symlink");

    fs::remove(link); fs::remove_all(target); write(target,"nameserver",0600);
    fs::create_symlink(target,link);

    Dac forbidden;
    Dac::StaticPathObject forbiddenObject{
        link,{{Dac::Profile::System,contract(0644)}}};
    forbidden.modeAndOwnerObjects.push_back({"forbidden",std::move(forbiddenObject),true});
    configure(r,"{\"forbidden\":\"system_or_not_exists\"}");
    DAC_mode_and_owner_profiles forbiddenPolicy(forbidden);
    require(!forbiddenPolicy.apply(),"unlisted final symlink accepted");
    require(mode(target)==0600,"forbidden symlink target was mutated");

    Dac allowed; auto allowedContract=contract(0640);
    allowedContract.allowedFinalSymlinkTargets={target};
    allowed.modeAndOwnerObjects.push_back({"allowed",Dac::StaticPathObject{
        link,{{Dac::Profile::System,allowedContract}}}});
    configure(r,"{\"allowed\":\"system\"}"); DAC_mode_and_owner_profiles allowedPolicy(allowed);
    require(allowedPolicy.apply()&&mode(target)==0640,"allowed final symlink not remediated exactly");

    const fs::path fifo=r/"unsafe-fifo"; fs::remove(fifo,ignored);
    require(::mkfifo(fifo.c_str(),0666)==0,"mkfifo failed");
    Dac unsafe; unsafe.modeAndOwnerObjects.push_back({"fifo",Dac::StaticPathObject{
        fifo,{{Dac::Profile::System,contract(0600)}}},true});
    configure(r,"{\"fifo\":\"system_or_not_exists\"}"); DAC_mode_and_owner_profiles fifoPolicy(unsafe);
    require(!fifoPolicy.apply(),"FIFO accepted as regular file");
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
    require(mode(root)==0710,"TCB root exact mode not applied");
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
int main() { const fs::path r=fs::temp_directory_path()/("fic-mode-owner-profiles-"+std::to_string(::getpid())); fs::remove_all(r); fs::create_directories(r); setupPaths(r); testParser(r); testExactTransitionsAndSpecialBits(r); testRequiredOptionalAndIdentityFailure(r); testDesiredStateAndRelease(r); testPreflightAndAggregation(r); testUserHomesDoesNotMutateRoot(r); testCollectionAndProviderSafety(r); testTcbTopology(r); fs::remove_all(r); }
