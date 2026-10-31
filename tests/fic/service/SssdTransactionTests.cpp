#include "service/sssd/SssdTransactionCoordinator.h"
#include "rollback/SssdJournalPayload.h"
#include <fic/core/fs/AtomicFileWriter.h>
#include <sys/wait.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <thread>
using namespace fic::service::sssd;
namespace r=fic::rollback;
namespace j=r::sssd_payload;
static void check(bool ok,const std::string& why){if(!ok)throw std::runtime_error(why);}
static SssdInputReference input(const std::string& providers="ldap") {
    SssdInputReference in;in.launch.profile.platform="debian-12";
    in.order={"/etc/sssd/sssd.conf"};in.sources["/etc/sssd"].present=true;
    in.sources["/etc/sssd"].tree.files["sssd.conf"]="[sssd]\ndomains=a,b\n[domain/a]\nid_provider="+providers+"\n[domain/b]\nid_provider=ldap\n";
    in.ini=detail_i1::project(in.order,{{in.order[0],in.sources["/etc/sssd"].tree.files["sssd.conf"]}});return in;
}
static r::SssdOwnershipTransition transition(const std::string& value="10") {
    r::SssdOwnershipTransition t;t.sequence=1;t.target={{"pam","offline_credentials_expiration",value}};
    t.targetScope="scope";t.inputFingerprint=std::string(64,'a');t.targetSha256=std::string(64,'b');return t;
}
static r::SssdImageWitness image(){return {true,1,2,0600,0,0,std::string(64,'b')};}
static void schemaTests() {
    auto t=transition();auto policy=detail_i4::policyIdentity(SssdManagedParameter::OfflineCredentialsExpiration);
    r::MutationRecord rec;rec.policy=policy;rec.resource="sssd/managed/"+policy.policyName;rec.undo={r::MutationBackend::Sssd,r::SssdJournalOwnership{{},t}};
    std::string error;check(j::validRecord(rec,error),"valid fresh intent: "+error);
    auto encoded=j::encode(std::get<r::SssdJournalOwnership>(rec.undo.payload));
    check(j::encode(j::decode(encoded))==encoded,"lossless typed payload");
    for(const auto& field:{"current","transition","version"}){auto bad=encoded;bad.erase(field);bool failed=false;try{j::decode(bad);}catch(...){failed=true;}check(failed,"missing field rejected");}
    for(const auto& phase:{"future","completed "}){auto bad=encoded;bad["transition"]["phase"]=phase;bool failed=false;try{j::decode(bad);}catch(...){failed=true;}check(failed,"unknown phase rejected");}
    auto bad=rec;std::get<r::SssdJournalOwnership>(bad.undo.payload).transition->version=2;check(!j::validRecord(bad,error),"unknown version rejected");
    bad=rec;bad.policy.policyName="sssd_cache_credentials";check(!j::validRecord(bad,error),"no raw section/key identity spoof");
    bad=rec;std::get<r::SssdJournalOwnership>(bad.undo.payload).transition->activationPossible=true;check(!j::validRecord(bad,error),"unarmed runtime impossible");
    for(const auto& v:{"-1","01","3651","1\n[sssd]","true","4294967296"}){bad=rec;std::get<r::SssdJournalOwnership>(bad.undo.payload).transition->target.front().value=v;check(!j::validRecord(bad,error),"bad scalar");}
    auto decoded=j::decode(encoded);check(decoded.current.assignments.empty()&&decoded.transition->previous.assignments.empty(),"fresh not falsely owned");
}
static void targetTests() {
    auto in=input();const auto scope=domainScope(in);
    auto cache=detail_i4::targetAssignments(scope,SssdManagedParameter::CacheCredentials,true);
    check(cache==std::vector<r::SssdAssignment>{{"domain/a","cache_credentials","true"},{"domain/b","cache_credentials","true"}},"full domains derived internally");
    auto account=detail_i4::targetAssignments(scope,SssdManagedParameter::AccountCacheExpiration,Days{30});check(account.size()==2,"account full set");
    auto disabled=input();disabled.sources["/etc/sssd"].tree.files["sssd.conf"]+="enabled=false\n";
    disabled.ini=detail_i1::project(disabled.order,{{disabled.order[0],disabled.sources["/etc/sssd"].tree.files["sssd.conf"]}});
    bool refusedPartial=false;try{detail_i4::targetAssignments(domainScope(disabled),SssdManagedParameter::CacheCredentials,true);}catch(...){refusedPartial=true;}
    check(refusedPartial,"explicitly selected but disabled root cannot be silently dropped");
    auto own=detail_i4::targetAssignments(scope,SssdManagedParameter::OfflineCredentialsExpiration,Days{10});check(own.size()==1&&own[0].section=="pam","global key");
    check(detail_i4::renderAssignments(own)=="[pam]\noffline_credentials_expiration = 10\n\n","canonical image");
    for(const auto& provider:{"proxy","ad","ipa","unknown"}) {
        bool failed=false;try{detail_i4::targetAssignments(domainScope(input(provider)),SssdManagedParameter::CacheCredentials,true);}catch(...){failed=true;}check(failed,"no partial provider coverage");
    }
    for(const SemanticValue value:{SemanticValue{},SemanticValue(Seconds{1}),SemanticValue(false),SemanticValue(Days{3651})}) {
        bool failed=false;try{detail_i4::targetAssignments(scope,SssdManagedParameter::AccountCacheExpiration,value);}catch(...){failed=true;}check(failed,"explicit account value only");
    }
}
static void journalTests() {
    char name[]="/tmp/fic-i4-journal-XXXXXX";check(mkdtemp(name),"temp");const std::filesystem::path dir(name);std::string error;
    r::MutationJournal journal(dir/"journal.json");check(journal.initializeOrLoad(error),"journal init: "+error);
    const auto policy=detail_i4::policyIdentity(SssdManagedParameter::OfflineCredentialsExpiration);
    // First operation holds the real coordinator mutex before journal/admission.
    // A second thread must time out without ever reaching those side effects.
    SssdTransactionRequest first{SssdTransactionOperation::Apply,policy,SssdManagedParameter::OfflineCredentialsExpiration,Days{10},std::chrono::steady_clock::now()+std::chrono::seconds(5)};
    detail_i4::TransactionTestHooks hooks;
    bool blocked=false;
    hooks.checkpoint=[&](const std::string& phase){if(phase!="locked")return;
        auto second=first;second.deadline=std::chrono::steady_clock::now()+std::chrono::milliseconds(50);
        std::thread competing([&](){SssdTransactionCoordinator c(journal);auto x=c.execute(second);blocked=!x.success()&&!x.prepared&&x.diagnostic.find("busy")!=std::string::npos;});
        competing.join();throw std::runtime_error("test ends before service admission");
    };
    auto refused=detail_i4::executeForTests(journal,first,hooks);
    check(blocked&&!refused.prepared&&journal.records().empty(),"deterministic shared resource serialization");
    auto t=transition();r::MutationId id=0;
    check(journal.beginSssdTransaction(policy,t,id,error),"begin: "+error);
    check(!journal.setStatus(id,r::MutationStatus::Applied,error),"generic completion rejected");
    check(!journal.discard(id,error),"generic discard rejected");
    auto sibling=detail_i4::policyIdentity(SssdManagedParameter::CacheCredentials);r::MutationId other=0;
    check(!journal.beginSssdTransaction(sibling,t,other,error),"shared gate");
    check(journal.abortSssdNoEffect(id,error)&&journal.records().empty(),"fresh no effect resolution");
    check(journal.beginSssdTransaction(policy,t,id,error),"begin again");
    t.phase=r::SssdTransitionPhase::MutationArmed;check(journal.advanceSssdTransaction(id,t,error),"arm");
    check(!journal.abortSssdNoEffect(id,error),"armed previous cannot imply no effect");
    t.phase=r::SssdTransitionPhase::Published;t.publication=image();check(journal.advanceSssdTransaction(id,t,error),"publication");
    check(!journal.commitSssdTransaction(id,error),"matching target no runtime permission");
    t.phase=r::SssdTransitionPhase::DurablePublished;t.publicationDurable=true;check(journal.advanceSssdTransaction(id,t,error),"durability");
    t.phase=r::SssdTransitionPhase::ActivationArmed;t.activationPossible=true;check(journal.advanceSssdTransaction(id,t,error),"activation intent");
    t.phase=r::SssdTransitionPhase::RuntimeVerified;t.a=t.b=t.c=t.p=t.clean=true;check(journal.advanceSssdTransaction(id,t,error),"runtime");
    // Reload is a real new object, not a projection of the previous live object.
    r::MutationJournal fresh(dir/"journal.json");check(fresh.initializeOrLoad(error),"reload");
    check(fresh.commitSssdTransaction(id,error),"finalize");
    const auto applied=std::get<r::SssdJournalOwnership>(fresh.records().front().undo.payload).current;
    check(applied.assignments==t.target&&applied.sequence==1,"target promoted only by finalization");
    t=transition("30");t.previous=applied;t.sequence=2;t.before=image();
    check(fresh.beginSssdTransaction(policy,t,id,error),"refresh same identity");
    check(std::get<r::SssdJournalOwnership>(fresh.records().front().undo.payload).current.assignments==applied.assignments,"old authority retained");
    check(fresh.abortSssdNoEffect(id,error),"refresh abort");
    check(fresh.records().size()==1&&fresh.records()[0].id==id&&std::get<r::SssdJournalOwnership>(fresh.records()[0].undo.payload).current.assignments==applied.assignments,"abort preserves predecessor");
    // Fork/crash after durable Prepared. Child dies with no C++ unwinding;
    // parent/new journal must see the pending intent and retained predecessor.
    pid_t child=fork();check(child>=0,"fork");if(child==0){r::MutationJournal cj(dir/"journal.json");if(!cj.initializeOrLoad(error)||!cj.beginSssdTransaction(policy,t,id,error))_exit(2);_exit(73);}
    int status;waitpid(child,&status,0);check(WIFEXITED(status)&&WEXITSTATUS(status)==73,"controlled process death");
    r::MutationJournal afterCrash(dir/"journal.json");check(afterCrash.initializeOrLoad(error),"crash reload");
    check(afterCrash.records()[0].status==r::MutationStatus::Prepared&&std::get<r::SssdJournalOwnership>(afterCrash.records()[0].undo.payload).current.assignments==applied.assignments,"crash retained ownership");
    check(!afterCrash.beginSssdTransaction(sibling,t,other,error),"crash sibling gate");
    {
        std::ifstream file(dir/"journal.json");j::J document;file>>document;
        document["schema_version"]=2u;
        std::ofstream edited(dir/"journal.json");edited<<document.dump();edited.close();
        r::MutationJournal oldSchema(dir/"journal.json");check(!oldSchema.initializeOrLoad(error)&&!oldSchema.usable(),"I4 payload requires schema 3");
        auto& rec=document["records"][0];rec["resource"]="pam/offline_credentials_expiration";
        rec["undo"]={{"backend","sssd"},{"action","remove_sssd_managed_setting"},{"section","pam"},{"option","offline_credentials_expiration"},{"applied_value","10"}};
        std::ofstream legacyFile(dir/"journal.json");legacyFile<<document.dump();legacyFile.close();
        r::MutationJournal legacy(dir/"journal.json");check(legacy.initializeOrLoad(error),"legacy scalar still readable: "+error);
        check(std::get<r::UndoRemoveSssdManagedSetting>(legacy.records()[0].undo.payload).appliedValue=="10"&&legacy.records()[0].status==r::MutationStatus::Prepared,"legacy ownership/Prepared meaning preserved");
    }
    std::filesystem::remove_all(dir);
}
static void counterBoundsTests() {
    for(const std::uint64_t counter:{std::uint64_t(0),UINT64_MAX}) {
        char name[]="/tmp/fic-i4-counter-XXXXXX";check(mkdtemp(name),"counter temp");
        const std::filesystem::path path=std::filesystem::path(name)/"journal.json";
        std::string error;r::MutationJournal initial(path);check(initial.initializeOrLoad(error),"counter journal init");
        std::ifstream input(path);j::J document;input>>document;input.close();document["next_id"]=counter;
        std::ofstream output(path);output<<document.dump();output.close();
        r::MutationJournal loaded(path);check(loaded.initializeOrLoad(error),"existing empty counter document");
        r::MutationId id=0;const bool accepted=loaded.beginSssdTransaction(
            detail_i4::policyIdentity(SssdManagedParameter::OfflineCredentialsExpiration),transition(),id,error);
        std::filesystem::remove_all(name);
        check(!accepted,"invalid/exhausted mutation ID must be refused before durable intent: "+std::to_string(counter));
    }
}
static void releaseJournalTests() {
    using Phase=r::SssdTransitionPhase;
    for(const auto count:{1,2,3})for(const auto releaseIndex:{0,count-1})for(const bool offline:{false,true})for(const bool disable:{false,true}) {
        char name[]="/tmp/fic-i5-journal-XXXXXX";check(mkdtemp(name),"release temp");
        const auto path=std::filesystem::path(name)/"journal.json";std::string error;
        r::MutationJournal journal(path);check(journal.initializeOrLoad(error),"release journal init");
        std::vector<r::MutationId> ids;
        const std::vector<SssdManagedParameter> kinds{SssdManagedParameter::OfflineCredentialsExpiration,SssdManagedParameter::CacheCredentials,SssdManagedParameter::AccountCacheExpiration};
        for(int i=0;i<count;++i) {
            auto t=transition();t.sequence=i+1;
            if(i==1)t.target={{"domain/a","cache_credentials","true"}};
            if(i==2)t.target={{"domain/a","account_cache_expiration","30"}};
            r::MutationId id=0;check(journal.beginSssdTransaction(detail_i4::policyIdentity(kinds[i]),t,id,error),"enroll: "+error);
            for(const auto phase:{Phase::MutationArmed,Phase::Published,Phase::DurablePublished,Phase::ActivationArmed,Phase::RuntimeVerified}) {
                t.phase=phase;
                if(phase==Phase::Published){t.publication=image();t.publication.inode+=i;}
                if(phase==Phase::DurablePublished)t.publicationDurable=true;
                if(phase==Phase::ActivationArmed)t.activationPossible=true;
                if(phase==Phase::RuntimeVerified)t.a=t.b=t.c=t.p=t.clean=true;
                check(journal.advanceSssdTransaction(id,t,error),"enroll advance: "+error);
            }
            check(journal.commitSssdTransaction(id,error),"enroll commit: "+error);ids.push_back(id);
        }
        r::SssdOwnershipTransition t;t.version=2;t.sequence=count+1;
        const auto& rec=journal.records().at(releaseIndex);
        t.previous=std::get<r::SssdJournalOwnership>(rec.undo.payload).current;
        t.before=j::publication(std::get<r::SssdJournalOwnership>(journal.records().back().undo.payload));
        t.inputFingerprint=std::string(64,'a');t.release.emplace();auto& release=*t.release;
        release.intent=disable?r::SssdReleaseIntent::DisableRelease:r::SssdReleaseIntent::ReleaseOnly;
        release.ownershipGeneration=std::string(64,'a');release.serviceBefore=std::string(64,'a');release.offline=offline;
        for(const auto& sibling:journal.records())if(sibling.id!=ids[releaseIndex]) {
            const auto& p=std::get<r::SssdJournalOwnership>(sibling.undo.payload);
            release.survivors.push_back({sibling.id,sibling.policy.policyName,p.current,p.container});
            release.remaining.insert(release.remaining.end(),p.current.assignments.begin(),p.current.assignments.end());
        }
        std::sort(release.remaining.begin(),release.remaining.end(),[](const auto& a,const auto& b){return std::tie(a.section,a.key)<std::tie(b.section,b.key);});
        release.targetAbsent=release.remaining.empty();
        t.targetSha256=fic::core::ContentDigest::sha256Hex(j::rendered(release.remaining));
        if(release.targetAbsent)release.stagedPath="/etc/sssd/conf.d/zzzz-fic.conf.fic-removing-i5-"+std::to_string(ids[releaseIndex])+"-"+std::to_string(t.sequence);
        auto bad=t;bad.release->remaining.push_back({"pam","offline_credentials_expiration","123"});
        check(!journal.beginSssdRelease(ids[releaseIndex],bad,error),"malformed surviving projection refused");
        check(journal.beginSssdRelease(ids[releaseIndex],t,error),"begin release: "+error);
        check(!journal.advanceSssdTransaction(ids[releaseIndex],t,error),"apply API cannot advance release");
        check(!journal.setStatus(ids[releaseIndex],r::MutationStatus::RolledBack,error),"generic release bypass refused");
        check(!journal.commitSssdTransaction(ids[releaseIndex],error),"apply commit bypass refused");
        check(journal.abortSssdNoEffect(ids[releaseIndex],error),"release unarmed abort retains owner");
        check(journal.records().at(releaseIndex).status==r::MutationStatus::Applied,"no effect retained Applied");
        check(journal.beginSssdRelease(ids[releaseIndex],t,error),"release rebegin");
        for(const auto phase:{Phase::MutationArmed,Phase::Published,Phase::DurablePublished}) {
            t.phase=phase;
            if(phase==Phase::Published&&!release.targetAbsent){t.publication=image();t.publication.inode=100;t.publication.sha256=t.targetSha256;}
            if(phase==Phase::DurablePublished)t.publicationDurable=true;
            check(journal.advanceSssdRelease(ids[releaseIndex],t,error),"release phase: "+error);
            check(!journal.abortSssdNoEffect(ids[releaseIndex],error),"armed release cannot abort");
            r::MutationId other=0;check(!journal.beginSssdTransaction(detail_i4::policyIdentity(SssdManagedParameter::CacheCredentials),transition(),other,error),"release gates siblings");
            r::MutationJournal fresh(path);check(fresh.initializeOrLoad(error),"release reload: "+error);
            check(std::get<r::SssdJournalOwnership>(fresh.records().at(releaseIndex).undo.payload).current.assignments==t.previous.assignments,"previous provenance retained");
        }
        if(!offline){t.phase=Phase::ActivationArmed;t.activationPossible=true;check(journal.advanceSssdRelease(ids[releaseIndex],t,error),"active arm");}
        t.phase=offline?Phase::OfflineVerified:Phase::RuntimeVerified;t.p=t.clean=true;
        if(offline)release.offlineVerified=true;else t.a=t.b=t.c=true;
        release.serviceAfter=release.releasedGraphFingerprint=std::string(64,'c');
        check(journal.advanceSssdRelease(ids[releaseIndex],t,error),"verified release: "+error);
        if(disable) {
            check(!journal.completeSssdRelease(ids[releaseIndex],error),"disable cannot terminate from runtime proof");
            t.phase=Phase::ReleasedAwaitingDisable;
            check(journal.advanceSssdRelease(ids[releaseIndex],t,error),"durable awaiting disable");
            check(!journal.completeSssdRelease(ids[releaseIndex],error),"I5 refuses production disable acknowledgement");
            auto fabricated=t;fabricated.release->disableGeneration=std::string(64,'f');
            check(!journal.advanceSssdRelease(ids[releaseIndex],fabricated,error),"raw disable generation cannot acknowledge pending release");
            r::MutationJournal pending(path);check(pending.initializeOrLoad(error),"pending disable reload");
            auto forged=pending.records().at(releaseIndex);forged.status=r::MutationStatus::RolledBack;
            auto& forgedTransition=*std::get<r::SssdJournalOwnership>(forged.undo.payload).transition;
            forgedTransition.phase=Phase::Completed;forgedTransition.release->disableGeneration=std::string(64,'f');
            check(!j::validRecord(forged,error),"I5 decoder refuses fabricated terminal DisableRelease proof");
            check(pending.records().at(releaseIndex).status==r::MutationStatus::Prepared&&
                  std::get<r::SssdJournalOwnership>(pending.records().at(releaseIndex).undo.payload).transition->phase==Phase::ReleasedAwaitingDisable,
                  "disable remains explicitly pending");
            std::filesystem::remove_all(name);continue;
        }
        check(journal.completeSssdRelease(ids[releaseIndex],error),"terminal release: "+error);
        r::MutationJournal final(path);check(final.initializeOrLoad(error),"terminal fresh reload: "+error);
        check(final.records().at(releaseIndex).status==r::MutationStatus::RolledBack,"terminal only released owner");
        for(const auto& sibling:final.records())if(sibling.isActive()) {
            const auto& p=std::get<r::SssdJournalOwnership>(sibling.undo.payload);
            check(p.container&&p.container->sequence==t.sequence&&p.container->releaseId==ids[releaseIndex]&&
                  j::image(j::publication(p))==j::image(t.publication),"atomic latest witness transfer");
        }
        const auto roundtrip=j::encode(std::get<r::SssdJournalOwnership>(final.records().at(releaseIndex).undo.payload));
        check(roundtrip.at("version")==2&&j::encode(j::decode(roundtrip))==roundtrip,"v2 lossless release codec");
        auto legacy=roundtrip;legacy["version"]=1u;bool rejected=false;try{j::decode(legacy);}catch(...){rejected=true;}check(rejected,"release cannot impersonate v1");
        if(count>1) {
            std::ifstream input(path);j::J doc;input>>doc;input.close();
            for(auto& r:doc["records"])if(r["status"]=="applied")r["undo"]["ownership"]["container"]["release_id"]=std::uint64_t(999);
            std::ofstream output(path);output<<doc.dump();output.close();
            r::MutationJournal tampered(path);check(!tampered.initializeOrLoad(error)&&!tampered.usable(),"unbound shared witness rejected on reload");
        }
        std::filesystem::remove_all(name);
    }
}
int main(){try{schemaTests();targetTests();journalTests();counterBoundsTests();releaseJournalTests();std::cout<<"SSSD I4 contracts PASS\n";return 0;}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
