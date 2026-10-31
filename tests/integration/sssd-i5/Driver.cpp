#include "platform/PlatformExecutableResolver.h"
#include "service/VerifiedConfigServiceActivatorTestAccess.h"
#include "service/sssd/SssdTransactionCoordinator.h"
#include "rollback/SssdJournalPayload.h"
#include "modules/identity_access/sssd/SssdConfiguration.h"
#include <fic/core/fs/AtomicFileWriter.h>
#include <fic/core/integrity/ContentDigest.h>
#include <fcntl.h>
#include <atomic>
extern std::atomic<bool> sssdI4CrashDuringWrite;
#include <fic/core/integrity/CommandHashStore.h>
#include <fic/core/process/ProcessExecutor.h>
#include <fic/core/runtime/FicRuntimePaths.h>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <signal.h>
#include <sstream>
#include <sys/mount.h>
#include <thread>
#include <unistd.h>
namespace s = fic::service::sssd;
namespace d = fic::service::detail;
using J = nlohmann::json;
std::string read(const std::string &path) {
  std::ifstream f(path);
  return {std::istreambuf_iterator<char>(f), {}};
}
const char *proof(s::SssdProofState state) {
  switch (state) {
  case s::SssdProofState::NotProven:
    return "NotProven";
  case s::SssdProofState::Proven:
    return "Proven";
  case s::SssdProofState::Unsupported:
    return "Unsupported";
  case s::SssdProofState::Drifted:
    return "Drifted";
  }
  return "NotProven";
}
const char *status(s::SssdActivationStatus state) {
  switch (state) {
  case s::SssdActivationStatus::Refused:
    return "Refused";
  case s::SssdActivationStatus::ActivationFailed:
    return "ActivationFailed";
  case s::SssdActivationStatus::RuntimeEffectUnknown:
    return "RuntimeEffectUnknown";
  case s::SssdActivationStatus::RuntimeActivatedButPersistentUnproven:
    return "RuntimeActivatedButPersistentUnproven";
  case s::SssdActivationStatus::CleanupFailed:
    return "CleanupFailed";
  case s::SssdActivationStatus::Success:
    return "Success";
  }
  return "Refused";
}
J value(const s::SemanticValue &v) {
  if (auto p = std::get_if<s::Days>(&v))
    return J{{"unit", "days"}, {"value", p->value}};
  if (auto p = std::get_if<s::Seconds>(&v))
    return J{{"unit", "seconds"}, {"value", p->value}};
  if (auto p = std::get_if<bool>(&v))
    return J{{"unit", "boolean"}, {"value", *p}};
  return nullptr;
}
J identity(const d::Identity &i) {
  return J::array({i.mount, i.device, i.inode, i.mode, i.uid, i.gid});
}
int main(int argc, char **argv) {
  J out;
  std::vector<pid_t> stopped;
  int source = -1;
  try {
    if (!getenv("FIC_SSSD_RESEARCH") ||
        std::string(getenv("FIC_SSSD_RESEARCH")) != "1" ||
        !std::filesystem::exists("/.dockerenv") ||
        read("/proc/1/comm") != "systemd\n" || getuid() != 0)
      throw std::runtime_error("disposable native guard");
    auto paths = fic::core::FicProductPaths::production();
    paths.configDir = "/run/sssd-i4/config";
    paths.dataDir = "/run/sssd-i4/state";
    paths.logDir = "/run/sssd-i4/log";
    paths.runtimeDir = "/run/sssd-i4";
    paths.commandHashFile = "/run/sssd-i4/hashes";
    paths.lockDebugLogFile = "/run/sssd-i4/log/locks";
    for (const auto &path : {paths.configDir, paths.dataDir, paths.logDir})
      std::filesystem::create_directories(path);
    std::string error;
    if (!fic::core::FicRuntimePaths::initialize(paths, error))
      throw std::runtime_error(error);
    std::filesystem::create_directories("/var/lib/fic-i4");
    const auto platform = fic::platform::makeBuildPlatformProfile();
    fic::platform::PlatformExecutableResolver resolver(platform.executables);
    std::filesystem::path ctl, packageTool;
    if (!resolver.resolve(fic::platform::ExecutableId::Systemctl, ctl, error) ||
        !resolver.resolve(fic::platform::ExecutableId::PackageQuery,
                          packageTool, error) ||
        !CommandHashStore::saveHashes({ctl.string(), packageTool.string(),
                                       "/usr/sbin/sssd", "/usr/bin/ldbsearch",
                                       "/usr/bin/dbus-send"},
                                      error))
      throw std::runtime_error(error);
    namespace r=fic::rollback;
    namespace j=r::sssd_payload;
    const std::string journalPath="/var/lib/fic-i4/journal.json";
    r::MutationJournal journal(journalPath);
    const auto operation=argc>1?std::string(argv[1]):"apply";
    const auto parameter=argc>2?std::string(argv[2]):"offline";
    const unsigned scalar=argc>3?std::stoul(argv[3]):10;
    const auto action=argc>4?std::string(argv[4]):"normal";
    const auto timeout=std::chrono::milliseconds(argc>5?std::stoul(argv[5]):60000);
    if(!journal.initializeOrLoad(error)) {
        out["initialization_error"]=error;out["success"]=false;
    } else {
        s::SssdTransactionCoordinator coordinator(journal);
        J checkpoints=J::array();
        auto checkpoint=[&](const std::string& name) {
            checkpoints.push_back(name);
            {std::ofstream f("/run/sssd-research-out/last-checkpoint");f<<name;}
            if(action=="crash-"+name)_exit(74);
        };
        auto inspect=[&](bool resolve) {
            auto in=resolve?coordinator.resolveNoEffect(std::chrono::steady_clock::now()+timeout):coordinator.inspect(std::chrono::steady_clock::now()+timeout);
            const std::map<s::SssdRecoveryClassification,std::string> names{
                {s::SssdRecoveryClassification::NoTransition,"NoTransition"},{s::SssdRecoveryClassification::NoEffectPrepared,"NoEffectPrepared"},
                {s::SssdRecoveryClassification::PreviousImage,"PreviousImage"},{s::SssdRecoveryClassification::TargetImage,"TargetImage"},
                {s::SssdRecoveryClassification::DurableTarget,"DurableTarget"},{s::SssdRecoveryClassification::ForeignDrift,"ForeignDrift"},
                {s::SssdRecoveryClassification::JournalIndeterminate,"JournalIndeterminate"},{s::SssdRecoveryClassification::RuntimeUnknown,"RuntimeUnknown"},
                {s::SssdRecoveryClassification::ResidualMounts,"ResidualMounts"},{s::SssdRecoveryClassification::UnsupportedSchema,"UnsupportedSchema"},{s::SssdRecoveryClassification::TargetBytesUnattributed,"TargetBytesUnattributed"}};
            out["inspection"]={{"classification",names.at(in.classification)},{"phase",j::phaseName(in.phase)},
                {"previous_matches",in.previousMatches},{"target_matches",in.targetMatches},{"target_bytes_match",in.targetBytesMatch},{"publication_durable",in.publicationDurable},
                {"activation_possible",in.activationPossible},{"resolvable",in.noEffectResolvable},{"residuals",in.residuals},{"diagnostic",in.diagnostic}};
        };
        if(operation=="inspect"||operation=="resolve")inspect(operation=="resolve");
        else {
            s::SssdManagedParameter p;
            if(parameter=="offline")p=s::SssdManagedParameter::OfflineCredentialsExpiration;
            else if(parameter=="cache")p=s::SssdManagedParameter::CacheCredentials;
            else if(parameter=="account")p=s::SssdManagedParameter::AccountCacheExpiration;
            else throw std::runtime_error("unknown parameter");
            s::SssdTransactionRequest request{operation=="refresh"?s::SssdTransactionOperation::Refresh:s::SssdTransactionOperation::Apply,
                s::detail_i4::policyIdentity(p),p,p==s::SssdManagedParameter::CacheCredentials?s::SemanticValue(true):s::SemanticValue(s::Days{scalar}),std::chrono::steady_clock::now()+timeout};
            d::TestHooks engine;s::detail_i3::AdapterTestHooks adapter;adapter.engine=&engine;
            s::detail_i4::TransactionTestHooks tests;tests.adapter=&adapter;
            if(action=="source-fd"||action=="persistent-drift")source=::open("/etc/sssd/sssd.conf",O_RDWR|O_CLOEXEC);
            tests.checkpoint=[&](const std::string& name) {
                checkpoint(name);
                if(name=="durable-published"&&(action=="offline-start"||action=="offline-start-stop")) {
                    if(!ProcessExecutor::execute(ctl.string(),{"start","sssd.service"}).success())throw std::runtime_error("fixture start failed");
                    if(action=="offline-start-stop"&&!ProcessExecutor::execute(ctl.string(),{"stop","sssd.service"}).success())throw std::runtime_error("fixture stop failed");
                }
                if(name=="runtime-verified"&&action=="post-i3-owned-touch") {
                    if(::utimensat(AT_FDCWD,"/etc/sssd/conf.d/zzzz-fic.conf",nullptr,0))throw std::runtime_error("fixture touch failed");
                }
                if(name=="before-finalization"&&(action=="finalization-not-installed"||action=="journal-indeterminate"||action=="crash-journal-installed")) {
                    AtomicFileWriter::setDirectoryFsyncHookForTests([&](const std::string& path) {
                        if(path!=journalPath)return true;
                        checkpoint("journal-installed");return action!="journal-indeterminate";
                    });
                    if(action=="finalization-not-installed")AtomicFileWriter::setPreInstallHookForTests([&](const std::string& path){
                        if(path==journalPath)for(const auto& e:std::filesystem::directory_iterator("/var/lib/fic-i4"))if(e.path().filename().string().rfind(".journal.json.tmp.",0)==0)std::filesystem::remove(e.path());
                    });
                }
                if(name=="mutation-armed") {
                    sssdI4CrashDuringWrite=action=="crash-partial-staged-write";
                    AtomicFileWriter::setPreInstallHookForTests([&](const std::string& path) {
                        if(path!="/etc/sssd/conf.d/zzzz-fic.conf")return;
                        checkpoint("staged-write");
                        if(action=="cas-drift") {std::ofstream f(path);f<<"[pam]\ndebug_level = 7\n";f.close();::chmod(path.c_str(),0600);}
                    });
                    AtomicFileWriter::setDirectoryFsyncHookForTests([&](const std::string& path) {
                        if(path!="/etc/sssd/conf.d/zzzz-fic.conf")return true;
                        checkpoint("atomic-published");return action!="publication-not-durable";
                    });
                }
            };
            engine.checkpoint=[&](d::TestPhase phase,const std::string&) {
                if(phase==d::TestPhase::RestartQueued) {
                    checkpoint("restart-dispatched");
                    if(action=="restart-timeout")std::this_thread::sleep_for(timeout+std::chrono::milliseconds(20));
                }
                if(phase==d::TestPhase::BeforeCleanup)checkpoint("before-cleanup");
                if(phase==d::TestPhase::Watching&&action=="source-fd") {
                    char c='#';out["hidden_write"]=::pwrite(source,&c,1,0);
                }
            };
            engine.fault=[&](const std::string& name,std::size_t index){return action=="cleanup-fail"&&name=="umount"&&index==0?EBUSY:0;};
            adapter.checkpoint=[&](const std::string& name) {
                checkpoint("i3-"+name);
                if(name=="persistent"&&action=="persistent-drift") {std::string appended="\n# fixture persistent drift\n";::lseek(source,0,SEEK_END);::write(source,appended.data(),appended.size());}
      if (action == "stale-configdb" && name == "ready") {
        ProcessOptions options;
        options.standardInput =
            "dn: cn=test,cn=domain,cn=config\nchangetype: modify\nreplace: "
            "cached_auth_timeout\ncached_auth_timeout: 99\n\n";
        const auto changed = ProcessExecutor::execute(
            "/usr/bin/ldbmodify", {"-H", "/var/lib/sss/db/config.ldb"},
            options);
        out["fixture_db_change"] = {{"exit_code", changed.exitCode},
                                    {"error", changed.standardError}};
      }
      if (((action == "stop-monitor" || action == "stop-pam" ||
            action == "stop-backend") &&
           name == "ready") ||
          (action == "stop-pam-after" && name == "persistent")) {
        const auto c = d::readSssdLaunchContract(
            std::chrono::steady_clock::now() + std::chrono::seconds(1));
        const auto monitor =
            J::parse(c.at("launch.MainPID")).at("value").get<pid_t>();
        if (action == "stop-monitor") {
          ::kill(monitor, SIGSTOP);
          stopped.push_back(monitor);
        } else
          for (const auto &p : std::filesystem::directory_iterator("/proc")) {
            const auto name = p.path().filename().string();
            if (name.find_first_not_of("0123456789") != name.npos)
              continue;
            auto text = read((p.path() / "stat").string());
            const auto end = text.rfind(')');
            if (end == text.npos)
              continue;
            std::istringstream f(text.substr(end + 1));
            char state;
            pid_t parent;
            f >> state >> parent;
            if (parent != monitor)
              continue;
            char exe[4096];
            auto n = ::readlink((p.path() / "exe").c_str(), exe, sizeof exe);
            if (n > 0 &&
                std::string(exe, n) == (action == "stop-backend"
                                            ? "/usr/libexec/sssd/sssd_be"
                                            : "/usr/libexec/sssd/sssd_pam")) {
              ::kill(std::stoi(name), SIGSTOP);
              stopped.push_back(std::stoi(name));
            }
          }
      }
            };
            std::optional<s::SssdReleaseResult> released;
            s::SssdTransactionResult result;
            if(operation=="release"||operation=="disable-release") {
                fic::identity::sssd::setManagedSnippetRemovalCheckpointForTests(checkpoint);
                released=s::detail_i4::releaseForTests(journal,{request.policy,p,
                    operation=="disable-release"?r::SssdReleaseIntent::DisableRelease:r::SssdReleaseIntent::ReleaseOnly,request.deadline},tests);
                // Common evidence serialization only; transaction semantics
                // remain separately reported below from the actual I5 result.
                const auto& x=*released;
                result.activation=x.activation;result.mutation=x.mutation;result.prepared=x.prepared;
                result.durable=x.durable;result.casRefused=x.casRefused;result.finalized=x.finalized;
                result.unresolved=x.unresolved;result.diagnostic=x.diagnostic;
            } else result=s::detail_i4::executeForTests(journal,request,tests);
            const std::map<s::SssdTransactionStatus,std::string> names{
                {s::SssdTransactionStatus::Refused,"Refused"},{s::SssdTransactionStatus::OwnershipConflict,"OwnershipConflict"},
                {s::SssdTransactionStatus::Unresolved,"Unresolved"},{s::SssdTransactionStatus::JournalFailed,"JournalFailed"},
                {s::SssdTransactionStatus::CasRefused,"CasRefused"},{s::SssdTransactionStatus::PersistentFailed,"PersistentFailed"},
                {s::SssdTransactionStatus::ActivationFailed,"ActivationFailed"},{s::SssdTransactionStatus::FinalizationFailed,"FinalizationFailed"},
                {s::SssdTransactionStatus::Success,"Success"}};
            const auto& a=result.activation;
            out["status"]=names.at(result.status);out["success"]=result.success();out["diagnostic"]=result.diagnostic;
            out["mutation"]=result.mutation;out["prepared"]=result.prepared;out["installed"]=result.installed;out["durable"]=result.durable;
            out["cas_refused"]=result.casRefused;out["same_value"]=result.sameValue;out["finalized"]=result.finalized;
            out["ownership_retained"]=result.ownershipRetained;out["unresolved"]=result.unresolved;
            out["required"]=j::assignments(result.required);out["confirmed"]=j::assignments(result.confirmed);
            out["proofs"]={{"A",proof(a.inputs)},{"B",proof(a.activation)},{"C",proof(a.semantics)},{"P",proof(a.persistent)}};
            out["engine"]={{"attempted",a.engine.activationAttempted},{"primary",fic::service::activationStatusName(a.engine.primaryStatus)},
                {"status",fic::service::activationStatusName(a.engine.status)},{"cleanup_errors",a.engine.cleanupErrors},{"residuals",a.engine.residualPaths}};
            out["activation_status"]=status(a.status);out["activation_diagnostic"]=a.diagnostic;
            out["runtime_possible"]=a.runtimeEffectPossible;out["old_invocation"]=a.oldInvocation;out["new_invocation"]=a.newInvocation;
            out["configdb_generation"]=a.configDbGeneration;out["parameters"]=J::array();
            for(const auto& e:a.parameters)out["parameters"].push_back({{"section",e.key.section},{"key",e.key.key},{"value",value(e.consumerValue)},
                {"consumer",e.consumer},{"process",e.processToken},{"generation",e.configDbGeneration},{"source_contract",e.sourceContract},{"read_moment",e.readMoment}});
            if(released) {
                const auto& x=*released;
                const std::map<s::SssdReleaseStatus,std::string> releaseNames{
                    {s::SssdReleaseStatus::Refused,"Refused"},{s::SssdReleaseStatus::OwnershipConflict,"OwnershipConflict"},
                    {s::SssdReleaseStatus::Unresolved,"Unresolved"},{s::SssdReleaseStatus::PersistentReleased,"PersistentReleased"},
                    {s::SssdReleaseStatus::RuntimeVerified,"RuntimeVerified"},{s::SssdReleaseStatus::ReleasedOffline,"ReleasedOffline"},
                    {s::SssdReleaseStatus::ReleasedAwaitingDisable,"ReleasedAwaitingDisable"},{s::SssdReleaseStatus::CleanupFailed,"CleanupFailed"},
                    {s::SssdReleaseStatus::JournalFailed,"JournalFailed"},{s::SssdReleaseStatus::Completed,"Completed"}};
                out["status"]=releaseNames.at(x.status);out["success"]=x.success();
                out["operation"]=operation;out["physical_released"]=x.physicalReleased;
                out["offline"]=x.offline;out["offline_verified"]=x.offlineVerified;
                out["disable_acknowledged"]=x.disableAcknowledged;
                out["released"]=j::assignments(x.released);out["surviving"]=j::assignments(x.surviving);
                out["staged_path"]=x.stagedPath;
            }
            out["checkpoints"]=checkpoints;
        }
        out["journal_health"]=journal.usable()?"Healthy":"Indeterminate";
        out["records"]=J::array();
        for(const auto& rec:journal.records()) {
            J e={{"id",rec.id},{"policy",rec.policy.policyName},{"status",r::mutationStatusToString(rec.status)}};
            if(auto own=std::get_if<r::SssdJournalOwnership>(&rec.undo.payload))e["ownership"]=j::encode(*own);
            out["records"].push_back(e);
        }
    }
    if(std::filesystem::exists(journalPath)) {
        try{out["raw_journal"]=J::parse(read(journalPath));}
        catch(const std::exception& e){out["raw_journal_error"]=e.what();out["raw_journal_bytes"]=read(journalPath);}
    }
    if(std::filesystem::exists("/etc/sssd/conf.d/zzzz-fic.conf"))out["managed_bytes"]=read("/etc/sssd/conf.d/zzzz-fic.conf");else out["managed_bytes"]=nullptr;
    out["staged_artifacts"]=J::array();
    if(std::filesystem::exists("/etc/sssd/conf.d"))for(const auto& e:std::filesystem::directory_iterator("/etc/sssd/conf.d"))
        if(e.path().filename().string().rfind(".zzzz-fic.conf",0)==0||e.path().filename().string().rfind(fic::identity::sssd::managedSnippetRemovalStagingPrefix("zzzz-fic.conf"),0)==0)out["staged_artifacts"].push_back({{"path",e.path().string()},{"sha256",fic::core::ContentDigest::sha256Hex(read(e.path().string()))}});
    out["main_sha256"]=fic::core::ContentDigest::sha256Hex(read("/etc/sssd/sssd.conf"));
    for(auto pid:stopped)::kill(pid,SIGCONT);
    if(source>=0)::close(source);
    std::cout<<out.dump(2)<<'\n';return 0;
  }catch(const std::exception& e){out["driver_error"]=e.what();std::cout<<out.dump(2)<<'\n';return 1;}
}
