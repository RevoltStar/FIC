#include "platform/PlatformExecutableResolver.h"
#include "service/VerifiedConfigServiceActivatorTestAccess.h"
#include "service/sssd/SssdVerifiedActivationAdapter.h"
#include <fcntl.h>
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
    paths.configDir = "/run/sssd-i3/config";
    paths.dataDir = "/run/sssd-i3/state";
    paths.logDir = "/run/sssd-i3/log";
    paths.runtimeDir = "/run/sssd-i3";
    paths.commandHashFile = "/run/sssd-i3/hashes";
    paths.lockDebugLogFile = "/run/sssd-i3/log/locks";
    for (const auto &path : {paths.configDir, paths.dataDir, paths.logDir})
      std::filesystem::create_directories(path);
    std::string error;
    if (!fic::core::FicRuntimePaths::initialize(paths, error))
      throw std::runtime_error(error);
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
    const auto action = argc > 1 ? std::string(argv[1]) : "positive";
    const auto timeout =
        std::chrono::milliseconds(argc > 2 ? std::stoi(argv[2]) : 15000);
    const auto input =
        s::capture(std::chrono::steady_clock::now() + std::chrono::seconds(30));
    const auto cfg = s::effectiveConfiguration(input);
    std::vector<s::SssdSemanticExpectation> expectations{
        {{"pam", "offline_credentials_expiration"}, cfg.offlineDays.value}};
    for (const auto &name : cfg.scope.data().enabled) {
      const auto &v = cfg.domains.at(name);
      expectations.push_back(
          {{"domain/" + name, "cache_credentials"}, v.cacheCredentials.value});
      expectations.push_back({{"domain/" + name, "account_cache_expiration"},
                              v.accountDays.value});
      expectations.push_back({{"domain/" + name, "cached_auth_timeout"},
                              v.cachedAuthSeconds.value});
    }
    s::SssdVerifiedActivationRequest request{input, s::domainScope(input),
                                             expectations, timeout};
    if (action == "bad-expectation")
      request.expectations.front().value = s::Days{3650};
    if (action == "account-only")
      request.expectations = {
          {{"domain/" + cfg.scope.data().enabled.at(0),
            "account_cache_expiration"},
           cfg.domains.at(cfg.scope.data().enabled.at(0)).accountDays.value}};
    if (action == "source-fd")
      source = ::open("/etc/sssd/sssd.conf", O_RDWR | O_CLOEXEC);
    d::TestHooks engine;
    s::detail_i3::AdapterTestHooks tests;
    tests.engine = &engine;
    J checkpoints = J::array();
    engine.checkpoint = [&](d::TestPhase phase, const std::string &) {
      if (phase == d::TestPhase::SnapshotReadOnly &&
          action == "snippet-inode") {
        const std::string p = "/etc/sssd/conf.d/10-input.conf";
        std::ofstream f(p + ".tmp");
        f << read(p);
        f.close();
        ::chmod((p + ".tmp").c_str(),
                std::filesystem::status(p).permissions() ==
                        std::filesystem::perms::unknown
                    ? 0600
                    : static_cast<unsigned>(
                          std::filesystem::status(p).permissions()) &
                          0777);
        ::rename((p + ".tmp").c_str(), p.c_str());
        checkpoints.push_back("replaced-original-snippet");
      }
      if (phase == d::TestPhase::Watching) {
        if (action == "source-fd") {
          char byte = '#';
          out["source_fd_write"] = ::pwrite(source, &byte, 1, 0);
          checkpoints.push_back("wrote-hidden-original");
        }
        if (action == "readonly-write") {
          errno = 0;
          int fd = ::open("/etc/sssd/sssd.conf", O_WRONLY);
          out["readonly_fd"] = fd;
          out["readonly_errno"] = errno;
          if (fd >= 0)
            ::close(fd);
          checkpoints.push_back("visible-ro-write-attempt");
        }
        if (action == "mount-change") {
          std::filesystem::create_directories("/run/i3-mount");
          out["mount_mutation"] =
              ::mount("i3-test", "/run/i3-mount", "tmpfs", 0, "mode=0700");
          checkpoints.push_back("mount-mutated");
        }
      }
    };
    engine.fault = [&](const std::string &name, std::size_t index) {
      return action == "cleanup-fail" && name == "umount" && index == 0 ? EBUSY
                                                                        : 0;
    };
    tests.checkpoint = [&](const std::string &phase) {
      checkpoints.push_back(phase);
      if ((action == "unit-before" && phase == "published") ||
          (action == "unit-after" && phase == "ready")) {
        std::ofstream f(input.launch.profile.fragment, std::ios::app);
        f << "\n# I3 deterministic unit mutation\n";
      }
      if (action == "stale-configdb" && phase == "ready") {
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
      if (action == "timeout-published" && phase == "published")
        std::this_thread::sleep_for(timeout + std::chrono::milliseconds(20));
      if (action == "environment-replace" && phase == "persistent") {
        const auto p = input.launch.profile.environment;
        std::ofstream f(p + ".i3-temp");
        f << read(p);
        f.close();
        ::chmod((p + ".i3-temp").c_str(), 0600);
        ::rename((p + ".i3-temp").c_str(), p.c_str());
      }
      if (action == "negative-create" && phase == "persistent") {
        std::ofstream f("/etc/sssd/conf.d/91-new.conf");
        f << "[pam]\ndebug_level=8\n";
        f.close();
        ::chmod("/etc/sssd/conf.d/91-new.conf", 0600);
      }
      if (action == "persistent-drift" && phase == "persistent") {
        std::ofstream f("/etc/sssd/sssd.conf", std::ios::app);
        f << "\n[pam]\noffline_credentials_expiration=99\n";
      }
      if (((action == "stop-monitor" || action == "stop-pam" ||
            action == "stop-backend") &&
           phase == "ready") ||
          (action == "stop-pam-after" && phase == "persistent")) {
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
    const auto result = s::detail_i3::activateForTests(request, tests);
    out["status"] = status(result.status);
    out["success"] = result.success();
    out["proofs"] = {{"admission", proof(result.admission)},
                     {"A", proof(result.inputs)},
                     {"B", proof(result.activation)},
                     {"C", proof(result.semantics)},
                     {"P", proof(result.persistent)}};
    out["engine"] = {
        {"status", fic::service::activationStatusName(result.engine.status)},
        {"primary",
         fic::service::activationStatusName(result.engine.primaryStatus)},
        {"attempted", result.engine.activationAttempted},
        {"readiness", result.engine.readinessConfirmed},
        {"diagnostic", result.engine.diagnostic},
        {"cleanup_errors", result.engine.cleanupErrors},
        {"residual_mounts", result.engine.residualPaths}};
    out["diagnostic"] = result.diagnostic;
    out["old_invocation"] = result.oldInvocation;
    out["new_invocation"] = result.newInvocation;
    out["runtime_effect_possible"] = result.runtimeEffectPossible;
    out["configdb_generation"] = result.configDbGeneration;
    out["native_code"] = result.nativeCode;
    out["checkpoints"] = checkpoints;
    out["policy_coverage"] = "NotEvaluated";
    out["policy_success"] = false;
    for (const auto &p : result.processes)
      out["processes"].push_back({{"pid", p.pid},
                                  {"parent", p.parent},
                                  {"role", p.role},
                                  {"domain", p.domain},
                                  {"token", p.startToken},
                                  {"exe", p.executable},
                                  {"uid", p.uid},
                                  {"gid", p.gid},
                                  {"namespace", p.mountNamespace},
                                  {"cgroup", p.cgroup},
                                  {"initialized", p.initializationConfirmed},
                                  {"consumer_socket", p.consumerSocket},
                                  {"monitor_socket", p.monitorSocket},
                                  {"backend_bus_owner", p.backendBusOwner},
                                  {"configdb", identity(p.configDbIdentity)}});
    for (const auto &p : result.parameters)
      out["parameters"].push_back({{"section", p.key.section},
                                   {"key", p.key.key},
                                   {"configured", value(p.configuredValue)},
                                   {"consumer_value", value(p.consumerValue)},
                                   {"consumer", p.consumer},
                                   {"token", p.processToken},
                                   {"generation", p.configDbGeneration},
                                   {"source_contract", p.sourceContract},
                                   {"read_moment", p.readMoment},
                                   {"scope", p.scope}});
  } catch (const d::Failure &e) {
    out["status"] = fic::service::activationStatusName(e.status);
    out["diagnostic"] = e.what();
    out["success"] = false;
  } catch (const std::exception &e) {
    out["status"] = "HARNESS_ERROR";
    out["diagnostic"] = e.what();
    out["success"] = false;
  }
  for (auto pid : stopped)
    ::kill(pid, SIGCONT);
  if (source >= 0)
    ::close(source);
  std::cout << out.dump(2) << '\n';
  return 0;
}
