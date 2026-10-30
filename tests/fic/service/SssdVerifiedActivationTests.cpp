#include "platform/PlatformProfile.h"
#include "service/VerifiedConfigMountSupport.h"
#include "service/sssd/SssdRuntimeProof.h"
#include <fstream>
#include <functional>
#include <iostream>
#include <nlohmann/json.hpp>
#include <stdexcept>
using namespace fic::service;
namespace s = fic::service::sssd;
namespace d = fic::service::detail;
namespace {
void check(bool x, const char *why) {
  if (!x)
    throw std::runtime_error(why);
}
void refuses(const std::function<void()> &f) {
  bool refused = false;
  try {
    f();
  } catch (const d::Failure &) {
    refused = true;
  }
  check(refused, "expected fail-closed refusal");
}
s::SssdInputReference input(const std::string &extra = "") {
  s::SssdInputReference x;
  x.launch.profile = s::launchProfile("debian-12");
  x.launch.processIdentity = "100:1:invocation";
  auto &parent = x.sources["/etc/sssd"];
  parent.present = true;
  parent.tree.files["sssd.conf"] =
      "[sssd]\ndomains=a\nservices=pam\n[pam]\noffline_credentials_expiration="
      "1\n[domain/"
      "a]\nid_provider=ldap\nauth_provider=ldap\ncache_credentials="
      "true\naccount_cache_expiration=2\ncached_auth_timeout=30\n" +
      extra;
  parent.tree.attributes[""].st_mode = S_IFDIR | 0700;
  parent.tree.attributes["conf.d"].st_mode = S_IFDIR | 0700;
  x.order = {"/etc/sssd/sssd.conf"};
  x.ini = s::detail_i2::merge(s::detail_i2::orderedGraph(x));
  auto &env = x.sources[x.launch.profile.environment];
  env.present = true;
  env.tree.files[""] = "";
  return x;
}
void expectations() {
  auto x = input();
  auto cfg = s::effectiveConfiguration(x);
  std::vector<s::SssdSemanticExpectation> good{
      {{"pam", "offline_credentials_expiration"}, s::Days{1}},
      {{"domain/a", "cache_credentials"}, true},
      {{"domain/a", "account_cache_expiration"}, s::Days{2}},
      {{"domain/a", "cached_auth_timeout"}, s::Seconds{30}}};
  s::detail_i3::validateExpectations(cfg, good);
  refuses([&] { s::detail_i3::validateExpectations(cfg, {}); });
  for (auto key : {s::SettingKey{"domain/ghost", "cache_credentials"},
                   s::SettingKey{"pam", "cache_credentials"},
                   s::SettingKey{"domain/a", "unknown"}})
    refuses([&] { s::detail_i3::validateExpectations(cfg, {{key, true}}); });
  for (auto v : {s::SemanticValue{s::Seconds{1}}, s::SemanticValue{s::Days{2}},
                 s::SemanticValue{std::monostate{}}})
    refuses([&] {
      s::detail_i3::validateExpectations(
          cfg, {{{"pam", "offline_credentials_expiration"}, v}});
    });
  good.push_back(good.front());
  refuses([&] { s::detail_i3::validateExpectations(cfg, good); });
  for (const auto &provider : {"ad", "ipa", "proxy", "unknown"}) {
    auto bad = input("id_provider=" + std::string(provider) + "\n");
    refuses([&] {
      s::detail_i3::validateExpectations(
          s::effectiveConfiguration(bad),
          {{{"domain/a", "cache_credentials"}, true}});
    });
  }
  auto conflict = input("cache_credentials=false\n");
  refuses([&] {
    s::detail_i3::validateExpectations(
        s::effectiveConfiguration(conflict),
        {{{"domain/a", "cache_credentials"}, true}});
  });
  auto data = s::domainScope(x).data();
  data.domains.at("a").enabled = false;
  s::SssdVerifiedActivationRequest request{
      x,
      s::DomainScopeReference(data),
      {{{"domain/a", "cache_credentials"}, true}},
      std::chrono::milliseconds(1)};
  auto result = s::activate(request);
  check(!result.success() && !result.engine.activationAttempted &&
            result.admission == s::SssdProofState::Unsupported,
        "forged scope refused before runtime");
  data = s::domainScope(x).data();
  data.hypothetical = true;
  request.scope = s::DomainScopeReference(data);
  check(!s::activate(request).engine.activationAttempted,
        "hypothetical scope has no authority");
}
void resultAlgebra() {
  s::SssdVerifiedActivationResult r;
  r.status = s::SssdActivationStatus::Success;
  r.admission = r.inputs = r.activation = r.semantics = r.persistent =
      s::SssdProofState::Proven;
  r.engine.status = r.engine.primaryStatus = ActivationStatus::Success;
  r.engine.activationAttempted = r.engine.readinessConfirmed = true;
  check(r.success(), "full proof success");
  check(r.policyCoverage == s::PolicyCoverage::NotEvaluated,
        "adapter not policy coverage");
  for (auto member : {&s::SssdVerifiedActivationResult::admission,
                      &s::SssdVerifiedActivationResult::inputs,
                      &s::SssdVerifiedActivationResult::activation,
                      &s::SssdVerifiedActivationResult::semantics,
                      &s::SssdVerifiedActivationResult::persistent})
    for (auto state :
         {s::SssdProofState::NotProven, s::SssdProofState::Unsupported,
          s::SssdProofState::Drifted}) {
      auto c = r;
      c.*member = state;
      check(!c.success(), "every proof mandatory");
    }
  for (auto status :
       {s::SssdActivationStatus::Refused,
        s::SssdActivationStatus::ActivationFailed,
        s::SssdActivationStatus::RuntimeEffectUnknown,
        s::SssdActivationStatus::RuntimeActivatedButPersistentUnproven,
        s::SssdActivationStatus::CleanupFailed}) {
    auto c = r;
    c.status = status;
    check(!c.success(), "partial never success");
  }
  auto c = r;
  c.engine.cleanupErrors = {"busy"};
  check(!c.success(), "cleanup failure");
  c = r;
  c.engine.residualPaths = {"/etc/sssd"};
  check(!c.success(), "residual mount");
  c = r;
  c.engine.primaryStatus = ActivationStatus::TimedOut;
  check(!c.success(), "primary failure retained");
  c = r;
  c.engine.activationAttempted = false;
  check(!c.success(), "no restart no success");
  c = r;
  c.engine.readinessConfirmed = false;
  check(!c.success(), "READY mandatory");
}
void manifest() {
  auto x = input();
  auto request = s::detail_i3::protectedRequest(x, std::chrono::seconds(1));
  check(request.paths.size() == 2 &&
            request.paths[0].directories.count("conf.d"),
        "full parent with empty directory");
  x.sources[x.launch.profile.environment].present = false;
  refuses([&] { s::detail_i3::protectedRequest(x, std::chrono::seconds(1)); });
  request.paths[0].directories.insert("../unsafe");
  refuses([&] { d::validateRequest(request); });
  request = s::detail_i3::protectedRequest(input(), std::chrono::seconds(1));
  request.paths[0].directories.insert("missing/parent/child");
  refuses([&] { d::validateRequest(request); });
  request = s::detail_i3::protectedRequest(input(), std::chrono::seconds(1));
  request.paths[1].directories.insert("a");
  refuses([&] { d::validateRequest(request); });
  d::LaunchContract before{
      {"launch.MainPID", "old"},        {"launch.InvocationID", "old"},
      {"launch.ActiveState", "active"}, {"launch.Job", "none"},
      {"launch.SubState", "running"},   {"launch.file:unit", "same"}};
  auto after = before;
  after["launch.MainPID"] = "new";
  after["launch.InvocationID"] = "new";
  check(s::detail_i3::configurationOnly(before) ==
            s::detail_i3::configurationOnly(after),
        "P excludes old runtime identity");
  after["launch.file:unit"] = "drift";
  check(s::detail_i3::configurationOnly(before) !=
            s::detail_i3::configurationOnly(after),
        "P retains source proof");
}
void profile(const std::string &path) {
  using J = nlohmann::json;
  std::ifstream f(path);
  J fixtures;
  f >> fixtures;
  const auto name = fic::platform::makeBuildPlatformProfile().id;
  d::LaunchContract c = fixtures.at(name).get<d::LaunchContract>();
  const auto p = s::launchProfile(name);
  std::vector<ControlledPath> env{
      {p.environment, ControlledPathKind::File, std::string(64, '0'), {}}};
  d::validateLaunchContract(c, &env, d::ActivationProfile::SssdNotify);
  auto changed = c;
  changed["launch.PIDFile"] =
      J{{"signature", "s"}, {"value", "/run/arbitrary.pid"}}.dump();
  refuses([&] {
    d::validateLaunchContract(changed, &env, d::ActivationProfile::SssdNotify);
  });
  changed = c;
  changed["launch.Id"] =
      J{{"signature", "s"}, {"value", "foreign.service"}}.dump();
  refuses([&] {
    d::validateLaunchContract(changed, &env, d::ActivationProfile::SssdNotify);
  });
  // Generic and both SSH profiles acquire no PIDFile exception from this
  // change.
  changed = c;
  changed["launch.PIDFile"] =
      J{{"signature", "s"}, {"value", "/run/sssd.pid"}}.dump();
  for (auto kind : {d::ActivationProfile::ActiveNotifyService,
                    d::ActivationProfile::UbuntuSshSocket,
                    d::ActivationProfile::AltSshSimple})
    refuses([&] { d::validateLaunchContract(changed, &env, kind); });
  env.clear();
  refuses([&] {
    d::validateLaunchContract(c, &env, d::ActivationProfile::SssdNotify);
  });
}
void parser() {
  check(s::detail_i3::backendBusName("a.b-c_d") == "sssd.domain_a_2eb_2dc_5fd",
        "native domain bus escaping");
  for (const auto &value : {":1.2", ":2.0"})
    check(s::detail_i3::validBusOwner(value), "unique bus owner");
  for (const auto &value :
       {"", ":...", ":1.2.3", ":.2", ":1.", "sssd.domain_a", ":1.x"})
    check(!s::detail_i3::validBusOwner(value), "invalid bus owner");
  auto r = s::detail_i3::parseConfigDb(
      "# comment\ndn: cn=a,cn=domain,cn=config\ncn: a\ncache_credentials: tr\n "
      "ue\n\n");
  check(r.at(s::detail_i3::domainDn("a")).at("cache_credentials") == "true",
        "bounded LDIF folding");
  for (const auto &text : {"dn: x\na: 1\na: 2\n", "dn:: eA==\n", "cn: a\n",
                           " continuation\n", "dn: x\n\ndn: x\n"})
    refuses([&] { s::detail_i3::parseConfigDb(text); });
  for (const auto &domain : {"", "a,b", "a/b", "a=", "a b"})
    refuses([&] { s::detail_i3::domainDn(domain); });
  refuses(
      [&] { s::detail_i3::parseConfigDb(std::string(1024 * 1024 + 1, 'a')); });
}
} // namespace
int main(int argc, char **argv) {
  try {
    check(argc == 2, "fixture path required");
    profile(argv[1]);
    std::cout << "expectations\n";
    expectations();
    std::cout << "results\n";
    resultAlgebra();
    std::cout << "manifest\n";
    manifest();
    std::cout << "parser\n";
    parser();
    std::cout << "SSSD activation contract PASS\n";
    return 0;
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
