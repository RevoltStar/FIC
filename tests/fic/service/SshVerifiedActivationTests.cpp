#include "service/ssh/SshVerifiedActivationAdapter.h"
#include "service/ssh/SshVerifiedInputClosure.h"
#include "service/ssh/SshPersistentMetadata.h"
#include "service/VerifiedConfigMountSupport.h"
#include <fic/core/integrity/ContentDigest.h>
#include <iostream>
#include <nlohmann/json.hpp>
#include <functional>
using namespace fic::service;
namespace s = fic::service::ssh;
namespace d = s::detail;
void require(bool yes, const char* why) { if (!yes) throw std::runtime_error(why); }
const std::string mainFile = "/etc/ssh/sshd_config", dir = "/etc/ssh/sshd_config.d";
const std::string host = "/etc/ssh/key";
std::string sha(const std::string& text) { return fic::core::ContentDigest::sha256Hex(text); }
struct Fixture {
    ActivationRequest reference;
    d::InputBytes bytes;
    Fixture() {
        reference.unit = "ssh.service";
        bytes = {{mainFile, "HostKey " + host + "\nInclude " + dir + "/*.conf\nPermitRootLogin no\n"}, {host,"private fixture"}, {host+".pub","public fixture"}, {"/etc/default/ssh","SSHD_OPTS=\n"}};
        sync();
    }
    void sync() {
        reference.paths.clear(); FileManifest manifest;
        for (const auto& [path, value] : bytes) {
            if (path.rfind(dir+"/", 0) == 0) manifest.emplace(path.substr(dir.size()+1), sha(value));
            else reference.paths.push_back({path, ControlledPathKind::File, sha(value), {}});
        }
        reference.paths.push_back({dir, ControlledPathKind::Directory, "", manifest});
    }
    auto closure(const std::map<std::string,std::string>& policies = {{"ssh_root_login","no"}}) { return d::validateClosure(reference, bytes, policies); }
};
int main() {
    unsigned checks = 0;
    const auto deny = [&](const std::function<void()>& action) {
        bool refused = false; try { action(); } catch (const fic::service::detail::Failure&) { refused = true; }
        require(refused, "unsupported input accepted"); ++checks;
    };
    using J = nlohmann::json;
    std::map<std::string,std::string> launch;
    auto put = [&](const char* name, const J& v) { launch[std::string("launch.")+name] = J{{"value",v}}.dump(); };
    for (const auto* name : {"ExecConditionEx","ExecStartPostEx","ExecStopEx","ExecStopPostEx","Environment","PassEnvironment","UnsetEnvironment","DropInPaths","SupplementaryGroups"}) put(name,J::array());
    put("ExecStartEx",J::array({J::array({"/usr/sbin/sshd",J::array({"/usr/sbin/sshd","-D","$SSHD_OPTS"}),J::array()})}));
    put("ExecStartPreEx",J::array({J::array({"/usr/sbin/sshd",J::array({"/usr/sbin/sshd","-t"}),J::array()})}));
    put("EnvironmentFiles",J::array({J::array({"/etc/default/ssh",true})}));
    put("User", ""); put("Group", "");
    put("FragmentPath","/lib/systemd/system/ssh.service"); launch["launch.ManagerEnvironment"] = "[]";
    d::validateLaunchProfile(launch); ++checks;
    launch["launch.ManagerEnvironment"] = J::array({"LANG=C.UTF-8","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"}).dump();
    d::validateLaunchProfile(launch); ++checks;
    const auto goodLaunch = launch;
    for (const auto* name : {"ExecStartEx","ExecStartPreEx","ExecConditionEx","ExecStartPostEx","ExecStopEx","ExecStopPostEx","Environment","PassEnvironment","UnsetEnvironment","DropInPaths"}) {
        launch = goodLaunch; put(name,J::array({"unsupported"})); deny([&] { d::validateLaunchProfile(launch); });
    }
    launch=goodLaunch; put("EnvironmentFiles",J::array({J::array({"/etc/other.env",true})})); deny([&] { d::validateLaunchProfile(launch); });
    for (const auto* name : {"User", "Group", "SupplementaryGroups"}) {
        launch=goodLaunch; put(name, name == std::string("SupplementaryGroups") ? J::array({"nobody"}) : J("nobody"));
        deny([&] { d::validateLaunchProfile(launch); });
    }
    launch=goodLaunch; put("FragmentPath","/etc/systemd/system/ssh.service"); deny([&] { d::validateLaunchProfile(launch); });
    for (const auto* env : {"SSHD_OPTS=-p2223", "LD_PRELOAD=/bad", "LANG=en_US.UTF-8", "UNKNOWN=yes"}) {
        launch=goodLaunch; launch["launch.ManagerEnvironment"] = J::array({env}).dump(); deny([&] { d::validateLaunchProfile(launch); });
    }
    Fixture f;
    require(f.closure().negativeSetDirectories.count(dir), "empty glob negative set not protected"); ++checks;
    f.bytes[dir+"/10.conf"] = "Port 2222\nInclude " + dir + "/nested.inc\n";
    f.bytes[dir+"/nested.inc"] = "MaxAuthTries 3\n"; f.sync();
    require(f.closure().order.size() == 3, "nested literal/glob order wrong"); ++checks;
    f.bytes[mainFile] += "Include " + dir + "/nested.inc " + dir + "/absent.conf\n"; f.sync();
    require(f.closure().order.size() == 4, "multiple/repeated literal Include rejected"); ++checks;
    require(f.closure().order == f.closure().order, "stable repeated reference diverged"); ++checks;
    for (const auto& text : {"Match all\nPermitRootLogin yes\n", "Match exec /bad\n", "UnknownFicDirective yes\n", "Include relative.conf\n", "Include /uncovered/*.conf\n", "Include /outside/missing.conf\n", "Include /etc/ssh/../escape\n", "Include /etc/ssh/?/*.conf\n", "Include \"/etc/a\"\n", "Port=22\n", "Include /etc/a\\\n"}) {
        Fixture bad; bad.bytes[mainFile] += text; bad.sync(); deny([&] { bad.closure(); });
    }
    Fixture relative; relative.bytes[mainFile] += "Include sshd_config.d/inside.inc\n";
    relative.bytes[dir+"/inside.inc"]="X11Forwarding no\n";relative.sync();
    require(relative.closure().order.size()==2,"in-bound relative Include rejected"); ++checks;
    Fixture match;match.bytes[mainFile]+="Match User backup\nX11Forwarding no\n";match.sync();
    match.closure(); ++checks;
    Fixture conditional;conditional.bytes[mainFile]+="Match User root\nInclude sshd_config.d/conditional.inc\n";
    conditional.bytes[dir+"/conditional.inc"]="PermitRootLogin yes\n";conditional.sync();
    deny([&]{conditional.closure();});
    conditional.closure({{"ssh_pubkey_auth","yes"}}); ++checks;
    for(const auto& text:{"Include /opt/evil/*.conf\n","Match User backup\nInclude /opt/evil/*.conf\n"}) {
        Fixture outside;outside.bytes[dir+"/outside.conf"]=text;outside.sync();deny([&]{outside.closure();});
    }
    // Even a caller-protected outside directory cannot expand Debian authority.
    Fixture external;external.bytes[mainFile]+="Include /opt/evil/*.conf\n";external.sync();
    external.reference.paths.push_back({"/opt/evil",ControlledPathKind::Directory,"",{}});
    deny([&]{external.closure();});
    Fixture cycle; cycle.bytes[dir+"/cycle.conf"] = "Include " + mainFile + "\n"; cycle.sync(); deny([&] { cycle.closure(); });
    Fixture deep;
    deep.bytes[mainFile] += "Include " + dir + "/1.inc\n";
    for (unsigned i=1; i<19; ++i) deep.bytes[dir+"/"+std::to_string(i)+".inc"] = "Include " + dir + "/" + std::to_string(i+1) + ".inc\n";
    deep.sync(); deny([&] { deep.closure(); });
    Fixture visits; visits.bytes[mainFile] += std::string();
    for (unsigned i=0; i<257; ++i) visits.bytes[mainFile] += "Include " + dir + "/one.inc\n";
    visits.bytes[dir+"/one.inc"] = "# repeated\n"; visits.sync(); deny([&] { visits.closure(); });
    Fixture mismatch; mismatch.bytes[mainFile] += "Port 1234\n"; deny([&] { mismatch.closure(); });
    Fixture lost; lost.bytes.erase(host); deny([&] { lost.closure(); });
    Fixture overlap; overlap.reference.paths.push_back({"/etc/ssh",ControlledPathKind::Directory,"",{}}); deny([&] { overlap.closure(); });
    Fixture duplicate; duplicate.reference.paths.push_back(duplicate.reference.paths[0]); deny([&] { duplicate.closure(); });
    Fixture badSha; badSha.reference.paths[0].sha256=std::string(64,'F'); deny([&] { badSha.closure(); });
    Fixture noDir; noDir.reference.paths.pop_back(); deny([&] { noDir.closure(); });
    Fixture doubleSlash;
    doubleSlash.bytes[mainFile] = "HostKey " + host + "\nInclude /etc/ssh//sshd_config.d/*.conf\n";
    doubleSlash.sync(); doubleSlash.reference.paths.back().path = "/etc/ssh//sshd_config.d";
    deny([&] { doubleSlash.closure(); });
    for (const auto& env : {"SSHD_OPTS=-f /other\n", "SSHD_OPTS=-oUsePAM=no\n", "SSHD_OPTS=-p2223\n", "SSHD_OPTS=\"\"\n", "SSHD_OPTS=\nSSHD_OPTS=\n", "OTHER=\n", "# no assignment\n", "SSHD_OPTS=\r\n"}) deny([&] { d::validateEmptyOptions(env); });
    for (const auto& env : {"SSHD_OPTS=\n", " # comment\n\tSSHD_OPTS=  \n\n"}) { d::validateEmptyOptions(env); ++checks; }
    d::validatePolicies({{"ssh_root_login","no"},{"ssh_pubkey_auth","yes"},{"ssh_use_pam","yes"},{"ssh_max_auth_tries","3"},{"ssh_port","2222"}}); ++checks;
    for (const auto& policies : {std::map<std::string,std::string>{}, {{"unknown","yes"}}, {{"ssh_port","65536"}}, {{"ssh_use_pam","ENABLE"}}, {{"ssh_use_pam","no"}}, {{"ssh_pubkey_auth","no"}}, {{"ssh_root_login","yes"}}, {{"ssh_max_auth_tries","6"}}, {{"ssh_port","22 23"}}}) deny([&] { d::validatePolicies(policies); });
    // Exact operation baseline: both map keys and metadata matter; atime does not.
    d::PersistentMetadata baseline;
    struct stat st{}; st.st_mode = S_IFREG | 0600; st.st_ino = 12; st.st_dev = 3;
    st.st_nlink = 1; st.st_size = 42; st.st_mtim = {10, 20}; st.st_ctim = {30, 40};
    baseline.roots[host] = {7, 12, 3, st.st_mode, 0, 0};
    baseline.attributes[host][""] = st;
    d::requireStableMetadata(baseline, baseline); ++checks;
    auto accessed = baseline; accessed.attributes[host][""].st_atim = {99, 12};
    d::requireStableMetadata(baseline, accessed); ++checks;
    const std::vector<std::function<void(struct stat&)>> changes = {
        [](auto& v){++v.st_dev;}, [](auto& v){++v.st_ino;}, [](auto& v){v.st_mode = S_IFDIR|0600;},
        [](auto& v){v.st_mode = S_IFREG|0644;}, [](auto& v){v.st_mode |= S_ISUID;},
        [](auto& v){++v.st_uid;}, [](auto& v){++v.st_gid;}, [](auto& v){++v.st_nlink;},
        [](auto& v){++v.st_size;}, [](auto& v){++v.st_mtim.tv_sec;}, [](auto& v){++v.st_mtim.tv_nsec;},
        [](auto& v){++v.st_ctim.tv_sec;}, [](auto& v){++v.st_ctim.tv_nsec;}
    };
    for (const auto& change : changes) {
        auto other = baseline; change(other.attributes[host][""]);
        deny([&]{d::requireStableMetadata(baseline, other);});
    }
    for (unsigned i=0; i<7; ++i) {
        auto other = baseline;
        if (i==0) ++other.roots[host].mount;
        if (i==1) ++other.roots[host].inode;
        if (i==2) other.attributes[host]["added"] = st;
        if (i==3) other.attributes[host].clear();
        if (i==4) {other.attributes[host].clear(); other.attributes[host]["renamed"] = st;}
        if (i==5) {other.roots.clear(); other.roots[host+".new"] = baseline.roots.at(host);}
        if (i==6) {other.attributes.clear(); other.attributes[host+".new"][""] = st;}
        deny([&]{d::requireStableMetadata(baseline, other);});
    }
    const auto proof = [&](const d::PersistentMetadata& current) {
        return d::persistentProof(baseline, [&]{return current;}, [](const auto&){});
    };
    require(proof(baseline)==s::ProofState::Proven && proof(accessed)==s::ProofState::Proven, "stable/atime P failed"); ++checks;
    for (const auto& change : changes) {
        auto other=baseline; change(other.attributes[host][""]);
        require(proof(other)==s::ProofState::NonCompliant, "metadata drift P not NonCompliant"); ++checks;
    }
    auto stricter=baseline; stricter.attributes[host][""].st_mode=S_IFREG|0400;
    require(proof(stricter)==s::ProofState::NonCompliant, "stricter mode accepted"); ++checks;
    auto publicBaseline=baseline; publicBaseline.attributes[host][""].st_mode=S_IFREG|0644;
    auto privateCurrent=publicBaseline; privateCurrent.attributes[host][""].st_mode=S_IFREG|0600;
    require(d::persistentProof(publicBaseline, [&]{return privateCurrent;}, [](const auto&){})==s::ProofState::NonCompliant, "0644 to 0600 accepted"); ++checks;
    for (auto status : {ActivationStatus::SnapshotFailed, ActivationStatus::ChecksumMismatch, ActivationStatus::UnsupportedConfiguration, ActivationStatus::TimedOut}) {
        require(d::persistentProof(baseline, [&]() -> d::PersistentMetadata {throw fic::service::detail::Failure(status,"read failure");}, [](const auto&){})==s::ProofState::NotProven, "failed metadata acquisition proven"); ++checks;
    }
    for (bool manifest : {false,true}) {
        Fixture changed;
        if (manifest) changed.bytes[dir+"/new.conf"]="Port 22\n";
        else changed.bytes[mainFile]+="Port 22\n";
        auto current=baseline;
        if (manifest) current.attributes[host]["new.conf"]=st;
        require(d::persistentProof(baseline, [&]{return current;}, [&](const auto&){changed.closure();})==s::ProofState::NonCompliant, "SHA/manifest drift not rejected"); ++checks;
    }
    for (auto mode : {0600,0400}) {st.st_mode=S_IFREG|mode; d::requireSafePrivateHostKey(st); ++checks;}
    for (auto mode : {0644,0640,0660,0700,04600,02600,01600}) {
        st.st_mode=S_IFREG|mode; deny([&]{d::requireSafePrivateHostKey(st);});
    }
    st.st_mode=S_IFLNK|0600; deny([&]{d::requireSafePrivateHostKey(st);});
    st.st_mode=S_IFREG|0600; st.st_uid=123; deny([&]{d::requireSafePrivateHostKey(st);});
    require(f.closure().hostKeys.count(host) && !f.closure().hostKeys.count(host+".pub"), "public companion treated as private key"); ++checks;
    for (const auto* root : {"no","prohibit-password","forced-commands-only"}) {d::validatePolicies({{"ssh_root_login",root}}); ++checks;}
    for (const auto* id : {"ssh_port","ssh_max_auth_tries"}) {
        for (const auto* v : {"1", id==std::string("ssh_port") ? "65535" : "5"}) {d::validatePolicies({{id,v}}); ++checks;}
        for (const auto* v : {"0","-1","+1","01","1x", id==std::string("ssh_port") ? "65536" : "6"}) deny([&]{d::validatePolicies({{id,v}});});
    }
    // Public adapter malformed references fail before any runtime activation.
    for (auto request : {s::SshVerifiedActivationRequest{}, s::SshVerifiedActivationRequest{f.reference,{{"unknown","yes"}}}}) {
        const auto result = s::SshVerifiedActivationAdapter::activate(request);
        require(!result.success() && !result.activationAttempted && !result.activation.readinessConfirmed, "malformed reference invoked runtime"); ++checks;
    }
    s::SshVerifiedActivationRequest oversized{f.reference, {{"ssh_port","2222"}}};
    oversized.reference.timeout = std::chrono::milliseconds::max();
    require(!s::SshVerifiedActivationAdapter::activate(oversized).activationAttempted, "oversized deadline escaped validation"); ++checks;
    oversized.reference.timeout = std::chrono::seconds(10);
    oversized.reference.paths[0].kind = static_cast<ControlledPathKind>(99);
    require(!s::SshVerifiedActivationAdapter::activate(oversized).activationAttempted, "unknown object kind escaped validation"); ++checks;
    std::cout << "SSH verified adapter " << checks << " contract checks PASS\n";
}
