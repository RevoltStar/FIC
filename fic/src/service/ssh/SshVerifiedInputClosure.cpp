#include "service/ssh/SshVerifiedInputClosure.h"
#include "service/VerifiedConfigMountSupport.h"
#include "modules/net/ssh/SshConfigSyntax.h"
#include "modules/net/ssh/SshPolicySemantics.h"
#include "modules/net/ssh/SshManagedBlock.h"
#include "platform/PlatformProfile.h"
#include <algorithm>
#include <fic/core/integrity/ContentDigest.h>
#include <functional>
#include <sstream>
namespace fic::service::ssh::detail {
namespace {
[[noreturn]] void unsupported(const std::string& why) {
    throw fic::service::detail::Failure(ActivationStatus::UnsupportedConfiguration, why);
}
bool path(const std::string& name) {
    const std::filesystem::path p(name);
    return !name.empty() && name[0] == '/' && p != "/" && name == p.lexically_normal().string() &&
        name.back() != '/' && name.find_first_not_of("/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-+") == std::string::npos &&
        std::none_of(p.begin(), p.end(), [](const auto& c) { return c == ".." || c == "."; });
}
}
InputProfile inputProfile() {
    const auto profile=fic::platform::makeBuildPlatformProfile();const auto& ssh=profile.ssh;
    return {ssh.serviceUnits.at(0),ssh.configPath.string(),ssh.includeBasePath.string(),ssh.verifiedIncludeDirectory.string(),ssh.optionFile.string(),ssh.optionVariable,profile.id=="alt-p11"};
}
void validatePolicies(const std::map<std::string, std::string>& policies) {
    if (policies.empty() || policies.size() > 5) unsupported("selected SSH policies required");
    for (const auto& [id, value] : policies) {
        if (sshPolicyDirectiveSemantics(id) == SshDirectiveSemantics::Unsupported)
            unsupported("unknown selected SSH policy");
        if (id == "ssh_root_login") {
            if (value != "no" && value != "prohibit-password" && value != "forced-commands-only") unsupported("invalid root login reference");
        } else if (id == "ssh_pubkey_auth" || id == "ssh_use_pam") {
            if (value != "yes") unsupported("FIC authentication policies require yes");
        } else if (id == "ssh_port" || id == "ssh_max_auth_tries") {
            if (value.empty() || value.size() > 5 || value[0] == '0' ||
                value.find_first_not_of("0123456789") != std::string::npos)
                unsupported("invalid numeric SSH reference");
            const auto number = std::stoul(value);
            if (!number || (id == "ssh_port" ? number > 65535 : number > 5)) unsupported("numeric SSH reference outside v1 bounds");
        } else unsupported("SSH policy lacks an explicit adapter v1 contract");
    }
}
void validateCompatibleDropIn(const std::string& bytes) {
    if (bytes.size()>65536 || bytes.find('\0')!=std::string::npos) unsupported("unsupported SSH drop-in size/content");
    std::istringstream input(bytes);std::string line,section;
    while(std::getline(input,line)) {
        const auto first=line.find_first_not_of(" \t");
        if(first==std::string::npos||line[first]=='#'||line[first]==';')continue;
        line=line.substr(first,line.find_last_not_of(" \t")-first+1);
        if(line=="[Unit]"||line=="[Service]"){section=line;continue;}
        if(section=="[Unit]" && line.rfind("Description=",0)==0 &&
           line.find_first_of("\\\r\n%$")==std::string::npos)continue;
        if(section=="[Service]" && line.rfind("CPUWeight=",0)==0) {
            const auto n=line.substr(10);
            if(!n.empty()&&n.size()<=5&&n.find_first_not_of("0123456789")==std::string::npos&&
               std::stoul(n)>=1&&std::stoul(n)<=10000)continue;
        }
        unsupported("SSH drop-in outside tested Description/CPUWeight allowlist");
    }
}
void validateEmptyOptions(const std::string& bytes, const std::string& variable) {
    if (bytes.size() > 65536 || bytes.find('\0') != std::string::npos) unsupported("unsupported SSH EnvironmentFile");
    std::istringstream stream(bytes); std::string line; unsigned assignments = 0;
    while (std::getline(stream, line)) {
        const auto first = line.find_first_not_of(" \t");
        if (first == std::string::npos || line[first] == '#') continue;
        const auto last = line.find_last_not_of(" \t");
        const auto assignment = line.substr(first, last-first+1);
        if ((assignment != variable+"=" && assignment != variable+"=\"\"" && assignment != variable+"=''" ) || ++assignments != 1)
            unsupported("only one literal empty "+variable+" assignment is supported");
    }
    if (assignments != 1) unsupported("explicit empty "+variable+" required");
}
static Closure classifyClosure(const ActivationRequest& r, const InputBytes& bytes, const std::map<std::string, std::string>& policies, bool requireKeys, const InputProfile& profile) {
    validatePolicies(policies);
    fic::service::detail::validateRequest(r);
    if (r.unit != profile.unit) unsupported("canonical platform SSH unit required");
    std::set<std::string> directories;
    for (const auto& p : r.paths) {
        if (!path(p.path.string())) unsupported("SSH reference path outside v1 grammar");
        if (p.kind == ControlledPathKind::Directory) directories.insert(p.path.string());
    }
    std::map<std::string, std::string> expected;
    for (const auto& p : r.paths) {
        if (p.kind == ControlledPathKind::File) expected.emplace(p.path.string(), p.sha256);
        else for (const auto& [relative, sha] : p.manifest) expected.emplace((p.path / relative).string(), sha);
    }
    if (expected.size() != bytes.size()) unsupported("reference input byte set mismatch");
    std::uint64_t used = 0;
    for (const auto& [name, content] : bytes) {
        used += content.size();
        if (!path(name) || !expected.count(name) || used > r.maxSnapshotBytes ||
            fic::core::ContentDigest::sha256Hex(content) != expected.at(name))
            throw fic::service::detail::Failure(ActivationStatus::ChecksumMismatch, "SSH reference bytes mismatch");
    }
    Closure result; std::set<std::string> active;
    std::size_t visits = 0, lines = 0;
    std::map<std::string,std::string> selected;
    for (const auto& [id, value] : policies) selected.emplace(normalizeSshKeyword(sshPolicyDirectiveKeyword(id)),value);
    const std::set<std::string> supported{
        "permitrootlogin", "pubkeyauthentication", "usepam", "maxauthtries", "port",
        "match", "include", "listenaddress", "addressfamily", "hostkey", "pidfile", "loglevel",
        "versionaddendum", "permittty", "passwordauthentication", "kbdinteractiveauthentication",
        "printmotd", "x11forwarding", "acceptenv", "subsystem", "authorizedkeysfile",
        "usedns", "permitemptypasswords", "strictmodes", "logingracetime"};
    std::function<void(const std::string&, unsigned, bool)> visit = [&](const std::string& name, unsigned depth, bool conditional) {
        if (depth > 16 || ++visits > 256 || !active.insert(name).second) unsupported("SSH Include recursion/depth/visit bound exceeded");
        const auto found = bytes.find(name);
        if (found == bytes.end()) unsupported("uncovered SSH configuration input");
        result.order.push_back(name);
        if (found->second.find('\0') != std::string::npos) unsupported("NUL in SSH configuration unsupported");
        std::istringstream stream(found->second); std::string line;
        while (std::getline(stream, line)) {
            if (++lines > 65536 || line.size() > 8192) unsupported("SSH classifier line bound exceeded");
            auto first = line.find_first_not_of(" \t");
            if (first == std::string::npos || line[first] == '#') continue;
            // A deliberate subset, not an attempted OpenSSH tokenizer clone.
            if (line.find_first_of("\"'\\=#$%~\r\v\f") != std::string::npos ||
                std::any_of(line.begin(), line.end(), [](unsigned char c) { return c >= 127 || (c < 32 && c != '\t'); }))
                unsupported("unsupported SSH quoting/escape/character syntax");
            const auto parsed = parseSshConfigLine(line);
            if (!parsed.ok || !parsed.hasDirective || parsed.directive.arguments.empty()) unsupported("invalid SSH directive");
            const auto key = normalizeSshKeyword(parsed.directive.keyword);
            if (!supported.count(key)) unsupported("unsupported SSH directive or Match context");
            const auto& args = parsed.directive.arguments;
            if (key == "match") {
                std::string error;
                if (!sshSupportedMatch(args,error)) unsupported(error);
                conditional = true; continue;
            }
            if (conditional && selected.count(key) &&
                (args.size()!=1 || !sshConditionalValueIsSafe(key,args.front(),selected.at(key))))
                unsupported("conditional SSH policy value is weaker, invalid or global-only");
            const auto portPolicy=policies.find("ssh_port");
            if(portPolicy!=policies.end()) {
                if(key=="port" && name!=profile.mainFile &&
                   (args.size()!=1 || args.front()!=portPolicy->second))
                    unsupported("foreign Include Port conflicts with selected SSH port; no mutation allowed");
                if(key=="listenaddress" && args.size()==1) {
                    const auto& address=args.front();
                    std::string port;
                    if(!address.empty()&&address.front()=='[') {
                        const auto close=address.find(']');
                        if(close!=std::string::npos && close+1<address.size() && address[close+1]==':') port=address.substr(close+2);
                    } else if(std::count(address.begin(),address.end(),':')==1) port=address.substr(address.find(':')+1);
                    if(!port.empty() && port!=portPolicy->second)
                        unsupported("explicit ListenAddress port conflicts with selected SSH port; no mutation allowed");
                }
            }
            if (key == "hostkey") {
                if (args.size() != 1 || !path(args[0])) unsupported("HostKey and public companion require explicit reference coverage");
                result.hostKeys.insert(args[0]);
            }
            if (key != "include") continue;
            for (const auto& arg : args) {
                std::filesystem::path resolved(arg);
                if (resolved.is_relative()) resolved = std::filesystem::path(profile.base) / resolved;
                const auto include = resolved.string();
                // Check the pattern itself BEFORE expansion, including empty
                // glob sets and Includes textually inside any Match context.
                const auto relative = resolved.lexically_relative(profile.fragments);
                if (include != resolved.lexically_normal().string() || relative.empty() ||
                    relative.is_absolute() || relative.begin()->string() == ".." ||
                    include.rfind(profile.fragments+"/", 0) != 0)
                    unsupported("Include outside supported platform SSH configuration boundary");
                const bool glob = include.size() > 6 && include.compare(include.size()-6, 6, "*.conf") == 0;
                const auto parent = std::filesystem::path(include).parent_path().string();
                if (glob) {
                    if (std::filesystem::path(include).filename() != "*.conf" || !path(parent) || !directories.count(parent))
                        unsupported("Include glob requires exact protected directory root");
                    result.negativeSetDirectories.insert(parent);
                    // Enumerate the verified manifest bytes, never glob a mutable tree.
                    for (const auto& [candidate, _] : bytes) {
                        auto file = std::filesystem::path(candidate);
                        const auto base = file.filename().string();
                        if (file.parent_path() == parent && !base.empty() && base[0] != '.' &&
                            base.size() >= 5 && base.compare(base.size()-5, 5, ".conf") == 0) visit(candidate, depth+1, conditional);
                    }
                } else {
                    if (!path(include)) unsupported("Include path outside literal absolute grammar");
                    if (bytes.count(include)) visit(include, depth+1, conditional);
                    else {
                        if (!directories.count(parent)) unsupported("absent literal Include requires protected exact parent");
                        result.negativeSetDirectories.insert(parent);
                    }
                }
            }
        }
        active.erase(name);
    };
    visit(profile.mainFile, 0, false);
    if (result.hostKeys.empty() || profile.alt) {
        // Native default key set. ALT also needs every stock keygen -A target
        // even with explicit HostKey: the vendor Pre hook must remain a no-op.
        for (const auto* key : {"ssh_host_rsa_key", "ssh_host_ecdsa_key", "ssh_host_ed25519_key"}) {
            result.hostKeys.insert((std::filesystem::path(profile.base)/key).string());
        }
    }
    if(requireKeys)for(const auto& key:result.hostKeys)
        if(!bytes.count(key)||!bytes.count(key+".pub"))unsupported("HostKey inputs require complete trusted reference coverage");
    return result;
}
Closure validateClosure(const ActivationRequest& r,const InputBytes& bytes,const std::map<std::string,std::string>& policies,const InputProfile& profile) {
    return classifyClosure(r,bytes,policies,true,profile);
}
std::set<std::string> discoverHostKeys(const ActivationRequest& r,const InputBytes& bytes,const std::map<std::string,std::string>& policies) {
    return classifyClosure(r,bytes,policies,false,inputProfile()).hostKeys;
}
} // namespace fic::service::ssh::detail
