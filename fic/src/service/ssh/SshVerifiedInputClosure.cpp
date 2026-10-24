#include "service/ssh/SshVerifiedInputClosure.h"
#include "service/VerifiedConfigMountSupport.h"
#include "modules/net/ssh/SshConfigSyntax.h"
#include "modules/net/ssh/SshManagedBlock.h"
#include <algorithm>
#include <fic/core/integrity/ContentDigest.h>
#include <functional>
#include <sstream>
namespace fic::service::ssh::detail {
namespace {
[[noreturn]] void unsupported(const char* why) {
    throw fic::service::detail::Failure(ActivationStatus::UnsupportedConfiguration, why);
}
bool path(const std::string& name) {
    const std::filesystem::path p(name);
    return !name.empty() && name[0] == '/' && p != "/" && name == p.lexically_normal().string() &&
        name.back() != '/' && name.find_first_not_of("/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-+") == std::string::npos &&
        std::none_of(p.begin(), p.end(), [](const auto& c) { return c == ".." || c == "."; });
}
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
void validateEmptyOptions(const std::string& bytes) {
    if (bytes.size() > 65536 || bytes.find('\0') != std::string::npos) unsupported("unsupported SSH EnvironmentFile");
    std::istringstream stream(bytes); std::string line; unsigned assignments = 0;
    while (std::getline(stream, line)) {
        const auto first = line.find_first_not_of(" \t");
        if (first == std::string::npos || line[first] == '#') continue;
        const auto last = line.find_last_not_of(" \t");
        if (line.substr(first, last - first + 1) != "SSHD_OPTS=" || ++assignments != 1)
            unsupported("only one literal empty SSHD_OPTS assignment is supported");
    }
    if (assignments != 1) unsupported("explicit empty SSHD_OPTS required");
}
Closure validateClosure(const ActivationRequest& r, const InputBytes& bytes, const std::map<std::string, std::string>& policies) {
    validatePolicies(policies);
    fic::service::detail::validateRequest(r);
    if (r.unit != "ssh.service") unsupported("only ssh.service is supported");
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
    bool conditional = false; // Include parsing shares OpenSSH textual Match context.
    std::set<std::string> selected;
    for (const auto& [id, value] : policies) selected.insert(normalizeSshKeyword(sshPolicyDirectiveKeyword(id)));
    const std::set<std::string> supported{
        "permitrootlogin", "pubkeyauthentication", "usepam", "maxauthtries", "port",
        "match", "include", "listenaddress", "addressfamily", "hostkey", "pidfile", "loglevel",
        "versionaddendum", "permittty", "passwordauthentication", "kbdinteractiveauthentication",
        "printmotd", "x11forwarding", "acceptenv", "subsystem", "authorizedkeysfile",
        "usedns", "permitemptypasswords", "strictmodes", "logingracetime"};
    std::function<void(const std::string&, unsigned)> visit = [&](const std::string& name, unsigned depth) {
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
                const std::set<std::string> criteria{"all","user","group","address","localaddress","localport","host"};
                if (!criteria.count(normalizeSshKeyword(args.front()))) unsupported("unsupported SSH Match criterion");
                conditional = true; continue;
            }
            if (conditional && selected.count(key))
                unsupported("conditional assignment of selected SSH policy unsupported");
            if (key == "hostkey") {
                if (args.size() != 1 || !path(args[0]) || !bytes.count(args[0]) || !bytes.count(args[0] + ".pub")) unsupported("HostKey and public companion require explicit reference coverage");
                result.hostKeys.insert(args[0]);
            }
            if (key != "include") continue;
            for (const auto& arg : args) {
                std::filesystem::path resolved(arg);
                if (resolved.is_relative()) resolved = std::filesystem::path("/etc/ssh") / resolved;
                const auto include = resolved.string();
                // Check the pattern itself BEFORE expansion, including empty
                // glob sets and Includes textually inside any Match context.
                const auto relative = resolved.lexically_relative("/etc/ssh/sshd_config.d");
                if (include != resolved.lexically_normal().string() || relative.empty() ||
                    relative.is_absolute() || relative.begin()->string() == ".." ||
                    include.rfind("/etc/ssh/sshd_config.d/", 0) != 0)
                    unsupported("Include outside supported Debian SSH configuration boundary");
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
                            base.size() >= 5 && base.compare(base.size()-5, 5, ".conf") == 0) visit(candidate, depth+1);
                    }
                } else {
                    if (!path(include)) unsupported("Include path outside literal absolute grammar");
                    if (bytes.count(include)) visit(include, depth+1);
                    else {
                        if (!directories.count(parent)) unsupported("absent literal Include requires protected exact parent");
                        result.negativeSetDirectories.insert(parent);
                    }
                }
            }
        }
        active.erase(name);
    };
    visit("/etc/ssh/sshd_config", 0);
    if (result.hostKeys.empty()) unsupported("explicit referenced HostKey required; implicit defaults unsupported");
    return result;
}
} // namespace fic::service::ssh::detail
