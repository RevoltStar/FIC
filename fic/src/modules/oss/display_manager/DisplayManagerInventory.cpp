#include "modules/oss/display_manager/DisplayManagerInventory.h"
#include <fic/core/fs/AtomicFileWriter.h>
#include <algorithm>
#include <sstream>

using fic::platform::ExecutableId;
namespace {
std::map<std::string, std::string> properties(const std::string& text) {
    std::map<std::string, std::string> p;
    std::istringstream in(text); std::string line;
    while (std::getline(in, line)) {
        auto at = line.find('='); if (at != std::string::npos) p[line.substr(0, at)] = line.substr(at+1);
    }
    return p;
}
bool active(const std::string& s) { return s == "active" || s == "activating" || s == "reloading"; }
}
SystemDisplayManagerInventory::SystemDisplayManagerInventory(
    const fic::platform::PlatformExecutableResolver& executables,
    fic::platform::DisplayManagerPlatformConfig config)
    : SystemDisplayManagerInventory([&executables](ExecutableId id, const std::vector<std::string>& args) {
        std::filesystem::path path; std::string error;
        if (!executables.resolve(id, path, error)) { ProcessResult r; r.error = error; return r; }
        ProcessOptions options; options.clearEnvironment = true;
        options.environment = {{"LC_ALL", "C"}, {"PATH", "/usr/sbin:/usr/bin:/sbin:/bin"}};
        return ProcessExecutor::execute(path.string(), args, options);
    }, std::move(config)) {
    executableProof_ = [&executables](const std::string& manager,std::string& error) {
        std::filesystem::path path;
        const auto id = manager=="SDDM"?ExecutableId::Sddm:manager=="GDM"?ExecutableId::Gdm:ExecutableId::LightDm;
        return executables.resolve(id,path,error);
    };
    unitExecutableProof_ = [&executables](const std::string& manager,const std::string& observed) {
        std::filesystem::path trusted;std::string error;std::error_code ec;
        const auto id=manager=="SDDM"?ExecutableId::Sddm:manager=="GDM"?ExecutableId::Gdm:ExecutableId::LightDm;
        return executables.resolve(id,trusted,error) &&
            std::filesystem::equivalent(trusted,observed,ec) && !ec;
    };
}
SystemDisplayManagerInventory::SystemDisplayManagerInventory(Run run,
    fic::platform::DisplayManagerPlatformConfig config) : run_(std::move(run)), config_(std::move(config)) {}
std::string SystemDisplayManagerInventory::canonicalName(const std::string& identity) {
    auto name = std::filesystem::path(identity).filename().string();
    if (name == "sddm" || name == "sddm.service" || name == "SDDM") return "SDDM";
    if (name == "gdm" || name == "gdm3" || name == "gdm.service" || name == "gdm3.service" || name == "GDM") return "GDM";
    if (name == "lightdm" || name == "lightdm.service" || name == "LIGHTDM") return "LIGHTDM";
    return {};
}
bool SystemDisplayManagerInventory::inspect(DisplayManagerSnapshot& result, std::string& error) const {
    result = {};
    for (const auto* name : {"SDDM", "GDM", "LIGHTDM"}) result.managers[name] = {};
    const auto query = [&](ExecutableId id, const std::vector<std::string>& args, std::string& output) {
        const auto r = run_(id, args);
        if (!r.success()) { error = "DM inventory command failed: " + r.error + r.standardError; return false; }
        output = r.standardOutput; return true;
    };
    std::string output;
    const auto packageArgs = config_.packageManagerKind == fic::platform::PackageManagerKind::Dpkg
        ? std::vector<std::string>{"--show", "--showformat=${binary:Package}\t${db:Status-Status}\n"}
        : std::vector<std::string>{"-qa", "--qf", "%{NAME}\tinstalled\n"};
    if(!query(ExecutableId::PackageQuery,packageArgs,output))return false;
    std::string line;
    std::istringstream packages(output);
    while(std::getline(packages,line)) {
        const auto tab=line.find('\t');if(tab==std::string::npos){error="incomplete native package inventory";return false;}
        auto name=line.substr(0,tab);const auto architecture=name.find(':');if(architecture!=std::string::npos)name=name.substr(0,architecture);
        const auto dm=canonicalName(name);
        if(!dm.empty() && line.substr(tab+1)=="installed")result.managers[dm].installed=true;
    }
    // Enumerate actual unit files and loaded units. Querying nonexistent
    // well-known names can itself fail and must not turn a proven headless
    // inventory into an infrastructure error. Alias selection is read from
    // complete unit-file enumeration and each loaded unit Names property.
    std::set<std::string> units;
    // Unit inventory needs its own command output after package enumeration.
    if (!query(ExecutableId::Systemctl, {"list-unit-files", "--type=service", "--no-legend", "--no-pager"}, output)) return false;
    std::istringstream files(output);
    while (std::getline(files,line)) {
        std::istringstream row(line); std::string unit, state; row >> unit >> state;
        if (unit.empty()) continue;
        if (unit.find('/') != std::string::npos || unit.front() == '-' || unit.size() > 256) { error = "invalid service identity"; return false; }
        units.insert(unit);
        auto dm = canonicalName(unit);
        if (!dm.empty() && (state == "enabled" || state == "enabled-runtime")) result.managers[dm].selected = true;
    }
    if (!query(ExecutableId::Systemctl, {"list-units", "--all", "--type=service", "--no-legend", "--no-pager", "--plain"}, output)) return false;
    std::istringstream loaded(output);
    while (std::getline(loaded, line)) { std::istringstream row(line); std::string unit; row >> unit;
        if (!unit.empty()) units.insert(unit); }
    if (units.size() > 2048) { error = "DM inventory service limit exceeded"; return false; }
    for (const auto& unit : units) {
        if (unit.find('/') != std::string::npos || unit.front() == '-' || unit.size() > 256) { error = "invalid service identity"; return false; }
        if (!query(ExecutableId::Systemctl, {"show", unit, "--no-pager",
            "--property=Id,Names,LoadState,ActiveState,Description,ExecStart,UnitFileState"}, output)) return false;
        const auto p = properties(output);
        if (!p.count("LoadState") || !p.count("ActiveState")) { error = "incomplete service inventory: " + unit; return false; }
        if (p.at("LoadState") == "not-found") continue;
        if (p.at("LoadState") != "loaded" && p.at("LoadState") != "masked") { error = "unclassifiable service: " + unit; return false; }
        auto get = [&](const char* k) { auto it=p.find(k); return it==p.end()?std::string():it->second; };
        std::string dm = canonicalName(get("Id"));
        const auto names = get("Names");
        const bool alias = unit == "display-manager.service" || names.find("display-manager.service") != std::string::npos;
        const bool running = active(p.at("ActiveState"));
        const auto description = get("Description");
        std::string lower = description; std::transform(lower.begin(),lower.end(),lower.begin(),[](unsigned char c){return std::tolower(c);});
        const bool candidate = alias || !dm.empty() || lower.find("display manager") != std::string::npos ||
            unit == "xdm.service" || unit == "lxdm.service" || unit == "greetd.service";
        // A differently named unit invoking a known DM is still a DM; unit
        // identity and executable must agree and custom config arguments fail closed.
        const auto exec = get("ExecStart");
        auto at = exec.find("path="); std::string executable;
        if (at != std::string::npos) { at += 5; auto end=exec.find_first_of(" ;}",at); executable=exec.substr(at,end-at); }
        const auto executableDm = canonicalName(executable);
        if (!candidate && executableDm.empty()) continue;
        if (dm.empty()) dm = executableDm;
        if (dm.empty() || (!executableDm.empty() && executableDm != dm) || exec.find("--config") != std::string::npos ||
            exec.find(" -c ") != std::string::npos || (!exec.empty() && executableDm.empty()) ||
            (running && executableDm.empty()) ||
            (!dm.empty() && !executable.empty() && unitExecutableProof_ && !unitExecutableProof_(dm,executable))) {
            if (!dm.empty()) result.managers[dm].configurationSupported = false;
            if (alias || running || get("UnitFileState") == "enabled") result.unknownSelectedOrRunning.push_back(unit);
            continue;
        }
        auto& state = result.managers[dm]; state.installed = true;
        state.running = state.running || running; state.selected = state.selected || alias;
    }
    // Debian/Ubuntu's selected executable is independent of the systemd alias.
    if (!config_.defaultDisplayManagerPath.empty()) {
        std::error_code ec; const bool exists = std::filesystem::exists(config_.defaultDisplayManagerPath, ec);
        if (ec) { error = ec.message(); return false; }
        if (exists) {
            AtomicTargetState state;
            if (!AtomicFileWriter::captureTargetState(config_.defaultDisplayManagerPath.string(), state, &error) ||
                state.owner != 0 || (state.mode & 0022)) { error = "unsafe selected DM file: " + error; return false; }
            std::istringstream in(state.content); std::string executable, extra; in >> executable >> extra;
            const auto dm = canonicalName(executable);
            if (!extra.empty() || dm.empty()) result.unknownSelectedOrRunning.push_back("selected executable: " + executable);
            else result.managers[dm].selected = true;
        }
    }
    // Independently launched greeters are visible through logind, even if
    // no display-manager.service alias or recognizable service is present.
    if (!query(ExecutableId::Loginctl, {"list-sessions", "--no-legend", "--no-pager"}, output)) return false;
    std::istringstream sessions(output); std::vector<std::string> ids;
    while (std::getline(sessions,line)) { std::istringstream row(line); std::string id; row >> id; if (!id.empty()) ids.push_back(id); }
    for (const auto& id : ids) {
        if (id.find('/') != std::string::npos || id.front()=='-') { error="invalid session identity"; return false; }
        if (!query(ExecutableId::Loginctl, {"show-session",id,"--property=Class,Service", "--no-pager"},output)) return false;
        const auto p=properties(output);
        if (!p.count("Class") || !p.count("Service")) { error="incomplete greeter inventory"; return false; }
        if (p.at("Class") != "greeter") continue;
        auto dm = canonicalName(p.at("Service"));
        if (p.at("Service") == "sddm-greeter") dm="SDDM";
        if (p.at("Service") == "gdm-launch-environment") dm="GDM";
        if (p.at("Service") == "lightdm-greeter") dm="LIGHTDM";
        if (dm.empty()) result.unknownSelectedOrRunning.push_back("greeter " + id + ": " + p.at("Service"));
        else { result.managers[dm].running=true; result.managers[dm].installed=true; }
    }
    if(executableProof_) for(const auto& [manager,state]:result.managers) if(state.installed && !executableProof_(manager,error)) {
        error="installed DM executable unavailable/untrusted: "+manager+": "+error;return false;
    }
    result.complete=true; error.clear(); return true;
}
