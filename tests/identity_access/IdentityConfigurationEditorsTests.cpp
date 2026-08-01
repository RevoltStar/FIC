#include "modules/identity_access/submodules/kerberos/KerberosConfiguration.h"
#include "modules/identity_access/submodules/nss/NssConfiguration.h"
#include "modules/identity_access/submodules/sssd/SssdConfiguration.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

namespace {

namespace fs = std::filesystem;

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

class TemporaryTree {
public:
    explicit TemporaryTree(const std::string& name)
        : root(fs::temp_directory_path() /
               ("fic-identity-editors-" + name + "-" +
                std::to_string(::getpid()))) {
        fs::remove_all(root);
        fs::create_directories(root);
        ::chmod(root.c_str(), 0755);
    }

    ~TemporaryTree() {
        std::error_code ignored;
        fs::remove_all(root, ignored);
    }

    fs::path root;
};

void ensureParent(const fs::path& path) {
    fs::create_directories(path.parent_path());
    ::chmod(path.parent_path().c_str(), 0755);
}

void writeFile(const fs::path& path,
               const std::string& content,
               mode_t mode) {
    ensureParent(path);
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    require(output.is_open(), "could not create " + path.string());
    output << content;
    output.close();
    require(output.good(), "could not write " + path.string());
    require(::chmod(path.c_str(), mode) == 0, "could not chmod " + path.string());
}

std::string readFile(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    require(input.is_open(), "could not read " + path.string());
    return std::string(
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>());
}

fic::identity::SecureConfigurationFileOptions secureFile(
    const fs::path& path,
    std::optional<mode_t> exactMode = std::nullopt) {
    fic::identity::SecureConfigurationFileOptions options;
    options.path = fs::absolute(path);
    options.expectedOwner = ::geteuid();
    options.expectedGroup = ::getegid();
    options.exactMode = exactMode;
    options.forbiddenMode = 0022;
    return options;
}

fic::identity::sssd::SssdConfigurationOptions sssdOptions(
    const fs::path& main,
    std::vector<fs::path> snippets = {}) {
    fic::identity::sssd::SssdConfigurationOptions options;
    options.mainFile = secureFile(main, 0600);
    options.snippetDirectories = std::move(snippets);
    return options;
}

fic::identity::kerberos::KerberosConfigurationOptions kerberosOptions(
    const fs::path& main) {
    fic::identity::kerberos::KerberosConfigurationOptions options;
    options.mainFile = secureFile(main);
    return options;
}

fic::identity::nss::NssConfigurationOptions nssOptions(const fs::path& main) {
    fic::identity::nss::NssConfigurationOptions options;
    options.mainFile = secureFile(main);
    return options;
}

std::size_t countOccurrences(const std::string& content,
                             const std::string& needle) {
    std::size_t count = 0;
    std::size_t position = 0;
    while ((position = content.find(needle, position)) != std::string::npos) {
        ++count;
        position += needle.size();
    }
    return count;
}

void testSssdEditsMainFileAndPreservesUnrelatedContent() {
    TemporaryTree tree("sssd-main");
    const fs::path main = tree.root / "etc/sssd/sssd.conf";
    writeFile(
        main,
        "# managed by administrator\n"
        "[sssd]\n"
        "domains = old.example\n"
        "\n"
        "[domain/example]\n"
        "id_provider = ldap\n"
        "krb5_realm = OLD.EXAMPLE\n"
        "krb5_realm = OLD.EXAMPLE\n",
        0600);

    fic::identity::sssd::SssdConfiguration editor(sssdOptions(main));
    std::string error;
    require(
        editor.setValues(
            {
                {"sssd", "domains", "example"},
                {"domain/example", "krb5_realm", "EXAMPLE.COM"},
                {"domain/example", "cache_credentials", "true"}
            },
            error),
        error);

    const std::string content = readFile(main);
    require(
        content.find("# managed by administrator") != std::string::npos &&
            content.find("id_provider = ldap") != std::string::npos,
        "SSSD editor lost unrelated content");
    require(
        countOccurrences(content, "krb5_realm = EXAMPLE.COM") == 2,
        "SSSD editor did not normalize duplicate target values");
    require(
        content.find("cache_credentials = true") != std::string::npos,
        "SSSD editor did not insert a setting");

    std::optional<std::string> value;
    require(
        editor.tryGetEffectiveValue(
            "domain/example", "krb5_realm", value, error),
        error);
    require(value == "EXAMPLE.COM", "SSSD effective value is incorrect");
}

void testSssdSnippetOverrideFailsBeforeWrite() {
    TemporaryTree tree("sssd-snippets");
    const fs::path main = tree.root / "etc/sssd/sssd.conf";
    const fs::path snippets = tree.root / "etc/sssd/conf.d";
    writeFile(main, "[sssd]\ndomains = main\n", 0600);
    writeFile(snippets / "10-first.conf", "[sssd]\ndomains = first\n", 0600);
    writeFile(snippets / "90-last.conf", "[sssd]\ndomains = last\n", 0600);
    const std::string original = readFile(main);

    fic::identity::sssd::SssdConfiguration editor(
        sssdOptions(main, {snippets}));
    std::string error;
    std::optional<std::string> value;
    require(
        editor.tryGetEffectiveValue("sssd", "domains", value, error), error);
    require(value == "last", "SSSD snippets were not read lexicographically");

    auto prepared = editor.prepareSetValue("sssd", "domains", "new");
    require(!prepared.ok(), "SSSD snippet override must fail preflight");
    require(
        prepared.error.find("owned by snippet") != std::string::npos,
        "SSSD override diagnostic is incomplete");
    require(readFile(main) == original, "SSSD preflight failure changed main file");
}

void testKerberosEditsScalarsAndTraversesIncludes() {
    TemporaryTree tree("kerberos-main");
    const fs::path main = tree.root / "etc/krb5.conf";
    const fs::path included = tree.root / "etc/krb5-extra.conf";
    writeFile(included, "[libdefaults]\ndns_lookup_kdc = true\n", 0644);
    writeFile(
        main,
        "include\t" + included.string() + "\n"
        "[libdefaults]\n"
        " default_realm = OLD.EXAMPLE\n"
        " ticket_lifetime* = 10h\n"
        "\n"
        "[realms]\n"
        " EXAMPLE.COM = {\n"
        "  kdc = kdc.example.com\n"
        " }\n",
        0644);

    fic::identity::kerberos::KerberosConfiguration editor(
        kerberosOptions(main));
    std::string error;
    require(
        editor.setScalars(
            {
                {"libdefaults", "default_realm", "EXAMPLE.COM"},
                {"libdefaults", "ticket_lifetime", "8h"}
            },
            error),
        error);
    const std::string content = readFile(main);
    require(
        content.find("default_realm = EXAMPLE.COM") != std::string::npos,
        "Kerberos scalar was not replaced");
    require(
        content.find("ticket_lifetime* = 8h") != std::string::npos,
        "Kerberos final marker was not preserved");
    require(
        content.find("kdc = kdc.example.com") != std::string::npos,
        "Kerberos nested subsection was damaged");

    std::optional<std::string> value;
    require(
        editor.tryGetScalarValue(
            "libdefaults", "default_realm", value, error),
        error);
    require(value == "EXAMPLE.COM", "Kerberos scalar lookup is incorrect");
}

void testKerberosExternalDefinitionAndModuleFailClosed() {
    TemporaryTree tree("kerberos-conflict");
    const fs::path main = tree.root / "etc/krb5.conf";
    const fs::path included = tree.root / "etc/conflict.conf";
    writeFile(
        included,
        "[libdefaults]\ndefault_realm = INCLUDED.EXAMPLE\n",
        0644);
    writeFile(
        main,
        "include " + included.string() + "\n"
        "[libdefaults]\ndefault_realm = MAIN.EXAMPLE\n",
        0644);
    const std::string original = readFile(main);
    fic::identity::kerberos::KerberosConfiguration editor(
        kerberosOptions(main));
    auto prepared = editor.prepareSetScalar(
        "libdefaults", "default_realm", "NEW.EXAMPLE");
    require(!prepared.ok(), "included Kerberos definition must fail preflight");
    require(readFile(main) == original, "Kerberos conflict changed main file");

    writeFile(
        main,
        "module /usr/lib/krb5/profile.so:test\n"
        "[libdefaults]\ndefault_realm = MAIN.EXAMPLE\n",
        0644);
    prepared = editor.prepareSetScalar(
        "libdefaults", "default_realm", "NEW.EXAMPLE");
    require(!prepared.ok(), "Kerberos module profile must fail closed");
}

void testKerberosIncludeCycleFailsClosed() {
    TemporaryTree tree("kerberos-cycle");
    const fs::path main = tree.root / "etc/krb5.conf";
    const fs::path includeDirectory = tree.root / "etc/krb5.conf.d";
    writeFile(
        main,
        "includedir " + includeDirectory.string() + "\n"
        "[libdefaults]\ndefault_realm = MAIN.EXAMPLE\n",
        0644);
    writeFile(
        includeDirectory / "cycle.conf",
        "include " + main.string() + "\n[libdefaults]\nrdns = false\n",
        0644);
    fic::identity::kerberos::KerberosConfiguration editor(
        kerberosOptions(main));
    auto prepared = editor.prepareSetScalar("libdefaults", "rdns", "true");
    require(!prepared.ok(), "Kerberos include cycle must fail closed");
    require(
        prepared.error.find("cycle") != std::string::npos,
        "Kerberos cycle diagnostic is incomplete");
}

void testNssParsesActionsAndUpdatesEveryDuplicate() {
    TemporaryTree tree("nss-main");
    const fs::path main = tree.root / "etc/nsswitch.conf";
    writeFile(
        main,
        "# NSS configuration\n"
        "passwd: files sss [SUCCESS=return NOTFOUND=continue] # keep\n"
        "group: files\n"
        "passwd: files\n"
        "hosts: files dns\n",
        0644);

    const std::vector<fic::identity::nss::NssService> services = {
        {"files", {}},
        {"sss", {{true, "UNAVAIL", "return"}}}
    };
    fic::identity::nss::NssConfiguration editor(nssOptions(main));
    std::string error;
    require(
        editor.setDatabases(
            {
                {"passwd", services},
                {"shadow", {{"files", {}}, {"sss", {}}}}
            },
            error),
        error);
    const std::string content = readFile(main);
    require(
        countOccurrences(content, "passwd: files sss [!UNAVAIL=return]") == 2,
        "NSS duplicate databases were not normalized");
    require(content.find("# keep") != std::string::npos,
            "NSS inline comment was lost");
    require(content.find("hosts: files dns") != std::string::npos,
            "NSS unrelated database was changed");
    require(content.find("shadow: files sss") != std::string::npos,
            "NSS database was not appended");

    std::optional<std::vector<fic::identity::nss::NssService>> observed;
    require(editor.tryGetServices("passwd", observed, error), error);
    require(observed.has_value() && observed->size() == 2,
            "NSS service lookup is incomplete");
    require(observed->at(1).actions.size() == 1 &&
                observed->at(1).actions.front().negated,
            "NSS action grammar was not preserved");
}

void testNssMalformedInputAndSymlinkFailClosed() {
    TemporaryTree tree("nss-invalid");
    const fs::path main = tree.root / "etc/nsswitch.conf";
    writeFile(main, "passwd: [SUCCESS=return] files\n", 0644);
    fic::identity::nss::NssConfiguration editor(nssOptions(main));
    auto prepared = editor.prepareSetServices(
        "passwd", {{"files", {}}, {"sss", {}}});
    require(!prepared.ok(), "malformed NSS action order must fail");

    const fs::path outside = tree.root / "outside";
    writeFile(outside, "passwd: files\n", 0644);
    fs::remove(main);
    fs::create_symlink(outside, main);
    prepared = editor.prepareSetServices(
        "passwd", {{"files", {}}, {"sss", {}}});
    require(!prepared.ok(), "NSS symlink must fail closed");
    require(readFile(outside) == "passwd: files\n",
            "NSS symlink target was modified");
}

void testMetadataAndDirectorySymlinkChecksFailClosed() {
    TemporaryTree tree("unsafe-metadata");
    const fs::path sssdMain = tree.root / "etc/sssd/sssd.conf";
    writeFile(sssdMain, "[sssd]\ndomains = old\n", 0644);
    fic::identity::sssd::SssdConfiguration sssdEditor(
        sssdOptions(sssdMain));
    auto prepared = sssdEditor.prepareSetValue("sssd", "domains", "new");
    require(!prepared.ok(), "SSSD editor accepted a non-0600 main file");
    require(readFile(sssdMain) == "[sssd]\ndomains = old\n",
            "SSSD metadata rejection changed the file");

    const fs::path realDirectory = tree.root / "real-etc";
    const fs::path linkedDirectory = tree.root / "linked-etc";
    const fs::path realNss = realDirectory / "nsswitch.conf";
    writeFile(realNss, "passwd: files\n", 0644);
    fs::create_directory_symlink(realDirectory, linkedDirectory);
    fic::identity::nss::NssConfiguration nssEditor(
        nssOptions(linkedDirectory / "nsswitch.conf"));
    prepared = nssEditor.prepareSetServices(
        "passwd", {{"files", {}}, {"sss", {}}});
    require(!prepared.ok(), "NSS editor traversed a directory symlink");
    require(readFile(realNss) == "passwd: files\n",
            "directory symlink rejection changed its target");
}

void testNoOpDoesNotReplaceFile() {
    TemporaryTree tree("no-op");
    const fs::path main = tree.root / "etc/nsswitch.conf";
    writeFile(main, "passwd: files sss\n", 0644);
    struct stat before {};
    require(::stat(main.c_str(), &before) == 0, "could not stat NSS file");

    fic::identity::nss::NssConfiguration editor(nssOptions(main));
    std::string error;
    require(
        editor.setServices("passwd", {{"files", {}}, {"sss", {}}}, error),
        error);
    struct stat after {};
    require(::stat(main.c_str(), &after) == 0, "could not restat NSS file");
    require(before.st_dev == after.st_dev && before.st_ino == after.st_ino,
            "no-op NSS edit replaced the file");
}

void testPreparedChangeRejectsExternalEditAndRollbackOverwrite() {
    TemporaryTree tree("snapshot-conflict");
    const fs::path main = tree.root / "etc/nsswitch.conf";
    writeFile(main, "passwd: files\n", 0644);
    fic::identity::nss::NssConfiguration editor(nssOptions(main));

    auto prepared = editor.prepareSetServices(
        "passwd", {{"files", {}}, {"sss", {}}});
    require(prepared.ok(), prepared.error);
    writeFile(main, "passwd: files dns\n", 0644);
    std::string error;
    require(
        !fic::identity::executePreparedFileChange(
            std::move(prepared.change), error),
        "snapshot conflict must fail commit");
    require(readFile(main) == "passwd: files dns\n",
            "failed commit overwrote external edit");

    writeFile(main, "passwd: files\n", 0644);
    prepared = editor.prepareSetServices(
        "passwd", {{"files", {}}, {"sss", {}}});
    require(prepared.ok(), prepared.error);
    const auto committed = prepared.change->commitPersistent();
    require(committed.ok && committed.changed, committed.message);
    writeFile(main, "passwd: compat\n", 0644);
    const auto rollback = prepared.change->rollbackPersistent();
    require(!rollback.ok, "rollback must reject a later external edit");
    require(readFile(main) == "passwd: compat\n",
            "rollback overwrote external edit");
}

} // namespace

int main() {
    try {
        testSssdEditsMainFileAndPreservesUnrelatedContent();
        testSssdSnippetOverrideFailsBeforeWrite();
        testKerberosEditsScalarsAndTraversesIncludes();
        testKerberosExternalDefinitionAndModuleFailClosed();
        testKerberosIncludeCycleFailsClosed();
        testNssParsesActionsAndUpdatesEveryDuplicate();
        testNssMalformedInputAndSymlinkFailClosed();
        testMetadataAndDirectorySymlinkChecksFailClosed();
        testNoOpDoesNotReplaceFile();
        testPreparedChangeRejectsExternalEditAndRollbackOverwrite();
    } catch (const std::exception& error) {
        std::cerr << "IdentityConfigurationEditorsTests failed: "
                  << error.what() << '\n';
        return 1;
    }
    std::cout << "IdentityConfigurationEditorsTests passed\n";
    return 0;
}
