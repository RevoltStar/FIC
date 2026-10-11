// Shared deterministic dconf/GSettings fixture; include inside the test namespace.
struct FakeCommands {
    bool resolveDconf = true;
    bool resolveGsettings = true;
    bool updateOk = true;
    int failUpdateNumber = 0;
    int updates = 0;
    std::map<std::string, std::string> values;
    std::map<std::string, bool> writable;
    bool repairOnUpdate = false;
    std::vector<ProcessOptions> options;
    // Test hook standing in for the real dconf compiler: a successful update
    // materialises the compiled database with a controllable mode.
    fs::path compiledPath;
    mode_t compiledMode = 0644;
    bool createCompiledOnUpdate = true;
    bool nativeModel = true;
    bool compileOk = true;
    std::string rejectedNativeSource;
    bool disagreeWithCompile = false;
    bool effectiveOk = true;
    std::string schemaRangeOverride;
    int compiles = 0;

    static std::string nativeBytes(const fs::path& source) {
        std::map<std::string, std::string> files;
        for (const auto& entry : fs::recursive_directory_iterator(source)) {
            if (!entry.is_regular_file()) continue;
            std::istringstream lines(read(entry.path()));
            std::string line, body;
            while (std::getline(lines, line)) {
                if (!line.empty() && line.back() == '\r') line.pop_back();
                if (!line.empty() && (line.front() == '#' || line.front() == ';')) continue;
                body += line + "\n";
            }
            files[entry.path().lexically_relative(source).string()] = body;
        }
        std::string result = "native-fixture\n";
        for (const auto& [name, body] : files) result += name + "\n" + body;
        return result;
    }

    void inspectSources() {
        values.clear(); writable.clear();
        const auto source = compiledPath.parent_path() / "fic.d";
        if (!fs::exists(source)) return;
        std::map<std::string, fs::path> keyfiles;
        for (const auto& entry : fs::directory_iterator(source))
            if (entry.is_regular_file()) keyfiles[entry.path().filename().string()] = entry.path();
        for (const auto& [name, file] : keyfiles) {
            (void)name;
            std::istringstream lines(read(file)); std::string group, line;
            while (std::getline(lines, line)) {
                if (!line.empty() && line.back() == '\r') line.pop_back();
                if (line.empty() || line.front() == '#' || line.front() == ';') continue;
                if (line.front() == '[') group = line.substr(1, line.size() - 2);
                else if (line.find('=') != std::string::npos)
                    values["/" + group + "/" + line.substr(0, line.find('='))] = line.substr(line.find('=') + 1);
            }
        }
        if (fs::exists(source / "locks")) for (const auto& entry : fs::directory_iterator(source / "locks")) {
            std::istringstream lines(read(entry.path())); std::string line;
            while (std::getline(lines, line)) {
                if (!line.empty() && line.back() == '\r') line.pop_back();
                if (!line.empty() && line.front() == '/') writable[line] = false;
            }
        }
        for (const auto& [key, value] : requirements()) {
            if (!values.count(key.setting)) values[key.setting] = value;
            if (!writable.count(key.setting)) writable[key.setting] = true;
        }
    }

    static std::string physical(const std::string& schema,
                                const std::string& key) {
        std::string group = schema;
        for (char& character : group)
            if (character == '.') character = '/';
        return "/" + group + "/" + key;
    }

    GnomeSystemBackendDependencies dependencies() {
        return {
            [this](fic::platform::ExecutableId id, fs::path& path,
                   std::string& error) {
                const bool available = id == fic::platform::ExecutableId::Dconf
                    ? resolveDconf : resolveGsettings;
                if (!available) { error = "not installed"; return false; }
                path = id == fic::platform::ExecutableId::Dconf
                    ? "/fake/dconf" : "/fake/gsettings";
                error.clear();
                return true;
            },
            [this](const fs::path& executable,
                   const std::vector<std::string>& arguments,
                   const ProcessOptions& processOptions) {
                options.push_back(processOptions);
                ProcessResult result;
                result.started = true;
                result.exitCode = 0;
                if (executable.filename() == "dconf") {
                    if (arguments.at(0) == "compile") {
                        ++compiles;
                        if (!compileOk || (!rejectedNativeSource.empty() &&
                            nativeBytes(arguments.at(2)).find(rejectedNativeSource) != std::string::npos)) {
                            result.exitCode = 1; result.standardError = "invalid source";
                        }
                        else write(arguments.at(1), nativeBytes(arguments.at(2)));
                        return result;
                    }
                    ++updates;
                    if (!updateOk || updates == failUpdateNumber) {
                        result.exitCode = 1;
                        result.standardError = "compile failed";
                    } else {
                        if (nativeModel && arguments.size() == 2) {
                            const fs::path isolated = arguments.at(1);
                            write(isolated / "fic", nativeBytes(isolated / "fic.d") +
                                (disagreeWithCompile ? "unexpected native update output" : ""));
                            ::chmod((isolated / "fic").c_str(), compiledMode);
                            inspectSources();
                            return result;
                        }
                        if (createCompiledOnUpdate && !compiledPath.empty()) {
                            std::ofstream(compiledPath, std::ios::binary)
                                << (nativeModel ? nativeBytes(compiledPath.parent_path() / "fic.d") : "compiled");
                            ::chmod(compiledPath.c_str(), compiledMode);
                        }
                        if (repairOnUpdate) {
                            for (const auto& [key, value] : requirements()) {
                                values[key.setting] = value;
                                writable[key.setting] = false;
                            }
                        }
                        if (nativeModel) inspectSources();
                    }
                    return result;
                }
                const std::string path = physical(arguments.at(1), arguments.at(2));
                if (arguments.at(0) == "range") {
                    result.standardOutput = schemaRangeOverride.empty() ?
                        (arguments.at(2) == "idle-delay" || arguments.at(2) == "lock-delay" ? "type u\n" : "type b\n") : schemaRangeOverride;
                    return result;
                }
                if (!effectiveOk) { result.exitCode = 1; result.standardError = "effective inspection failed"; return result; }
                if (arguments.at(0) == "get")
                    result.standardOutput = values[path] + "\n";
                else
                    result.standardOutput = writable[path] ? "true\n" : "false\n";
                return result;
            }
        };
    }
};
