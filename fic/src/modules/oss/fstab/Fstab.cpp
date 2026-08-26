#include "modules/oss/fstab/Fstab.h"

#include <fic/core/fs/FileHandler.h>

#include <algorithm>
#include <memory>
#include <sstream>
#include <sys/stat.h>

namespace {

class FstabFileHandler : public FileHandler {
public:
    explicit FstabFileHandler(const std::string& path)
        : FileHandler(path, " ")
    {
    }

    bool loadConfig() override
    {
        return loadFile();
    }

    bool setValue(const std::string&, const std::string&) override
    {
        return false;
    }

    std::vector<std::string>& lines()
    {
        return original_lines_;
    }
};

bool isCommentOrBlank(std::string line)
{
    auto first = line.find_first_not_of(" \t\r\n");
    return first == std::string::npos || line[first] == '#';
}

std::vector<std::string> splitFields(const std::string& line)
{
    std::istringstream input(line);
    std::vector<std::string> fields;
    std::string field;
    while (input >> field) {
        fields.push_back(field);
    }
    return fields;
}

bool contains(const std::vector<std::string>& values, const std::string& value)
{
    return std::find(values.begin(), values.end(), value) != values.end();
}

} // namespace

Fstab::Fstab()
    : OSS()
{
    this->submoduleName = "Fstab";
}

void Fstab::configureFixedOptions(const std::vector<std::string>& options)
{
    this->requiredOptions = options;
    this->optionProfiles.clear();
    this->policyTypeValue = std::make_unique<FixedPolicyTypeValue>();
}

void Fstab::configureProfiles(const std::vector<OptionProfile>& profiles)
{
    this->optionProfiles = profiles;
    this->requiredOptions.clear();

    std::vector<std::string> profileNames;
    for (const auto& profile : profiles) {
        profileNames.push_back(profile.name);
    }
    this->policyTypeValue = std::make_unique<PossibleListPolicyTypeValue>(profileNames);
}

bool Fstab::apply()
{
    this->log("Запущена проверка политики " + this->policyName + " для /etc/fstab", logLevel::INFO);

    FstabFileHandler fstab("/etc/fstab");
    if (!fstab.loadConfig()) {
        this->log("Не удалось открыть для чтения файл /etc/fstab", logLevel::ERROR);
        return false;
    }

    auto optionsToRequire = this->selectedOptions();
    if (!optionsToRequire.has_value()) {
        return false;
    }

    auto entries = this->loadEntries();
    bool changed = false;
    int checked = 0;

    for (auto& entry : entries) {
        if (!this->shouldProcessEntry(entry)) {
            continue;
        }

        checked++;
        if (this->ensureOptions(entry, optionsToRequire.value())) {
            fstab.lines()[entry.lineIndex] = this->formatEntry(entry);
            changed = true;
            this->log("Исправлены параметры монтирования для " + entry.fields[1], logLevel::INFO);
        }
    }

    if (checked == 0) {
        if (this->scope == Scope::ExplicitMountPoints) {
            this->log("В /etc/fstab не найдены записи для заданных точек монтирования политики " +
                          this->policyName,
                      logLevel::ERROR);
            this->notify("В /etc/fstab не найдены записи для заданных точек монтирования политики " +
                          this->policyName,
                 notifyLevel::ERROR);
            return false;
        }

        this->log("Подходящих записей в /etc/fstab не найдено", logLevel::INFO);
        return true;
    }

    if (!changed) {
        this->log("Отклонений в /etc/fstab не обнаружено", logLevel::INFO);
        return true;
    }

    if (!fstab.saveFile()) {
        this->log("Не удалось сохранить /etc/fstab", logLevel::ERROR);
        return false;
    }

    const std::vector<Entry> verifiedEntries = this->loadEntries();
    int verified = 0;
    for (Entry entry : verifiedEntries) {
        if (!this->shouldProcessEntry(entry)) {
            continue;
        }
        ++verified;
        if (this->ensureOptions(entry, optionsToRequire.value())) {
            this->log(
                "После записи /etc/fstab параметры точки монтирования " +
                    entry.fields[1] + " не соответствуют политике",
                logLevel::ERROR
            );
            return false;
        }
    }
    if (this->scope == Scope::ExplicitMountPoints && verified == 0) {
        this->log(
            "После записи /etc/fstab не удалось подтвердить целевые точки монтирования политики " +
                this->policyName,
            logLevel::ERROR
        );
        return false;
    }

    this->log(
        "Persistent-конфигурация /etc/fstab перечитана и соответствует политике; "
        "runtime remount намеренно не выполняется",
        logLevel::INFO
    );
    this->notify("Исправлены параметры монтирования в /etc/fstab для политики " + this->policyName +
                     ". Для уже смонтированных файловых систем может потребоваться явный remount или перезагрузка.",
                 notifyLevel::WARN);
    return true;
}

std::optional<std::vector<std::string>> Fstab::selectedOptions()
{
    if (this->optionProfiles.empty()) {
        return this->requiredOptions;
    }

    std::string selectedProfile;
    if (this->hasConfiguredValue()) {
        std::optional<std::string> configuredProfile = this->getValue();
        if (!configuredProfile.has_value()) {
            this->log("Не удалось получить профиль политики " + this->policyName, logLevel::ERROR);
            return std::nullopt;
        }
        selectedProfile = configuredProfile.value();
    } else {
        selectedProfile = this->getDefaultValue();
        this->log("Профиль политики " + this->policyName + " не задан. Используется значение по умолчанию: " +
                      selectedProfile,
                  logLevel::WARN);
    }

    for (const auto& profile : this->optionProfiles) {
        if (profile.name == selectedProfile) {
            return profile.options;
        }
    }

    this->log("Неизвестный профиль '" + selectedProfile + "' для политики " +
                  this->policyName,
              logLevel::ERROR);
    return std::nullopt;
}

std::vector<Fstab::Entry> Fstab::loadEntries() const
{
    FstabFileHandler fstab("/etc/fstab");
    std::vector<Entry> entries;
    if (!fstab.loadConfig()) {
        return entries;
    }

    const auto& lines = fstab.lines();
    for (size_t i = 0; i < lines.size(); ++i) {
        if (isCommentOrBlank(lines[i])) {
            continue;
        }

        auto fields = splitFields(lines[i]);
        if (fields.size() < 4) {
            continue;
        }

        entries.push_back({i, fields});
    }

    return entries;
}

bool Fstab::shouldProcessEntry(const Entry& entry) const
{
    if (entry.fields.size() < 4) {
        return false;
    }

    const std::string& mountPoint = entry.fields[1];
    if (this->scope == Scope::ExplicitMountPoints) {
        return contains(this->mountPoints, mountPoint);
    }

    return this->isWorldWritableDirectory(mountPoint);
}

bool Fstab::isWorldWritableDirectory(const std::string& path) const
{
    struct stat st {};
    if (::stat(path.c_str(), &st) != 0) {
        return false;
    }

    return S_ISDIR(st.st_mode) && ((st.st_mode & S_IWOTH) != 0);
}

bool Fstab::ensureOptions(Entry& entry, const std::vector<std::string>& optionsToRequire) const
{
    auto options = this->splitOptions(entry.fields[3]);
    bool changed = false;

    for (const auto& required : optionsToRequire) {
        for (const std::string& opposite : this->oppositeOptions(required)) {
            const auto oldSize = options.size();
            options.erase(std::remove(options.begin(), options.end(), opposite), options.end());
            changed = changed || options.size() != oldSize;
        }

        const std::string requiredKey = this->optionKey(required);
        if (required.find('=') != std::string::npos) {
            const auto oldSize = options.size();
            options.erase(std::remove_if(options.begin(), options.end(),
                                         [this, &required, &requiredKey](const std::string& option) {
                                             return option != required && this->optionKey(option) == requiredKey;
                                         }),
                          options.end());
            changed = changed || options.size() != oldSize;
        }

        if (!contains(options, required)) {
            options.push_back(required);
            changed = true;
        }
    }

    if (changed) {
        entry.fields[3] = this->joinOptions(options);
    }
    return changed;
}

std::vector<std::string> Fstab::splitOptions(const std::string& options) const
{
    std::vector<std::string> result;
    std::stringstream input(options);
    std::string option;

    while (std::getline(input, option, ',')) {
        if (!option.empty()) {
            result.push_back(option);
        }
    }

    if (result.empty()) {
        result.push_back("defaults");
    }
    return result;
}

std::string Fstab::joinOptions(const std::vector<std::string>& options) const
{
    std::string result;
    for (const auto& option : options) {
        if (!result.empty()) {
            result += ",";
        }
        result += option;
    }
    return result;
}

std::string Fstab::optionKey(const std::string& option) const
{
    const size_t delimiter = option.find('=');
    if (delimiter == std::string::npos) {
        return option;
    }
    return option.substr(0, delimiter);
}

std::vector<std::string> Fstab::oppositeOptions(const std::string& option) const
{
    if (option == "nodev") {
        return {"dev"};
    }
    if (option == "dev") {
        return {"nodev"};
    }
    if (option == "nosuid") {
        return {"suid"};
    }
    if (option == "suid") {
        return {"nosuid"};
    }
    if (option == "noexec") {
        return {"exec"};
    }
    if (option == "exec") {
        return {"noexec"};
    }
    if (option == "rw") {
        return {"ro"};
    }
    if (option == "ro") {
        return {"rw"};
    }
    if (option == "relatime") {
        return {"noatime", "strictatime"};
    }
    return {};
}

std::string Fstab::formatEntry(const Entry& entry) const
{
    std::string line;
    for (const auto& field : entry.fields) {
        if (!line.empty()) {
            line += "\t";
        }
        line += field;
    }
    return line;
}
