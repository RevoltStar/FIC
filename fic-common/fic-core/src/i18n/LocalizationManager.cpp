#include <fic/core/i18n/LocalizationManager.h>

#include <fic/core/runtime/FicRuntimePaths.h>
#include <fic/core/config/PolicyConfig.h>

namespace {
const char* kDefaultLanguage = "ru";
const char* kGlobalLanguageParameter = "lang";
const char* kLangFileExtension = ".lang";

std::string languageFilePath(const std::string& language)
{
    return (fic::core::FicRuntimePaths::get().languageDir /
            (language + kLangFileExtension)).string();
}
}

std::string LocalizationManager::currLang = kDefaultLanguage;
std::string LocalizationManager::langFilePath;
std::unique_ptr<MultilineConfigFileHandler> LocalizationManager::langFile;

bool LocalizationManager::ensureLanguageLoaded()
{
    if (langFilePath.empty()) {
        langFilePath = languageFilePath(currLang);
    }
    if (!langFile) {
        langFile = std::make_unique<MultilineConfigFileHandler>(langFilePath, "=");
        if (!langFile->loadConfig()) {
            if (currLang != kDefaultLanguage) {
                setCurrentLanguage(kDefaultLanguage);
                return ensureLanguageLoaded();
            }

            langFile.reset();
            return false;
        }
    }

    return true;
}

std::string LocalizationManager::getCurrentLanguage()
{
    return currLang;
}

bool LocalizationManager::setCurrentLanguage(const std::string& lang)
{
    if (lang.empty()) {
        return false;
    }

    if (currLang == lang) {
        return true;
    }

    currLang = lang;
    langFilePath = languageFilePath(currLang);
    langFile.reset();
    return true;
}

std::string LocalizationManager::readLanguageFromGlobalConfig()
{
    const std::optional<std::string> lang =
        PolicyConfig::getEnabledValue("GLOBAL", kGlobalLanguageParameter);
    if (!lang.has_value() || lang.value().empty()) {
        return kDefaultLanguage;
    }

    return lang.value();
}

void LocalizationManager::syncLanguageWithConfig()
{
    const std::string configuredLanguage = readLanguageFromGlobalConfig();
    if (configuredLanguage != currLang) {
        setCurrentLanguage(configuredLanguage);
    }
}

std::string LocalizationManager::getLang(std::string key)
{
    syncLanguageWithConfig();

    if (!ensureLanguageLoaded()) {
        return key;
    }

    if (langFile->isParameterExists(key)) {
        return langFile->getValue(key);
    }

    return key;
}

std::unordered_map<std::string, std::string> LocalizationManager::getTranslations()
{
    syncLanguageWithConfig();

    if (!ensureLanguageLoaded()) {
        return {};
    }

    return langFile->entries();
}
