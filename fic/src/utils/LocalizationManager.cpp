#include "utils/LocalizationManager.h"

namespace {
const char* kDefaultLanguage = "ru";
const char* kGlobalModuleName = "GLOBAL";
const char* kGlobalLanguageParameter = "lang";
const char* kEnabledFlag = "ENABLE";
const char* kLangDirectory = "/opt/fic/lang/";
const char* kLangFileExtension = ".lang";
}

std::string LocalizationManager::currLang = kDefaultLanguage;
std::string LocalizationManager::langFilePath = std::string(kLangDirectory) + LocalizationManager::currLang + kLangFileExtension;
std::unique_ptr<MultilineConfigFileHandler> LocalizationManager::langFile;

bool LocalizationManager::ensureLanguageLoaded()
{
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
    langFilePath = std::string(kLangDirectory) + currLang + kLangFileExtension;
    langFile.reset();
    return true;
}

std::string LocalizationManager::readLanguageFromGlobalConfig()
{
    ModuleConfigFileHandler globalConfig(kGlobalModuleName);
    if (!globalConfig.loadConfig()) {
        return kDefaultLanguage;
    }

    if (!globalConfig.isParameterExists(kGlobalLanguageParameter)) {
        return kDefaultLanguage;
    }

    if (globalConfig.getIsEnable(kGlobalLanguageParameter) != kEnabledFlag) {
        return kDefaultLanguage;
    }

    const std::string lang = globalConfig.getValue(kGlobalLanguageParameter);
    if (lang.empty()) {
        return kDefaultLanguage;
    }

    return lang;
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
