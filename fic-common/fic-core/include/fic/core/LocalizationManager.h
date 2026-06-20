#ifndef LOCALIZATIONMANAGER_H
#define LOCALIZATIONMANAGER_H

#include <iostream>
#include <memory>
#include <unordered_map>
#include <fic/core/ConfigFileHandler.h>
#include <fic/core/MultilineConfigFileHandler.h>

// Class for application localization.
class LocalizationManager {
private:
    static std::string langFilePath;
    static std::string currLang;
    static std::unique_ptr<MultilineConfigFileHandler> langFile;

    static bool ensureLanguageLoaded();

public:
    static std::string getCurrentLanguage();
    static bool setCurrentLanguage(const std::string& lang);
    static std::string readLanguageFromGlobalConfig();
    static void syncLanguageWithConfig();
    static std::string getLang(std::string key);
    static std::unordered_map<std::string, std::string> getTranslations();
};

#endif // LOCALIZATIONMANAGER_H
