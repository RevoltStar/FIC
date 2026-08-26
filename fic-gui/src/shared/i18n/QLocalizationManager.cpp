#include "QLocalizationManager.h"

#include <QHash>

#include <fic/ipc/FicIpcClient.h>

namespace {
struct LocalizationCache {
    bool loaded = false;
    QString language;
    QHash<QString, QString> translations;
};

LocalizationCache& cache()
{
    static LocalizationCache instance;
    return instance;
}

bool loadLocalizationBundle()
{
    auto response = fic::ipc::Client().request({{"command", "localization_bundle"}});
    if (!response.value("ok", false)) {
        return false;
    }

    LocalizationCache& localizationCache = cache();
    localizationCache.language = QString::fromStdString(response.value("language", ""));
    localizationCache.translations.clear();

    if (response.contains("translations") && response["translations"].is_object()) {
        for (auto it = response["translations"].begin(); it != response["translations"].end(); ++it) {
            if (it.value().is_string()) {
                localizationCache.translations.insert(
                    QString::fromStdString(it.key()),
                    QString::fromStdString(it.value().get<std::string>())
                );
            }
        }
    }

    localizationCache.loaded = true;
    return true;
}
} // namespace

QString QLocalizationManager::getLang(const QString& key)
{
    LocalizationCache& localizationCache = cache();
    if (!localizationCache.loaded && !loadLocalizationBundle()) {
        return key;
    }

    const auto it = localizationCache.translations.constFind(key);
    if (it == localizationCache.translations.constEnd()) {
        return key;
    }

    return it.value();
}
