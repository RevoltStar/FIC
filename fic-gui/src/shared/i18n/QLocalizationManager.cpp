#include "QLocalizationManager.h"

#include <QHash>
#include <QFile>
#include <QLocale>
#include <QTextStream>

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

QString incidentFallback(const QString& key, bool russian)
{
    static const auto load = [](const char* path) {
        QHash<QString, QString> values;
        QFile file(QString::fromLatin1(path));
        if (file.open(QIODevice::ReadOnly)) {
            QTextStream stream(&file);
#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
            stream.setCodec("UTF-8");
#endif
            while (!stream.atEnd()) {
                const auto line = stream.readLine();
                const auto separator = line.indexOf('=');
                if (separator > 0 && line.startsWith("[incident:"))
                    values.insert(line.left(separator).trimmed(), line.mid(separator + 1).trimmed());
            }
        }
        return values;
    };
    static const auto ru = load(":/fic/lang/ru.lang");
    static const auto en = load(":/fic/lang/en.lang");
    return (russian ? ru : en).value(key, key);
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
    // New incident labels have an embedded fallback and never initiate
    // synchronous IPC during a polling render, including incomplete bundles.
    if (key.startsWith("[incident:")) {
        const auto translated = localizationCache.translations.constFind(key);
        if (localizationCache.loaded && translated != localizationCache.translations.constEnd()) return translated.value();
        const bool russian = localizationCache.loaded
            ? localizationCache.language.startsWith("ru", Qt::CaseInsensitive)
            : QLocale::system().language() == QLocale::Russian;
        return incidentFallback(key, russian);
    }
    if (!localizationCache.loaded && !loadLocalizationBundle()) {
        return key;
    }

    const auto it = localizationCache.translations.constFind(key);
    if (it == localizationCache.translations.constEnd()) {
        return key;
    }

    return it.value();
}


bool QLocalizationManager::installBundle(const QByteArray& bundle)
{
    if (bundle.size() > static_cast<int>(fic::ipc::MAX_RESPONSE_BYTES)) return false;
    try {
        const auto response = nlohmann::json::parse(bundle.constData(), bundle.constData() + bundle.size(),
            [](int depth, nlohmann::json::parse_event_t, nlohmann::json&) {
                if (depth > static_cast<int>(fic::ipc::MAX_JSON_DEPTH)) throw std::runtime_error("Localization depth exceeded");
                return true;
            });
        std::string error;
        if (!fic::ipc::validate_json_value(response, 0, error) || !response.at("ok").is_boolean() ||
            !response.at("ok").get<bool>() || !response.at("message").is_string() ||
            !response.at("api_version").is_number_integer() || response.at("api_version") != fic::ipc::API_VERSION ||
            !response.at("language").is_string() || !response.at("translations").is_object()) return false;
        QHash<QString, QString> translations;
        for (const auto& entry : response.at("translations").items()) {
            if (!entry.value().is_string()) return false;
            translations.insert(QString::fromStdString(entry.key()), QString::fromStdString(entry.value().get<std::string>()));
        }
        auto& localizationCache = cache();
        localizationCache.translations = std::move(translations);
        localizationCache.language = QString::fromStdString(response.at("language").get<std::string>());
        localizationCache.loaded = true;
        return true;
    } catch (const std::exception&) { return false; }
}
