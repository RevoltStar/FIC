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
    // Incident UI must remain usable offline and must not perform synchronous
    // localization IPC on every polling render. Prefer the daemon bundle once
    // another module has loaded it; otherwise use the shipped RU/EN strings.
    if (!localizationCache.loaded && key.startsWith("[incident:")) {
        static const QHash<QString, QString> fallback = [] {
            QHash<QString, QString> values;
            QFile file(QLocale::system().language() == QLocale::Russian
                ? ":/fic/lang/ru.lang" : ":/fic/lang/en.lang");
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
        }();
        return fallback.value(key, key);
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
