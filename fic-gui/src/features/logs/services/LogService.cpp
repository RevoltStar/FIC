#include "features/logs/services/LogService.h"

#include <algorithm>

#include <QTimeZone>

#include <fic/ipc/FicIpcClient.h>

LogService::LogService(QObject *parent)
    : QObject(parent)
{
    refreshTimer_.setInterval(10000);
    connect(&refreshTimer_, &QTimer::timeout, this, &LogService::refreshIncremental);
}

void LogService::start()
{
    if (bootId_.isEmpty()) {
        bootId_ = currentBootId();
    }

    if (!refreshTimer_.isActive()) {
        refreshTimer_.start();
    }

    refreshIncremental();
}

void LogService::stop()
{
    refreshTimer_.stop();
}

void LogService::reloadAll()
{
    if (bootId_.isEmpty()) {
        bootId_ = currentBootId();
    }

    sequenceCounter_ = 0;
    logCursor_.clear();

    QStringList categories;
    QString newCursor;
    bool reloadRequired = false;

    QVector<LogRecord> records =
        loadRecordsFromDaemon(
            &categories,
            {},
            true,
            &newCursor,
            &reloadRequired);

    if (reloadRequired) {
        sequenceCounter_ = 0;
        categories.clear();
        newCursor.clear();
        reloadRequired = false;
        records = loadRecordsFromDaemon(
            &categories,
            {},
            true,
            &newCursor,
            &reloadRequired);
        if (reloadRequired) {
            return;
        }
    }

    logCursor_ = newCursor;

    std::sort(
        records.begin(),
        records.end(),
        recordLessThan);

    updateCategories(categories);

    emit fullReloaded(records);
    emit lastUpdateChanged(
        QDateTime::currentDateTime());
}

void LogService::refreshIncremental()
{
    const QString actualBootId =
        currentBootId();

    if (!actualBootId.isEmpty() &&
        actualBootId != bootId_) {

        bootId_ = actualBootId;
        reloadAll();
        return;
    }

    if (bootId_.isEmpty()) {
        bootId_ = actualBootId;
    }

    QStringList categories;
    QString newCursor = logCursor_;
    bool reloadRequired = false;

    QVector<LogRecord> records =
        loadRecordsFromDaemon(
            &categories,
            logCursor_,
            false,
            &newCursor,
            &reloadRequired);

    if (reloadRequired) {
        reloadAll();
        return;
    }

    logCursor_ = newCursor;

    updateCategories(categories);

    if (!records.isEmpty()) {
        emit recordsAppended(records);
    }

    emit lastUpdateChanged(
        QDateTime::currentDateTime());
}

QString LogService::bootId() const
{
    return bootId_;
}

void LogService::setBootId(const QString &bootId)
{
    const QString normalized = bootId.trimmed();
    if (normalized == bootId_) {
        return;
    }

    bootId_ = normalized;
    reloadAll();
}

QStringList LogService::availableCategories() const
{
    return categories_;
}

void LogService::onWatchedPathChanged(const QString &)
{
    refreshIncremental();
}

QString LogService::currentBootId() const
{
    const auto response = fic::ipc::Client().request({{"command", "boot_id"}});
    if (!response.value("ok", false)) {
        return {};
    }
    return QString::fromStdString(response.value("boot_id", ""));
}

QVector<LogRecord> LogService::loadRecordsFromDaemon(
    QStringList* categories,
    const QString& cursor,
    bool loadAllPages,
    QString* resultingCursor,
    bool* reloadRequired)
{
    QVector<LogRecord> records;

    if (categories != nullptr) {
        categories->clear();
    }

    constexpr int pageSize = 500;
    constexpr int maximumPages = 200;

    QString currentCursor = cursor;
    if (reloadRequired != nullptr) {
        *reloadRequired = false;
    }

    for (int page = 0;
         page < maximumPages;
         ++page) {

        auto response =
            fic::ipc::Client().request({
                {"command", "log_records"},
                {"boot_id", bootId_.toStdString()},
                {"cursor", currentCursor.toStdString()},
                {"limit", pageSize}
            });

        if (!response.value("ok", false)) {
            break;
        }

        if (response.value("reload_required", false)) {
            if (reloadRequired != nullptr) {
                *reloadRequired = true;
            }
            break;
        }

        const std::string responseBootId =
        response.value("boot_id", "");

        if (!responseBootId.empty()) {
            bootId_ =
                QString::fromStdString(responseBootId);
        }

        if (categories != nullptr &&
            response.contains("categories") &&
            response["categories"].is_array()) {

            for (const auto& category :
                response["categories"]) {

                if (category.is_string()) {
                    categories->append(
                        QString::fromStdString(
                            category.get<std::string>())
                            .trimmed());
                }
            }
        }
        if (response.contains("records") &&
            response["records"].is_array()) {

            for (const auto& item :
                 response["records"]) {

                if (!item.is_object()) {
                    continue;
                }

                const QString line =
                    QString::fromStdString(
                        item.value("line", ""));

                const QString category =
                    QString::fromStdString(
                        item.value("category", ""));

                const QString sourceFile =
                    QString::fromStdString(
                        item.value("source_file", ""));

                if (line.isEmpty()) {
                    continue;
                }

                LogRecord record;

                if (!parseLogLine(
                        line,
                        category,
                        sourceFile,
                        &record)) {
                    continue;
                }

                record.byteSize =
                    static_cast<qint64>(
                        item.value(
                            "byte_size",
                            line.toUtf8().size()));

                records.append(record);
            }
        }

        const QString nextCursor = QString::fromStdString(
            response.value("next_cursor", currentCursor.toStdString()));

        if (nextCursor == currentCursor &&
            response.value("has_more", false)) {
            break;
        }

        currentCursor = nextCursor;

        if (!response.value("has_more", false) ||
            !loadAllPages) {
            break;
        }
    }

    if (resultingCursor != nullptr) {
        *resultingCursor = currentCursor;
    }

    if (categories != nullptr) {
        categories->removeDuplicates();
        categories->sort();
    }

    return records;
}
bool LogService::parseLogLine(const QString &line,
                              const QString &category,
                              const QString &sourceFile,
                              LogRecord *record)
{
    const int timeEnd = line.indexOf(QStringLiteral("] "));
    if (timeEnd <= 1) {
        return false;
    }

    const QString timestampText = line.mid(1, timeEnd - 1);
    const int levelStart = line.indexOf('[', timeEnd + 2);
    if (levelStart < 0) {
        return false;
    }

    const int levelEnd = line.indexOf(QStringLiteral("] "), levelStart);
    if (levelEnd < 0 || levelEnd <= levelStart + 1) {
        return false;
    }

    const QString levelText = line.mid(levelStart + 1, levelEnd - levelStart - 1).trimmed();
    logLevel level = logLevel::NoLog;
    if (levelText == QStringLiteral("TRACE")) {
        level = logLevel::TRACE;
    } else if (levelText == QStringLiteral("DEBUG")) {
        level = logLevel::DEBUG;
    } else if (levelText == QStringLiteral("INFO")) {
        level = logLevel::INFO;
    } else if (levelText == QStringLiteral("WARN")) {
        level = logLevel::WARN;
    } else if (levelText == QStringLiteral("ERROR")) {
        level = logLevel::ERROR;
    } else if (levelText == QStringLiteral("FATAL")) {
        level = logLevel::FATAL;
    } else {
        return false;
    }

    const QString message = line.mid(levelEnd + 2);
    const QString sortableTimestamp = timestampText.left(23);
    QDateTime parsedTime = QDateTime::fromString(sortableTimestamp, QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"));
    if (parsedTime.isValid()) {
        parsedTime.setTimeZone(QTimeZone::systemTimeZone());
    }

    record->timestamp = parsedTime;
    record->timestampText = timestampText;
    record->level = level;
    record->category = category;
    record->message = message;
    record->sourceFile = sourceFile;
    record->sequence = ++sequenceCounter_;

    return true;
}

void LogService::updateCategories(const QStringList &categories)
{
    QStringList normalized = categories;
    normalized.removeDuplicates();
    normalized.sort();

    if (normalized == categories_) {
        return;
    }

    categories_ = normalized;
    emit categoriesChanged(categories_);
}

bool LogService::recordLessThan(const LogRecord &left, const LogRecord &right)
{
    if (left.timestamp.isValid() && right.timestamp.isValid() && left.timestamp != right.timestamp) {
        return left.timestamp < right.timestamp;
    }

    if (left.timestampText != right.timestampText) {
        return left.timestampText < right.timestampText;
    }

    return left.sequence < right.sequence;
}
