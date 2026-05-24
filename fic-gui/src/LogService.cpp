#include "LogService.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTextStream>

#include "utils/SystemBootInfo.h"

namespace {
QString normalizeCategoryListEntry(const QString &value)
{
    return value.trimmed();
}
}

LogService::LogService(QObject *parent)
    : QObject(parent)
{
    refreshTimer_.setInterval(2000);
    connect(&refreshTimer_, &QTimer::timeout, this, &LogService::refreshIncremental);
    connect(&watcher_, &QFileSystemWatcher::directoryChanged, this, &LogService::onWatchedPathChanged);
    connect(&watcher_, &QFileSystemWatcher::fileChanged, this, &LogService::onWatchedPathChanged);
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
    if (!watcher_.files().isEmpty()) {
        watcher_.removePaths(watcher_.files());
    }
    if (!watcher_.directories().isEmpty()) {
        watcher_.removePaths(watcher_.directories());
    }
}

void LogService::reloadAll()
{
    if (bootId_.isEmpty()) {
        bootId_ = currentBootId();
    }

    fileCursors_.clear();
    sequenceCounter_ = 0;

    const QStringList categories = discoverCategories();
    updateCategories(categories);

    QVector<LogRecord> records;
    const QStringList logFiles = discoverLogFiles();
    for (const QString &filePath : logFiles) {
        const QString category = QFileInfo(filePath).dir().dirName();
        qint64 endOffset = 0;
        QVector<LogRecord> parsedRecords = readRecordsFromFile(filePath, category, 0, &endOffset);
        fileCursors_.insert(filePath, FileCursor{endOffset, category});
        records += parsedRecords;
    }

    std::sort(records.begin(), records.end(), recordLessThan);
    rebuildWatcher();

    emit fullReloaded(records);
    emit lastUpdateChanged(QDateTime::currentDateTime());
}

void LogService::refreshIncremental()
{
    const QString actualBootId = currentBootId();
    if (!actualBootId.isEmpty() && actualBootId != bootId_) {
        bootId_ = actualBootId;
        reloadAll();
        return;
    }

    if (bootId_.isEmpty()) {
        bootId_ = actualBootId;
    }

    const QStringList categories = discoverCategories();
    updateCategories(categories);

    QVector<LogRecord> appendedRecords;
    QSet<QString> discoveredFiles;

    const QStringList logFiles = discoverLogFiles();
    for (const QString &filePath : logFiles) {
        discoveredFiles.insert(filePath);

        const QFileInfo fileInfo(filePath);
        const QString category = fileInfo.dir().dirName();
        const qint64 fileSize = fileInfo.size();

        qint64 startOffset = 0;
        if (fileCursors_.contains(filePath)) {
            startOffset = fileCursors_.value(filePath).offset;
            if (fileSize < startOffset) {
                startOffset = 0;
            }
        }

        qint64 endOffset = startOffset;
        QVector<LogRecord> parsedRecords = readRecordsFromFile(filePath, category, startOffset, &endOffset);
        fileCursors_.insert(filePath, FileCursor{endOffset, category});
        appendedRecords += parsedRecords;
    }

    for (auto it = fileCursors_.begin(); it != fileCursors_.end();) {
        if (!discoveredFiles.contains(it.key())) {
            it = fileCursors_.erase(it);
        } else {
            ++it;
        }
    }

    std::sort(appendedRecords.begin(), appendedRecords.end(), recordLessThan);
    rebuildWatcher();

    if (!appendedRecords.isEmpty()) {
        emit recordsAppended(appendedRecords);
    }
    emit lastUpdateChanged(QDateTime::currentDateTime());
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
    return QString::fromStdString(SystemBootInfo::get_boot_id());
}

QString LogService::currentBootDirectory() const
{
    if (bootId_.isEmpty()) {
        return {};
    }

    return QDir(baseLogDirectory_).filePath(bootId_);
}

QStringList LogService::discoverCategories() const
{
    QStringList categories;
    const QDir bootDir(currentBootDirectory());
    if (!bootDir.exists()) {
        return categories;
    }

    const QFileInfoList entries = bootDir.entryInfoList(QDir::Dirs | QDir::NoDotAndDotDot, QDir::Name);
    for (const QFileInfo &entry : entries) {
        categories.append(normalizeCategoryListEntry(entry.fileName()));
    }

    categories.removeDuplicates();
    return categories;
}

QStringList LogService::discoverLogFiles() const
{
    QStringList files;
    const QDir bootDir(currentBootDirectory());
    if (!bootDir.exists()) {
        return files;
    }

    const QFileInfoList categoryDirs = bootDir.entryInfoList(QDir::Dirs | QDir::NoDotAndDotDot, QDir::Name);
    for (const QFileInfo &categoryDirInfo : categoryDirs) {
        const QDir categoryDir(categoryDirInfo.absoluteFilePath());
        const QFileInfoList fileInfos = categoryDir.entryInfoList(QStringList() << QStringLiteral("*.txt"),
                                                                  QDir::Files,
                                                                  QDir::Name);
        for (const QFileInfo &fileInfo : fileInfos) {
            files.append(fileInfo.absoluteFilePath());
        }
    }

    files.sort();
    return files;
}

QVector<LogRecord> LogService::readRecordsFromFile(const QString &filePath,
                                                   const QString &category,
                                                   qint64 startOffset,
                                                   qint64 *endOffset)
{
    QVector<LogRecord> records;
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        if (endOffset) {
            *endOffset = startOffset;
        }
        return records;
    }

    if (startOffset > 0) {
        file.seek(startOffset);
        if (startOffset > 0) {
            file.readLine();
        }
    }

    QTextStream stream(&file);
    while (!stream.atEnd()) {
        const QString line = stream.readLine();
        if (line.isEmpty()) {
            continue;
        }

        LogRecord record;
        if (!parseLogLine(line, category, filePath, &record)) {
            continue;
        }

        record.byteSize = line.toUtf8().size();
        records.append(record);
    }

    if (endOffset) {
        *endOffset = file.pos();
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
    QString sortableTimestamp = timestampText.left(23);
    QDateTime parsedTime = QDateTime::fromString(sortableTimestamp, QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"));
    if (parsedTime.isValid()) {
        parsedTime.setTimeSpec(Qt::LocalTime);
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

void LogService::rebuildWatcher()
{
    QStringList desiredDirectories;
    QStringList desiredFiles;

    const QString bootDirPath = currentBootDirectory();
    if (!bootDirPath.isEmpty() && QDir(bootDirPath).exists()) {
        desiredDirectories.append(bootDirPath);

        const QStringList categories = discoverCategories();
        for (const QString &category : categories) {
            desiredDirectories.append(QDir(bootDirPath).filePath(category));
        }
    }

    desiredFiles = discoverLogFiles();

    const QStringList currentDirectories = watcher_.directories();
    const QStringList currentFiles = watcher_.files();

    QStringList directoriesToRemove;
    for (const QString &path : currentDirectories) {
        if (!desiredDirectories.contains(path)) {
            directoriesToRemove.append(path);
        }
    }

    QStringList filesToRemove;
    for (const QString &path : currentFiles) {
        if (!desiredFiles.contains(path)) {
            filesToRemove.append(path);
        }
    }

    if (!directoriesToRemove.isEmpty()) {
        watcher_.removePaths(directoriesToRemove);
    }
    if (!filesToRemove.isEmpty()) {
        watcher_.removePaths(filesToRemove);
    }

    QStringList directoriesToAdd;
    for (const QString &path : desiredDirectories) {
        if (!currentDirectories.contains(path)) {
            directoriesToAdd.append(path);
        }
    }

    QStringList filesToAdd;
    for (const QString &path : desiredFiles) {
        if (!currentFiles.contains(path)) {
            filesToAdd.append(path);
        }
    }

    if (!directoriesToAdd.isEmpty()) {
        watcher_.addPaths(directoriesToAdd);
    }
    if (!filesToAdd.isEmpty()) {
        watcher_.addPaths(filesToAdd);
    }
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
