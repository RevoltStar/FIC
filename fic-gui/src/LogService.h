#ifndef LOGSERVICE_H
#define LOGSERVICE_H

#include <QFileSystemWatcher>
#include <QObject>
#include <QTimer>
#include <QVector>
#include <QSet>
#include <QString>

#include "LogRecord.h"

class LogService : public QObject
{
    Q_OBJECT

public:
    explicit LogService(QObject *parent = nullptr);

    void start();
    void stop();
    void reloadAll();
    void refreshIncremental();

    QString bootId() const;
    void setBootId(const QString &bootId);
    QStringList availableCategories() const;

signals:
    void fullReloaded(const QVector<LogRecord> &records);
    void recordsAppended(const QVector<LogRecord> &records);
    void categoriesChanged(const QStringList &categories);
    void lastUpdateChanged(const QDateTime &timestamp);

private slots:
    void onWatchedPathChanged(const QString &path);

private:
    struct FileCursor {
        qint64 offset = 0;
        QString category;
    };

    QString baseLogDirectory_ = QStringLiteral("/opt/fic/log");
    QString bootId_;
    QStringList categories_;
    QHash<QString, FileCursor> fileCursors_;
    QFileSystemWatcher watcher_;
    QTimer refreshTimer_;
    quint64 sequenceCounter_ = 0;

    QString currentBootId() const;
    QString currentBootDirectory() const;
    QStringList discoverCategories() const;
    QStringList discoverLogFiles() const;
    QVector<LogRecord> readRecordsFromFile(const QString &filePath,
                                           const QString &category,
                                           qint64 startOffset,
                                           qint64 *endOffset);
    bool parseLogLine(const QString &line,
                      const QString &category,
                      const QString &sourceFile,
                      LogRecord *record);
    void rebuildWatcher();
    void updateCategories(const QStringList &categories);
    static bool recordLessThan(const LogRecord &left, const LogRecord &right);
};

#endif // LOGSERVICE_H
