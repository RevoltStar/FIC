#ifndef LOGSERVICE_H
#define LOGSERVICE_H

#include <QObject>
#include <QTimer>
#include <QVector>
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
    QString bootId_;
    QStringList categories_;
    QTimer refreshTimer_;
    quint64 sequenceCounter_ = 0;
    int logCursor_ = 0;

    QString currentBootId() const;
    QVector<LogRecord> loadRecordsFromDaemon(
        QStringList* categories,
        int offset,
        bool loadAllPages,
        int* resultingOffset);
    bool parseLogLine(const QString &line,
                      const QString &category,
                      const QString &sourceFile,
                      LogRecord *record);
    void updateCategories(const QStringList &categories);
    static bool recordLessThan(const LogRecord &left, const LogRecord &right);
};

#endif // LOGSERVICE_H
