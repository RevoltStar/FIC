#ifndef LOGRECORD_H
#define LOGRECORD_H

#include <QDateTime>
#include <QString>

#include "features/logs/models/LogLevel.h"

struct LogRecord {
    QDateTime timestamp;
    QString timestampText;
    logLevel level = logLevel::INFO;
    QString category;
    QString message;
    QString sourceFile;
    quint64 sequence = 0;
    qint64 byteSize = 0;
};

#endif // LOGRECORD_H
