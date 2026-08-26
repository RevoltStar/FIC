#ifndef LOGLEVEL_H
#define LOGLEVEL_H

#include <QString>

enum class logLevel {
    NoLog = 0,
    TRACE = 1,
    DEBUG = 2,
    INFO  = 3,
    WARN  = 4,
    ERROR = 5,
    FATAL = 6
};

inline QString logLevelToString(logLevel level)
{
    switch (level) {
    case logLevel::TRACE:
        return QStringLiteral("TRACE");
    case logLevel::DEBUG:
        return QStringLiteral("DEBUG");
    case logLevel::INFO:
        return QStringLiteral("INFO");
    case logLevel::WARN:
        return QStringLiteral("WARN");
    case logLevel::ERROR:
        return QStringLiteral("ERROR");
    case logLevel::FATAL:
        return QStringLiteral("FATAL");
    default:
        return QStringLiteral("NOLOG");
    }
}

#endif // LOGLEVEL_H
