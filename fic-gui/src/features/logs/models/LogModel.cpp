#include "features/logs/models/LogModel.h"

#include <QApplication>
#include <QColor>
#include <QFileInfo>
#include <QPalette>

#include "shared/i18n/QLocalizationManager.h"

LogModel::LogModel(QObject *parent)
    : QAbstractTableModel(parent)
{
}

int LogModel::rowCount(const QModelIndex &parent) const
{
    if (parent.isValid()) {
        return 0;
    }

    return records_.size();
}

int LogModel::columnCount(const QModelIndex &parent) const
{
    if (parent.isValid()) {
        return 0;
    }

    return ColumnCount;
}

QVariant LogModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() < 0 || index.row() >= records_.size()) {
        return {};
    }

    const LogRecord &record = records_.at(index.row());

    if (role == TimestampRole) {
        return record.timestamp.isValid() ? QVariant(record.timestamp) : QVariant(record.timestampText);
    }
    if (role == LevelRole) {
        return static_cast<int>(record.level);
    }
    if (role == CategoryRole) {
        return record.category;
    }
    if (role == MessageRole) {
        return record.message;
    }
    if (role == SourceRole) {
        return record.sourceFile;
    }
    if (role == SequenceRole) {
        return QVariant::fromValue<qulonglong>(record.sequence);
    }
    if (role == ByteSizeRole) {
        return QVariant::fromValue<qlonglong>(record.byteSize);
    }

    if (role == Qt::DisplayRole) {
        switch (index.column()) {
        case TimestampColumn:
            return record.timestampText;
        case LevelColumn:
            return levelText(record.level);
        case CategoryColumn:
            return record.category;
        case MessageColumn:
            return record.message;
        case SourceColumn:
            return QFileInfo(record.sourceFile).fileName();
        default:
            return {};
        }
    }

    if (role == Qt::ForegroundRole) {
        if (index.column() == LevelColumn || index.column() == MessageColumn) {
            return levelBrush(record.level);
        }
    }

    if (role == Qt::ToolTipRole) {
        return QString("%1\n[%2] %3\n%4")
            .arg(record.timestampText,
                 levelText(record.level),
                 record.category,
                 record.message);
    }

    return {};
}

QVariant LogModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) {
        return QAbstractTableModel::headerData(section, orientation, role);
    }

    switch (section) {
    case TimestampColumn:
        return QLocalizationManager::getLang("[logs:ui][time]");
    case LevelColumn:
        return QLocalizationManager::getLang("[logs:ui][level_plain]");
    case CategoryColumn:
        return QLocalizationManager::getLang("[logs:ui][category_plain]");
    case MessageColumn:
        return QLocalizationManager::getLang("[logs:ui][message]");
    case SourceColumn:
        return QLocalizationManager::getLang("[logs:ui][source]");
    default:
        return {};
    }
}

void LogModel::setRecords(const QVector<LogRecord> &records)
{
    beginResetModel();
    records_ = records;
    endResetModel();
}

void LogModel::appendRecords(const QVector<LogRecord> &records)
{
    if (records.isEmpty()) {
        return;
    }

    const int firstRow = records_.size();
    const int lastRow = firstRow + records.size() - 1;

    beginInsertRows(QModelIndex(), firstRow, lastRow);
    records_ += records;
    endInsertRows();
}

void LogModel::clear()
{
    beginResetModel();
    records_.clear();
    endResetModel();
}

const LogRecord &LogModel::recordAt(int row) const
{
    return records_.at(row);
}

bool LogModel::hasRecords() const
{
    return !records_.isEmpty();
}

QString LogModel::levelText(logLevel level) const
{
    return logLevelToString(level);
}

QBrush LogModel::levelBrush(logLevel level) const
{
    const QPalette palette = QApplication::palette();
    const bool darkTheme =
        palette.color(QPalette::Base).lightness() < palette.color(QPalette::Text).lightness();

    switch (level) {
    case logLevel::TRACE:
        return palette.brush(QPalette::Disabled, QPalette::Text);
    case logLevel::DEBUG:
        return palette.brush(QPalette::Link);
    case logLevel::INFO:
        return palette.brush(QPalette::Text);
    case logLevel::WARN:
        return QBrush(QColor(darkTheme ? QStringLiteral("#ffb74d")
                                      : QStringLiteral("#9a5b00")));
    case logLevel::ERROR:
        return QBrush(QColor(darkTheme ? QStringLiteral("#ff6b6b")
                                      : QStringLiteral("#b71c1c")));
    case logLevel::FATAL:
        return QBrush(QColor(darkTheme ? QStringLiteral("#ff8a80")
                                      : QStringLiteral("#7f0000")));
    default:
        return palette.brush(QPalette::Text);
    }
}
