#ifndef LOGMODEL_H
#define LOGMODEL_H

#include <QAbstractTableModel>
#include <QBrush>
#include <QVector>

#include "LogRecord.h"

class LogModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    enum Column {
        TimestampColumn = 0,
        LevelColumn,
        CategoryColumn,
        MessageColumn,
        SourceColumn,
        ColumnCount
    };

    enum Role {
        TimestampRole = Qt::UserRole + 1,
        LevelRole,
        CategoryRole,
        MessageRole,
        SourceRole,
        SequenceRole,
        ByteSizeRole
    };

    explicit LogModel(QObject *parent = nullptr);

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;

    void setRecords(const QVector<LogRecord> &records);
    void appendRecords(const QVector<LogRecord> &records);
    void clear();

    const LogRecord &recordAt(int row) const;
    bool hasRecords() const;

private:
    QVector<LogRecord> records_;

    QString levelText(logLevel level) const;
    QBrush levelBrush(logLevel level) const;
};

#endif // LOGMODEL_H
