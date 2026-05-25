#include "LogFilterProxyModel.h"

#include "LogModel.h"

LogFilterProxyModel::LogFilterProxyModel(QObject *parent)
    : QSortFilterProxyModel(parent)
{
    setDynamicSortFilter(true);
}

void LogFilterProxyModel::setCategoryFilter(const QString &category)
{
    if (categoryFilter_ == category) {
        return;
    }

    categoryFilter_ = category;
    refreshFilter();
}

void LogFilterProxyModel::setMinimumLevel(logLevel level)
{
    if (minimumLevel_ == level) {
        return;
    }

    minimumLevel_ = level;
    refreshFilter();
}

void LogFilterProxyModel::setSearchText(const QString &text)
{
    const QString normalized = text.trimmed();
    if (searchText_ == normalized) {
        return;
    }

    searchText_ = normalized;
    refreshFilter();
}

void LogFilterProxyModel::refreshFilter()
{
#if QT_VERSION >= QT_VERSION_CHECK(6, 10, 0)
    beginFilterChange();
    endFilterChange();
#else
    invalidateFilter();
#endif
}

QString LogFilterProxyModel::categoryFilter() const
{
    return categoryFilter_;
}

logLevel LogFilterProxyModel::minimumLevel() const
{
    return minimumLevel_;
}

QString LogFilterProxyModel::searchText() const
{
    return searchText_;
}

bool LogFilterProxyModel::filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const
{
    const QModelIndex levelIndex = sourceModel()->index(sourceRow, LogModel::LevelColumn, sourceParent);
    const QModelIndex categoryIndex = sourceModel()->index(sourceRow, LogModel::CategoryColumn, sourceParent);
    const QModelIndex messageIndex = sourceModel()->index(sourceRow, LogModel::MessageColumn, sourceParent);
    const QModelIndex timeIndex = sourceModel()->index(sourceRow, LogModel::TimestampColumn, sourceParent);
    const QModelIndex sourceIndex = sourceModel()->index(sourceRow, LogModel::SourceColumn, sourceParent);

    const logLevel rowLevel = static_cast<logLevel>(sourceModel()->data(levelIndex, LogModel::LevelRole).toInt());
    if (static_cast<int>(rowLevel) < static_cast<int>(minimumLevel_)) {
        return false;
    }

    const QString rowCategory = sourceModel()->data(categoryIndex, LogModel::CategoryRole).toString();
    if (categoryFilter_ != QStringLiteral("all") && rowCategory != categoryFilter_) {
        return false;
    }

    if (searchText_.isEmpty()) {
        return true;
    }

    const QString haystack = QStringLiteral("%1 %2 %3 %4")
        .arg(sourceModel()->data(timeIndex, Qt::DisplayRole).toString(),
             sourceModel()->data(levelIndex, Qt::DisplayRole).toString(),
             sourceModel()->data(messageIndex, LogModel::MessageRole).toString(),
             sourceModel()->data(sourceIndex, LogModel::SourceRole).toString())
        .toLower();

    return haystack.contains(searchText_.toLower());
}

bool LogFilterProxyModel::lessThan(const QModelIndex &sourceLeft, const QModelIndex &sourceRight) const
{
    if (sourceLeft.column() == LogModel::TimestampColumn &&
        sourceRight.column() == LogModel::TimestampColumn) {
        const QVariant leftTime = sourceModel()->data(sourceLeft, LogModel::TimestampRole);
        const QVariant rightTime = sourceModel()->data(sourceRight, LogModel::TimestampRole);

        if (leftTime.canConvert<QDateTime>() &&
            rightTime.canConvert<QDateTime>()) {
            const QDateTime leftDateTime = leftTime.toDateTime();
            const QDateTime rightDateTime = rightTime.toDateTime();
            if (leftDateTime != rightDateTime) {
                return leftDateTime < rightDateTime;
            }
        } else {
            const QString leftText = sourceLeft.data(Qt::DisplayRole).toString();
            const QString rightText = sourceRight.data(Qt::DisplayRole).toString();
            if (leftText != rightText) {
                return leftText < rightText;
            }
        }

        return sourceModel()->data(sourceLeft, LogModel::SequenceRole).toULongLong() <
               sourceModel()->data(sourceRight, LogModel::SequenceRole).toULongLong();
    }

    return QSortFilterProxyModel::lessThan(sourceLeft, sourceRight);
}
