#ifndef LOGFILTERPROXYMODEL_H
#define LOGFILTERPROXYMODEL_H

#include <QSortFilterProxyModel>

#include "LogLevel.h"

class LogFilterProxyModel : public QSortFilterProxyModel
{
    Q_OBJECT

public:
    explicit LogFilterProxyModel(QObject *parent = nullptr);

    void setCategoryFilter(const QString &category);
    void setMinimumLevel(logLevel level);
    void setSearchText(const QString &text);

    QString categoryFilter() const;
    logLevel minimumLevel() const;
    QString searchText() const;

protected:
    bool filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const override;
    bool lessThan(const QModelIndex &sourceLeft, const QModelIndex &sourceRight) const override;

private:
    void refreshFilter();

    QString categoryFilter_ = QStringLiteral("all");
    logLevel minimumLevel_ = logLevel::TRACE;
    QString searchText_;
};

#endif // LOGFILTERPROXYMODEL_H
