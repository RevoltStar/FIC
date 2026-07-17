#include "DeviceEventList.h"

#include <QDebug>
#include <QHeaderView>
#include <QTreeWidgetItem>
#include <QVBoxLayout>
#include <fic/ipc/FicIpcClient.h>

DeviceEventList::DeviceEventList(QWidget *parent)
    : QWidget(parent)
{
    setupUI();
}

void DeviceEventList::setupUI()
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(0, 0, 0, 0);

    treeWidget = new QTreeWidget(this);
    treeWidget->setColumnCount(4);
    treeWidget->setHeaderLabels({"Время", "Событие", "Результат", "Описание"});
    treeWidget->setAlternatingRowColors(true);
    treeWidget->setRootIsDecorated(false);
    treeWidget->setSortingEnabled(true);
    treeWidget->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    treeWidget->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
    treeWidget->setTextElideMode(Qt::ElideNone);
    treeWidget->header()->setStretchLastSection(false);
    treeWidget->header()->setSectionResizeMode(0, QHeaderView::Interactive);
    treeWidget->header()->setSectionResizeMode(1, QHeaderView::Interactive);
    treeWidget->header()->setSectionResizeMode(2, QHeaderView::Interactive);
    treeWidget->header()->setSectionResizeMode(3, QHeaderView::Interactive);
    treeWidget->setColumnWidth(0, 150);
    treeWidget->setColumnWidth(1, 110);
    treeWidget->setColumnWidth(2, 140);
    treeWidget->setColumnWidth(3, 360);

    mainLayout->addWidget(treeWidget);
    setLayout(mainLayout);
}

void DeviceEventList::clear()
{
    treeWidget->clear();
}

void DeviceEventList::showDeviceEvents(int deviceId)
{
    clear();

    if (deviceId <= 0)
    {
        QTreeWidgetItem *emptyItem = new QTreeWidgetItem(treeWidget);
        emptyItem->setText(0, "Устройство не выбрано");
        emptyItem->setFlags(emptyItem->flags() & ~Qt::ItemIsSelectable);
        return;
    }

    auto response = fic::ipc::Client(fic::ipc::Endpoint::DeviceDaemon).request({
        {"command", "device_events"},
        {"device_id", deviceId},
        {"limit", 100}
    });

    if (!response.value("ok", false) || !response.contains("events") || !response["events"].is_array())
    {
        qDebug() << "Failed to load device events:"
                 << QString::fromStdString(response.value("message", "unknown daemon error"));
        QTreeWidgetItem *errorItem = new QTreeWidgetItem(treeWidget);
        errorItem->setText(0, "Не удалось загрузить события");
        errorItem->setText(3, QString::fromStdString(response.value("message", "unknown daemon error")));
        errorItem->setFlags(errorItem->flags() & ~Qt::ItemIsSelectable);
        return;
    }

    for (const auto& event : response["events"])
    {
        if (!event.is_object())
        {
            continue;
        }

        QTreeWidgetItem *item = new QTreeWidgetItem(treeWidget);
        const QString createdAt = QString::fromStdString(event.value("created_at", ""));
        const QString type = QString::fromStdString(event.value("event_type", ""));
        const QString result = QString::fromStdString(event.value("event_result", ""));
        const QString details = QString::fromStdString(event.value("event_details", ""));
        item->setText(0, createdAt);
        item->setText(1, type);
        item->setText(2, result);
        item->setText(3, details);
        item->setToolTip(0, createdAt);
        item->setToolTip(1, type);
        item->setToolTip(2, result);
        item->setToolTip(3, details);
    }

    if (treeWidget->topLevelItemCount() == 0)
    {
        QTreeWidgetItem *emptyItem = new QTreeWidgetItem(treeWidget);
        emptyItem->setText(0, "Событий нет");
        emptyItem->setFlags(emptyItem->flags() & ~Qt::ItemIsSelectable);
        return;
    }

    treeWidget->sortItems(0, Qt::DescendingOrder);
}
