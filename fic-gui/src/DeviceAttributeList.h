#ifndef DEVICEATTRIBUTELIST_H
#define DEVICEATTRIBUTELIST_H

#include <QWidget>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QMap>
#include <QString>
#include "utils/DB.h"

class DeviceAttributeList : public QWidget
{
    Q_OBJECT

public:
    explicit DeviceAttributeList(QWidget *parent = nullptr);
    virtual ~DeviceAttributeList();

    // Очистить список
    void clear();

    // Показать атрибуты устройства
    void showDeviceAttributes(int deviceId);

    // Показать конкретные атрибуты (если уже получены извне)
    void showAttributes(const std::map<std::string, std::string>& attributes);

signals:
    // Сигнал о том, что список атрибутов обновлен
    void attributesUpdated(int deviceId, int attributeCount);

private:
    void setupUI();
    void populateTree(const std::map<std::string, std::string>& attributes);

    QTreeWidget *treeWidget;
    DB database;
};

#endif // DEVICEATTRIBUTELIST_H
