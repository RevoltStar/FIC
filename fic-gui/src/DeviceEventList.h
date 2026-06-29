#ifndef DEVICEEVENTLIST_H
#define DEVICEEVENTLIST_H

#include <QTreeWidget>
#include <QWidget>

class DeviceEventList : public QWidget
{
public:
    explicit DeviceEventList(QWidget *parent = nullptr);
    void clear();
    void showDeviceEvents(int deviceId);

private:
    void setupUI();

    QTreeWidget *treeWidget;
};

#endif // DEVICEEVENTLIST_H
