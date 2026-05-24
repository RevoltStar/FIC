#ifndef DEVICETREEWIDGET_H
#define DEVICETREEWIDGET_H

#include <QWidget>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QPushButton>
#include <QPoint>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFileSystemWatcher>
#include <QSet>
#include <QTimer>
#include <vector>
#include <string>
#include "utils/DB.h"
#include <fstream>
#include <istream>
#include <filesystem>
#include "ConfigFileHandler.h"

class DeviceTree : public QWidget
{
    Q_OBJECT

public:
    explicit DeviceTree(QWidget *parent = nullptr);
    void loadDeviceTree();
    ~DeviceTree();
signals:
    void deviceClicked(const DeviceInfo& device);
private slots:
    void onItemExpanded(QTreeWidgetItem *item);
    void expandAllNodes();
    void collapseAllNodes();
    void onItemClicked(QTreeWidgetItem *item, int column);
    void showControlLevelContextMenu(const QPoint &position);
    void scheduleDeviceTreeRefresh();

private:
    static const QString dbPath;

    DB db;
    QTreeWidget *treeWidget;
    QPushButton *btnExpandAll;
    QPushButton *btnCollapseAll;
    QFileSystemWatcher *dbWatcher;
    QTimer *refreshTimer;

    void setupUI();
    void setupDatabaseWatcher();
    void refreshWatchedDatabasePaths();
    void refreshPreservingState();
    void collectExpandedDeviceIds(QTreeWidgetItem *item, QSet<int> &expandedIds) const;
    bool restoreExpandedDeviceIds(QTreeWidgetItem *item, const QSet<int> &expandedIds, int selectedId);
    QTreeWidgetItem* findItemByDeviceId(QTreeWidgetItem *item, int deviceId) const;
    void ensureChildrenLoaded(QTreeWidgetItem *item);
    void expandNodeRecursively(QTreeWidgetItem *item);
    void loadChildDevices(QTreeWidgetItem *parentItem, int parentId);
    void setDeviceControlLevel(int deviceId, const std::string &controlLevel);
    void deleteDeviceFromDatabase(int deviceId, const QString &deviceName);
    bool canDeleteDevice(const DeviceInfo& device);
    bool canDeleteDeviceSubtree(int deviceId, const std::string &currentBootId);

    std::string getSystemBootId();
    bool isDeviceBootIdValid(const DeviceInfo& device);
    void setupTreeItemStyle(QTreeWidgetItem *item, const DeviceInfo& device);
    void setupControlLevelColumn(QTreeWidgetItem *item, const DeviceInfo& device);

    std::string generateNodeName(const DeviceInfo& device);
};

#endif // DEVICETREEWIDGET_H
