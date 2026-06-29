#ifndef DEVICETREEWIDGET_H
#define DEVICETREEWIDGET_H

#include <QWidget>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QPushButton>
#include <QCheckBox>
#include <QComboBox>
#include <QLabel>
#include <QLineEdit>
#include <QPoint>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSet>
#include <QTimer>
#include <map>
#include <vector>
#include <string>
#include <fstream>
#include <istream>
#include <filesystem>

struct DeviceInfo {
    int id = -1;
    std::string device_hash;
    std::string devpath;
    std::string subsystem;
    std::string device_type;
    int parent_id = 0;
    std::string control_level;
    bool control_explicit = true;
    bool ignore_hierarchy = false;
    std::string effective_control_level;
    std::string effective_source;
    int effective_source_device_id = -1;
    std::string effective_reason;
    bool connected = false;
    std::string boot_id;
    std::string created_at;
    std::string last_event_at;
    std::string notes;
};

class DeviceTree : public QWidget
{
    Q_OBJECT

public:
    explicit DeviceTree(QWidget *parent = nullptr);
    void loadDeviceTree();
    int currentDeviceId() const;
    ~DeviceTree();
public slots:
    void applyControlLevelToCurrentDevice(const QString &controlLevel);
    void applyIgnoreHierarchyToCurrentDevice(bool ignoreHierarchy);
    void resetCurrentDeviceControl();
signals:
    void deviceClicked(const DeviceInfo& device);
private slots:
    void onItemExpanded(QTreeWidgetItem *item);
    void expandAllNodes();
    void collapseAllNodes();
    void onItemClicked(QTreeWidgetItem *item, int column);
    void showControlLevelContextMenu(const QPoint &position);
    void scheduleDeviceTreeRefresh();
    void scheduleFilterUpdate();
    void applyDeviceFilter();

private:
    QTreeWidget *treeWidget;
    QLineEdit *searchEdit;
    QComboBox *quickFilterCombo;
    QPushButton *btnExpandAll;
    QPushButton *btnCollapseAll;
    QPushButton *btnClearFilter;
    QCheckBox *chkShowHistory;
    QLabel *filterStatsLabel;
    QTimer *refreshTimer;
    QTimer *filterTimer;

    void setupUI();
    void setupRefreshTimer();
    void refreshPreservingState();
    void collectExpandedDeviceIds(QTreeWidgetItem *item, QSet<int> &expandedIds) const;
    bool restoreExpandedDeviceIds(QTreeWidgetItem *item, const QSet<int> &expandedIds, int selectedId);
    QTreeWidgetItem* findItemByDeviceId(QTreeWidgetItem *item, int deviceId) const;
    void ensureChildrenLoaded(QTreeWidgetItem *item);
    void expandNodeRecursively(QTreeWidgetItem *item);
    void loadChildDevices(QTreeWidgetItem *parentItem, int parentId);
    bool filterActive() const;
    bool itemMatchesFilter(QTreeWidgetItem *item) const;
    bool applyFilterToItem(QTreeWidgetItem *item, int &totalCount, int &visibleCount);
    void setDeviceControlLevel(int deviceId, const std::string &controlLevel);
    void setDeviceIgnoreHierarchy(int deviceId, bool ignoreHierarchy);
    void resetDeviceControl(int deviceId);
    void deleteDeviceFromDatabase(int deviceId, const QString &deviceName);
    bool canDeleteDevice(const DeviceInfo& device);
    bool canDeleteDeviceSubtree(int deviceId, const std::string &currentBootId);

    DeviceInfo fetchDeviceById(int deviceId) const;
    std::vector<DeviceInfo> fetchChildDevices(int parentId, bool includeDisconnected = false) const;
    std::map<std::string, std::string> fetchDeviceAttributes(int deviceId) const;
    std::string getDeviceAttribute(int deviceId, const std::string& attributeName, const std::string& defaultValue = "") const;
    bool updateDeviceControlLevelRemote(int deviceId, const std::string& controlLevel, QString *errorMessage = nullptr) const;
    bool updateDeviceIgnoreHierarchyRemote(int deviceId, bool ignoreHierarchy, QString *errorMessage = nullptr) const;
    bool resetDeviceControlRemote(int deviceId, QString *errorMessage = nullptr) const;
    bool deleteDeviceRemote(int deviceId, QString *errorMessage = nullptr) const;

    std::string getSystemBootId();
    bool isDeviceBootIdValid(const DeviceInfo& device);
    void setupTreeItemMetadata(QTreeWidgetItem *item, const DeviceInfo& device);
    void setupTreeItemStyle(QTreeWidgetItem *item, const DeviceInfo& device);
    void setupControlLevelColumn(QTreeWidgetItem *item, const DeviceInfo& device);

    std::string generateNodeName(const DeviceInfo& device);
};

#endif // DEVICETREEWIDGET_H
