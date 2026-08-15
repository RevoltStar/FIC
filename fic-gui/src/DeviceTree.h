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
#include <QIcon>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSet>
#include <QTimer>
#include <cstdint>
#include <map>
#include <optional>
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
    std::string children_control = "inherit";
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

using DeviceAttributes = std::map<std::string, std::string>;

struct DeviceTreeSnapshotEntry {
    DeviceInfo device;
    DeviceAttributes attributes;
};

struct DeviceTreeSnapshotData {
    std::int64_t revision = -1;
    std::string bootId;
    std::vector<DeviceTreeSnapshotEntry> entries;
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
    void applyChildrenControlToCurrentDevice(const QString &childrenControl);
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
    std::optional<std::int64_t> lastTreeRevision;
    bool fullSnapshotLoaded = false;
    bool snapshotIncludesDisconnected = false;

    void setupUI();
    void setupRefreshTimer();
    void refreshIfTreeChanged();
    bool refreshPreservingState(bool forceSnapshot = false);
    bool loadDeviceTreeSnapshot(bool includeDisconnected);
    void collectExpandedDeviceIds(QTreeWidgetItem *item, QSet<int> &expandedIds) const;
    bool restoreExpandedDeviceIds(QTreeWidgetItem *item, const QSet<int> &expandedIds, int selectedId);
    QTreeWidgetItem* findItemByDeviceId(QTreeWidgetItem *item, int deviceId) const;
    void ensureChildrenLoaded(QTreeWidgetItem *item);
    void loadChildDevices(QTreeWidgetItem *parentItem, int parentId);
    bool filterActive() const;
    bool itemMatchesFilter(QTreeWidgetItem *item) const;
    bool applyFilterToItem(QTreeWidgetItem *item, int &totalCount, int &visibleCount);
    void setDeviceControlLevel(int deviceId, const std::string &controlLevel);
    void setDeviceIgnoreHierarchy(int deviceId, bool ignoreHierarchy);
    void setDeviceChildrenControl(int deviceId, const std::string &childrenControl);
    void resetDeviceControl(int deviceId);
    void deleteDeviceFromDatabase(int deviceId, const QString &deviceName);
    bool canDeleteDevice(const DeviceInfo& device);
    bool canDeleteDeviceSubtree(int deviceId, const std::string &currentBootId);

    DeviceInfo fetchDeviceById(int deviceId) const;
    std::optional<std::int64_t> fetchTreeRevision() const;
    std::optional<DeviceTreeSnapshotData> fetchDeviceTreeSnapshot(bool includeDisconnected) const;
    std::vector<DeviceInfo> fetchChildDevices(int parentId, bool includeDisconnected = false) const;
    std::map<std::string, std::string> fetchDeviceAttributes(int deviceId) const;
    bool updateDeviceControlLevelRemote(int deviceId, const std::string& controlLevel, QString *errorMessage = nullptr, QString *warningMessage = nullptr) const;
    bool updateDeviceIgnoreHierarchyRemote(int deviceId, bool ignoreHierarchy, QString *errorMessage = nullptr, QString *warningMessage = nullptr) const;
    bool updateDeviceChildrenControlRemote(int deviceId, const std::string& childrenControl, QString *errorMessage = nullptr, QString *warningMessage = nullptr) const;
    bool resetDeviceControlRemote(int deviceId, QString *errorMessage = nullptr, QString *warningMessage = nullptr) const;
    bool deleteDeviceRemote(int deviceId, QString *errorMessage = nullptr) const;

    std::string getSystemBootId();
    bool isDeviceBootIdValid(const DeviceInfo& device, const std::string& currentBootId = "");
    void setupTreeItemMetadata(QTreeWidgetItem *item, const DeviceInfo& device,
                               const DeviceAttributes& attributes,
                               const std::string& currentBootId = "");
    void setupTreeItemStyle(QTreeWidgetItem *item, const DeviceInfo& device,
                            const std::string& currentBootId = "");
    void setupControlLevelColumn(QTreeWidgetItem *item, const DeviceInfo& device);
    QIcon deviceIcon(const DeviceInfo& device, const DeviceAttributes& attributes) const;
    std::string generateNodeName(const DeviceInfo& device, const DeviceAttributes& attributes);
};

#endif // DEVICETREEWIDGET_H
