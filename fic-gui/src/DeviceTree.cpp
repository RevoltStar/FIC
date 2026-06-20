#include "DeviceTree.h"
#include <QAction>
#include <QDebug>
#include <QDir>
#include <QFileInfo>
#include <QHeaderView>
#include <QMenu>
#include <QMessageBox>
#include <QScrollBar>
#include <QSignalBlocker>
#include <QStyle>
#include <fic/ipc/FicIpcClient.h>
#include "wrappers/QLocalizationManager.h"
#include <algorithm>
#include <cctype>
#include <exception>
#include <iomanip>
#include <sstream>
#include <sys/utsname.h> // Для получения времени старта ОС

namespace {
std::string upperCopy(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::toupper(ch));
    });
    return value;
}

std::string normalizePciClassKey(std::string value)
{
    value.erase(std::remove_if(value.begin(), value.end(), [](unsigned char ch) {
        return std::isxdigit(ch) == 0;
    }), value.end());

    while (value.length() < 6) {
        value = "0" + value;
    }
    if (value.length() > 6) {
        value = value.substr(value.length() - 6);
    }

    value = upperCopy(value);
    return value.substr(0, 2) + "|" + value.substr(2, 2) + "|" + value.substr(4, 2);
}

std::string normalizeUsbTypePart(std::string value)
{
    if (value.empty()) {
        return "00";
    }

    const bool containsHexLetter = std::any_of(value.begin(), value.end(), [](unsigned char ch) {
        return std::isalpha(ch) != 0;
    });

    try {
        const unsigned long number = std::stoul(value, nullptr, containsHexLetter ? 16 : 10);
        std::stringstream ss;
        ss << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << (number & 0xFF);
        return ss.str();
    } catch (const std::exception&) {
        value.erase(std::remove_if(value.begin(), value.end(), [](unsigned char ch) {
            return std::isxdigit(ch) == 0;
        }), value.end());
        while (value.length() < 2) {
            value = "0" + value;
        }
        if (value.length() > 2) {
            value = value.substr(value.length() - 2);
        }
        return upperCopy(value);
    }
}

std::string normalizeUsbTypeKey(const std::string& type)
{
    std::vector<std::string> parts;
    std::stringstream ss(type);
    std::string token;

    while (std::getline(ss, token, '/')) {
        parts.push_back(normalizeUsbTypePart(token));
    }

    if (parts.empty()) {
        return "";
    }
    while (parts.size() < 3) {
        parts.push_back("00");
    }
    if (parts.size() > 3) {
        parts.resize(3);
    }

    return parts[0] + "|" + parts[1] + "|" + parts[2];
}

std::string localizeDeviceClass(const std::string& subsystem, const std::string& classKey)
{
    if (classKey.empty()) {
        return "";
    }

    const std::string key = "[devices:class][subsystem:" + subsystem + "][class:" + classKey + "]";
    const QString localized = QLocalizationManager::getLang(QString::fromStdString(key));
    return localized.toStdString() == key ? "" : localized.toStdString();
}
} // namespace

DeviceTree::DeviceTree(QWidget *parent)
    : QWidget(parent)
{
    setupUI();
    setupRefreshTimer();
}

DeviceTree::~DeviceTree()
{
}

void DeviceTree::setupUI()
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);

    // Панель кнопок
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    btnExpandAll = new QPushButton("Развернуть все", this);
    btnCollapseAll = new QPushButton("Свернуть все", this);

    buttonLayout->addWidget(btnExpandAll);
    buttonLayout->addWidget(btnCollapseAll);
    buttonLayout->addStretch();

    // Дерево устройств
    treeWidget = new QTreeWidget(this);
    treeWidget->setColumnCount(2);
    treeWidget->setHeaderLabels({"Дерево устройств Linux", "Контроль"});
    treeWidget->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    treeWidget->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
    treeWidget->setTextElideMode(Qt::ElideRight);
    treeWidget->setContextMenuPolicy(Qt::CustomContextMenu);
    treeWidget->setMinimumWidth(460);
    setMinimumWidth(480);
    setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Expanding);
    treeWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    treeWidget->header()->setStretchLastSection(false);
    treeWidget->header()->setSectionResizeMode(0, QHeaderView::Interactive);
    treeWidget->header()->setSectionResizeMode(1, QHeaderView::Fixed);
    treeWidget->setColumnWidth(0, 340);
    treeWidget->setColumnWidth(1, 125);

    connect(treeWidget, &QTreeWidget::itemExpanded,
            this, &DeviceTree::onItemExpanded);
    connect(btnExpandAll, &QPushButton::clicked,
            this, &DeviceTree::expandAllNodes);
    connect(btnCollapseAll, &QPushButton::clicked,
            this, &DeviceTree::collapseAllNodes);
    connect(treeWidget, &QTreeWidget::itemClicked,
            this, &DeviceTree::onItemClicked);
    connect(treeWidget, &QTreeWidget::currentItemChanged,
            this, [this](QTreeWidgetItem *current, QTreeWidgetItem *previous) {
                Q_UNUSED(previous);
                onItemClicked(current, 0);
            });
    connect(treeWidget, &QWidget::customContextMenuRequested,
            this, &DeviceTree::showControlLevelContextMenu);

    mainLayout->addLayout(buttonLayout);
    mainLayout->addWidget(treeWidget);

    // Устанавливаем макет для виджета
    setLayout(mainLayout);
}


DeviceInfo DeviceTree::fetchDeviceById(int deviceId) const
{
    DeviceInfo device{};
    device.id = -1;

    auto response = fic::ipc::Client().request({{"command", "device_get"}, {"device_id", deviceId}});
    if (!response.value("ok", false) || !response.contains("device") || !response["device"].is_object()) {
        qDebug() << "Failed to load device:" << QString::fromStdString(response.value("message", "unknown daemon error"));
        return device;
    }

    const auto& item = response["device"];
    device.id = item.value("id", -1);
    device.device_hash = item.value("device_hash", "");
    device.devpath = item.value("devpath", "");
    device.subsystem = item.value("subsystem", "");
    device.device_type = item.value("device_type", "");
    device.parent_id = item.value("parent_id", 0);
    device.control_level = item.value("control_level", "");
    device.ignore_hierarchy = item.value("ignore_hierarchy", false);
    device.boot_id = item.value("boot_id", "");
    device.created_at = item.value("created_at", "");
    device.last_event_at = item.value("last_event_at", "");
    device.notes = item.value("notes", "");
    return device;
}

std::vector<DeviceInfo> DeviceTree::fetchChildDevices(int parentId) const
{
    std::vector<DeviceInfo> children;
    auto response = fic::ipc::Client().request({{"command", "device_children"}, {"parent_id", parentId}});
    if (!response.value("ok", false) || !response.contains("children") || !response["children"].is_array()) {
        qDebug() << "Failed to load device children:" << QString::fromStdString(response.value("message", "unknown daemon error"));
        return children;
    }

    for (const auto& childJson : response["children"]) {
        if (!childJson.is_object()) {
            continue;
        }
        DeviceInfo child{};
        child.id = childJson.value("id", -1);
        child.device_hash = childJson.value("device_hash", "");
        child.devpath = childJson.value("devpath", "");
        child.subsystem = childJson.value("subsystem", "");
        child.device_type = childJson.value("device_type", "");
        child.parent_id = childJson.value("parent_id", 0);
        child.control_level = childJson.value("control_level", "");
        child.ignore_hierarchy = childJson.value("ignore_hierarchy", false);
        child.boot_id = childJson.value("boot_id", "");
        child.created_at = childJson.value("created_at", "");
        child.last_event_at = childJson.value("last_event_at", "");
        child.notes = childJson.value("notes", "");
        if (child.id != -1) {
            children.push_back(child);
        }
    }

    return children;
}

std::map<std::string, std::string> DeviceTree::fetchDeviceAttributes(int deviceId) const
{
    std::map<std::string, std::string> attributes;
    auto response = fic::ipc::Client().request({{"command", "device_attributes"}, {"device_id", deviceId}});
    if (!response.value("ok", false) || !response.contains("attributes") || !response["attributes"].is_object()) {
        qDebug() << "Failed to load device attributes:" << QString::fromStdString(response.value("message", "unknown daemon error"));
        return attributes;
    }

    for (auto it = response["attributes"].begin(); it != response["attributes"].end(); ++it) {
        if (it.value().is_string()) {
            attributes[it.key()] = it.value().get<std::string>();
        }
    }
    return attributes;
}

std::string DeviceTree::getDeviceAttribute(int deviceId, const std::string& attributeName, const std::string& defaultValue) const
{
    const auto attributes = fetchDeviceAttributes(deviceId);
    auto it = attributes.find(attributeName);
    if (it == attributes.end()) {
        return defaultValue;
    }
    return it->second;
}

bool DeviceTree::updateDeviceControlLevelRemote(int deviceId, const std::string& controlLevel) const
{
    auto response = fic::ipc::Client().request({
        {"command", "device_update_control_level"},
        {"device_id", deviceId},
        {"control_level", controlLevel}
    });
    if (!response.value("ok", false)) {
        qDebug() << "Failed to update device control level:" << QString::fromStdString(response.value("message", "unknown daemon error"));
        return false;
    }
    return true;
}

bool DeviceTree::deleteDeviceRemote(int deviceId) const
{
    auto response = fic::ipc::Client().request({{"command", "device_delete"}, {"device_id", deviceId}});
    if (!response.value("ok", false)) {
        qDebug() << "Failed to delete device:" << QString::fromStdString(response.value("message", "unknown daemon error"));
        return false;
    }
    return true;
}

void DeviceTree::setupRefreshTimer()
{
    refreshTimer = new QTimer(this);
    refreshTimer->setInterval(5000);

    connect(refreshTimer, &QTimer::timeout,
            this, &DeviceTree::refreshPreservingState);
    refreshTimer->start();
}

void DeviceTree::scheduleDeviceTreeRefresh()
{
    refreshPreservingState();
}

void DeviceTree::onItemClicked(QTreeWidgetItem *item, int column)
{
    Q_UNUSED(column);

    // Получаем ID устройства из данных элемента
    if (item == nullptr)
    {
        return;
    }

    int deviceId = item->data(0, Qt::UserRole).toInt();

    // Получаем информацию об устройстве из базы данных
    DeviceInfo device = fetchDeviceById(deviceId);

    if (device.id != -1)
    {
        // Отправляем сигнал с данными устройства
        emit deviceClicked(device);
    }
}

void DeviceTree::showControlLevelContextMenu(const QPoint &position)
{
    QTreeWidgetItem *item = treeWidget->itemAt(position);
    if (item == nullptr || !item->data(0, Qt::UserRole).isValid())
    {
        return;
    }

    treeWidget->setCurrentItem(item);

    int deviceId = item->data(0, Qt::UserRole).toInt();
    const std::string currentBootId = getSystemBootId();
    bool canDelete = false;
    DeviceInfo device = fetchDeviceById(deviceId);
    if (device.id != -1)
    {
        canDelete = canDeleteDeviceSubtree(deviceId, currentBootId);
    }

    if (device.id == -1)
    {
        return;
    }

    QMenu menu(this);
    QMenu *controlMenu = menu.addMenu("Уровень контроля");

    auto addControlAction = [&](const QString &title, const std::string &controlLevel)
    {
        QAction *action = controlMenu->addAction(title);
        action->setCheckable(true);
        action->setChecked(device.control_level == controlLevel);
        connect(action, &QAction::triggered, this, [this, deviceId, controlLevel]() {
            setDeviceControlLevel(deviceId, controlLevel);
        });
    };

    addControlAction("Запрещено", "blocked");
    addControlAction("Разрешено", "allowed");
    addControlAction("Постоянно", "permanent");
    addControlAction("Не контролируется", "ignored");

    menu.addSeparator();
    QAction *deleteAction = menu.addAction("Удалить");
    deleteAction->setEnabled(canDelete);
    const QString deviceName = item->text(0);
    connect(deleteAction, &QAction::triggered, this, [this, deviceId, deviceName]() {
        deleteDeviceFromDatabase(deviceId, deviceName);
    });

    menu.exec(treeWidget->viewport()->mapToGlobal(position));
}

void DeviceTree::setDeviceControlLevel(int deviceId, const std::string &controlLevel)
{
    if (deviceId <= 0)
    {
        return;
    }
    DeviceInfo device = fetchDeviceById(deviceId);
    if (device.id == -1)
    {
        return;
    }

    bool updated = updateDeviceControlLevelRemote(deviceId, controlLevel);
    if (updated)
    {
        device.control_level = controlLevel;
    }

    if (!updated)
    {
        qDebug() << "Failed to update control_level for device" << deviceId;
        return;
    }

    QTreeWidgetItem *updatedItem = nullptr;
    for (int i = 0; i < treeWidget->topLevelItemCount(); ++i)
    {
        updatedItem = findItemByDeviceId(treeWidget->topLevelItem(i), deviceId);
        if (updatedItem != nullptr)
        {
            break;
        }
    }

    if (updatedItem != nullptr)
    {
        setupTreeItemStyle(updatedItem, device);
    }
    else
    {
        refreshPreservingState();
    }

    emit deviceClicked(device);
}

bool DeviceTree::canDeleteDevice(const DeviceInfo& device)
{
    if (device.id <= 0 || device.id == 1 || device.parent_id <= 0)
    {
        return false;
    }

    if (device.boot_id == "-1")
    {
        return false;
    }

    const std::string currentBootId = getSystemBootId();
    if (currentBootId.empty())
    {
        return false;
    }

    return device.boot_id != currentBootId;
}

bool DeviceTree::canDeleteDeviceSubtree(int deviceId, const std::string &currentBootId)
{
    if (currentBootId.empty())
    {
        return false;
    }

    DeviceInfo device = fetchDeviceById(deviceId);
    if (device.id <= 0 || device.id == 1 || device.parent_id <= 0 ||
        device.boot_id == "-1" || device.boot_id == currentBootId)
    {
        return false;
    }

    const std::vector<DeviceInfo> children = fetchChildDevices(deviceId);
    for (const DeviceInfo &child : children)
    {
        if (!canDeleteDeviceSubtree(child.id, currentBootId))
        {
            return false;
        }
    }

    return true;
}

void DeviceTree::deleteDeviceFromDatabase(int deviceId, const QString &deviceName)
{
    DeviceInfo device = fetchDeviceById(deviceId);

    if (device.id == -1)
    {
        refreshPreservingState();
        return;
    }

    if (!canDeleteDevice(device))
    {
        QMessageBox::warning(this,
                             "Удаление устройства",
                             "Это устройство нельзя удалить: оно является корневым или относится к текущей загрузке.");
        return;
    }

    const QMessageBox::StandardButton answer =
        QMessageBox::question(this,
                              "Удаление устройства",
                              "Удалить устройство \"" + deviceName + "\" и всех его потомков из БД?",
                              QMessageBox::Yes | QMessageBox::No,
                              QMessageBox::No);

    if (answer != QMessageBox::Yes)
    {
        return;
    }

    const std::string currentBootId = getSystemBootId();
    device = fetchDeviceById(deviceId);
    bool deleted = false;
    if (device.id != -1 && canDeleteDeviceSubtree(deviceId, currentBootId))
    {
        deleted = deleteDeviceRemote(deviceId);
    }

    if (!deleted)
    {
        QMessageBox::warning(this,
                             "Удаление устройства",
                             "Не удалось удалить устройство. Возможно, оно уже изменилось или снова относится к текущей загрузке.");
        refreshPreservingState();
        return;
    }

    refreshPreservingState();
}
// Функция для получения времени старта ОС
std::string DeviceTree::getSystemBootId()
{
    const auto response = fic::ipc::Client().request({{"command", "boot_id"}});
    if (!response.value("ok", false)) {
        qDebug() << "Failed to load boot_id:" << QString::fromStdString(response.value("message", "unknown daemon error"));
        return "";
    }
    return response.value("boot_id", "");
}

// Проверка, совпадает ли время старта устройства с временем старта ОС
bool DeviceTree::isDeviceBootIdValid(const DeviceInfo &device)
{
    static std::string systemBootId;
    if (systemBootId.empty()) {
        systemBootId = getSystemBootId();
    }

    // Сравниваем boot_id с временем старта системы
    // Или на равенство -1 (для предустановленных устройств)
    return device.boot_id == systemBootId || device.boot_id == "-1";
}

std::string DeviceTree::generateNodeName(const DeviceInfo &device)
{
    std::string device_name = "[" + device.subsystem + "] " + device.devpath;
    if (device.subsystem == "__computer__")
    {
        char hostname[256];
        if (gethostname(hostname, sizeof(hostname)) == 0)
        {
            device_name = "Компьютер [" + std::string(hostname) + "]";
        }
        else
        {
            device_name = "Компьютер";
        }
        return device_name;
    }
    if (device.subsystem == "__cpu__")
    {
        device_name = "Процессоры";
        return device_name;
    }
    if (device.subsystem == "__board__")
    {
        device_name = "Материнские платы";
        return device_name;
    }
    if (device.subsystem == "__memory__")
    {
        device_name = "Оперативная память";
        return device_name;
    }
    if (device.subsystem == "__virtual__")
    {
        device_name = "[Виртуальное устройство] " + device.devpath;
        return device_name;
    }
    if (device.subsystem == "cpu")
    {
        std::string model_name = getDeviceAttribute(device.id, "Model name", "Unknown Model");
        device_name = "Процессор [" + model_name + "]";
        return device_name;
    }
    if (device.subsystem == "board")
    {
        std::string manufacturer = getDeviceAttribute(device.id, "Manufacturer", "Unknown Manufacturer");
        std::string product_name = getDeviceAttribute(device.id, "Product Name", "Unknown Product Name");
        device_name = "Материнская плата [" + manufacturer + "]" + " [" + product_name + "]";
        return device_name;
    }
    if (device.subsystem == "memory")
    {
        std::string manufacturer = getDeviceAttribute(device.id, "Manufacturer", "Unknown Manufacturer");
        std::string size = getDeviceAttribute(device.id, "Size", "Unknown Size");
        std::string locator = getDeviceAttribute(device.id, "Locator", "Unknown Locator");
        std::string serial_number = getDeviceAttribute(device.id, "Serial Number", "Unknown Serial");
        device_name = "ОЗУ [" + manufacturer + "] " + "[" + serial_number + "]" + " [" + size + "] " + "[" + locator + "]";
        return device_name;
    }
    if (device.subsystem == "__udev__")
    {
        device_name = "Устройства ядра";
        return device_name;
    }
    if (device.subsystem == "__pci__")
    {
        device_name = "PCI-мост";
        return device_name;
    }
    /*pci*/
    if (device.subsystem == "pci")
    {
        std::string pci_class = getDeviceAttribute(device.id, "PCI_CLASS", "");
        std::string pci_id = getDeviceAttribute(device.id, "PCI_ID", "");
        std::string pci_class_prepared = normalizePciClassKey(pci_class);
        std::string pci_device_info = localizeDeviceClass("pci", pci_class_prepared);
        device_name = pci_device_info.empty() ? "[PCI] class " + pci_class_prepared : pci_device_info;
        if (!pci_id.empty())
        {
            device_name += " [" + pci_id + "]";
        }
        return device_name;
    }
    if (device.subsystem == "usb")
    {
        std::string type = getDeviceAttribute(device.id, "TYPE", "");
        std::string usb_class_prepared = normalizeUsbTypeKey(type);
        std::string usb_class_info = localizeDeviceClass("usb", usb_class_prepared);
        if (!usb_class_info.empty())
        {
            return usb_class_info;
        }
        return usb_class_prepared.empty() ? "[USB]" : "[USB] class " + usb_class_prepared;
    }
    if (device.subsystem == "block")
    {
        std::string major_digit = getDeviceAttribute(device.id, "MAJOR", "");
        std::string minor_digit = getDeviceAttribute(device.id, "MINOR", "");

        if (major_digit.empty() || minor_digit.empty())
        {
            device_name = "[block] [MAJOR/MINOR отсутствуют]";
            return device_name;
        }

        int major_num = 0;
        int minor_num = 0;

        try
        {
            major_num = std::stoi(major_digit);
            minor_num = std::stoi(minor_digit);
        }
        catch (const std::exception &)
        {
            device_name = "[block] [Некорректные MAJOR/MINOR: " + major_digit + ":" + minor_digit + "]";
            return device_name;
        }

        std::string major;
        std::string minor;

        auto alphaSuffix = [](int index)
        {
            // 0 -> a
            // 1 -> b
            // ...
            // 25 -> z
            // 26 -> aa
            // 27 -> ab
            std::string result;
            index++;

            while (index > 0)
            {
                index--;
                result.insert(result.begin(), char('a' + (index % 26)));
                index /= 26;
            }

            return result;
        };

        auto makeSdName = [&](int disk_index, int partition_num)
        {
            std::string name = "sd" + alphaSuffix(disk_index);

            if (partition_num == 0)
            {
                return std::string("Диск /dev/") + name;
            }

            return std::string("Раздел /dev/") + name + std::to_string(partition_num);
        };

        auto makeHdName = [&](int disk_index, int partition_num)
        {
            std::string name = "hd" + alphaSuffix(disk_index);

            if (partition_num == 0)
            {
                return std::string("Диск /dev/") + name;
            }

            return std::string("Раздел /dev/") + name + std::to_string(partition_num);
        };

        auto makeMmcName = [&](int minor_num)
        {
            // Для MMC обычно:
            // minor = device * 8 + partition
            // 0 -> mmcblk0
            // 1 -> mmcblk0p1
            // 8 -> mmcblk1
            int disk_num = minor_num / 8;
            int partition_num = minor_num % 8;

            std::string name = "mmcblk" + std::to_string(disk_num);

            if (partition_num == 0)
            {
                return std::string("Диск /dev/") + name;
            }

            return std::string("Раздел /dev/") + name + "p" + std::to_string(partition_num);
        };

        auto makeIdeName = [&](int first_disk_index)
        {
            // Для IDE major обычно содержит два диска.
            // minor 0..63   -> первый диск
            // minor 64..127 -> второй диск
            int disk_offset = minor_num / 64;
            int partition_num = minor_num % 64;
            int disk_index = first_disk_index + disk_offset;

            return makeHdName(disk_index, partition_num);
        };

        auto isScsiDiskMajor = [](int major_num)
        {
            return major_num == 8 ||
                   (major_num >= 65 && major_num <= 71) ||
                   (major_num >= 128 && major_num <= 135);
        };

        auto scsiDiskBaseIndex = [](int major_num)
        {
            if (major_num == 8)
            {
                return 0;
            }

            if (major_num >= 65 && major_num <= 71)
            {
                return 16 + (major_num - 65) * 16;
            }

            if (major_num >= 128 && major_num <= 135)
            {
                return 128 + (major_num - 128) * 16;
            }

            return 0;
        };

        if (isScsiDiskMajor(major_num))
        {
            major = "SCSI/SATA/SAS/USB disk";

            // Для sd-дисков:
            // minor = disk * 16 + partition
            int disk_index = scsiDiskBaseIndex(major_num) + minor_num / 16;
            int partition_num = minor_num % 16;

            minor = makeSdName(disk_index, partition_num);
        }
        else if (major_num == 1)
        {
            major = "RAM disk";
            minor = "/dev/ram" + std::to_string(minor_num);
        }
        else if (major_num == 2)
        {
            major = "Floppy disk";
            minor = "/dev/fd" + std::to_string(minor_num);
        }
        else if (major_num == 3)
        {
            major = "IDE disk";
            minor = makeIdeName(0); // hda, hdb
        }
        else if (major_num == 7)
        {
            major = "Loop device";
            minor = "/dev/loop" + std::to_string(minor_num);
        }
        else if (major_num == 9)
        {
            major = "MD RAID device";
            minor = "/dev/md" + std::to_string(minor_num);
        }
        else if (major_num == 11)
        {
            major = "SCSI CD/DVD-ROM";
            minor = "/dev/sr" + std::to_string(minor_num);
        }
        else if (major_num == 22)
        {
            major = "IDE disk";
            minor = makeIdeName(2); // hdc, hdd
        }
        else if (major_num == 33)
        {
            major = "IDE disk";
            minor = makeIdeName(4); // hde, hdf
        }
        else if (major_num == 34)
        {
            major = "IDE disk";
            minor = makeIdeName(6); // hdg, hdh
        }
        else if (major_num == 43)
        {
            major = "Network block device";
            minor = "/dev/nbd" + std::to_string(minor_num);
        }
        else if (major_num == 56)
        {
            major = "IDE disk";
            minor = makeIdeName(8); // hdi, hdj
        }
        else if (major_num == 57)
        {
            major = "IDE disk";
            minor = makeIdeName(10); // hdk, hdl
        }
        else if (major_num == 88)
        {
            major = "IDE disk";
            minor = makeIdeName(12); // hdm, hdn
        }
        else if (major_num == 89)
        {
            major = "IDE disk";
            minor = makeIdeName(14); // hdo, hdp
        }
        else if (major_num == 90)
        {
            major = "IDE disk";
            minor = makeIdeName(16); // hdq, hdr
        }
        else if (major_num == 91)
        {
            major = "IDE disk";
            minor = makeIdeName(18); // hds, hdt
        }
        else if (major_num == 179)
        {
            major = "MMC/SD card";
            minor = makeMmcName(minor_num);
        }
        else if (major_num == 202)
        {
            major = "Xen virtual block device";
            minor = "Xen block minor " + std::to_string(minor_num);
        }
        else if (major_num == 253)
        {
            major = "Device Mapper";
            minor = "/dev/dm-" + std::to_string(minor_num);
        }
        else if (major_num == 259)
        {
            major = "Extended block device";
            minor = "Невозможно надежно определить имя только по MAJOR/MINOR: " + major_digit + ":" + minor_digit;
        }
        else
        {
            major = "Неизвестный block major (" + major_digit + ")";
            minor = "minor " + minor_digit;
        }

        device_name = "[" + major + "] [" + minor + "]";
        return device_name;
    }
    // Заглушка: используем только devpath
    // В будущем можно добавить дополнительную информацию
    return device_name;
}

void DeviceTree::setupControlLevelColumn(QTreeWidgetItem *item, const DeviceInfo &device)
{
    if (item == nullptr)
    {
        return;
    }

    QString text;
    QString tooltip;
    QColor color;
    QStyle::StandardPixmap icon = QStyle::SP_MessageBoxInformation;
    bool emphasize = false;

    if (device.control_level == "blocked")
    {
        text = "Запрещено";
        tooltip = "Устройство запрещено политикой";
        color = QColor(180, 44, 44);
        icon = QStyle::SP_DialogCancelButton;
        emphasize = true;
    }
    else if (device.control_level == "allowed")
    {
        text = "Разрешено";
        tooltip = "Устройство разрешено политикой";
        color = QColor(38, 128, 72);
        icon = QStyle::SP_DialogApplyButton;
    }
    else if (device.control_level == "permanent")
    {
        text = "Постоянно";
        tooltip = "Устройство разрешено и должно быть подключено постоянно";
        color = QColor(36, 94, 166);
        icon = QStyle::SP_DialogSaveButton;
        emphasize = true;
    }
    else if (device.control_level == "ignored")
    {
        text = "Не контрол.";
        tooltip = "Устройство не контролируется";
        color = QColor(120, 120, 120);
        icon = QStyle::SP_DialogDiscardButton;
    }
    else
    {
        text = QString::fromStdString(device.control_level.empty() ? "unknown" : device.control_level);
        tooltip = "Неизвестный уровень контроля";
        color = QColor(120, 120, 120);
    }

    item->setText(1, text);
    item->setIcon(1, style()->standardIcon(icon));
    item->setForeground(1, QBrush(color));
    item->setTextAlignment(1, Qt::AlignCenter);
    item->setToolTip(1, tooltip + "\ncontrol_level: " + QString::fromStdString(device.control_level));

    QFont font = item->font(1);
    font.setBold(emphasize);
    item->setFont(1, font);
}

// Функция для установки стиля элемента дерева
void DeviceTree::setupTreeItemStyle(QTreeWidgetItem *item, const DeviceInfo &device)
{
    setupControlLevelColumn(item, device);

    // Проверяем, совпадает ли время старта устройства с временем старта ОС
    bool isValid = isDeviceBootIdValid(device);

    if (!isValid)
    {
        // Устанавливаем стиль с зачеркиванием текста
        item->setForeground(0, QBrush(QColor(128, 128, 128))); // Серый цвет

        // Создаем QFont с зачеркиванием
        QFont font = item->font(0);
        font.setStrikeOut(true);
        item->setFont(0, font);

        // Добавляем всплывающую подсказку
        std::string tooltip = "Устройство зарегистрировано при предыдущем запуске ОС\n";
        tooltip += "boot_id устройства: " + device.boot_id + "\n";
        tooltip += "Текущий boot_id ОС: " + getSystemBootId();
        item->setToolTip(0, QString::fromStdString(tooltip));
    }
    else
    {
        // Сбрасываем стиль для валидных устройств
        item->setForeground(0, QBrush()); // Сбрасываем цвет
        QFont font = item->font(0);
        font.setStrikeOut(false);
        item->setFont(0, font);
        item->setToolTip(0, QString()); // Очищаем подсказку
    }
}

void DeviceTree::collectExpandedDeviceIds(QTreeWidgetItem *item, QSet<int> &expandedIds) const
{
    if (item == nullptr)
    {
        return;
    }

    if (item->data(0, Qt::UserRole).isValid() && item->isExpanded())
    {
        expandedIds.insert(item->data(0, Qt::UserRole).toInt());
    }

    for (int i = 0; i < item->childCount(); ++i)
    {
        collectExpandedDeviceIds(item->child(i), expandedIds);
    }
}

bool DeviceTree::restoreExpandedDeviceIds(QTreeWidgetItem *item, const QSet<int> &expandedIds, int selectedId)
{
    if (item == nullptr || !item->data(0, Qt::UserRole).isValid())
    {
        return false;
    }

    const int deviceId = item->data(0, Qt::UserRole).toInt();
    const bool mustExpand = expandedIds.contains(deviceId);
    bool containsSelection = deviceId == selectedId;

    if (mustExpand)
    {
        ensureChildrenLoaded(item);

        for (int i = 0; i < item->childCount(); ++i)
        {
            containsSelection |= restoreExpandedDeviceIds(item->child(i), expandedIds, selectedId);
        }

        item->setExpanded(true);
    }

    return containsSelection;
}

QTreeWidgetItem* DeviceTree::findItemByDeviceId(QTreeWidgetItem *item, int deviceId) const
{
    if (item == nullptr || deviceId <= 0)
    {
        return nullptr;
    }

    if (item->data(0, Qt::UserRole).isValid() &&
        item->data(0, Qt::UserRole).toInt() == deviceId)
    {
        return item;
    }

    for (int i = 0; i < item->childCount(); ++i)
    {
        QTreeWidgetItem *found = findItemByDeviceId(item->child(i), deviceId);
        if (found != nullptr)
        {
            return found;
        }
    }

    return nullptr;
}

void DeviceTree::refreshPreservingState()
{
    QSet<int> expandedIds;
    for (int i = 0; i < treeWidget->topLevelItemCount(); ++i)
    {
        collectExpandedDeviceIds(treeWidget->topLevelItem(i), expandedIds);
    }

    int selectedId = -1;
    if (treeWidget->currentItem() != nullptr &&
        treeWidget->currentItem()->data(0, Qt::UserRole).isValid())
    {
        selectedId = treeWidget->currentItem()->data(0, Qt::UserRole).toInt();
    }

    const int scrollValue = treeWidget->verticalScrollBar()->value();

    QTreeWidgetItem *selectedItem = nullptr;
    {
        QSignalBlocker blocker(treeWidget);
        Q_UNUSED(blocker);

        loadDeviceTree();

        for (int i = 0; i < treeWidget->topLevelItemCount(); ++i)
        {
            restoreExpandedDeviceIds(treeWidget->topLevelItem(i), expandedIds, selectedId);
        }

        for (int i = 0; i < treeWidget->topLevelItemCount(); ++i)
        {
            selectedItem = findItemByDeviceId(treeWidget->topLevelItem(i), selectedId);
            if (selectedItem != nullptr)
            {
                treeWidget->setCurrentItem(selectedItem);
                break;
            }
        }

        treeWidget->verticalScrollBar()->setValue(scrollValue);
    }

    if (selectedItem != nullptr)
    {
        onItemClicked(selectedItem, 0);
    }
}

void DeviceTree::loadDeviceTree()
{
    treeWidget->clear();
    // Загружаем корневое устройство (id = 1)
    DeviceInfo rootDevice = fetchDeviceById(1);

    if (rootDevice.id == -1)
    {
        qDebug() << "Root device not found!";
        return;
    }

    // Создаем корневой элемент
    QTreeWidgetItem *rootItem = new QTreeWidgetItem(treeWidget);
    rootItem->setText(0, QString::fromStdString(generateNodeName(rootDevice)));
    rootItem->setData(0, Qt::UserRole, rootDevice.id);

    // Устанавливаем стиль для корневого элемента
    setupTreeItemStyle(rootItem, rootDevice);

    // Добавляем пустой дочерний элемент для отображения "+"
    QTreeWidgetItem *dummyItem = new QTreeWidgetItem(rootItem);
    dummyItem->setText(0, "Загрузка...");
    treeWidget->addTopLevelItem(rootItem);
}

void DeviceTree::onItemExpanded(QTreeWidgetItem *item)
{
    // Удаляем заглушку "Загрузка..." если она есть
    if (item->childCount() == 1 && item->child(0)->text(0) == "Загрузка...")
    {
        delete item->child(0);

        int deviceId = item->data(0, Qt::UserRole).toInt();
        loadChildDevices(item, deviceId);
    }
}

void DeviceTree::loadChildDevices(QTreeWidgetItem *parentItem, int parentId)
{
    std::vector<DeviceInfo> allChildren = fetchChildDevices(parentId);

    for (const auto &child : allChildren)
    {
        QTreeWidgetItem *childItem = new QTreeWidgetItem(parentItem);
        childItem->setText(0, QString::fromStdString(generateNodeName(child)));
        childItem->setData(0, Qt::UserRole, child.id);

        // Устанавливаем стиль в зависимости от времени старта устройства
        setupTreeItemStyle(childItem, child);

        // Добавляем заглушку для ленивой загрузки
        QTreeWidgetItem *dummy = new QTreeWidgetItem(childItem);
        dummy->setText(0, "Загрузка...");
    }
}

void DeviceTree::ensureChildrenLoaded(QTreeWidgetItem *item)
{
    if (item == nullptr)
    {
        return;
    }

    if (item->childCount() != 1 || item->child(0)->data(0, Qt::UserRole).isValid())
    {
        return;
    }

    delete item->child(0);

    int deviceId = item->data(0, Qt::UserRole).toInt();
    loadChildDevices(item, deviceId);
}

void DeviceTree::expandNodeRecursively(QTreeWidgetItem *item)
{
    if (item == nullptr)
    {
        return;
    }

    ensureChildrenLoaded(item);

    for (int i = 0; i < item->childCount(); ++i)
    {
        expandNodeRecursively(item->child(i));
    }

    item->setExpanded(true);
}

void DeviceTree::expandAllNodes()
{
    treeWidget->setUpdatesEnabled(false);

    for (int i = 0; i < treeWidget->topLevelItemCount(); ++i)
    {
        expandNodeRecursively(treeWidget->topLevelItem(i));
    }

    treeWidget->setUpdatesEnabled(true);
}

void DeviceTree::collapseAllNodes()
{
    treeWidget->collapseAll();
}
