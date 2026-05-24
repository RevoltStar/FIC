#include "DeviceAttributeList.h"
#include <QVBoxLayout>
#include <QLabel>
#include <QHeaderView>
#include <QDebug>
#include "ipc/FicIpcClient.h"

DeviceAttributeList::DeviceAttributeList(QWidget *parent)
    : QWidget(parent)
{
    setupUI();
}

DeviceAttributeList::~DeviceAttributeList()
{

}

void DeviceAttributeList::setupUI()
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(0, 0, 0, 0);

    // Заголовок
    /*QLabel *titleLabel = new QLabel("Параметры устройства", this);
    titleLabel->setAlignment(Qt::AlignCenter);
    QFont titleFont = titleLabel->font();
    titleFont.setBold(true);
    titleLabel->setFont(titleFont);
    */
    // Дерево атрибутов
    treeWidget = new QTreeWidget(this);
    treeWidget->setHeaderLabels({"Параметр", "Значение"});
    treeWidget->setColumnCount(2);
    treeWidget->setAlternatingRowColors(true);
    treeWidget->setRootIsDecorated(false);
    treeWidget->setSortingEnabled(true);

    // Настройка размеров столбцов
    treeWidget->header()->setStretchLastSection(false);
    treeWidget->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    treeWidget->header()->setSectionResizeMode(1, QHeaderView::Stretch);

    //mainLayout->addWidget(titleLabel);
    mainLayout->addWidget(treeWidget);

    setLayout(mainLayout);
}


void DeviceAttributeList::clear()
{
    treeWidget->clear();
}

void DeviceAttributeList::showDeviceAttributes(int deviceId)
{
    clear();

    std::map<std::string, std::string> attributes;
    auto response = fic::ipc::Client().request({{"command", "device_attributes"}, {"device_id", deviceId}});
    if (!response.value("ok", false)) {
        qDebug() << "Failed to load device attributes:" << QString::fromStdString(response.value("message", "unknown daemon error"));
        populateTree(attributes);
        emit attributesUpdated(deviceId, 0);
        return;
    }

    if (response.contains("attributes") && response["attributes"].is_object()) {
        for (auto it = response["attributes"].begin(); it != response["attributes"].end(); ++it) {
            if (it.value().is_string()) {
                attributes[it.key()] = it.value().get<std::string>();
            }
        }
    }

    populateTree(attributes);

    emit attributesUpdated(deviceId, attributes.size());
}

void DeviceAttributeList::showAttributes(const std::map<std::string, std::string>& attributes)
{
    clear();
    populateTree(attributes);
    emit attributesUpdated(-1, attributes.size()); // -1 означает, что deviceId неизвестен
}

void DeviceAttributeList::populateTree(const std::map<std::string, std::string>& attributes)
{
    if (attributes.empty()) {
        QTreeWidgetItem *emptyItem = new QTreeWidgetItem(treeWidget);
        emptyItem->setText(0, "Атрибуты отсутствуют");
        emptyItem->setText(1, "");
        emptyItem->setFlags(emptyItem->flags() & ~Qt::ItemIsSelectable);
        return;
    }

    // Сортировка ключей для более красивого отображения
    QMap<QString, QString> sortedAttributes;
    for (const auto& [key, value] : attributes) {
        sortedAttributes[QString::fromStdString(key)] = QString::fromStdString(value);
    }

    // Добавляем атрибуты в дерево
    for (auto it = sortedAttributes.begin(); it != sortedAttributes.end(); ++it) {
        QTreeWidgetItem *item = new QTreeWidgetItem(treeWidget);
        item->setText(0, it.key());
        item->setText(1, it.value());

        // Делаем значения редактируемыми (если нужно)
        // item->setFlags(item->flags() | Qt::ItemIsEditable);
    }

    // Сортируем по имени параметра
    treeWidget->sortItems(0, Qt::AscendingOrder);
}
