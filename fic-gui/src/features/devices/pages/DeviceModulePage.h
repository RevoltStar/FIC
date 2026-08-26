#ifndef DEVICE_MODULE_PAGE_H
#define DEVICE_MODULE_PAGE_H

#include <string>
#include <vector>

#include <QWidget>

#include "features/devices/widgets/DeviceTree.h"
#include "features/policies/models/PolicyDescriptor.h"

class QCheckBox;
class QComboBox;
class QLabel;
class QPushButton;
class DeviceAttributeList;
class DeviceEventList;

class DeviceModulePage : public QWidget
{
public:
    DeviceModulePage(const std::string& module,
                     const std::vector<PolicyDescriptor>& policies,
                     QWidget* parent = nullptr);

private:
    void onDeviceClicked(const DeviceInfo& device);
    QWidget* createTreePage();
    QString deviceSummary(const DeviceInfo& device) const;

    DeviceTree* deviceTree_ = nullptr;
    DeviceAttributeList* attributes_ = nullptr;
    DeviceEventList* events_ = nullptr;
    QComboBox* control_ = nullptr;
    QCheckBox* globalRule_ = nullptr;
    QComboBox* childrenControl_ = nullptr;
    QPushButton* reset_ = nullptr;
    QPushButton* copyPath_ = nullptr;
    QPushButton* copySummary_ = nullptr;
    QLabel* subsystem_ = nullptr;
    QLabel* controlLevel_ = nullptr;
    QLabel* devpath_ = nullptr;
    QLabel* currentBootId_ = nullptr;
    QLabel* deviceBootId_ = nullptr;
    QLabel* status_ = nullptr;
    DeviceInfo currentDevice_;
};

#endif // DEVICE_MODULE_PAGE_H
