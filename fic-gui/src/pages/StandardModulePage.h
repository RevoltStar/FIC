#ifndef STANDARD_MODULE_PAGE_H
#define STANDARD_MODULE_PAGE_H

#include <string>
#include <vector>

#include <QWidget>

#include "models/PolicyDescriptor.h"

class StandardModulePage : public QWidget
{
public:
    StandardModulePage(const std::string& module,
                       const std::vector<PolicyDescriptor>& policies,
                       QWidget* parent = nullptr);
};

#endif // STANDARD_MODULE_PAGE_H
