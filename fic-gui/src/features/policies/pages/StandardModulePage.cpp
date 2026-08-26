#include "features/policies/pages/StandardModulePage.h"

#include <QVBoxLayout>

#include "features/policies/widgets/PolicyEditorWidget.h"

StandardModulePage::StandardModulePage(
    const std::string& module,
    const std::vector<PolicyDescriptor>& policies,
    QWidget* parent)
    : QWidget(parent)
{
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->addWidget(new PolicyEditorWidget(module, policies, this));
}
