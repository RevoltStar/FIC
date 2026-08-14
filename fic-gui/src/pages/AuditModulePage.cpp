#include "pages/AuditModulePage.h"

#include <QTabWidget>
#include <QVBoxLayout>

#include "LogViewer.h"
#include "widgets/PolicyEditorWidget.h"
#include "wrappers/QLocalizationManager.h"

AuditModulePage::AuditModulePage(
    const std::string& module,
    const std::vector<PolicyDescriptor>& policies,
    QWidget* parent)
    : QWidget(parent)
{
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    auto* tabs = new QTabWidget(this);
    tabs->addTab(new LogViewer(tabs),
                 QLocalizationManager::getLang("[module:AUDIT][page:logs]"));
    tabs->addTab(new PolicyEditorWidget(module, policies, tabs),
                 QLocalizationManager::getLang("[module:AUDIT][page:settings]"));
    layout->addWidget(tabs);
}
