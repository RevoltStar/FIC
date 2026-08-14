#ifndef POLICY_EDITOR_WIDGET_H
#define POLICY_EDITOR_WIDGET_H

#include <string>
#include <vector>

#include <QWidget>

#include "models/PolicyDescriptor.h"

class PolicyEditorWidget : public QWidget
{
public:
    PolicyEditorWidget(const std::string& moduleName,
                       const std::vector<PolicyDescriptor>& policies,
                       QWidget* parent = nullptr);

private:
    enum class EditorType { Label, SpinBox, TextEdit, ComboBox, Unknown };

    static EditorType editorType(const std::string& editor);
    static bool validateValue(const PolicyDescriptor& policy,
                              const std::string& value,
                              QString& error);
};

#endif // POLICY_EDITOR_WIDGET_H
