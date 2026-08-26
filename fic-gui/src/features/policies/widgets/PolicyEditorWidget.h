#ifndef POLICY_EDITOR_WIDGET_H
#define POLICY_EDITOR_WIDGET_H

#include <string>
#include <vector>

#include <QWidget>

#include "features/policies/models/PolicyDescriptor.h"

class PolicyEditorWidget : public QWidget
{
public:
    PolicyEditorWidget(const std::string& moduleName,
                       const std::vector<PolicyDescriptor>& policies,
                       QWidget* parent = nullptr);

private:
    enum class EditorType {
        Label,
        SpinBox,
        LineEdit,
        TextEdit,
        ComboBox,
        Unknown
    };

    static EditorType editorType(const std::string& editor);
};

#endif // POLICY_EDITOR_WIDGET_H
