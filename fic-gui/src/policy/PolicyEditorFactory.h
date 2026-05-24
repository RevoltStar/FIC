#ifndef POLICYEDITORFACTORY_H
#define POLICYEDITORFACTORY_H

#include "utils/PolicyTypeValue.h"

enum class PolicyEditorType { CheckBox, SpinBox, TextEdit, ComboBox };

struct PolicyEditorSpec {
    PolicyEditorType type;
};

PolicyEditorSpec buildEditorSpec(const PolicyTypeValue& value);

#endif // POLICYEDITORFACTORY_H
