#include "policy/PolicyEditorFactory.h"

#include <stdexcept>

PolicyEditorSpec buildEditorSpec(const PolicyTypeValue& value) {
    if (dynamic_cast<const EnableDisablePolicyTypeValue*>(&value) != nullptr) {
        return {PolicyEditorType::CheckBox};
    }
    if (dynamic_cast<const IntPolicyTypeValue*>(&value) != nullptr) {
        return {PolicyEditorType::SpinBox};
    }
    if (dynamic_cast<const PossibleListPolicyTypeValue*>(&value) != nullptr) {
        return {PolicyEditorType::ComboBox};
    }
    if (dynamic_cast<const MultiLineTextPolicyTypeValue*>(&value) != nullptr) {
        return {PolicyEditorType::TextEdit};
    }

    throw std::runtime_error("Unsupported PolicyTypeValue in GUI");
}
