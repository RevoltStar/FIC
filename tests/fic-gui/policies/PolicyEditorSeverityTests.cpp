#include "features/policies/widgets/PolicyEditorWidget.h"
#include "features/policies/models/PolicyDescriptor.h"

#include <QApplication>
#include <QComboBox>
#include <iostream>

int main(int argc, char** argv) {
    QApplication app(argc, argv);

    PolicyDescriptor policy;
    policy.moduleName = "DAC";
    policy.submoduleName = "Sudo";
    policy.policyName = "sudo_timeout";
    policy.editor = "label";
    policy.validator = "none";
    policy.enabled = true;
    policy.isSet = true;
    policy.valueValid = true;
    policy.value = "10";
    policy.defaultValue = "5";
    policy.restriction = "integer from 0 to 60";
    policy.possibleValues = {};
    policy.violationSeverity = "HARD";
    policy.defaultViolationSeverity = "STANDARD";
    policy.violationSeverityValues = {
        "NONE", "SOFT", "STANDARD", "HARD", "ISOLATE"};

    PolicyEditorWidget widget(policy.moduleName, {policy});

    // Find the violation severity combo box.
    auto* combo = widget.findChild<QComboBox*>();
    if (!combo) {
        std::cerr << "no combo box found" << std::endl;
        return 1;
    }

    // Verify combo box is populated with all severity values.
    if (combo->count() != 5) {
        std::cerr << "expected 5 severity values, got " << combo->count()
                  << std::endl;
        return 1;
    }

    // Verify the effective severity is selected.
    if (combo->currentText() != "HARD") {
        std::cerr << "expected current severity HARD, got "
                  << combo->currentText().toStdString() << std::endl;
        return 1;
    }

    // Verify the items are in the correct order.
    const std::vector<std::string> expected{
        "NONE", "SOFT", "STANDARD", "HARD", "ISOLATE"};
    for (std::size_t i = 0; i < expected.size(); ++i) {
        if (combo->itemText(static_cast<int>(i)).toStdString() != expected[i]) {
            std::cerr << "expected item " << i << " to be " << expected[i]
                      << ", got "
                      << combo->itemText(static_cast<int>(i)).toStdString()
                      << std::endl;
            return 1;
        }
    }

    std::cout << "PolicyEditorWidget severity combo box test passed" << std::endl;
    return 0;
}