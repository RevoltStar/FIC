#include "widgets/PolicyEditorWidget.h"

#include <algorithm>
#include <map>
#include <stdexcept>

#include <QCheckBox>
#include <QComboBox>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QPushButton>
#include <QScrollArea>
#include <QSpinBox>
#include <QTextEdit>
#include <QVBoxLayout>
#include <QWheelEvent>

#include <nlohmann/json.hpp>

#include "services/PolicyService.h"
#include "wrappers/QLocalizationManager.h"

namespace {
class NoWheelSpinBox final : public QSpinBox
{
public:
    using QSpinBox::QSpinBox;

protected:
    void wheelEvent(QWheelEvent* event) override { event->ignore(); }
};

QString applySummary(const nlohmann::json& response)
{
    if (!response.contains("summary") || !response["summary"].is_object()) {
        return QString::fromStdString(response.value("message", "unknown daemon response"));
    }
    const auto& summary = response["summary"];
    return QString("Total: %1, applied: %2, failed: %3, disabled: %4, not found: %5")
        .arg(summary.value("total", 0))
        .arg(summary.value("applied", 0))
        .arg(summary.value("failed", 0))
        .arg(summary.value("disabled", 0))
        .arg(summary.value("not_found", 0));
}

QString applyDetails(const nlohmann::json& response)
{
    QStringList lines;
    if (!response.contains("results") || !response["results"].is_array()) {
        return {};
    }
    for (const auto& item : response["results"]) {
        QString reference = QString::fromStdString(item.value("module", ""));
        const QString submodule = QString::fromStdString(item.value("submodule", ""));
        if (!submodule.isEmpty()) reference += ":" + submodule;
        reference += ":" + QString::fromStdString(item.value("policy", ""));
        lines << reference + " " + QString::fromStdString(item.value("status", "unknown")) +
            " - " + QString::fromStdString(item.value("message", ""));
        if (item.contains("diagnostics") && item["diagnostics"].is_array()) {
            for (const auto& diagnostic : item["diagnostics"]) {
                lines << QString("  [%1] [%2] %3")
                    .arg(QString::fromStdString(diagnostic.value("timestamp", "")),
                         QString::fromStdString(diagnostic.value("level", "UNKNOWN")),
                         QString::fromStdString(diagnostic.value("message", "")));
            }
        }
    }
    return lines.join("\n");
}
}

PolicyEditorWidget::PolicyEditorWidget(
    const std::string& moduleName,
    const std::vector<PolicyDescriptor>& policies,
    QWidget* parent)
    : QWidget(parent)
{
    auto* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(0, 0, 0, 0);

    auto* scrollArea = new QScrollArea(this);
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);
    auto* content = new QFrame(scrollArea);
    auto* grid = new QGridLayout(content);
    grid->setContentsMargins(10, 10, 10, 10);
    grid->setSpacing(10);

    const QStringList headers = {
        QLocalizationManager::getLang("[module:all][col:is_policy_active]"),
        QLocalizationManager::getLang("[module:all][col:policy_name]"),
        QLocalizationManager::getLang("[module:all][col:policy_value]"),
        QLocalizationManager::getLang("[module:all][col:policy_descr]")
    };
    for (int column = 0; column < headers.size(); ++column) {
        auto* label = new QLabel(headers[column], content);
        QFont font = label->font();
        font.setBold(true);
        label->setFont(font);
        label->setAlignment(Qt::AlignCenter);
        grid->addWidget(label, 0, column);
    }

    struct Row {
        PolicyDescriptor policy;
        QCheckBox* enabled = nullptr;
        QWidget* value = nullptr;
        EditorType type = EditorType::Unknown;
    };
    std::vector<Row> controls;
    std::map<std::string, std::vector<PolicyDescriptor>> bySubmodule;
    for (const PolicyDescriptor& policy : policies) {
        bySubmodule[policy.submoduleName].push_back(policy);
    }

    int rowNumber = 1;
    for (const auto& [submodule, submodulePolicies] : bySubmodule) {
        auto* header = new QLabel(
            QLocalizationManager::getLang(QString::fromStdString(
                "[module:" + moduleName + "][submodule:" + submodule + "]")), content);
        header->setAlignment(Qt::AlignCenter);
        QFont font = header->font();
        font.setBold(true);
        header->setFont(font);
        grid->addWidget(header, rowNumber++, 0, 1, 4);

        for (const PolicyDescriptor& policy : submodulePolicies) {
            auto* enabled = new QCheckBox(content);
            enabled->setChecked(policy.enabled && policy.valueValid);
            grid->addWidget(enabled, rowNumber, 0, Qt::AlignCenter);

            const std::string key = "[module:" + moduleName + "][policy:" + policy.policyName + "]";
            auto* name = new QLabel(
                QLocalizationManager::getLang(QString::fromStdString(key)), content);
            name->setWordWrap(true);
            grid->addWidget(name, rowNumber, 1);

            const EditorType type = editorType(policy.editor);
            const std::string initialValue = policy.valueValid ? policy.value : policy.defaultValue;
            QWidget* valueWidget = nullptr;
            switch (type) {
            case EditorType::Label: {
                auto* label = new QLabel(
                    QLocalizationManager::getLang("[utils:policytypevalue][type:fixedpolicytypevalue]"), content);
                label->setTextInteractionFlags(Qt::TextSelectableByMouse);
                valueWidget = label;
                break;
            }
            case EditorType::SpinBox: {
                auto* spin = new NoWheelSpinBox(content);
                spin->setRange(policy.min, policy.max);
                try { spin->setValue(std::stoi(initialValue)); }
                catch (const std::exception&) { spin->setValue(policy.min); }
                valueWidget = spin;
                break;
            }
            case EditorType::TextEdit: {
                auto* edit = new QTextEdit(content);
                QString text = QString::fromStdString(initialValue);
                const QString delimiter = QString::fromStdString(policy.textDelimiter);
                if (!delimiter.isEmpty() && delimiter != "\n") text.replace(delimiter, "\n");
                edit->setPlainText(text);
                valueWidget = edit;
                break;
            }
            case EditorType::ComboBox: {
                auto* combo = new QComboBox(content);
                for (const auto& value : policy.possibleValues) {
                    combo->addItem(QString::fromStdString(value));
                }
                const int index = combo->findText(QString::fromStdString(initialValue));
                if (index >= 0) combo->setCurrentIndex(index);
                valueWidget = combo;
                break;
            }
            case EditorType::Unknown:
                valueWidget = new QLabel(
                    "Unsupported policy editor: " + QString::fromStdString(policy.editor), content);
                enabled->setEnabled(false);
                break;
            }
            grid->addWidget(valueWidget, rowNumber, 2);

            QString description = QLocalizationManager::getLang(
                QString::fromStdString(key + "[description]"));
            description += "\n--------------------------------\n" +
                QString::fromStdString(policy.restriction);
            if (!policy.valueValid) {
                description += "\n--------------------------------\nCurrent config value is invalid; default value is shown.";
            }
            auto* descriptionWidget = new QTextEdit(content);
            descriptionWidget->setPlainText(description);
            descriptionWidget->setReadOnly(true);
            descriptionWidget->setMaximumHeight(100);
            grid->addWidget(descriptionWidget, rowNumber, 3);

            controls.push_back({policy, enabled, valueWidget, type});
            ++rowNumber;
        }
    }
    grid->setColumnStretch(1, 1);
    grid->setColumnStretch(3, 2);
    scrollArea->setWidget(content);
    mainLayout->addWidget(scrollArea);

    auto* applyButton = new QPushButton(QLocalizationManager::getLang("[apply_button]"), this);
    applyButton->setMinimumHeight(40);
    mainLayout->addWidget(applyButton);

    connect(applyButton, &QPushButton::clicked, this,
            [this, moduleName, controls]() {
        std::vector<PolicyChange> changes;
        QStringList validationErrors;
        for (const Row& row : controls) {
            std::string value;
            switch (row.type) {
            case EditorType::Label:
                value = row.policy.valueValid ? row.policy.value : row.policy.defaultValue;
                break;
            case EditorType::SpinBox:
                value = std::to_string(qobject_cast<QSpinBox*>(row.value)->value());
                break;
            case EditorType::TextEdit: {
                QString text = qobject_cast<QTextEdit*>(row.value)->toPlainText();
                const QString delimiter = QString::fromStdString(row.policy.textDelimiter);
                if (!delimiter.isEmpty() && delimiter != "\n") {
                    text.replace("\r\n", "\n");
                    text.replace("\n", delimiter);
                }
                value = text.toStdString();
                break;
            }
            case EditorType::ComboBox:
                value = qobject_cast<QComboBox*>(row.value)->currentText().toStdString();
                break;
            case EditorType::Unknown:
                continue;
            }
            QString validationError;
            if (!validateValue(row.policy, value, validationError)) {
                validationErrors << validationError;
                continue;
            }
            changes.push_back({row.policy.policyName, value,
                               row.enabled->isChecked(),
                               row.type != EditorType::Label});
        }
        if (!validationErrors.isEmpty()) {
            QMessageBox::warning(this, "Validation errors", validationErrors.join("\n"));
            return;
        }

        nlohmann::json response;
        QString error;
        if (!PolicyService().applyChanges(moduleName, changes, response, error)) {
            QMessageBox::warning(this, "Apply errors", error);
            return;
        }
        QMessageBox box(this);
        const bool ok = response.value("ok", false);
        box.setIcon(ok ? QMessageBox::Information : QMessageBox::Warning);
        box.setWindowTitle(ok ? "Policies applied" : "Policy apply failed");
        box.setText(QString::fromStdString(response.value("message", ok ? "OK" : "ERROR")));
        box.setInformativeText(applySummary(response));
        const QString details = applyDetails(response);
        if (!details.isEmpty()) box.setDetailedText(details);
        box.exec();
    });
}

PolicyEditorWidget::EditorType PolicyEditorWidget::editorType(const std::string& editor)
{
    if (editor == "label") return EditorType::Label;
    if (editor == "spinbox") return EditorType::SpinBox;
    if (editor == "textedit") return EditorType::TextEdit;
    if (editor == "combobox") return EditorType::ComboBox;
    return EditorType::Unknown;
}

bool PolicyEditorWidget::validateValue(
    const PolicyDescriptor& policy,
    const std::string& value,
    QString& error)
{
    const EditorType type = editorType(policy.editor);
    if (type == EditorType::SpinBox) {
        try {
            const int parsed = std::stoi(value);
            if (parsed < policy.min || parsed > policy.max) {
                error = QString("Policy %1 is outside allowed range [%2; %3]")
                    .arg(QString::fromStdString(policy.policyName)).arg(policy.min).arg(policy.max);
                return false;
            }
        } catch (const std::exception&) {
            error = QString("Policy %1 is not an integer")
                .arg(QString::fromStdString(policy.policyName));
            return false;
        }
    }
    if (type == EditorType::ComboBox && !policy.possibleValues.empty() &&
        std::find(policy.possibleValues.begin(), policy.possibleValues.end(), value) ==
            policy.possibleValues.end()) {
        error = QString("Policy %1 is not in the allowed values list")
            .arg(QString::fromStdString(policy.policyName));
        return false;
    }
    return true;
}
