#include "features/policies/widgets/PolicyEditorWidget.h"

#include <map>
#include <stdexcept>

#include <QCheckBox>
#include <QComboBox>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPalette>
#include <QPushButton>
#include <QScrollArea>
#include <QSizePolicy>
#include <QSpinBox>
#include <QTextEdit>
#include <QVBoxLayout>
#include <QWheelEvent>

#include <nlohmann/json.hpp>

#include "features/policies/services/PolicyService.h"
#include "shared/i18n/QLocalizationManager.h"

namespace {
class NoWheelSpinBox final : public QSpinBox
{
public:
    using QSpinBox::QSpinBox;

protected:
    void wheelEvent(QWheelEvent* event) override { event->ignore(); }
};

QFrame* createTableCell(
    QWidget* child,
    QWidget* parent,
    Qt::Alignment alignment = {})
{
    auto* cell = new QFrame(parent);
    cell->setObjectName("policyTableCell");
    cell->setFrameShape(QFrame::StyledPanel);
    cell->setFrameShadow(QFrame::Plain);
    cell->setLineWidth(1);

    auto* layout = new QVBoxLayout(cell);
    layout->setContentsMargins(8, 6, 8, 6);
    layout->setSpacing(0);
    layout->addWidget(child, 0, alignment);
    return cell;
}

QFrame* createHeaderCell(const QString& text, QWidget* parent)
{
    auto* label = new QLabel(text);
    label->setAlignment(Qt::AlignCenter);
    label->setWordWrap(true);
    QFont font = label->font();
    font.setBold(true);
    label->setFont(font);

    QFrame* cell = createTableCell(label, parent, Qt::AlignCenter);
    cell->setObjectName("policyTableHeaderCell");
    cell->setBackgroundRole(QPalette::Midlight);
    cell->setAutoFillBackground(true);
    return cell;
}

QFrame* createSubmoduleHeader(const QString& text, QWidget* parent)
{
    auto* label = new QLabel(text);
    label->setAlignment(Qt::AlignCenter);
    QFont font = label->font();
    font.setBold(true);
    label->setFont(font);

    QFrame* cell = createTableCell(label, parent, Qt::AlignCenter);
    cell->setObjectName("policySubmoduleHeaderCell");
    cell->setBackgroundRole(QPalette::Mid);
    cell->setAutoFillBackground(true);
    return cell;
}

QString applySummary(const nlohmann::json& response)
{
    if (!response.contains("summary") || !response["summary"].is_object()) {
        return {};
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
    const nlohmann::json results = response.value(
        "results", nlohmann::json::array());
    for (const auto& item : results) {
        QString reference = QString::fromStdString(item.value("module", ""));
        const QString submodule = QString::fromStdString(item.value("submodule", ""));
        if (!submodule.isEmpty()) reference += ":" + submodule;
        reference += ":" + QString::fromStdString(item.value("policy", ""));
        lines << reference + " " + QString::fromStdString(item.value("status", "unknown")) +
            " - " + QString::fromStdString(item.value("message", ""));
        if (item.contains("diagnostics") && item["diagnostics"].is_array()) {
            for (const auto& diagnostic : item["diagnostics"]) {
                QString line = QString("  [%1] [%2]")
                    .arg(QString::fromStdString(diagnostic.value("timestamp", "")),
                         QString::fromStdString(diagnostic.value("level", "UNKNOWN")));
                const QString category = QString::fromStdString(
                    diagnostic.value("category", ""));
                if (!category.isEmpty()) line += " [" + category + "]";
                lines << line + " " + QString::fromStdString(
                    diagnostic.value("message", ""));
            }
        }
        if (item.value("diagnostics_truncated", false)) {
            lines << "  ... diagnostics truncated";
        }
    }
    if (response.value("diagnostics_truncated", false)) {
        lines << "... response diagnostics truncated";
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
    mainLayout->setSpacing(0);

    auto* scrollArea = new QScrollArea(this);
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);
    auto* content = new QFrame(scrollArea);
    content->setObjectName("policyTable");
    content->setFrameShape(QFrame::StyledPanel);
    content->setFrameShadow(QFrame::Plain);
    content->setLineWidth(1);
    auto* grid = new QGridLayout(content);
    grid->setContentsMargins(8, 8, 8, 8);
    grid->setHorizontalSpacing(4);
    grid->setVerticalSpacing(4);

    const QStringList headers = {
        QLocalizationManager::getLang("[module:all][col:is_policy_active]"),
        QLocalizationManager::getLang("[module:all][col:policy_name]"),
        QLocalizationManager::getLang("[module:all][col:policy_value]"),
        QLocalizationManager::getLang("[module:all][col:policy_descr]")
    };
    for (int column = 0; column < headers.size(); ++column) {
        grid->addWidget(createHeaderCell(headers[column], content), 0, column);
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
        grid->addWidget(
            createSubmoduleHeader(
                QLocalizationManager::getLang(QString::fromStdString(
                    "[module:" + moduleName + "][submodule:" + submodule + "]")),
                content),
            rowNumber++, 0, 1, 4);

        for (const PolicyDescriptor& policy : submodulePolicies) {
            auto* enabled = new QCheckBox;
            enabled->setChecked(policy.enabled && policy.valueValid);

            const std::string key = "[module:" + moduleName + "][policy:" + policy.policyName + "]";
            auto* name = new QLabel(
                QLocalizationManager::getLang(QString::fromStdString(key)));
            name->setWordWrap(true);

            const EditorType type = editorType(policy.editor);
            const std::string initialValue = policy.valueValid ? policy.value : policy.defaultValue;
            QWidget* valueWidget = nullptr;
            switch (type) {
            case EditorType::Label: {
                auto* label = new QLabel(
                    QLocalizationManager::getLang("[utils:policytypevalue][type:fixedpolicytypevalue]"));
                label->setWordWrap(true);
                label->setTextInteractionFlags(Qt::TextSelectableByMouse);
                valueWidget = label;
                break;
            }
            case EditorType::SpinBox: {
                auto* spin = new NoWheelSpinBox;
                spin->setRange(policy.min, policy.max);
                try { spin->setValue(std::stoi(initialValue)); }
                catch (const std::exception&) { spin->setValue(policy.min); }
                spin->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
                valueWidget = spin;
                break;
            }
            case EditorType::LineEdit: {
                auto* edit = new QLineEdit(QString::fromStdString(initialValue));
                edit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
                valueWidget = edit;
                break;
            }
            case EditorType::TextEdit: {
                auto* edit = new QTextEdit;
                QString text = QString::fromStdString(initialValue);
                const QString delimiter = QString::fromStdString(policy.textDelimiter);
                if (!delimiter.isEmpty() && delimiter != "\n") text.replace(delimiter, "\n");
                edit->setPlainText(text);
                edit->setMinimumHeight(96);
                edit->setMaximumHeight(120);
                edit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
                valueWidget = edit;
                break;
            }
            case EditorType::ComboBox: {
                auto* combo = new QComboBox;
                for (const auto& value : policy.possibleValues) {
                    combo->addItem(QString::fromStdString(value));
                }
                const int index = combo->findText(QString::fromStdString(initialValue));
                if (index >= 0) combo->setCurrentIndex(index);
                combo->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
                valueWidget = combo;
                break;
            }
            case EditorType::Unknown:
                valueWidget = new QLabel(
                    "Unsupported policy editor: " + QString::fromStdString(policy.editor));
                enabled->setEnabled(false);
                break;
            }

            QString description = QLocalizationManager::getLang(
                QString::fromStdString(key + "[description]"));
            description += "\n--------------------------------\n" +
                QString::fromStdString(policy.restriction);
            if (!policy.valueValid) {
                description += "\n--------------------------------\nCurrent config value is invalid; default value is shown.";
            }
            auto* descriptionWidget = new QTextEdit;
            descriptionWidget->setPlainText(description);
            descriptionWidget->setReadOnly(true);
            descriptionWidget->setMinimumHeight(84);
            descriptionWidget->setMaximumHeight(100);
            descriptionWidget->setSizePolicy(
                QSizePolicy::Expanding, QSizePolicy::Preferred);

            grid->addWidget(
                createTableCell(enabled, content, Qt::AlignCenter), rowNumber, 0);
            grid->addWidget(createTableCell(name, content), rowNumber, 1);
            grid->addWidget(createTableCell(valueWidget, content), rowNumber, 2);
            grid->addWidget(
                createTableCell(descriptionWidget, content), rowNumber, 3);

            controls.push_back({policy, enabled, valueWidget, type});
            ++rowNumber;
        }
    }
    grid->setColumnMinimumWidth(0, 80);
    grid->setColumnMinimumWidth(1, 200);
    grid->setColumnMinimumWidth(2, 220);
    grid->setColumnStretch(0, 0);
    grid->setColumnStretch(1, 1);
    grid->setColumnStretch(2, 1);
    grid->setColumnStretch(3, 2);
    grid->setRowStretch(rowNumber, 1);
    scrollArea->setWidget(content);
    mainLayout->addWidget(scrollArea);

    auto* saveButton = new QPushButton(
        QLocalizationManager::getLang("[save_button]"), this);
    saveButton->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    saveButton->setMinimumHeight(40);
    auto* saveApplyButton = new QPushButton(
        QLocalizationManager::getLang("[save_apply_button]"), this);
    saveApplyButton->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    saveApplyButton->setMinimumHeight(40);
    auto* buttonLayout = new QHBoxLayout;
    buttonLayout->setContentsMargins(10, 10, 10, 10);
    buttonLayout->addWidget(saveButton);
    buttonLayout->addWidget(saveApplyButton);
    mainLayout->addLayout(buttonLayout);

    const auto collectChanges = [controls](
        std::vector<PolicyChange>& changes,
        QStringList& validationErrors) {
        for (const Row& row : controls) {
            std::string value;
            switch (row.type) {
            case EditorType::Label:
                value = row.policy.valueValid ? row.policy.value : row.policy.defaultValue;
                break;
            case EditorType::SpinBox:
                value = std::to_string(qobject_cast<QSpinBox*>(row.value)->value());
                break;
            case EditorType::LineEdit:
                value = qobject_cast<QLineEdit*>(row.value)->text().toStdString();
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
            std::string validationError;
            if (!validatePolicyDescriptorValue(
                    row.policy, value, validationError)) {
                validationErrors << QString::fromStdString(validationError);
                continue;
            }
            changes.push_back({row.policy.policyName, value,
                               row.enabled->isChecked(),
                               row.type != EditorType::Label});
        }
    };
    const auto validateAndCollect = [this, collectChanges](
        std::vector<PolicyChange>& changes) {
        QStringList validationErrors;
        collectChanges(changes, validationErrors);
        if (!validationErrors.isEmpty()) {
            QMessageBox::warning(this, "Validation errors", validationErrors.join("\n"));
            return false;
        }
        return true;
    };

    connect(saveButton, &QPushButton::clicked, this,
            [this, moduleName, validateAndCollect]() {
        std::vector<PolicyChange> changes;
        if (!validateAndCollect(changes)) {
            return;
        }

        QString error;
        if (!PolicyService().saveChanges(moduleName, changes, error)) {
            QMessageBox::warning(this, "Save errors", error);
            return;
        }
        QMessageBox::information(
            this,
            QLocalizationManager::getLang("[save_button]"),
            QLocalizationManager::getLang("[configuration_saved]"));
    });

    connect(saveApplyButton, &QPushButton::clicked, this,
            [this, moduleName, validateAndCollect]() {
        std::vector<PolicyChange> changes;
        if (!validateAndCollect(changes)) {
            return;
        }

        const PolicyService::ApplyResult result =
            PolicyService().saveAndApplyChanges(moduleName, changes);
        if (result.status == PolicyService::ApplyStatus::ServiceError) {
            QMessageBox::warning(this, "Apply errors", result.error);
            return;
        }
        const nlohmann::json& response = result.response;
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
    if (editor == "lineedit") return EditorType::LineEdit;
    if (editor == "textedit") return EditorType::TextEdit;
    if (editor == "combobox") return EditorType::ComboBox;
    return EditorType::Unknown;
}
