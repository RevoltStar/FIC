#!/usr/bin/env python3
import sys
import re
from pathlib import Path


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    root = Path(sys.argv[1])
    registry = (root / "fic/src/core/PolicyRegistry.h").read_text(encoding="utf-8")
    init = (root / "fic/src/core/main_function.cpp").read_text(encoding="utf-8")
    daemon = (root / "fic/src/main.cpp").read_text(encoding="utf-8")
    logger = (root / "fic-common/fic-core/src/Logger.cpp").read_text(encoding="utf-8")
    main_window = (root / "fic-gui/src/mainwindow.cpp").read_text(encoding="utf-8")
    editor = (root / "fic-gui/src/widgets/PolicyEditorWidget.cpp").read_text(encoding="utf-8")
    device_page = (root / "fic-gui/src/pages/DeviceModulePage.cpp").read_text(encoding="utf-8")
    audit_page = (root / "fic-gui/src/pages/AuditModulePage.cpp").read_text(encoding="utf-8")
    log_viewer = (root / "fic-gui/src/LogViewer.cpp").read_text(encoding="utf-8")
    log_model = (root / "fic-gui/src/LogModel.cpp").read_text(encoding="utf-8")
    global_config = (root / "fic/src/scripts/config/GLOBAL.conf").read_text(encoding="utf-8")
    audit_config = (root / "fic/src/scripts/config/AUDIT.conf").read_text(encoding="utf-8")
    ru_lang = (root / "fic/src/scripts/lang/ru.lang").read_text(encoding="utf-8")
    en_lang = (root / "fic/src/scripts/lang/en.lang").read_text(encoding="utf-8")

    for marker in ["enum class ModuleView", "struct PolicyModule", "ModuleView view", "SubmoduleMap submodules"]:
        require(marker in registry, f"missing registry model marker: {marker}")
    require("PolicyMap" not in registry and "PolicyMap" not in init,
            "legacy PolicyMap name must be removed from implementation")
    require("moduleDescriptorsJson(policyRegistry)" in daemon,
            "module_list must serialize module descriptors")
    policy_serializer = daemon.split("json policy_to_json", 1)[1].split("json policy_list_json", 1)[0]
    require('"view"' not in policy_serializer,
            "policy_list descriptors must not duplicate ModuleView")
    require('PolicyConfig::getEnabledValue("AUDIT", "log_level")' in logger,
            "Logger must read AUDIT/log_level")
    audit_writer = daemon.split("void write_audit_log", 1)[1].split("void audit_ipc_request", 1)[0]
    require("Logger::log" not in audit_writer,
            "security audit trail must not be filtered through Logger")
    require("log_level" not in global_config,
            "GLOBAL.conf must not contain log_level")
    require("log_level.status" in audit_config and "log_level.value" in audit_config,
            "AUDIT.conf must own log_level")

    require("ModulePageFactory" in main_window and "for (const ModuleDescriptor& module : modules)" in main_window,
            "MainWindow must create pages from module descriptors")
    require("tab_modules->count() > 2" not in main_window and "setTabText(0" not in main_window,
            "MainWindow must not preserve legacy first-tab assumptions")
    require("DeviceTree" not in main_window and "LogViewer" not in main_window,
            "MainWindow must not own specialized page implementations")
    for marker in ["policy.editor", "policy.value", "policy.defaultValue", "policy.enabled",
                   "policy.min", "policy.max", "policy.possibleValues", "policy.textDelimiter",
                   "policy.restriction"]:
        require(marker in editor, f"policy editor ignores descriptor field: {marker}")
    require("QFrame* createTableCell(" in editor and
            editor.count("createTableCell(") >= 5,
            "policy editor must build reusable framed table cells")
    require("QFrame::StyledPanel" in editor and
            "setBackgroundRole(QPalette::" in editor,
            "policy table cells and headers must use palette-aware Qt frames")
    require("setRowStretch(rowNumber, 1)" in editor,
            "policy table must place vertical stretch after its semantic rows")
    for direct_child in ["enabled", "name", "valueWidget", "descriptionWidget"]:
        require(re.search(
            rf"grid->addWidget\(\s*{direct_child}\s*,\s*rowNumber", editor) is None,
            f"policy row widget {direct_child} must be placed inside a cell container")
    require(re.search(r"setStyleSheet\s*\([^;]*border", editor, re.DOTALL) is None,
            "policy table borders must not cascade into native editor controls")
    require("new PolicyEditorWidget(module, policies" in device_page,
            "DeviceModulePage must reuse PolicyEditorWidget")
    require("new PolicyEditorWidget(module, policies" in audit_page,
            "AuditModulePage must reuse PolicyEditorWidget")
    require("new DeviceTree" in device_page and "new DeviceEventList" in device_page,
            "DeviceModulePage must own device UI")
    require("setupUi();" in log_viewer and "initializeUI" not in log_viewer,
            "LogViewer must own its UI")
    for source, name in [(device_page, "DeviceModulePage"),
                         (log_viewer, "LogViewer"),
                         (log_model, "LogModel")]:
        require(re.search(r"[А-Яа-яЁё]", source) is None,
                f"{name} must not contain hardcoded Russian UI text")
    for prefix in ["[devices:ui]", "[logs:ui]"]:
        require(prefix in ru_lang and prefix in en_lang,
                f"both localization bundles must contain {prefix} keys")
    localized_keys = {
        *(f"[devices:ui][{key}]" for key in re.findall(r'deviceText\("([^"]+)"\)', device_page)),
        *(f"[logs:ui][{key}]" for key in re.findall(r'logText\("([^"]+)"\)', log_viewer)),
        "[devices:ui][yes]",
        "[devices:ui][no]",
    }
    for key in localized_keys:
        require(f"{key}=" in ru_lang and f"{key}=" in en_lang,
                f"missing GUI localization key in one of the bundles: {key}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
