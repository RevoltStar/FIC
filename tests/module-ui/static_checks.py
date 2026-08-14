#!/usr/bin/env python3
import sys
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
    global_config = (root / "fic/src/scripts/config/GLOBAL.conf").read_text(encoding="utf-8")
    audit_config = (root / "fic/src/scripts/config/AUDIT.conf").read_text(encoding="utf-8")

    for marker in ["enum class ModuleView", "struct PolicyModule", "ModuleView view", "SubmoduleMap submodules"]:
        require(marker in registry, f"missing registry model marker: {marker}")
    require("PolicyMap" not in registry and "PolicyMap" not in init,
            "legacy PolicyMap name must be removed from implementation")
    require("moduleViewForName(moduleName)" in init,
            "registry initialization must assign module views once")
    require("moduleDescriptorsJson(policyRegistry)" in daemon,
            "module_list must serialize module descriptors")
    require('PolicyConfig::getEnabledValue("AUDIT", "log_level")' in logger,
            "Logger must read AUDIT/log_level")
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
    require("new PolicyEditorWidget(module, policies" in device_page,
            "DeviceModulePage must reuse PolicyEditorWidget")
    require("new PolicyEditorWidget(module, policies" in audit_page,
            "AuditModulePage must reuse PolicyEditorWidget")
    require("new DeviceTree" in device_page and "new DeviceEventList" in device_page,
            "DeviceModulePage must own device UI")
    require("setupUi();" in log_viewer and "initializeUI" not in log_viewer,
            "LogViewer must own its UI")
    return 0


if __name__ == "__main__":
    sys.exit(main())
