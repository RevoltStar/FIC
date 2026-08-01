if(DEFINED FIC_INSTALL_LAYOUT_INCLUDED)
    return()
endif()
set(FIC_INSTALL_LAYOUT_INCLUDED TRUE)

# FIC currently ships as an add-on product under /opt.  Keep every semantic
# location independent: a future FHS profile must be able to move config,
# state, logs and static data without inventing a second "root" abstraction.
set(FIC_PRIVATE_BINDIR "/opt/fic/bin" CACHE PATH "Private FIC executable directory")
set(FIC_CONFIG_DIR "/opt/fic/config" CACHE PATH "FIC policy configuration directory")
set(FIC_LANGUAGE_DIR "/opt/fic/lang" CACHE PATH "FIC localization directory")
set(FIC_LOG_DIR "/opt/fic/log" CACHE PATH "FIC log directory")
set(FIC_NOTIFY_DIR "/opt/fic/notify" CACHE PATH "FIC notification spool")
set(FIC_DATA_DIR "/opt/fic/db" CACHE PATH "FIC mutable data directory")
set(FIC_STATE_DIR "/opt/fic/state" CACHE PATH "FIC upgrade and persistent state directory")
set(FIC_SHARE_DIR "/opt/fic/share" CACHE PATH "FIC package-owned shared data directory")
set(FIC_IMAGE_DIR "/opt/fic/image" CACHE PATH "FIC image directory")
set(FIC_QT_DIR "/opt/fic/qt" CACHE PATH "Bundled GUI Qt runtime directory")
set(FIC_RUNTIME_DIR "/run/fic" CACHE PATH "FIC runtime directory")
set(FIC_DAEMON_SOCKET_FILE "${FIC_RUNTIME_DIR}/fic.sock" CACHE FILEPATH "FIC daemon socket")
set(FIC_DEVICE_SOCKET_FILE "${FIC_RUNTIME_DIR}/fic-device.sock" CACHE FILEPATH "FIC device daemon socket")

set(FIC_LOCK_STATUS_FILE "/opt/fic/lockstatus" CACHE FILEPATH "FIC lock status file")
set(FIC_COMMAND_HASH_FILE "${FIC_DATA_DIR}/commandhash.txt" CACHE FILEPATH "Trusted command hash store")
set(FIC_DEVICE_DB_FILE "${FIC_DATA_DIR}/devices.db" CACHE FILEPATH "FIC device database")
set(FIC_DEVICE_DB_LOCK_FILE "${FIC_LOG_DIR}/db_lock" CACHE FILEPATH "FIC device database lock")
set(FIC_LOCK_DEBUG_LOG_FILE "${FIC_LOG_DIR}/lock_log.txt" CACHE FILEPATH "PID lock debug log")

set(FIC_SYSTEMD_UNIT_DIR "/lib/systemd/system" CACHE PATH "systemd unit installation directory")
set(FIC_TMPFILES_DIR "/usr/lib/tmpfiles.d" CACHE PATH "systemd-tmpfiles installation directory")
set(FIC_UDEV_RULES_DIR "/etc/udev/rules.d" CACHE PATH "udev rules installation directory")
set(FIC_XDG_AUTOSTART_DIR "/etc/xdg/autostart" CACHE PATH "XDG autostart installation directory")
set(FIC_BASH_COMPLETION_DIR "/usr/share/bash-completion/completions" CACHE PATH "bash completion directory")
set(FIC_PUBLIC_BINDIR "/bin" CACHE PATH "Public command link directory")
