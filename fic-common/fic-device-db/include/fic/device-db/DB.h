#ifndef DB_H
#define DB_H

#include <string>
#include <vector>
#include <map>
#include <sqlite3.h>
#include <memory>
#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/file.h>
#include <chrono>
#include <cstdint>
#include <thread>
#include <cstring>
#include <cerrno>
#include <filesystem>
#include <functional>

struct DBOptions {
    std::filesystem::path databaseFile;
    std::filesystem::path lockFile;
    std::filesystem::path lockDebugLogFile;
    bool lockDebugEnabled = true;
};

struct KnownDeviceIdentity {
    std::string device_hash;
    std::string subsystem;
    std::map<std::string, std::string> attributes;
};

struct DeviceCategoryPolicyState {
    std::string block_usb_storage = "disabled";
    std::string block_printers_scanners = "disabled";
    std::string block_optical_drives = "disabled";
    std::map<std::string, std::int64_t> epochs;
    std::map<std::string, std::vector<KnownDeviceIdentity>> known;
};

class ExclusivePidLock;
enum class logLevel;

// Структуры для данных устройств
struct DeviceInfo {
    int id = -1;
    std::string device_hash;
    std::string devpath;
    std::string subsystem;
    std::string device_type;
    int parent_id = -1;
    std::string control_level;
    bool control_explicit = true;
    bool ignore_hierarchy = false;
    std::string boot_id;
    std::string created_at;
    std::string last_event_at;
    std::string notes;
    std::string children_control = "inherit";
};

// Атрибуты устройства
struct DeviceAttribute {
    int id;
    int device_id;
    std::string attribute_name;
    std::string attribute_value;
};

struct DeviceTreeEntry {
    DeviceInfo device;
    std::map<std::string, std::string> attributes;
};

struct DeviceTreeSnapshot {
    std::int64_t revision = -1;
    std::vector<DeviceTreeEntry> entries;
    std::vector<DeviceInfo> identityOccurrences;
    DeviceCategoryPolicyState categoryPolicy;
};

// События устройств
struct DeviceEvent {
    int id;
    int device_id;
    std::string event_type;
    std::string event_result;
    std::string event_details;
    std::string created_at;
};

class DB {
private:
    std::string db_path;
    sqlite3* db;
    bool databaseHadContent_ = false;
    std::string lastError_;

    DB(const DB&) = delete;
    DB& operator=(const DB&) = delete;

    std::unique_ptr<ExclusivePidLock> lock_;

    bool openDatabase();
    void closeDatabase();
    bool verifyDatabaseSchemaMetadata(std::string& error);

    // Test-only fault injection for the checked inventory read (never set in
    // production); see setInventoryFaultHookForTests.
    std::function<bool(const char* stage)> inventoryFaultHook_;

    bool log(std::string message, logLevel logLev);
public:
    // Методы для работы с блокировкой
    bool acquireLock();           // Блокирующий вызов, ждет пока не получит блокировку
    void releaseLock();           // Освобождает блокировку
    explicit DB(DBOptions options);
    ~DB();
    /* Основные методы */
    // Инициализация БД (если не существует)
    bool initializeDatabase();
    bool verifyDatabaseSchema(std::string& error);
    const std::string& lastError() const;

    // Получить device_id по пути
    int getDeviceIdByPath(const std::string& devpath);
    // Методы для работы с устройствами
    int addDevice(const DeviceInfo& device);
    bool updateDevice(const DeviceInfo& device, const int& device_id);
    bool updateDeviceControlLevel(int device_id, const std::string& control_level);
    bool updateDeviceControl(int device_id,
                             const std::string& control_level,
                             bool control_explicit,
                             bool ignore_hierarchy,
                             const std::string& children_control);
    bool updateDeviceIgnoreHierarchy(int device_id, bool ignore_hierarchy);
    bool updateDeviceChildrenControl(int device_id, const std::string& children_control);
    bool deleteDevice(int device_id);
    DeviceInfo getDeviceByHash(const std::string& device_hash);
    DeviceInfo getDeviceByPath(const std::string& devpath);
    DeviceInfo getDeviceByPathAndBootId(const std::string& devpath, const std::string& boot_id);
    DeviceInfo getDeviceByHashAndSubsystem(const std::string& device_hash, const std::string& subsystem);
    std::vector<DeviceInfo> getDevicesByHashAndSubsystem(const std::string& device_hash, const std::string& subsystem);
    std::vector<DeviceInfo> getAllDevices();

    // A PROVEN full inventory read for security-critical paths.
    //
    // The plain getAllDevices() silently maps SQLite failures to an empty or
    // partial list, which a caller could mistake for "no devices exist". The
    // checked variant only reports ok=true when the statement was prepared,
    // stepped to SQLITE_DONE and finalized without error, and then returns the
    // complete list. Any failure returns ok=false with a diagnostic and NO
    // device list, so a partial read can never pass as a complete inventory.
    struct DeviceListResult {
        bool ok = false;
        std::vector<DeviceInfo> devices;
        std::string error;
    };
    DeviceListResult getAllDevicesChecked();

    // Minimal fault-injection seam for the checked inventory read, used ONLY
    // by regression tests to prove the prepare/step failure paths without
    // corrupting a real database. Production code must never set it. When the
    // hook returns true for a stage ("prepare" or "step"), that stage is
    // reported as failed.
    void setInventoryFaultHookForTests(
        std::function<bool(const char* stage)> hook);
    std::vector<DeviceInfo> getDevicesByType(const std::string& device_type);
    std::vector<DeviceInfo> getChildDevices(int parent_id);
    std::vector<DeviceInfo> getDescendantDevices(int parent_id);

    bool updateBootId(int device_id, const std::string& boot_id);
    DeviceInfo getDeviceByHashAndSubsystemAndParent(const std::string& device_hash,
                                                    const std::string& subsystem,
                                                    int parent_id);

    //Дать устройство по подсистеме и пути (devpath)
    DeviceInfo getDeviceByDevpathAndSubsystem(const std::string& devpath,
                                                    const std::string& subsystem);
    DeviceInfo getDeviceByDevpathSubsystemAndBootId(const std::string& devpath,
                                                    const std::string& subsystem,
                                                    const std::string& boot_id);

    // Методы для работы с атрибутами
    bool addDeviceAttribute(int device_id, const std::string& name, const std::string& value);
    bool updateDeviceAttribute(int device_id, const std::string& name, const std::string& value);
    bool deleteDeviceAttribute(int device_id, const std::string& name);

    DeviceInfo getDeviceById(int id);
    std::int64_t getDeviceTreeRevision();
    bool getDeviceTreeSnapshot(int rootId,
                               bool includeDisconnected,
                               const std::string& bootId,
                               DeviceTreeSnapshot& snapshot,
                               std::string& error);
    std::int64_t getDesiredPolicyRevision();
    std::int64_t getActivePolicyRevision();
    bool setActivePolicyRevision(std::int64_t revision);
    DeviceCategoryPolicyState getDeviceCategoryPolicyState();
    bool updateDeviceCategoryPolicyState(const DeviceCategoryPolicyState& state);

    std::string getDeviceAttribute(int device_id, const std::string& attribute_name, const std::string& default_string = "");
    std::map<std::string, std::string> getDeviceAttributes(int device_id);

    // Методы для работы с событиями
    int addDeviceEvent(const DeviceEvent& event);
    std::vector<DeviceEvent> getDeviceEvents(int device_id, int limit = 100);
    std::vector<DeviceEvent> getRecentEvents(const std::string& event_type = "", int limit = 100);

    // Вспомогательные методы
    DeviceInfo getComputerRoot();
    int getVirtualContainerId(const std::string& container_type); // cpu, memory, board, devices
    bool deviceExists(const std::string& device_hash);
    int getDeviceIdByHash(const std::string& device_hash);

    // Методы для пакетной вставки
    bool beginTransaction();
    bool commitTransaction();
    bool rollbackTransaction();

private:
    // Вспомогательные методы для подготовки данных
    DeviceInfo resultToDeviceInfo(sqlite3_stmt* stmt);
    DeviceAttribute resultToDeviceAttribute(sqlite3_stmt* stmt);
    DeviceEvent resultToDeviceEvent(sqlite3_stmt* stmt);
};

#endif // DB_H
