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
#include <thread>
#include <cstring>
#include <cerrno>

class ExclusivePidLock;
enum class logLevel;

// Структуры для данных устройств
struct DeviceInfo {
    int id;
    std::string device_hash;
    std::string devpath;
    std::string subsystem;
    std::string device_type;
    int parent_id;
    std::string control_level;
    bool ignore_hierarchy;
    std::string boot_id;
    std::string created_at;
    std::string last_event_at;
    std::string notes;
};

// Атрибуты устройства
struct DeviceAttribute {
    int id;
    int device_id;
    std::string attribute_name;
    std::string attribute_value;
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

    DB(const DB&) = delete;
    DB& operator=(const DB&) = delete;

    std::unique_ptr<ExclusivePidLock> lock_;

    bool openDatabase();
    void closeDatabase();

    bool log(std::string message, logLevel logLev);
public:
    // Методы для работы с блокировкой
    bool acquireLock();           // Блокирующий вызов, ждет пока не получит блокировку
    void releaseLock();           // Освобождает блокировку
    DB(const std::string& db_path);
    ~DB();
    /* Основные методы */
    // Инициализация БД (если не существует)
    bool initializeDatabase();

    // Получить device_id по пути
    int getDeviceIdByPath(const std::string& devpath);
    // Методы для работы с устройствами
    int addDevice(const DeviceInfo& device);
    bool updateDevice(const DeviceInfo& device, const int& device_id);
    bool updateDeviceControlLevel(int device_id, const std::string& control_level);
    bool deleteDevice(int device_id);
    DeviceInfo getDeviceByHash(const std::string& device_hash);
    DeviceInfo getDeviceByPath(const std::string& devpath);
    DeviceInfo getDeviceByPathAndBootId(const std::string& devpath, const std::string& boot_id);
    DeviceInfo getDeviceByHashAndSubsystem(const std::string& device_hash, const std::string& subsystem);
    std::vector<DeviceInfo> getDevicesByType(const std::string& device_type);
    std::vector<DeviceInfo> getChildDevices(int parent_id);

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

    std::string getDeviceAttribute(int device_id, const std::string& attribute_name, const std::string& default_string = "");
    std::map<std::string, std::string> getDeviceAttributes(int device_id);

    // Методы для работы с событиями
    int addDeviceEvent(const DeviceEvent& event);
    std::vector<DeviceEvent> getDeviceEvents(int device_id, int limit = 100);
    std::vector<DeviceEvent> getRecentEvents(const std::string& event_type = "", int limit = 100);

    // Вспомогательные методы
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
