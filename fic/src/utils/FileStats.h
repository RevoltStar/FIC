#ifndef FILESTATS_H
#define FILESTATS_H

#include <iostream>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <sys/stat.h>

class FileStats
{
public:
    //Владелец
    std::string _owner;
    //Группа
    std::string _group;
    //Права
    mode_t _permissions;
    //Файл существует?
    bool exists;

    //Берем данные из реального файла
    FileStats(const std::string &path);
    //Забиваем свои данные
    FileStats(const std::string& owner, const std::string& group, const mode_t& permissions);
    //Меняем владельца на эталон
    bool change_owner_group(const std::string& path, const std::string& owner, const std::string& group);
    //Меняем права на эталон
    bool change_permissions(const std::string& path, mode_t permissions);
    //Проверка существования группы
    static bool group_exists(const std::string& group);
    //Проверить владельца/группу
    bool check_owner_group(FileStats& fs);
    //Проверить права
    bool check_permission(FileStats& fs);
    //Изменить группу на root
    void change_group_to_root();

    //Преобразовать права в STRING
    std::string permToString();
};

#endif // FILESTATS_H
