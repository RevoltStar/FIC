#include <fic/core/FileStats.h>
#include <sstream>

FileStats::FileStats(const std::string &path)
{
    struct stat file_stat;
    if (stat(path.c_str(), &file_stat) != 0) {
        this->exists = false;
        return;
    }

    this->exists = true;

    // Получаем имя владельца
    struct passwd *pw = getpwuid(file_stat.st_uid);
    this->_owner = (pw != nullptr) ? pw->pw_name : std::to_string(file_stat.st_uid);

    // Получаем имя группы
    struct group *gr = getgrgid(file_stat.st_gid);
    this->_group = (gr != nullptr) ? gr->gr_name : std::to_string(file_stat.st_gid);

    // Получаем права
    this->_permissions = file_stat.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO);
}
FileStats::FileStats(const std::string& owner, const std::string& group, const mode_t& permissions) :
    _owner(owner),
    _group(group),
    _permissions(permissions),
    exists(true) //  Инициализируйте член exists
{
    // Инициализация членов класса (если нужно)
}
//Смена владельца
bool FileStats::change_owner_group(const std::string& path, const std::string& owner, const std::string& group_name) {
    struct passwd *pw = getpwnam(owner.c_str());
    if (!pw) return false;

    struct group *gr = getgrnam(group_name.c_str());
    if (!gr) return false;

    return chown(path.c_str(), pw->pw_uid, gr->gr_gid) == 0;
}

//Смена прав
bool FileStats::change_permissions(const std::string& path, mode_t permissions) {
    return chmod(path.c_str(), permissions) == 0;
}

//Проверка существования группы
bool FileStats::group_exists(const std::string &group) {
    struct group *grp = getgrnam(group.c_str());
    return grp != nullptr;
}

//Проверка группы/владельца
bool FileStats::check_owner_group(FileStats& fs){
    if(this->_owner == fs._owner && this->_group == fs._group){
        return true;
    }
    return false;
}
//Проверить права
bool FileStats::check_permission(FileStats& fs){
    if(this->_permissions == fs._permissions){
        return true;
    }
    return false;
}
//Изменить группу на root
void FileStats::change_group_to_root(){
    this->_group = "root";
}

//Преобразовать права в STRING
std::string FileStats::permToString(){

        std::stringstream ss;
        ss << std::oct << static_cast<unsigned int>(this->_permissions); // Преобразуем в unsigned int и выводим в восьмеричном формате
        std::string result = ss.str();
        return result;
}
