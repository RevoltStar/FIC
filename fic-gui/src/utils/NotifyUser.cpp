#include "utils/NotifyUser.h"
#include <sys/stat.h>
#include <fstream>


const std::string NotifyUser::NOTIFY_DIR = "/opt/fic/notify/";
const notifyLevel NotifyUser::currNotifyLevel = notifyLevel::NoNotify;

bool NotifyUser::notify_user(const std::string& filename, const std::string& content, const notifyLevel& notifyLev){
        std::string notifyUserString = NotifyUser::enumToString(notifyLev);
        // Создаем директорию, если не существует
         int status = mkdir(NOTIFY_DIR.c_str(), 0755);
         if(status != 0 && errno != EEXIST){
             std::cout << "Ошибка при создании каталога " + NOTIFY_DIR << ":" <<strerror(errno) << std::endl;
             return false;
         }

        // Получаем текущее время
        time_t now = time(nullptr);
        std::string datetime = ctime(&now);
        datetime.pop_back(); // Удаляем \n

        // Создаем файл уведомления
        std::ofstream notify_file(NotifyUser::NOTIFY_DIR + filename);
        if (!notify_file.is_open()) {
            std::cerr << "Ошибка создания файла уведомления" << '\n';
            return false;
        }

        notify_file << "datetime=" << datetime << "\n"
                    << "type=" << notifyUserString << "\n"
                    << "content=" << content << "\n";
        return true;

        //std::cout << "Ошибка создания уведомления" << '\n';
        //return false;
}
