#include "modules/oss/submodules/DesktopEnvironment/OSS_screenlock_timeout.h"

OSS_screenlock_timeout::OSS_screenlock_timeout()
    :DesktopEnvironment()
{
    this->policyName = "screenlock_timeout";
    this->policyTypeValue = std::make_unique<IntPolicyTypeValue>(1,20,5);
}

bool OSS_screenlock_timeout::check_and_fix (){
    //Определяем DE
    std::string de = this->DesktopEnvironment::detectDE();
    this->log("Была определена графическая оболочка: " + de, logLevel::DEBUG);
    if(de == "UNKNOWN"){
        this->log("Не удалось применить политику OSS_screenlock_timeout. Графическая оболочка не находится в списке допустимых", logLevel::ERROR);
        return false;
    }
    //Время блокировки в минутах
    int timeout = 10;
    //Время блокировки в секундах (для некоторых DE)
    int timeout_second = timeout * 60;

    std::string timeout_str = std::to_string(timeout);
    std::string timeout_sec_str = std::to_string(timeout_second);

    //Успешно?
    bool success = false;

    if(de == "GNOME" || de == "UNITY"){

    }else
    if(de == "KDE"){

    }else
    if(de == "XFCE"){

    }else
    if(de == "MATE"){

    }else
    if(de == "CINNAMON"){

    }else
    if(de == "LXDE"){

    }else
    if(de == "LXQT"){

    }else
    if(de == "BUDGIE"){

    }else
    if(de == "DEEPIN"){

    }
    return success;
}
