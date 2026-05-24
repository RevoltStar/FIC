#include "modules/oss/submodules/DesktopEnvironment.h"

DesktopEnvironment::DesktopEnvironment()
    :OSS()
{
    this->submoduleName = "DesktopEnvironment";
}

//Определяем текущую графическую оболочку
std::string DesktopEnvironment::detectDE(){
    // Проверяем переменные окружения, которые могут указывать на DE
    const char* xdg_current_desktop = std::getenv("XDG_CURRENT_DESKTOP");
    const char* desktop_session = std::getenv("DESKTOP_SESSION");
    const char* gdm_session = std::getenv("GDMSESSION");
    const char* gnome_desktop_session_id = std::getenv("GNOME_DESKTOP_SESSION_ID");

    if (xdg_current_desktop) {
        std::string de = xdg_current_desktop;
        // Некоторые системы могут содержать несколько значений через двоеточие
        size_t colon_pos = de.find(':');
        if (colon_pos != std::string::npos) {
            de = de.substr(0, colon_pos);
        }
        return de;
    }

    if (desktop_session) {
        std::string session = desktop_session;
        // Приводим к нижнему регистру для удобства сравнения
        for (char &c : session) c = tolower(c);

        if (session.find("gnome") != std::string::npos) return "GNOME";
        if (session.find("kde") != std::string::npos) return "KDE";
        if (session.find("xfce") != std::string::npos) return "XFCE";
        if (session.find("lxde") != std::string::npos) return "LXDE";
        if (session.find("mate") != std::string::npos) return "MATE";
        if (session.find("cinnamon") != std::string::npos) return "CINNAMON";
        if (session.find("budgie") != std::string::npos) return "BUDGIE";
        if (session.find("deepin") != std::string::npos) return "DEEPIN";
        if (session.find("unity") != std::string::npos) return "UNITY";
        if (session.find("lxqt") != std::string::npos) return "LXQT";
        if (session.find("enlightenment") != std::string::npos) return "ENLIGHTENMENT";
        //Astra Linux
        if (session.find("fly") != std::string::npos) return "FLY";

        return session;
    }

    if (gdm_session) {
        std::string session = gdm_session;
        for (char &c : session) c = tolower(c);

        if (session.find("gnome") != std::string::npos) return "GNOME";
        if (session.find("kde") != std::string::npos) return "KDE";
        if (session.find("xfce") != std::string::npos) return "XFCE";
        if (session.find("lxde") != std::string::npos) return "LXDE";
        if (session.find("mate") != std::string::npos) return "MATE";

        return session;
    }

    if (gnome_desktop_session_id) {
        return "GNOME";
    }

    // Дополнительные проверки для специфических DE
    if (std::getenv("KDE_FULL_SESSION")) return "KDE";
    if (std::getenv("TDE_FULL_SESSION")) return "TRINITY";
    if (std::getenv("GNOME_DESKTOP_SESSION_ID")) return "GNOME";

    // Неизвестная графическая оболочка
    return "UNKNOWN";
}



bool DesktopEnvironment::check_and_fix() {
    return true;
}

