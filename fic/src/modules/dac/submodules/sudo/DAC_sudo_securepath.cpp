#include "modules/dac/submodules/sudo/DAC_sudo_securepath.h"

#include <algorithm>
#include <cctype>

//Кастомный валидатор для DAC_sudo_securepath
class SudoSecurePathPolicyTypeValue : public MultiLineTextPolicyTypeValue{
private:
    static std::string trim_copy(std::string value) {
        value.erase(value.begin(), std::find_if(value.begin(), value.end(), [](unsigned char ch) {
            return !std::isspace(ch);
        }));
        value.erase(std::find_if(value.rbegin(), value.rend(), [](unsigned char ch) {
            return !std::isspace(ch);
        }).base(), value.end());
        return value;
    }

    static bool is_secure_path_separator(char c) {
        return c == ',' || c == ':' || c == '\n' || c == '\r';
    }

    std::vector<std::string> split_secure_path(const std::string& value) const {
        std::vector<std::string> paths;
        std::string current;

        for (char c : value) {
            if (is_secure_path_separator(c)) {
                std::string path = trim_copy(current);
                if (!path.empty()) {
                    paths.push_back(path);
                }
                current.clear();
            } else {
                current += c;
            }
        }

        std::string path = trim_copy(current);
        if (!path.empty()) {
            paths.push_back(path);
        }

        return paths;
    }

    static std::string join_secure_path(const std::vector<std::string>& paths, const std::string& delimiter) {
        std::string result;
        for (size_t i = 0; i < paths.size(); ++i) {
            if (i != 0) {
                result += delimiter;
            }
            result += paths[i];
        }
        return result;
    }

    bool is_valid_absolute_directory_path(const std::string& path) {
        // Путь должен начинаться с '/'
        if (path.empty() || path[0] != '/') {
            return false;
        }

        // Путь не должен содержать запрещённых символов
        const std::string forbidden_chars = "\"\'\\|<>!@#$%^&*()[]{};:";
        for (char c : path) {
            if (std::isspace(static_cast<unsigned char>(c))) {
                return false;
            }
            if (forbidden_chars.find(c) != std::string::npos) {
                return false;
            }
        }

        // Путь не должен заканчиваться на '/', кроме корня
        if (path.size() > 1 && path.back() == '/') {
            return false;
        }

        // Проверка на наличие "." или ".." в пути
        size_t dot_pos = path.find(".");
        while (dot_pos != std::string::npos) {
            // Проверяем, является ли это "." или ".."
            if (dot_pos + 1 < path.size() && path[dot_pos + 1] == '.') {
                // Обнаружено ".."
                return false;
            } else if (
                // Обнаружено "." в середине пути (например, "/dir./sub")
                (dot_pos > 0 && path[dot_pos - 1] != '.' && dot_pos + 1 < path.size() && path[dot_pos + 1] != '/') ||
                // Обнаружено "." в конце пути (например, "/dir.")
                (dot_pos > 0 && dot_pos == path.size() - 1 && path[dot_pos - 1] != '.')
            ) {
                return false;
            }
            dot_pos = path.find(".", dot_pos + 1);
        }

        return true;
    }
public:
    SudoSecurePathPolicyTypeValue()
        :MultiLineTextPolicyTypeValue(",", ":", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"){
    }
    bool validate(const std::string& value)override{
        if (value.empty()) {
            //std::cout << "" << std::endl;
            return false;
        }

            std::vector<std::string> paths = split_secure_path(value);
            if (paths.empty()) {
                return false;
            }

            for (const std::string& path : paths) {
                if (!is_valid_absolute_directory_path(path)) {
                    return false;
                }
            }

          return true;
    };
    std::string postProcessingValue(const std::string& value) override{
        std::vector<std::string> paths = split_secure_path(value);
        if (paths.empty()) {
            return "";
        }

        for (const std::string& path : paths) {
            if (!is_valid_absolute_directory_path(path)) {
                return "";
            }
        }

        return json(paths).dump();
    }
    std::string reverse_postProcessingValue(const std::string& value) override{
        std::vector<std::string> paths;

        try {
            auto parsedValue = json::parse(value);
            if (parsedValue.is_array()) {
                for (const auto& item : parsedValue) {
                    if (!item.is_string()) {
                        return value;
                    }
                    paths.push_back(item.get<std::string>());
                }
            }
        } catch (const json::parse_error&) {
            paths = split_secure_path(value);
        } catch (const json::type_error&) {
            return value;
        }

        if (paths.empty()) {
            return value;
        }

        return join_secure_path(paths, ":");
    }
    std::string getPolicyRestrictionInfo()override{
        return "Укажите абсолютные пути к каталогам, из которых должна формироваться переменная PATH. Не используйте '.' и '..'";
    }
};

DAC_sudo_securepath::DAC_sudo_securepath(
    const fic::platform::SudoPlatformConfig& platformConfig)
    : Sudo(platformConfig) {
    //Какой параметр рассматриваем?
    this->Sudo::sudoParameter = std::make_unique<KeyValueDefaultsSudoersParam>(
        "Defaults", "", "", "secure_path", "=", "", 0);
    this->policyName = "sudo_securepath";
    this->policyTypeValue = std::make_unique<SudoSecurePathPolicyTypeValue>();
}

DAC_sudo_securepath::~DAC_sudo_securepath() {

}

bool DAC_sudo_securepath::apply() {
    return this->Sudo::apply();
}
