cmake_minimum_required(VERSION 3.5)

project(fic LANGUAGES CXX)

include(GNUInstallDirs)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Автоматическое сканирование исходников
file(GLOB_RECURSE SRC_FILES
    "src/*.cpp"
    "src/*/*.cpp"
    "src/*/*/*.cpp"
)

# Собираем заголовки для IDE и MOC
file(GLOB_RECURSE HDR_FILES
    "src/*.h"
    "src/*/*.h"
    "src/*/*/*.h"
)

# Исключаем тесты
list(FILTER SRC_FILES EXCLUDE REGEX ".*test.*")
list(FILTER SRC_FILES EXCLUDE REGEX ".*Test.*")
find_package(SQLite3 REQUIRED)
find_package(OpenSSL REQUIRED)

# Создаем исполняемый файл
add_executable(fic ${SRC_FILES} ${HDR_FILES})

# Подключаем заголовки
target_include_directories(fic PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core
    ${CMAKE_CURRENT_SOURCE_DIR}/src/modules
    ${CMAKE_CURRENT_SOURCE_DIR}/src/utils
)

target_link_libraries(fic PRIVATE OpenSSL::Crypto)
target_link_libraries(fic PRIVATE SQLite::SQLite3)
# Установка
install(TARGETS fic DESTINATION bin)
install(PROGRAMS src/scripts/notify/fic-notify-dispatcher DESTINATION bin)
install(DIRECTORY src/scripts/config/ DESTINATION /opt/fic/config)
install(DIRECTORY src/scripts/lang/ DESTINATION /opt/fic/lang)
install(FILES src/scripts/service/fic.service
              src/scripts/service/fic.timer
              src/scripts/service/fic-notify.service
        DESTINATION /lib/systemd/system)
# Bash completion is installed by fic-cli package/component.
