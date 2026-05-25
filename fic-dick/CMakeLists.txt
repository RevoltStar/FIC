cmake_minimum_required(VERSION 3.5)

project(fic_dick LANGUAGES CXX)

include(GNUInstallDirs)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Автоматическое сканирование исходников
file(GLOB_RECURSE SRC_FILES
    "src/*.cpp"
    "src/*/*.cpp"
    "src/*/*/*.cpp"
)

list(APPEND SRC_FILES
    "${CMAKE_CURRENT_SOURCE_DIR}/../fic/src/utils/FileHandler.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/../fic/src/utils/ModuleConfigFileHandler.cpp"
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
add_executable(fic-dick ${SRC_FILES} ${HDR_FILES})

# Подключаем заголовки
target_include_directories(fic-dick PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core
    ${CMAKE_CURRENT_SOURCE_DIR}/src/modules
    ${CMAKE_CURRENT_SOURCE_DIR}/src/utils
    ${CMAKE_CURRENT_SOURCE_DIR}/../fic/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../fic/src/utils
)

target_link_libraries(fic-dick PRIVATE
    OpenSSL::Crypto
    SQLite::SQLite3
)
# Установка
install(TARGETS fic-dick DESTINATION bin)
install(DIRECTORY configs/ DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/fic)
