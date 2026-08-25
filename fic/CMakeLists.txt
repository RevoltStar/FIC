cmake_minimum_required(VERSION 3.5)

project(fic LANGUAGES CXX)

include(GNUInstallDirs)
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/FicInstallLayout.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/FicTargetPlatform.cmake)

if(NOT TARGET fic-ipc)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../fic-common/fic-ipc ${CMAKE_CURRENT_BINARY_DIR}/fic-ipc)
endif()
if(NOT TARGET fic-core)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../fic-common/fic-core ${CMAKE_CURRENT_BINARY_DIR}/fic-core)
endif()
if(NOT TARGET fic-policy)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../fic-common/fic-policy ${CMAKE_CURRENT_BINARY_DIR}/fic-policy)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Автоматическое сканирование исходников
file(GLOB_RECURSE SRC_FILES
    "src/*.cpp"
    "src/*/*.cpp"
    "src/*/*/*.cpp"
    "src/*/*/*/*.cpp"
)

# Собираем заголовки для IDE и MOC
file(GLOB_RECURSE HDR_FILES
    "src/*.h"
    "src/*/*.h"
    "src/*/*/*.h"
    "src/*/*/*/*.h"
)

# Исключаем тесты
list(FILTER SRC_FILES EXCLUDE REGEX "[/\\\\][^/\\\\]*[Tt]est[^/\\\\]*\\.cpp$")
# Distribution profiles export the same factory symbol, so exactly one of them
# must be selected by FicTargetPlatform.cmake.
list(FILTER SRC_FILES EXCLUDE REGEX "[/\\\\]platform[/\\\\].*\\.cpp$")
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

set(FIC_GENERATED_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated/include")
file(MAKE_DIRECTORY "${FIC_GENERATED_INCLUDE_DIR}/platform")
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/src/platform/PasswordAgingPolicyDefaultsGenerated.h.in"
    "${FIC_GENERATED_INCLUDE_DIR}/platform/PasswordAgingPolicyDefaultsGenerated.h"
    @ONLY)
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/src/platform/UserCreationPolicyDefaultsGenerated.h.in"
    "${FIC_GENERATED_INCLUDE_DIR}/platform/UserCreationPolicyDefaultsGenerated.h"
    @ONLY)

add_library(fic-platform STATIC
    src/platform/PlatformCompatibility.cpp
    src/platform/PlatformExecutableResolver.cpp
    ${FIC_TARGET_PLATFORM_PROFILE_SOURCE}
)
target_include_directories(fic-platform PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${FIC_GENERATED_INCLUDE_DIR}
)
if(CMAKE_LIBRARY_ARCHITECTURE)
    target_compile_definitions(fic-platform PRIVATE
        FIC_LIBRARY_ARCHITECTURE="${CMAKE_LIBRARY_ARCHITECTURE}")
endif()

# Создаем исполняемый файл
add_executable(fic ${SRC_FILES} ${HDR_FILES})

# Подключаем заголовки
target_include_directories(fic PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core
    ${CMAKE_CURRENT_SOURCE_DIR}/src/modules
)

target_link_libraries(fic PRIVATE OpenSSL::Crypto)
target_link_libraries(fic PRIVATE Threads::Threads)
target_link_libraries(fic PRIVATE fic-ipc)
target_link_libraries(fic PRIVATE fic-core)
target_link_libraries(fic PRIVATE fic-policy)
target_link_libraries(fic PRIVATE fic-platform)
set(FIC_GENERATED_SCRIPTS_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated/scripts")
file(MAKE_DIRECTORY "${FIC_GENERATED_SCRIPTS_DIR}")
file(MAKE_DIRECTORY "${FIC_GENERATED_SCRIPTS_DIR}/config")
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/src/scripts/config/IDENTITY_ACCESS.conf.in"
    "${FIC_GENERATED_SCRIPTS_DIR}/config/IDENTITY_ACCESS.conf"
    @ONLY)
foreach(template
        service/fic.service
        service/fic-notify.service
        service/fic_get_device_udev_info.service
        service/fic-udevadm-trigger
        tmpfiles/fic.conf)
    get_filename_component(template_dir "${template}" DIRECTORY)
    file(MAKE_DIRECTORY "${FIC_GENERATED_SCRIPTS_DIR}/${template_dir}")
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/src/scripts/${template}.in"
        "${FIC_GENERATED_SCRIPTS_DIR}/${template}"
        @ONLY)
endforeach()

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/src/scripts/notify/fic-notify-dispatcher"
    "${FIC_GENERATED_SCRIPTS_DIR}/notify/fic-notify-dispatcher"
    @ONLY)

install(TARGETS fic RUNTIME DESTINATION "${FIC_PRIVATE_BINDIR}" COMPONENT fic)
install(PROGRAMS
        "${FIC_GENERATED_SCRIPTS_DIR}/notify/fic-notify-dispatcher"
        "${FIC_GENERATED_SCRIPTS_DIR}/service/fic-udevadm-trigger"
        DESTINATION "${FIC_PRIVATE_BINDIR}" COMPONENT fic)
install(DIRECTORY src/scripts/config/ DESTINATION "${FIC_DEFAULT_CONFIG_DIR}"
        COMPONENT fic PATTERN "IDENTITY_ACCESS.conf.in" EXCLUDE)
install(FILES "${FIC_GENERATED_SCRIPTS_DIR}/config/IDENTITY_ACCESS.conf"
        DESTINATION "${FIC_DEFAULT_CONFIG_DIR}" COMPONENT fic)
install(DIRECTORY DESTINATION "${FIC_CONFIG_DIR}" COMPONENT fic)
install(DIRECTORY src/scripts/lang/ DESTINATION "${FIC_LANGUAGE_DIR}" COMPONENT fic)
install(FILES
        "${FIC_GENERATED_SCRIPTS_DIR}/service/fic.service"
        "${FIC_GENERATED_SCRIPTS_DIR}/service/fic-notify.service"
        "${FIC_GENERATED_SCRIPTS_DIR}/service/fic_get_device_udev_info.service"
        DESTINATION "${FIC_SYSTEMD_UNIT_DIR}" COMPONENT fic)
install(FILES "${FIC_GENERATED_SCRIPTS_DIR}/tmpfiles/fic.conf"
        DESTINATION "${FIC_TMPFILES_DIR}" COMPONENT fic)
install(FILES src/scripts/db/PCI_CLASS_ru.txt src/scripts/db/USB_CLASS_ru.txt
        DESTINATION "${FIC_DATA_DIR}" COMPONENT fic)
install(DIRECTORY src/scripts/image/ DESTINATION "${FIC_IMAGE_DIR}" COMPONENT fic)
