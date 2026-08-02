cmake_minimum_required(VERSION 3.5)

project(fic_gui LANGUAGES CXX)

include(GNUInstallDirs)
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/FicInstallLayout.cmake)

if(NOT TARGET fic-ipc)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../fic-common/fic-ipc ${CMAKE_CURRENT_BINARY_DIR}/fic-ipc)
endif()
get_target_property(FIC_GUI_PRODUCT_VERSION_CORE fic-version FIC_PRODUCT_VERSION_CORE)
if(NOT FIC_GUI_PRODUCT_VERSION_CORE)
    message(FATAL_ERROR "fic-version does not expose FIC_PRODUCT_VERSION_CORE")
endif()

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets)
find_package(OpenSSL REQUIRED)

file(GLOB_RECURSE SRC_FILES
    "src/*.ui"
    "src/*.qrc"
    "src/*.cpp"
    "src/*/*.cpp"
    "src/*/*/*.cpp"
)

file(GLOB_RECURSE HDR_FILES
    "src/*.h"
    "src/*/*.h"
    "src/*/*/*.h"
)

list(FILTER SRC_FILES EXCLUDE REGEX "[/\\\\][^/\\\\]*[Tt]est[^/\\\\]*\\.cpp$")
list(FILTER SRC_FILES EXCLUDE REGEX ".*/src/core/.*")
list(FILTER SRC_FILES EXCLUDE REGEX ".*/src/modules/.*")
list(FILTER HDR_FILES EXCLUDE REGEX ".*/src/core/.*")
list(FILTER HDR_FILES EXCLUDE REGEX ".*/src/modules/.*")

if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_executable(fic-gui
        MANUAL_FINALIZATION
        ${SRC_FILES} ${HDR_FILES}
    )
else()
    if(ANDROID)
        add_library(fic-gui SHARED
            ${SRC_FILES} ${HDR_FILES}
        )
    else()
        add_executable(fic-gui
            ${SRC_FILES} ${HDR_FILES}
        )
    endif()
endif()

target_link_libraries(fic-gui PRIVATE
    Qt${QT_VERSION_MAJOR}::Widgets
    OpenSSL::SSL
    OpenSSL::Crypto
    fic-ipc
)

target_include_directories(fic-gui PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/wrappers
)

set_target_properties(fic-gui PROPERTIES
    MACOSX_BUNDLE_GUI_IDENTIFIER my.example.com
    MACOSX_BUNDLE_BUNDLE_VERSION ${FIC_GUI_PRODUCT_VERSION_CORE}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${FIC_GUI_PRODUCT_VERSION_CORE}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

install(TARGETS fic-gui
    RUNTIME DESTINATION "${FIC_PRIVATE_BINDIR}" COMPONENT fic-gui
    BUNDLE DESTINATION "${FIC_PRIVATE_BINDIR}" COMPONENT fic-gui
    LIBRARY DESTINATION "${FIC_PRIVATE_BINDIR}"
    COMPONENT fic-gui)

if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(fic-gui)
endif()
