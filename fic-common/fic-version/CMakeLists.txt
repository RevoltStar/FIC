cmake_minimum_required(VERSION 3.5)

project(fic_version LANGUAGES CXX)

set(FIC_PRODUCT_VERSION "0.0.0-alpha" CACHE STRING "FIC product version embedded in binaries")
set(FIC_BUILD_COMMIT "unknown" CACHE STRING "Full source commit embedded in binaries")
set(FIC_RELEASE_TAG "none" CACHE STRING "Exact release tag embedded in binaries")
option(FIC_RELEASE_BUILD "Enable the fail-closed compiled release contract" OFF)

if(NOT FIC_PRODUCT_VERSION MATCHES "^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\\.[0-9A-Za-z-]+)*)?$")
    message(FATAL_ERROR
        "FIC_PRODUCT_VERSION must be a Semantic Version without build metadata "
        "(for example 2.0.0 or 2.0.0-rc.1)")
endif()
string(REGEX MATCH "-([0-9A-Za-z.-]+)$" FIC_PRODUCT_PRERELEASE_MATCH "${FIC_PRODUCT_VERSION}")
if(FIC_PRODUCT_PRERELEASE_MATCH)
    set(FIC_PRODUCT_PRERELEASE "${CMAKE_MATCH_1}")
    string(REPLACE "." ";" FIC_PRODUCT_PRERELEASE_IDENTIFIERS
        "${FIC_PRODUCT_PRERELEASE}")
    foreach(FIC_PRODUCT_PRERELEASE_IDENTIFIER IN LISTS FIC_PRODUCT_PRERELEASE_IDENTIFIERS)
        if(FIC_PRODUCT_PRERELEASE_IDENTIFIER MATCHES "^0[0-9]+$")
            message(FATAL_ERROR
                "FIC_PRODUCT_VERSION numeric prerelease identifiers must not have leading zeroes")
        endif()
    endforeach()
endif()

string(REGEX MATCH
    "^([0-9]+)\\.([0-9]+)\\.([0-9]+)"
    FIC_PRODUCT_VERSION_CORE_MATCH
    "${FIC_PRODUCT_VERSION}")
set(FIC_PRODUCT_VERSION_MAJOR "${CMAKE_MATCH_1}")
set(FIC_PRODUCT_VERSION_MINOR "${CMAKE_MATCH_2}")
set(FIC_PRODUCT_VERSION_PATCH "${CMAKE_MATCH_3}")
set(FIC_PRODUCT_VERSION_CORE
    "${FIC_PRODUCT_VERSION_MAJOR}.${FIC_PRODUCT_VERSION_MINOR}.${FIC_PRODUCT_VERSION_PATCH}")

if(NOT FIC_BUILD_COMMIT STREQUAL "unknown")
    string(LENGTH "${FIC_BUILD_COMMIT}" FIC_BUILD_COMMIT_LENGTH)
    if(NOT FIC_BUILD_COMMIT MATCHES "^[0-9a-f]+$" OR
       NOT FIC_BUILD_COMMIT_LENGTH EQUAL 40)
        message(FATAL_ERROR "FIC_BUILD_COMMIT must be 'unknown' or a full 40-character lowercase Git SHA")
    endif()
endif()

if(FIC_RELEASE_BUILD)
    set(FIC_BUILD_KIND "release")
    if(FIC_BUILD_COMMIT STREQUAL "unknown")
        message(FATAL_ERROR "FIC_RELEASE_BUILD requires FIC_BUILD_COMMIT")
    endif()
    if(NOT FIC_RELEASE_TAG STREQUAL "v${FIC_PRODUCT_VERSION}")
        message(FATAL_ERROR
            "FIC_RELEASE_TAG must exactly match v${FIC_PRODUCT_VERSION} for a release build")
    endif()
else()
    set(FIC_BUILD_KIND "development")
    if(NOT FIC_RELEASE_TAG STREQUAL "none")
        message(FATAL_ERROR "Development builds must use FIC_RELEASE_TAG=none")
    endif()
endif()

set(FIC_VERSION_GENERATED_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated/include)
file(MAKE_DIRECTORY ${FIC_VERSION_GENERATED_INCLUDE_DIR}/fic/version)
configure_file(
    include/fic/version/ProductVersion.h.in
    ${FIC_VERSION_GENERATED_INCLUDE_DIR}/fic/version/ProductVersion.h
    @ONLY
)

add_library(fic-version INTERFACE)
set_property(TARGET fic-version PROPERTY
    FIC_PRODUCT_VERSION_CORE "${FIC_PRODUCT_VERSION_CORE}")
target_include_directories(fic-version INTERFACE
    $<BUILD_INTERFACE:${FIC_VERSION_GENERATED_INCLUDE_DIR}>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

install(FILES
        ${FIC_VERSION_GENERATED_INCLUDE_DIR}/fic/version/ProductVersion.h
        include/fic/version/BuildInfo.h
        DESTINATION include/fic/version COMPONENT Development)
