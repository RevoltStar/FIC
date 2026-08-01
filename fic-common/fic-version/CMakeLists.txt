cmake_minimum_required(VERSION 3.5)

project(fic_version LANGUAGES CXX)

set(FIC_PRODUCT_VERSION "0.0.0-dev" CACHE STRING "FIC product version embedded in binaries")
if(NOT FIC_PRODUCT_VERSION MATCHES "^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\\.[0-9A-Za-z-]+)*)?(\\+[0-9A-Za-z-]+(\\.[0-9A-Za-z-]+)*)?$")
    message(FATAL_ERROR
        "FIC_PRODUCT_VERSION must be a Semantic Version (for example 1.2.3 or 1.2.3-rc.1)")
endif()
string(REGEX MATCH "-([^+]+)" FIC_PRODUCT_PRERELEASE_MATCH "${FIC_PRODUCT_VERSION}")
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

set(FIC_VERSION_GENERATED_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated/include)
file(MAKE_DIRECTORY ${FIC_VERSION_GENERATED_INCLUDE_DIR}/fic/version)
configure_file(
    include/fic/version/ProductVersion.h.in
    ${FIC_VERSION_GENERATED_INCLUDE_DIR}/fic/version/ProductVersion.h
    @ONLY
)

add_library(fic-version INTERFACE)
target_include_directories(fic-version INTERFACE
    $<BUILD_INTERFACE:${FIC_VERSION_GENERATED_INCLUDE_DIR}>
    $<INSTALL_INTERFACE:include>
)

install(FILES ${FIC_VERSION_GENERATED_INCLUDE_DIR}/fic/version/ProductVersion.h
        DESTINATION include/fic/version COMPONENT Development)
