if(DEFINED FIC_TARGET_PLATFORM_INCLUDED)
    return()
endif()
set(FIC_TARGET_PLATFORM_INCLUDED TRUE)

set(FIC_TARGET_PLATFORM "" CACHE STRING
    "Target operating system profile: debian-12, debian-13, ubuntu-24.04, ubuntu-26.04 or alt-p11")
set_property(CACHE FIC_TARGET_PLATFORM PROPERTY STRINGS
    debian-12
    debian-13
    ubuntu-24.04
    ubuntu-26.04
    alt-p11)

set(FIC_PASSWORD_MIN_AGE_DEFAULT 0)
set(FIC_PASSWORD_MAX_AGE_DEFAULT 99999)
set(FIC_PASSWORD_WARN_AGE_DEFAULT 7)
set(FIC_REGULAR_UID_MIN_DEFAULT 1000)
set(FIC_REGULAR_UID_MAX_DEFAULT 60000)

if(FIC_TARGET_PLATFORM STREQUAL "debian-12")
    set(FIC_TARGET_PLATFORM_PROFILE_SOURCE
        "${CMAKE_CURRENT_LIST_DIR}/../fic/src/platform/profiles/Debian12Profile.cpp")
elseif(FIC_TARGET_PLATFORM STREQUAL "debian-13")
    set(FIC_TARGET_PLATFORM_PROFILE_SOURCE
        "${CMAKE_CURRENT_LIST_DIR}/../fic/src/platform/profiles/Debian13Profile.cpp")
elseif(FIC_TARGET_PLATFORM STREQUAL "ubuntu-24.04")
    set(FIC_TARGET_PLATFORM_PROFILE_SOURCE
        "${CMAKE_CURRENT_LIST_DIR}/../fic/src/platform/profiles/Ubuntu2404Profile.cpp")
elseif(FIC_TARGET_PLATFORM STREQUAL "ubuntu-26.04")
    set(FIC_TARGET_PLATFORM_PROFILE_SOURCE
        "${CMAKE_CURRENT_LIST_DIR}/../fic/src/platform/profiles/Ubuntu2604Profile.cpp")
elseif(FIC_TARGET_PLATFORM STREQUAL "alt-p11")
    set(FIC_TARGET_PLATFORM_PROFILE_SOURCE
        "${CMAKE_CURRENT_LIST_DIR}/../fic/src/platform/profiles/AltP11Profile.cpp")
    set(FIC_PASSWORD_MAX_AGE_DEFAULT -1)
    set(FIC_PASSWORD_WARN_AGE_DEFAULT -1)
else()
    message(FATAL_ERROR
        "FIC_TARGET_PLATFORM must be explicitly set to one of: "
        "debian-12, debian-13, ubuntu-24.04, ubuntu-26.04, alt-p11. "
        "Example: -DFIC_TARGET_PLATFORM=alt-p11")
endif()

message(STATUS "FIC target platform: ${FIC_TARGET_PLATFORM}")
