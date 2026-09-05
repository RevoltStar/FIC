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

set(FIC_PASSWORD_AGING_POLICY_MIN_DAYS_DEFAULT 0)
set(FIC_PASSWORD_AGING_POLICY_MAX_DAYS_DEFAULT 99999)
set(FIC_PASSWORD_AGING_POLICY_WARNING_DAYS_DEFAULT 7)
set(FIC_PASSWORD_AGING_POLICY_UID_MIN_DEFAULT 1000)
set(FIC_PASSWORD_AGING_POLICY_UID_MAX_DEFAULT 60000)
set(FIC_USER_CREATION_HOME_BASE_DEFAULT "/home")
set(FIC_USER_CREATION_CREATE_HOME_DEFAULT "no")
set(FIC_USER_CREATION_SKEL_DEFAULT "/etc/skel")
set(FIC_USER_CREATION_SHELL_DEFAULT "/bin/sh")
set(FIC_USER_CREATION_PRIVATE_GROUP_DEFAULT "yes")
set(FIC_USER_CREATION_PRIMARY_GROUP_DEFAULT "users")
set(FIC_PAM_PASSWORD_QUALITY_PROVIDER "pwquality")
set(FIC_PAM_PASSWORD_HISTORY_PROVIDER "pwhistory")
set(FIC_PAM_PASSWORD_TRANSACTION_MODULE OFF)
set(FIC_SUDO_SECURE_PATH_DEFAULT
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")

if(FIC_TARGET_PLATFORM STREQUAL "debian-12")
    set(FIC_TARGET_PLATFORM_PROFILE_SOURCE
        "${CMAKE_CURRENT_LIST_DIR}/../fic/src/platform/profiles/Debian12Profile.cpp")
elseif(FIC_TARGET_PLATFORM STREQUAL "debian-13")
    set(FIC_TARGET_PLATFORM_PROFILE_SOURCE
        "${CMAKE_CURRENT_LIST_DIR}/../fic/src/platform/profiles/Debian13Profile.cpp")
elseif(FIC_TARGET_PLATFORM STREQUAL "ubuntu-24.04")
    set(FIC_TARGET_PLATFORM_PROFILE_SOURCE
        "${CMAKE_CURRENT_LIST_DIR}/../fic/src/platform/profiles/Ubuntu2404Profile.cpp")
    set(FIC_SUDO_SECURE_PATH_DEFAULT
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin")
elseif(FIC_TARGET_PLATFORM STREQUAL "ubuntu-26.04")
    set(FIC_TARGET_PLATFORM_PROFILE_SOURCE
        "${CMAKE_CURRENT_LIST_DIR}/../fic/src/platform/profiles/Ubuntu2604Profile.cpp")
    set(FIC_SUDO_SECURE_PATH_DEFAULT
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin")
elseif(FIC_TARGET_PLATFORM STREQUAL "alt-p11")
    set(FIC_TARGET_PLATFORM_PROFILE_SOURCE
        "${CMAKE_CURRENT_LIST_DIR}/../fic/src/platform/profiles/AltP11Profile.cpp")
    set(FIC_PASSWORD_AGING_POLICY_UID_MIN_DEFAULT 500)
    set(FIC_USER_CREATION_CREATE_HOME_DEFAULT "yes")
    set(FIC_USER_CREATION_SHELL_DEFAULT "/bin/bash")
    set(FIC_PAM_PASSWORD_QUALITY_PROVIDER "passwdqc")
    set(FIC_PAM_PASSWORD_HISTORY_PROVIDER "pwhistory")
    set(FIC_PAM_PASSWORD_TRANSACTION_MODULE ON)
    set(FIC_SUDO_SECURE_PATH_DEFAULT
        "/sbin:/usr/sbin:/usr/local/sbin:/bin:/usr/bin:/usr/local/bin")
else()
    message(FATAL_ERROR
        "FIC_TARGET_PLATFORM must be explicitly set to one of: "
        "debian-12, debian-13, ubuntu-24.04, ubuntu-26.04, alt-p11. "
        "Example: -DFIC_TARGET_PLATFORM=alt-p11")
endif()

string(REPLACE ":" "\",\"" FIC_SUDO_SECURE_PATH_DEFAULT_JSON_ITEMS
    "${FIC_SUDO_SECURE_PATH_DEFAULT}")

set(FIC_REQUIRED_PAM_ENFORCEMENT_DEFAULT
    "pam_faillock,pam_${FIC_PAM_PASSWORD_QUALITY_PROVIDER}")
if(NOT FIC_PAM_PASSWORD_HISTORY_PROVIDER STREQUAL "none")
    string(APPEND FIC_REQUIRED_PAM_ENFORCEMENT_DEFAULT
        ",pam_${FIC_PAM_PASSWORD_HISTORY_PROVIDER}")
endif()

# Expose the selected composition to sibling validation targets. The values
# remain derived above from the same target-platform branch used by fic.
set(FIC_PAM_PASSWORD_QUALITY_PROVIDER
    "${FIC_PAM_PASSWORD_QUALITY_PROVIDER}" CACHE INTERNAL
    "Selected PAM password-quality provider" FORCE)
set(FIC_PAM_PASSWORD_HISTORY_PROVIDER
    "${FIC_PAM_PASSWORD_HISTORY_PROVIDER}" CACHE INTERNAL
    "Selected PAM password-history provider" FORCE)
set(FIC_PAM_PASSWORD_TRANSACTION_MODULE
    "${FIC_PAM_PASSWORD_TRANSACTION_MODULE}" CACHE INTERNAL
    "Whether the selected PAM composition requires the FIC transaction module"
    FORCE)

message(STATUS "FIC target platform: ${FIC_TARGET_PLATFORM}")
