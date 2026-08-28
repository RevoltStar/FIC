include("${FIC_SOURCE_DIR}/cmake/FicPamPolicyDefaults.cmake")

fic_resolve_pam_policy_defaults(
    "passwdqc" "pwhistory" synthetic_quality synthetic_history)
if(NOT synthetic_quality MATCHES "passwdqc_strength_thresholds.value=")
    message(FATAL_ERROR
        "synthetic passwdqc profile did not receive passwdqc defaults")
endif()
if(synthetic_quality MATCHES "password_min_length.value=")
    message(FATAL_ERROR
        "synthetic passwdqc profile received pwquality defaults")
endif()
if(NOT synthetic_history MATCHES "password_history_depth.value=")
    message(FATAL_ERROR
        "synthetic pwhistory capability did not receive history defaults")
endif()

fic_resolve_pam_policy_defaults(
    "pwquality" "none" synthetic_quality synthetic_history)
if(NOT synthetic_quality MATCHES "password_min_length.value=")
    message(FATAL_ERROR
        "synthetic pwquality profile did not receive pwquality defaults")
endif()
if(NOT synthetic_history STREQUAL "")
    message(FATAL_ERROR
        "profile without history capability received history defaults")
endif()
