function(fic_resolve_pam_policy_defaults
         quality_provider history_provider
         quality_output history_output)
    if(quality_provider STREQUAL "passwdqc")
        set(quality_defaults
"passwdqc_strength_thresholds.status=DISABLE
passwdqc_strength_thresholds.value=disabled,24,11,8,7
passwdqc_passphrase_words.status=DISABLE
passwdqc_passphrase_words.value=3
passwdqc_match_length.status=DISABLE
passwdqc_match_length.value=4
passwdqc_similar_password.status=DISABLE
passwdqc_similar_password.value=deny
passwdqc_retry_count.status=DISABLE
passwdqc_retry_count.value=3")
    elseif(quality_provider STREQUAL "pwquality")
        set(quality_defaults
"password_min_length.status=DISABLE
password_min_length.value=12
password_min_classes.status=DISABLE
password_min_classes.value=3
password_check_username.status=DISABLE
password_check_username.value=yes
password_check_gecos.status=DISABLE
password_check_gecos.value=yes
password_min_changed_characters.status=DISABLE
password_min_changed_characters.value=1
password_min_lowercase.status=DISABLE
password_min_lowercase.value=0
password_min_uppercase.status=DISABLE
password_min_uppercase.value=0
password_min_digits.status=DISABLE
password_min_digits.value=0
password_min_other.status=DISABLE
password_min_other.value=0")
    else()
        message(FATAL_ERROR
            "Unsupported PAM password-quality provider for generated defaults: "
            "${quality_provider}")
    endif()

    if(history_provider STREQUAL "pwhistory")
        set(history_defaults
"password_history_depth.status=DISABLE
password_history_depth.value=5
password_history_enforce_for_root.status=DISABLE
password_history_enforce_for_root.value=yes")
    elseif(history_provider STREQUAL "none")
        set(history_defaults "")
    else()
        message(FATAL_ERROR
            "Unsupported PAM password-history provider for generated defaults: "
            "${history_provider}")
    endif()

    set(${quality_output} "${quality_defaults}" PARENT_SCOPE)
    set(${history_output} "${history_defaults}" PARENT_SCOPE)
endfunction()
