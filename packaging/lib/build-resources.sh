#!/usr/bin/env bash

# Shared resource policy for native and containerized package builders.
# Call fic_configure_build_resources before using BUILD_JOBS. Container
# wrappers must additionally call fic_configure_container_resources.

fic_resource_error() {
    printf 'Build resource configuration error: %s\n' "$1" >&2
    return 1
}

fic_require_positive_integer() {
    local variable_name="$1"
    local value="$2"

    case "$value" in
        ''|*[!0-9]*|0)
            fic_resource_error "$variable_name must be a positive integer, got '$value'"
            return 1
            ;;
    esac
}

fic_require_non_negative_integer() {
    local variable_name="$1"
    local value="$2"

    case "$value" in
        ''|*[!0-9]*)
            fic_resource_error "$variable_name must be a non-negative integer, got '$value'"
            return 1
            ;;
    esac
}

fic_detect_cpu_count() {
    local cpu_count
    local quota
    local period
    local quota_cpus

    cpu_count="$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')"
    fic_require_positive_integer "detected CPU count" "$cpu_count" || return 1

    if [ -r /sys/fs/cgroup/cpu.max ]; then
        read -r quota period < /sys/fs/cgroup/cpu.max
        if [ "$quota" != "max" ]; then
            fic_require_positive_integer "cgroup CPU quota" "$quota" || return 1
            fic_require_positive_integer "cgroup CPU period" "$period" || return 1
            quota_cpus=$((quota / period))
            if [ "$quota_cpus" -lt 1 ]; then
                quota_cpus=1
            fi
            if [ "$quota_cpus" -lt "$cpu_count" ]; then
                cpu_count="$quota_cpus"
            fi
        fi
    elif [ -r /sys/fs/cgroup/cpu/cpu.cfs_quota_us ] &&
         [ -r /sys/fs/cgroup/cpu/cpu.cfs_period_us ]; then
        quota="$(cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us)"
        period="$(cat /sys/fs/cgroup/cpu/cpu.cfs_period_us)"
        if [ "$quota" -gt 0 ]; then
            quota_cpus=$((quota / period))
            if [ "$quota_cpus" -lt 1 ]; then
                quota_cpus=1
            fi
            if [ "$quota_cpus" -lt "$cpu_count" ]; then
                cpu_count="$quota_cpus"
            fi
        fi
    fi

    printf '%s\n' "$cpu_count"
}

fic_detect_available_memory_mb() {
    local available_kb
    local available_mb
    local cgroup_max
    local cgroup_current
    local cgroup_available_mb

    available_kb="$(awk '/^MemAvailable:/ { print $2; exit }' /proc/meminfo)"
    fic_require_positive_integer "detected available memory" "$available_kb" || return 1
    available_mb=$((available_kb / 1024))

    if [ -r /sys/fs/cgroup/memory.max ] &&
       [ -r /sys/fs/cgroup/memory.current ]; then
        cgroup_max="$(cat /sys/fs/cgroup/memory.max)"
        cgroup_current="$(cat /sys/fs/cgroup/memory.current)"
        if [ "$cgroup_max" != "max" ] && [ "$cgroup_max" -gt "$cgroup_current" ]; then
            cgroup_available_mb=$(((cgroup_max - cgroup_current) / 1024 / 1024))
            if [ "$cgroup_available_mb" -lt "$available_mb" ]; then
                available_mb="$cgroup_available_mb"
            fi
        fi
    elif [ -r /sys/fs/cgroup/memory/memory.limit_in_bytes ] &&
         [ -r /sys/fs/cgroup/memory/memory.usage_in_bytes ]; then
        cgroup_max="$(cat /sys/fs/cgroup/memory/memory.limit_in_bytes)"
        cgroup_current="$(cat /sys/fs/cgroup/memory/memory.usage_in_bytes)"
        if [ "$cgroup_max" -gt "$cgroup_current" ]; then
            cgroup_available_mb=$(((cgroup_max - cgroup_current) / 1024 / 1024))
            if [ "$cgroup_available_mb" -lt "$available_mb" ]; then
                available_mb="$cgroup_available_mb"
            fi
        fi
    fi

    if [ "$available_mb" -lt 1 ]; then
        available_mb=1
    fi
    printf '%s\n' "$available_mb"
}

fic_configure_build_resources() {
    local cpu_count
    local available_memory_mb
    local cpu_reserve
    local cpu_jobs
    local memory_jobs
    local calculated_jobs

    if [ "${FIC_BUILD_RESOURCES_CONFIGURED:-0}" = "1" ] &&
       [ -n "${BUILD_JOBS:-}" ] &&
       [ -n "${FIC_BUILD_MEMORY_BUDGET_MB:-}" ] &&
       [ -n "${FIC_DETECTED_AVAILABLE_MEMORY_MB:-}" ] &&
       [ -n "${FIC_DETECTED_CPUS:-}" ]; then
        return 0
    fi

    FIC_HOST_MEMORY_RESERVE_MB="${FIC_HOST_MEMORY_RESERVE_MB:-2048}"
    FIC_BUILD_MEMORY_PER_JOB_MB="${FIC_BUILD_MEMORY_PER_JOB_MB:-2048}"
    FIC_BUILD_MAX_JOBS="${FIC_BUILD_MAX_JOBS:-8}"

    fic_require_non_negative_integer \
        "FIC_HOST_MEMORY_RESERVE_MB" "$FIC_HOST_MEMORY_RESERVE_MB" || return 1
    fic_require_positive_integer \
        "FIC_BUILD_MEMORY_PER_JOB_MB" "$FIC_BUILD_MEMORY_PER_JOB_MB" || return 1
    fic_require_positive_integer "FIC_BUILD_MAX_JOBS" "$FIC_BUILD_MAX_JOBS" || return 1

    FIC_DETECTED_CPUS="$(fic_detect_cpu_count)" || return 1
    FIC_DETECTED_AVAILABLE_MEMORY_MB="$(fic_detect_available_memory_mb)" || return 1
    cpu_count="$FIC_DETECTED_CPUS"
    available_memory_mb="$FIC_DETECTED_AVAILABLE_MEMORY_MB"

    if [ "$cpu_count" -ge 4 ]; then
        cpu_reserve=2
    elif [ "$cpu_count" -ge 2 ]; then
        cpu_reserve=1
    else
        cpu_reserve=0
    fi
    cpu_jobs=$((cpu_count - cpu_reserve))
    if [ "$cpu_jobs" -lt 1 ]; then
        cpu_jobs=1
    fi

    if [ "$available_memory_mb" -ge $((FIC_HOST_MEMORY_RESERVE_MB + 1024)) ]; then
        FIC_BUILD_MEMORY_BUDGET_MB=$((available_memory_mb - FIC_HOST_MEMORY_RESERVE_MB))
    else
        FIC_BUILD_MEMORY_BUDGET_MB=1024
        printf 'Warning: only %s MiB is available; using the minimum 1024 MiB build budget.\n' \
            "$available_memory_mb" >&2
    fi

    memory_jobs=$((FIC_BUILD_MEMORY_BUDGET_MB / FIC_BUILD_MEMORY_PER_JOB_MB))
    if [ "$memory_jobs" -lt 1 ]; then
        memory_jobs=1
    fi

    calculated_jobs="$cpu_jobs"
    if [ "$memory_jobs" -lt "$calculated_jobs" ]; then
        calculated_jobs="$memory_jobs"
    fi
    if [ "$FIC_BUILD_MAX_JOBS" -lt "$calculated_jobs" ]; then
        calculated_jobs="$FIC_BUILD_MAX_JOBS"
    fi

    if [ -n "${BUILD_JOBS:-}" ]; then
        fic_require_positive_integer "BUILD_JOBS" "$BUILD_JOBS" || return 1
    else
        BUILD_JOBS="$calculated_jobs"
    fi

    export BUILD_JOBS
    export FIC_BUILD_MEMORY_BUDGET_MB
    export FIC_DETECTED_AVAILABLE_MEMORY_MB
    export FIC_DETECTED_CPUS
    export FIC_BUILD_RESOURCES_CONFIGURED=1

    printf 'Build resources: jobs=%s, detected=%s CPU/%s MiB available, memory budget=%s MiB.\n' \
        "$BUILD_JOBS" \
        "$FIC_DETECTED_CPUS" \
        "$FIC_DETECTED_AVAILABLE_MEMORY_MB" \
        "$FIC_BUILD_MEMORY_BUDGET_MB"
}

fic_apply_build_priority() {
    local build_nice="${FIC_BUILD_NICE:-10}"
    local ionice_priority="${FIC_BUILD_IONICE_PRIORITY:-7}"

    if [ "${FIC_BUILD_PRIORITY_APPLIED:-0}" = "1" ]; then
        return 0
    fi

    fic_require_non_negative_integer "FIC_BUILD_NICE" "$build_nice" || return 1
    fic_require_non_negative_integer \
        "FIC_BUILD_IONICE_PRIORITY" "$ionice_priority" || return 1

    if [ "$build_nice" -gt 19 ]; then
        fic_resource_error "FIC_BUILD_NICE must not exceed 19"
        return 1
    fi
    if [ "$ionice_priority" -gt 7 ]; then
        fic_resource_error "FIC_BUILD_IONICE_PRIORITY must not exceed 7"
        return 1
    fi

    if command -v renice >/dev/null 2>&1; then
        renice -n "$build_nice" -p "$$" >/dev/null 2>&1 || true
    fi
    if command -v ionice >/dev/null 2>&1; then
        ionice -c 2 -n "$ionice_priority" -p "$$" >/dev/null 2>&1 || true
    fi
    export FIC_BUILD_PRIORITY_APPLIED=1
}

fic_configure_container_resources() {
    local cpu_quota

    CONTAINER_CPUS="${CONTAINER_CPUS:-$BUILD_JOBS}"
    CONTAINER_MEMORY_MB="${CONTAINER_MEMORY_MB:-$FIC_BUILD_MEMORY_BUDGET_MB}"
    CONTAINER_MEMORY_SWAP_MB="${CONTAINER_MEMORY_SWAP_MB:-$CONTAINER_MEMORY_MB}"

    fic_require_positive_integer "CONTAINER_CPUS" "$CONTAINER_CPUS" || return 1
    fic_require_positive_integer \
        "CONTAINER_MEMORY_MB" "$CONTAINER_MEMORY_MB" || return 1
    fic_require_positive_integer \
        "CONTAINER_MEMORY_SWAP_MB" "$CONTAINER_MEMORY_SWAP_MB" || return 1

    if [ "$CONTAINER_MEMORY_SWAP_MB" -lt "$CONTAINER_MEMORY_MB" ]; then
        fic_resource_error \
            "CONTAINER_MEMORY_SWAP_MB must be greater than or equal to CONTAINER_MEMORY_MB"
        return 1
    fi

    cpu_quota=$((CONTAINER_CPUS * 100000))
    FIC_CONTAINER_BUILD_ARGS=(
        --cpu-period 100000
        --cpu-quota "$cpu_quota"
        --memory "${CONTAINER_MEMORY_MB}m"
        --memory-swap "${CONTAINER_MEMORY_SWAP_MB}m"
    )
    FIC_CONTAINER_RUN_ARGS=(
        --cpus "$CONTAINER_CPUS"
        --memory "${CONTAINER_MEMORY_MB}m"
        --memory-swap "${CONTAINER_MEMORY_SWAP_MB}m"
    )

    printf 'Container limits: cpus=%s, memory=%s MiB, memory+swap=%s MiB.\n' \
        "$CONTAINER_CPUS" \
        "$CONTAINER_MEMORY_MB" \
        "$CONTAINER_MEMORY_SWAP_MB"
}
