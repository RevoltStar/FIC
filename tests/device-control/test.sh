#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SCRIPT_NAME=$(basename "$0")
TEST_TYPE=smoke
MUTATION_ACK=false

usage() {
    cat <<USAGE
Usage:
  $SCRIPT_NAME --yes-i-know-this-mutates-vm --type [smoke|api|events|hierarchy|devices|enforcement|persistence|coldboot|race|security|secure|all]

Environment:
  FIC_VM_IP                 Guest IP, default: 10.88.0.250
  FIC_VM_USER               SSH user, default: admsys
  FIC_VM_PASSWORD           SSH/sudo password, default: value from task
  FIC_VM_DOMAIN             libvirt domain name. If empty, script tries domifaddr.
  FIC_LIBVIRT_URI           libvirt URI, default: qemu:///system
  FIC_TEST_WORK_DIR         Host temp dir for transient qcow2 images.
  FIC_VIRTIO_TARGET         Guest disk target for virtio block test, default: vdb
  FIC_USB_ALLOWED_TARGET    Guest disk target for USB allowed test, default: sdb
  FIC_USB_BLOCKED_TARGET    Guest disk target for USB blocked test, default: sdc
  FIC_CDROM_TARGET          Guest disk target for CD-ROM test, default: sdd
  FIC_VIRTIO_NET_TYPE       libvirt interface type for virtio-net test, autodetected
  FIC_VIRTIO_NET_SOURCE     libvirt source for virtio-net test, autodetected
  FIC_VIRTIO_NET_MAC        MAC for transient virtio-net test NIC, default: 52:54:00:dc:10:01

Types:
  smoke      basic QEMU/KVM attach/detach and DC allow/block path
  api        daemon API contracts, negative payloads, delete/reset/permanent
  events     device event records, limits, filtering, event order
  hierarchy  inherited effective policy checks
  devices    hotplug coverage for USB HID, input, PCI mock, CD-ROM, net, serial
  enforcement explicit allow/block/ignore/permanent enforcement and inheritance
  persistence daemon restart and persisted DB/policy state checks
  coldboot   configured-device enforcement across guest reboot
  race       concurrent IPC, rapid hotplug, and policy-toggle race checks
  security   socket/API rejection checks and CLI error propagation
  all        run all suites in one VM session
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --yes-i-know-this-mutates-vm)
            MUTATION_ACK=true
            shift
            ;;
        --type)
            TEST_TYPE=${2:-}
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'Unknown argument: %s\n\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ "$MUTATION_ACK" != "true" ]]; then
    usage >&2
    exit 2
fi

case "$TEST_TYPE" in
    smoke|api|events|hierarchy|devices|enforcement|persistence|coldboot|race|security|secure|all)
        ;;
    *)
        printf 'Unknown --type: %s\n\n' "$TEST_TYPE" >&2
        usage >&2
        exit 2
        ;;
esac

# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

abort_run() {
    printf '\nInterrupted, running cleanup...\n' >&2
    trap - EXIT
    cleanup
    exit 130
}

trap abort_run INT TERM

prepare_environment || {
    print_summary
    exit 1
}

run_suite_file() {
    local type=$1
    local before=$TESTS_TOTAL
    case "$type" in
        smoke)
            # shellcheck source=suites/smoke.sh
            source "$SCRIPT_DIR/suites/smoke.sh"
            run_smoke_suite
            ;;
        api)
            # shellcheck source=suites/api.sh
            source "$SCRIPT_DIR/suites/api.sh"
            run_api_suite
            ;;
        events)
            # shellcheck source=suites/events.sh
            source "$SCRIPT_DIR/suites/events.sh"
            run_events_suite
            ;;
        hierarchy)
            # shellcheck source=suites/hierarchy.sh
            source "$SCRIPT_DIR/suites/hierarchy.sh"
            run_hierarchy_suite
            ;;
        devices)
            # shellcheck source=suites/devices.sh
            source "$SCRIPT_DIR/suites/devices.sh"
            run_devices_suite
            ;;
        enforcement)
            # shellcheck source=suites/enforcement.sh
            source "$SCRIPT_DIR/suites/enforcement.sh"
            run_enforcement_suite
            ;;
        persistence)
            # shellcheck source=suites/persistence.sh
            source "$SCRIPT_DIR/suites/persistence.sh"
            run_persistence_suite
            ;;
        coldboot)
            # shellcheck source=suites/coldboot.sh
            source "$SCRIPT_DIR/suites/coldboot.sh"
            run_coldboot_suite
            ;;
        race)
            # shellcheck source=suites/race.sh
            source "$SCRIPT_DIR/suites/race.sh"
            run_race_suite
            ;;
        security|secure)
            # shellcheck source=suites/security.sh
            source "$SCRIPT_DIR/suites/security.sh"
            run_security_suite
            ;;
    esac
    if [[ "$TESTS_TOTAL" -eq "$before" ]]; then
        TESTS_TOTAL=$((TESTS_TOTAL + 1))
        TESTS_FAILED=$((TESTS_FAILED + 1))
        printf 'FAIL: suite %s did not run any tests\n' "$type" >&2
    fi
}

if [[ "$TEST_TYPE" == "all" ]]; then
    run_suite_file smoke
    run_suite_file api
    run_suite_file events
    run_suite_file hierarchy
    run_suite_file devices
    run_suite_file enforcement
    run_suite_file persistence
    run_suite_file coldboot
    run_suite_file race
    run_suite_file security
else
    run_suite_file "$TEST_TYPE"
fi

print_summary
