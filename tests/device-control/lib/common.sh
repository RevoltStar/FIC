#!/usr/bin/env bash

SCRIPT_NAME=${SCRIPT_NAME:-$(basename "$0")}

VM_IP=${FIC_VM_IP:-10.88.0.250}
VM_USER=${FIC_VM_USER:-admsys}
VM_PASSWORD=${FIC_VM_PASSWORD:-123123123}
VM_DOMAIN=${FIC_VM_DOMAIN:-}
LIBVIRT_URI=${FIC_LIBVIRT_URI:-qemu:///system}

REMOTE_HELPER=${FIC_REMOTE_HELPER:-/tmp/fic-dc-ipc.py}
REMOTE_FIC_CLI=${FIC_REMOTE_FIC_CLI:-/opt/fic/bin/fic-cli}
REMOTE_FIC_DICK=${FIC_REMOTE_FIC_DICK:-/opt/fic/bin/fic-dick}

WORK_DIR=${FIC_TEST_WORK_DIR:-/tmp/fic-device-control-qemu}
VIRTIO_TARGET=${FIC_VIRTIO_TARGET:-vdb}
USB_ALLOWED_TARGET=${FIC_USB_ALLOWED_TARGET:-sdb}
USB_BLOCKED_TARGET=${FIC_USB_BLOCKED_TARGET:-sdc}
CDROM_TARGET=${FIC_CDROM_TARGET:-sdd}
VIRTIO_NET_MAC=${FIC_VIRTIO_NET_MAC:-52:54:00:dc:10:01}
VIRTIO_NET_TYPE=${FIC_VIRTIO_NET_TYPE:-}
VIRTIO_NET_SOURCE=${FIC_VIRTIO_NET_SOURCE:-}

SSH_OPTS=(
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o LogLevel=ERROR
    -o ConnectTimeout=10
    -o ServerAliveInterval=5
    -o ServerAliveCountMax=3
)

TESTS_TOTAL=${TESTS_TOTAL:-0}
TESTS_FAILED=${TESTS_FAILED:-0}
CURRENT_TEST=${CURRENT_TEST:-}

ORIG_BLOCK_USB_STATUS=${ORIG_BLOCK_USB_STATUS:-}
ORIG_BLOCK_USB_VALUE=${ORIG_BLOCK_USB_VALUE:-}

VIRTIO_DISK="$WORK_DIR/fic-dc-virtio.qcow2"
USB_ALLOWED_DISK="$WORK_DIR/fic-dc-usb-allowed.qcow2"
USB_BLOCKED_DISK="$WORK_DIR/fic-dc-usb-blocked.qcow2"
CDROM_IMAGE="$WORK_DIR/fic-dc-cdrom.raw"
USB_HID_XML="$WORK_DIR/fic-dc-usb-hid.xml"
USB_TABLET_XML="$WORK_DIR/fic-dc-usb-tablet.xml"
PCI_RNG_XML="$WORK_DIR/fic-dc-pci-rng.xml"
SERIAL_CHANNEL_XML="$WORK_DIR/fic-dc-serial-channel.xml"

VIRTIO_SERIAL="FICDCVIRTIO01"
USB_ALLOWED_SERIAL="FICDCUSBOK01"
USB_BLOCKED_SERIAL="FICDCUSBBLOCK01"

log() {
    printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"
}

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    return 1
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "missing command: $1"
}

ssh_base() {
    sshpass -p "$VM_PASSWORD" ssh "${SSH_OPTS[@]}" "$VM_USER@$VM_IP" "$@"
}

virsh_cmd() {
    if [[ -n "$LIBVIRT_URI" ]]; then
        virsh --connect "$LIBVIRT_URI" "$@"
    else
        virsh "$@"
    fi
}

remote() {
    local cmd=$1
    ssh_base "bash -lc $(printf '%q' "$cmd")"
}

remote_sudo() {
    local cmd=$1
    local quoted_pw quoted_cmd
    quoted_pw=$(printf '%q' "$VM_PASSWORD")
    quoted_cmd=$(printf '%q' "$cmd")
    ssh_base "printf '%s\n' $quoted_pw | sudo -S -p '' bash -lc $quoted_cmd"
}

json_field() {
    local field=$1
    python3 -c 'import json,sys; data=json.load(sys.stdin); print(data.get(sys.argv[1], ""))' "$field"
}

device_field() {
    local field=$1
    python3 -c 'import json,sys; data=json.load(sys.stdin); print(data.get("device", data).get(sys.argv[1], ""))' "$field"
}

expect_eq() {
    local actual=$1
    local expected=$2
    local message=$3
    [[ "$actual" == "$expected" ]] || fail "$message: expected '$expected', got '$actual'"
}

expect_nonempty() {
    local actual=$1
    local message=$2
    [[ -n "$actual" ]] || fail "$message"
}

run_test() {
    CURRENT_TEST=$1
    shift
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    log "TEST $TESTS_TOTAL: $CURRENT_TEST"
    if "$@"; then
        printf 'PASS: %s\n' "$CURRENT_TEST"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        printf 'FAIL: %s\n' "$CURRENT_TEST" >&2
    fi
    CURRENT_TEST=""
}

create_test_image() {
    local image=$1
    rm -f "$image"
    qemu-img create -f qcow2 "$image" 64M >/dev/null
}

detect_domain() {
    if [[ -n "$VM_DOMAIN" ]]; then
        return 0
    fi

    local domain mac
    while IFS= read -r domain; do
        [[ -n "$domain" ]] || continue
        if virsh_cmd domifaddr "$domain" --source agent 2>/dev/null | grep -q "$VM_IP"; then
            VM_DOMAIN=$domain
            return 0
        fi
        if virsh_cmd domifaddr "$domain" --source lease 2>/dev/null | grep -q "$VM_IP"; then
            VM_DOMAIN=$domain
            return 0
        fi
    done < <(virsh_cmd list --name)

    mac=$(ip neigh show "$VM_IP" 2>/dev/null | awk '/lladdr/ {print tolower($5); exit}')
    if [[ -n "$mac" ]]; then
        while IFS= read -r domain; do
            [[ -n "$domain" ]] || continue
            if virsh_cmd domiflist "$domain" 2>/dev/null | awk -v mac="$mac" 'tolower($5) == mac {found=1} END {exit found ? 0 : 1}'; then
                VM_DOMAIN=$domain
                return 0
            fi
        done < <(virsh_cmd list --name)
    fi

    fail "cannot detect libvirt domain for $VM_IP on $LIBVIRT_URI; set FIC_VM_DOMAIN"
}

domain_is_running() {
    virsh_cmd list --state-running --name | awk -v domain="$VM_DOMAIN" '$0 == domain {found=1} END {exit found ? 0 : 1}'
}

install_remote_helper() {
    ssh_base "cat > $(printf '%q' "$REMOTE_HELPER")" <<'PY'
#!/usr/bin/env python3
import json
import os
import subprocess
import socket
import sys

SOCKET = "/run/fic/fic-device.sock"


def request(payload):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.connect(SOCKET)
        sock.sendall((json.dumps(payload) + "\n").encode())
        sock.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    return json.loads(b"".join(chunks).decode())


def request_text(text):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.connect(SOCKET)
        sock.sendall(text.encode())
        sock.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    return json.loads(b"".join(chunks).decode())


def all_devices(include_disconnected=True):
    root_response = request({"command": "device_root"})
    if not root_response.get("ok"):
        raise RuntimeError(root_response.get("message", "device_root failed"))

    root = root_response["device"]
    result = [root]
    queue = [root]
    seen = {root["id"]}
    while queue:
        parent = queue.pop(0)
        children_response = request({
            "command": "device_children",
            "parent_id": parent["id"],
            "include_disconnected": include_disconnected,
        })
        if not children_response.get("ok"):
            raise RuntimeError(children_response.get("message", "device_children failed"))
        for child in children_response.get("children", []):
            child_id = child.get("id")
            if child_id in seen:
                continue
            seen.add(child_id)
            result.append(child)
            queue.append(child)
    return result


def attrs(device_id):
    response = request({"command": "device_attributes", "device_id": int(device_id)})
    if not response.get("ok"):
        raise RuntimeError(response.get("message", "device_attributes failed"))
    return response.get("attributes", {})


def print_json(value):
    print(json.dumps(value, ensure_ascii=False, sort_keys=True))


def udev_env_for_sysfs(sysfs_path):
    real_path = os.path.realpath(sysfs_path)
    if not real_path.startswith("/sys/devices/"):
        raise RuntimeError(f"sysfs path is outside /sys/devices: {real_path}")
    devpath = real_path[4:]
    env = {}
    completed = subprocess.run(
        ["udevadm", "info", "--query=property", f"--path={devpath}"],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    for line in completed.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator and key and value:
            env[key] = value
    env.setdefault("DEVPATH", devpath)
    return devpath, env


def main(argv):
    if len(argv) < 2:
        print("usage: fic-dc-ipc.py <raw|invalid-json|udev-from-sysfs|find-subsystem|count-subsystem|find-attr|find-current-attr|find-any-attr|events|set|reset|reset-path|ignore|delete> ...", file=sys.stderr)
        return 2

    mode = argv[1]
    if mode == "raw":
        print_json(request(json.loads(argv[2])))
        return 0

    if mode == "invalid-json":
        print_json(request_text("{not-json}\n"))
        return 0

    if mode == "udev-from-sysfs":
        action, subsystem, sysfs_path = argv[2], argv[3], argv[4]
        devpath, env = udev_env_for_sysfs(sysfs_path)
        response = request({
            "command": "udev_event",
            "action": action,
            "devpath": devpath,
            "subsystem": subsystem,
            "env": env,
        })
        print_json(response)
        return 0 if response.get("ok") else 1

    if mode == "find-subsystem":
        subsystem = argv[2]
        connected = argv[3].lower() == "true" if len(argv) > 3 else None
        for device in all_devices(include_disconnected=True):
            if device.get("subsystem") != subsystem:
                continue
            if connected is not None and bool(device.get("connected")) != connected:
                continue
            print_json(device)
            return 0
        return 3

    if mode == "count-subsystem":
        subsystem = argv[2]
        connected = argv[3].lower() == "true" if len(argv) > 3 else None
        count = 0
        for device in all_devices(include_disconnected=True):
            if device.get("subsystem") != subsystem:
                continue
            if connected is not None and bool(device.get("connected")) != connected:
                continue
            count += 1
        print(count)
        return 0

    if mode == "find-attr":
        name, needle = argv[2], argv[3]
        connected = argv[4].lower() == "true" if len(argv) > 4 else None
        for device in all_devices(include_disconnected=True):
            if connected is not None and bool(device.get("connected")) != connected:
                continue
            value = attrs(device["id"]).get(name, "")
            if needle in value:
                print_json({"device": device, "attributes": attrs(device["id"])})
                return 0
        return 3

    if mode == "find-current-attr":
        name, needle = argv[2], argv[3]
        for device in all_devices(include_disconnected=False):
            value = attrs(device["id"]).get(name, "")
            if needle in value:
                print_json({"device": device, "attributes": attrs(device["id"])})
                return 0
        return 3

    if mode == "find-any-attr":
        names, needle = argv[2].split(","), argv[3]
        connected = argv[4].lower() == "true" if len(argv) > 4 else None
        for device in all_devices(include_disconnected=True):
            if connected is not None and bool(device.get("connected")) != connected:
                continue
            attributes = attrs(device["id"])
            for name in names:
                value = attributes.get(name, "")
                if needle in value:
                    print_json({"device": device, "attributes": attributes, "matched_attribute": name})
                    return 0
        return 3

    if mode == "events":
        response = request({"command": "device_events", "device_id": int(argv[2]), "limit": int(argv[3])})
        print_json(response)
        return 0 if response.get("ok") else 1

    if mode == "set":
        response = request({
            "command": "device_update_control_level",
            "device_id": int(argv[2]),
            "control_level": argv[3],
        })
        print_json(response)
        return 0 if response.get("ok") else 1

    if mode == "reset":
        response = request({"command": "device_reset_control", "device_id": int(argv[2])})
        print_json(response)
        return 0 if response.get("ok") else 1

    if mode == "reset-path":
        current_id = int(argv[2])
        reset_ids = []
        seen = set()
        while current_id > 0 and current_id not in seen:
            seen.add(current_id)
            current = request({"command": "device_get", "device_id": current_id})
            if not current.get("ok"):
                break
            device = current.get("device", {})
            parent_id = int(device.get("parent_id") or 0)
            if parent_id > 0:
                reset = request({"command": "device_reset_control", "device_id": current_id})
                if reset.get("ok"):
                    reset_ids.append(current_id)
            current_id = parent_id
        print_json({"ok": True, "message": "device path reset", "reset_ids": reset_ids})
        return 0

    if mode == "ignore":
        response = request({
            "command": "device_update_ignore_hierarchy",
            "device_id": int(argv[2]),
            "ignore_hierarchy": argv[3].lower() == "true",
        })
        print_json(response)
        return 0 if response.get("ok") else 1

    if mode == "delete":
        response = request({"command": "device_delete", "device_id": int(argv[2])})
        print_json(response)
        return 0 if response.get("ok") else 1

    print(f"unknown mode: {mode}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
PY
    remote "chmod 700 $(printf '%q' "$REMOTE_HELPER")"
}

device_ipc() {
    local payload=$1
    remote_sudo "python3 $(printf '%q' "$REMOTE_HELPER") raw $(printf '%q' "$payload")"
}

device_ipc_user() {
    local payload=$1
    remote "python3 $(printf '%q' "$REMOTE_HELPER") raw $(printf '%q' "$payload")"
}

find_device_attr() {
    local name=$1
    local needle=$2
    local connected=${3:-}
    if [[ -n "$connected" ]]; then
        remote_sudo "python3 $(printf '%q' "$REMOTE_HELPER") find-attr $(printf '%q' "$name") $(printf '%q' "$needle") $(printf '%q' "$connected")"
    else
        remote_sudo "python3 $(printf '%q' "$REMOTE_HELPER") find-attr $(printf '%q' "$name") $(printf '%q' "$needle")"
    fi
}

find_current_device_attr() {
    local name=$1
    local needle=$2
    remote_sudo "python3 $(printf '%q' "$REMOTE_HELPER") find-current-attr $(printf '%q' "$name") $(printf '%q' "$needle")"
}

find_device_any_attr() {
    local names=$1
    local needle=$2
    local connected=${3:-}
    if [[ -n "$connected" ]]; then
        remote_sudo "python3 $(printf '%q' "$REMOTE_HELPER") find-any-attr $(printf '%q' "$names") $(printf '%q' "$needle") $(printf '%q' "$connected")"
    else
        remote_sudo "python3 $(printf '%q' "$REMOTE_HELPER") find-any-attr $(printf '%q' "$names") $(printf '%q' "$needle")"
    fi
}

count_subsystem() {
    local subsystem=$1
    local connected=${2:-}
    if [[ -n "$connected" ]]; then
        remote_sudo "python3 $(printf '%q' "$REMOTE_HELPER") count-subsystem $(printf '%q' "$subsystem") $(printf '%q' "$connected")"
    else
        remote_sudo "python3 $(printf '%q' "$REMOTE_HELPER") count-subsystem $(printf '%q' "$subsystem")"
    fi
}

send_udev_from_sysfs() {
    local action=$1
    local subsystem=$2
    local sysfs_path=$3
    remote_sudo "python3 $(printf '%q' "$REMOTE_HELPER") udev-from-sysfs $(printf '%q' "$action") $(printf '%q' "$subsystem") $(printf '%q' "$sysfs_path")"
}

sysfs_names() {
    local dir=$1
    remote_sudo "if test -d $(printf '%q' "$dir"); then find $(printf '%q' "$dir") -mindepth 1 -maxdepth 1 -printf '%f\n' | sort; fi"
}

first_new_name() {
    local before=$1
    local after=$2
    python3 -c '
import sys
before = set(sys.argv[1].splitlines())
for item in sys.argv[2].splitlines():
    if item and item not in before:
        print(item)
        raise SystemExit(0)
raise SystemExit(1)
' "$before" "$after"
}

wait_for_attr() {
    local name=$1
    local needle=$2
    local connected=${3:-}
    local attempts=${4:-30}
    local response=""
    for _ in $(seq 1 "$attempts"); do
        if response=$(find_device_attr "$name" "$needle" "$connected" 2>/dev/null); then
            printf '%s\n' "$response"
            return 0
        fi
        sleep 1
    done
    return 1
}

wait_for_subsystem_count_gt() {
    local subsystem=$1
    local baseline=$2
    local connected=${3:-true}
    local attempts=${4:-30}
    local count=""
    for _ in $(seq 1 "$attempts"); do
        count=$(count_subsystem "$subsystem" "$connected" 2>/dev/null || printf '0')
        if [[ "$count" =~ ^[0-9]+$ && "$count" -gt "$baseline" ]]; then
            printf '%s\n' "$count"
            return 0
        fi
        sleep 1
    done
    fail "subsystem $subsystem connected count did not grow above $baseline"
}

wait_for_any_attr() {
    local names=$1
    local needle=$2
    local connected=${3:-}
    local attempts=${4:-30}
    local response=""
    for _ in $(seq 1 "$attempts"); do
        if response=$(find_device_any_attr "$names" "$needle" "$connected" 2>/dev/null); then
            printf '%s\n' "$response"
            return 0
        fi
        sleep 1
    done
    return 1
}

wait_for_test_disk() {
    local serial=$1
    local fallback_devname=$2
    local connected=${3:-}
    local attempts=${4:-45}
    local response=""
    if response=$(wait_for_any_attr "ID_SERIAL,ID_SERIAL_SHORT,SERIAL" "$serial" "$connected" "$attempts"); then
        printf '%s\n' "$response"
        return 0
    fi
    wait_for_attr DEVNAME "$fallback_devname" "$connected" 10
}

attach_disk() {
    local image=$1
    local target=$2
    local bus=$3
    local serial=$4
    virsh_cmd attach-disk "$VM_DOMAIN" "$image" "$target" \
        --live \
        --driver qemu \
        --subdriver qcow2 \
        --targetbus "$bus" \
        --serial "$serial"
}

attach_cdrom() {
    rm -f "$CDROM_IMAGE"
    qemu-img create -f raw "$CDROM_IMAGE" 1M >/dev/null || return
    virsh_cmd attach-disk "$VM_DOMAIN" "$CDROM_IMAGE" "$CDROM_TARGET" \
        --live \
        --type cdrom \
        --mode readonly \
        --driver qemu \
        --subdriver raw \
        --targetbus usb
}

detach_disk() {
    local target=$1
    virsh_cmd detach-disk "$VM_DOMAIN" "$target" --live >/dev/null 2>&1 || true
}

write_device_xmls() {
    mkdir -p "$WORK_DIR"
    cat > "$USB_HID_XML" <<XML
<input type='keyboard' bus='usb'/>
XML
    cat > "$USB_TABLET_XML" <<XML
<input type='tablet' bus='usb'/>
XML
    cat > "$PCI_RNG_XML" <<XML
<rng model='virtio'>
  <backend model='random'>/dev/urandom</backend>
</rng>
XML
    cat > "$SERIAL_CHANNEL_XML" <<XML
<channel type='pty'>
  <target type='virtio' name='fic.dc.serial.0'/>
</channel>
XML
}

attach_device_xml() {
    local xml=$1
    virsh_cmd attach-device "$VM_DOMAIN" "$xml" --live
}

detach_device_xml() {
    local xml=$1
    [[ -f "$xml" ]] || return 0
    virsh_cmd detach-device "$VM_DOMAIN" "$xml" --live >/dev/null 2>&1 || true
}

detect_net_attachment() {
    if [[ -n "$VIRTIO_NET_TYPE" && -n "$VIRTIO_NET_SOURCE" ]]; then
        return 0
    fi

    local detected
    detected=$(virsh_cmd domiflist "$VM_DOMAIN" 2>/dev/null | awk 'NR > 2 && NF >= 5 && $2 != "" && $3 != "" {print $2 " " $3; exit}')
    if [[ -z "$detected" ]]; then
        fail "cannot detect VM network attachment; set FIC_VIRTIO_NET_TYPE and FIC_VIRTIO_NET_SOURCE"
        return 1
    fi
    VIRTIO_NET_TYPE=${VIRTIO_NET_TYPE:-${detected%% *}}
    VIRTIO_NET_SOURCE=${VIRTIO_NET_SOURCE:-${detected#* }}
}

attach_virtio_net() {
    detect_net_attachment || return
    virsh_cmd attach-interface "$VM_DOMAIN" \
        --type "$VIRTIO_NET_TYPE" \
        --source "$VIRTIO_NET_SOURCE" \
        --model virtio \
        --mac "$VIRTIO_NET_MAC" \
        --live
}

detach_virtio_net() {
    if [[ -n "$VIRTIO_NET_TYPE" ]]; then
        virsh_cmd detach-interface "$VM_DOMAIN" --type "$VIRTIO_NET_TYPE" --mac "$VIRTIO_NET_MAC" --live >/dev/null 2>&1 || true
    else
        virsh_cmd detach-interface "$VM_DOMAIN" --mac "$VIRTIO_NET_MAC" --live >/dev/null 2>&1 || true
    fi
}

set_usb_storage_policy() {
    local enabled=$1
    local value=$2
    remote_sudo "$REMOTE_FIC_CLI policy set DC block_usb_storage $(printf '%q' "$value")"
    if [[ "$enabled" == "true" ]]; then
        remote_sudo "$REMOTE_FIC_CLI policy enable DC block_usb_storage"
    else
        remote_sudo "$REMOTE_FIC_CLI policy disable DC block_usb_storage"
    fi
}

save_policy_state() {
    ORIG_BLOCK_USB_STATUS=$(remote_sudo "$REMOTE_FIC_CLI policy isenable DC block_usb_storage" | tail -n 1 | tr -d '\r')
    ORIG_BLOCK_USB_VALUE=$(remote_sudo "$REMOTE_FIC_CLI policy value DC block_usb_storage" | tail -n 1 | tr -d '\r')
    expect_nonempty "$ORIG_BLOCK_USB_STATUS" "cannot read original block_usb_storage status"
    expect_nonempty "$ORIG_BLOCK_USB_VALUE" "cannot read original block_usb_storage value"
}

restore_policy_state() {
    [[ -n "$ORIG_BLOCK_USB_STATUS" && -n "$ORIG_BLOCK_USB_VALUE" ]] || return 0
    set_usb_storage_policy "$ORIG_BLOCK_USB_STATUS" "$ORIG_BLOCK_USB_VALUE" >/dev/null 2>&1 || true
}

reset_device_from_response() {
    local response=$1
    local id
    id=$(printf '%s\n' "$response" | device_field id 2>/dev/null)
    if [[ -n "$id" && "$id" != "0" && "$id" != "-1" ]]; then
        remote_sudo "python3 $(printf '%q' "$REMOTE_HELPER") reset-path $id" >/dev/null 2>&1 || true
    fi
}

reset_test_device_controls() {
    local response
    response=$(find_device_any_attr "ID_SERIAL,ID_SERIAL_SHORT,SERIAL" "$USB_ALLOWED_SERIAL" 2>/dev/null) &&
        reset_device_from_response "$response"
    response=$(find_device_any_attr "ID_SERIAL,ID_SERIAL_SHORT,SERIAL" "$USB_BLOCKED_SERIAL" 2>/dev/null) &&
        reset_device_from_response "$response"
    response=$(find_device_attr DEVNAME "/dev/$VIRTIO_TARGET" 2>/dev/null) &&
        reset_device_from_response "$response"
    response=$(find_device_attr DEVNAME "/dev/$CDROM_TARGET" 2>/dev/null) &&
        reset_device_from_response "$response"
    return 0
}

cleanup() {
    set +e
    reset_test_device_controls
    restore_policy_state
    detach_virtio_net
    detach_device_xml "$SERIAL_CHANNEL_XML"
    detach_device_xml "$PCI_RNG_XML"
    detach_device_xml "$USB_TABLET_XML"
    detach_device_xml "$USB_HID_XML"
    detach_disk "$CDROM_TARGET"
    detach_disk "$USB_BLOCKED_TARGET"
    detach_disk "$USB_ALLOWED_TARGET"
    detach_disk "$VIRTIO_TARGET"
    if [[ "$WORK_DIR" == /tmp/fic-device-control-* || "$WORK_DIR" == /tmp/fic-device-control-qemu ]]; then
        rm -rf "$WORK_DIR"
    fi
    remote "rm -f $(printf '%q' "$REMOTE_HELPER")" >/dev/null 2>&1
}

test_host_dependencies() {
    local missing=0
    for cmd in sshpass ssh virsh qemu-img python3 ip awk; do
        require_cmd "$cmd" || missing=1
    done
    [[ "$missing" -eq 0 ]]
}

test_ssh_reachable() {
    remote "printf 'ready\n'"
}

test_domain_running() {
    detect_domain || return
    local state
    if domain_is_running; then
        return 0
    fi
    state=$(virsh_cmd domstate "$VM_DOMAIN" | tr -d '\r')
    fail "domain $VM_DOMAIN must be running; virsh domstate returned '$state'"
}

test_fic_tools_ready() {
    remote_sudo "test -x $(printf '%q' "$REMOTE_FIC_CLI")" || return
    remote_sudo "test -x $(printf '%q' "$REMOTE_FIC_DICK")" || return
    remote_sudo "$REMOTE_FIC_DICK wait-daemon 10"
}

prepare_environment() {
    mkdir -p "$WORK_DIR"
    trap cleanup EXIT

    run_test "host dependencies are installed" test_host_dependencies
    if [[ "$TESTS_FAILED" -ne 0 ]]; then
        return 1
    fi
    run_test "guest SSH is reachable" test_ssh_reachable
    run_test "libvirt domain is running" test_domain_running
    if [[ "$TESTS_FAILED" -ne 0 ]]; then
        return 1
    fi
    install_remote_helper
    write_device_xmls
    run_test "FIC tools and fic-dick daemon are ready" test_fic_tools_ready
    if [[ "$TESTS_FAILED" -ne 0 ]]; then
        return 1
    fi
    save_policy_state
    reset_test_device_controls
}

print_summary() {
    printf '\nSummary: %s tests, %s failed\n' "$TESTS_TOTAL" "$TESTS_FAILED"
    [[ "$TESTS_FAILED" -eq 0 ]]
}
