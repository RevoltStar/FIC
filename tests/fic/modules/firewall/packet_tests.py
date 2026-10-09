#!/usr/bin/env python3
"""Real packet validation. Run ONLY in disposable Podman with NET_ADMIN/SYS_ADMIN.

The executable runs the production coordinator/backend with a real nft transport.
All kernel mutations, sysctls and netns fixtures belong to the disposable container.
"""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time


def run(*args):
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f"{args}: {result.stderr}")
    return result.stdout


def rule(direction, peer, port, protocol="tcp"):
    return dict(direction=direction, protocol=protocol, source="any" if direction == "outgoing" else peer,
                destination=peer if direction == "outgoing" else "any", source_port="any",
                destination_port=port, action="allow")


def connect(address, port, expected=True, udp=False):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as sock:
        sock.settimeout(0.8)
        try:
            if udp:
                sock.sendto(b"fic-test", (address, port))
            else:
                sock.connect((address, port))
                sock.sendall(b"fic-test")
            received = sock.recv(64) == b"fic-test"
        except (TimeoutError, OSError):
            received = False
        assert received == expected, (address, port, udp, received, expected)


SERVER = r'''
import socket, threading, time

def serve(family, address, port, udp=False):
    sock=socket.socket(family, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    if family == socket.AF_INET6: sock.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
    sock.bind((address,port))
    if udp:
        while True:
            data,peer=sock.recvfrom(4096); sock.sendto(data,peer)
    else:
        sock.listen()
        def echo(client):
            try:
                while True:
                    data=client.recv(4096)
                    if not data: break
                    client.sendall(data)
            except OSError: pass
            finally: client.close()
        while True:
            client,_=sock.accept(); threading.Thread(target=echo,args=(client,),daemon=True).start()
for family,address in [(socket.AF_INET,"0.0.0.0"),(socket.AF_INET6,"::")]:
    for port,udp in [(18000,False),(18001,False),(18002,True),(53,True)]:
        threading.Thread(target=serve,args=(family,address,port,udp),daemon=True).start()
while True: time.sleep(1)
'''


def main():
    if not Path("/run/.containerenv").exists() or os.environ.get("FIC_DISPOSABLE_PACKET_TEST") != "1":
        raise RuntimeError("packet tests require explicitly authorized disposable Podman namespace")
    executable = sys.argv[1]
    run("ip", "netns", "add", "fic-peer")
    run("ip", "link", "add", "fic-main", "type", "veth", "peer", "name", "fic-peer-link")
    run("ip", "link", "set", "fic-peer-link", "netns", "fic-peer")
    for prefix, interface, v4, v6 in [([], "fic-main", "10.200.1.1/24", "fd00:200:1::1/64"),
                                   (["nsenter", "--net=/run/netns/fic-peer"], "fic-peer-link", "10.200.1.2/24", "fd00:200:1::2/64")]:
        run(*prefix, "ip", "addr", "add", v4, "dev", interface)
        run(*prefix, "ip", "-6", "addr", "add", v6, "dev", interface, "nodad")
        run(*prefix, "ip", "link", "set", interface, "up")
        run(*prefix, "ip", "link", "set", "lo", "up")
    run("ip", "netns", "add", "fic-forward")
    run("ip", "link", "add", "fic-main2", "type", "veth", "peer", "name", "fic-fwd-link")
    run("ip", "link", "set", "fic-fwd-link", "netns", "fic-forward")
    for prefix, interface, v4, v6 in [([], "fic-main2", "10.200.2.1/24", "fd00:200:2::1/64"),
                                   (["nsenter", "--net=/run/netns/fic-forward"], "fic-fwd-link", "10.200.2.2/24", "fd00:200:2::2/64")]:
        run(*prefix, "ip", "addr", "add", v4, "dev", interface)
        run(*prefix, "ip", "-6", "addr", "add", v6, "dev", interface, "nodad")
        run(*prefix, "ip", "link", "set", interface, "up")
        run(*prefix, "ip", "link", "set", "lo", "up")
    for namespace, network, gateway, network6, gateway6 in [
            ("fic-peer", "10.200.2.0/24", "10.200.1.1", "fd00:200:2::/64", "fd00:200:1::1"),
            ("fic-forward", "10.200.1.0/24", "10.200.2.1", "fd00:200:1::/64", "fd00:200:2::1")]:
        run("nsenter", "--net=/run/netns/" + namespace, "ip", "route", "add", network, "via", gateway)
        run("nsenter", "--net=/run/netns/" + namespace, "ip", "-6", "route", "add", network6, "via", gateway6)
    # Keep the routed leg deterministic; ND is exercised separately on the
    # directly attached IPv6 exception peer, with explicit neighbour flushing.
    peer2_mac = json.loads(run("nsenter", "--net=/run/netns/fic-forward", "ip", "-j", "link", "show", "fic-fwd-link"))[0]["address"]
    router2_mac = json.loads(run("ip", "-j", "link", "show", "fic-main2"))[0]["address"]
    run("ip", "-6", "neigh", "replace", "fd00:200:2::2", "lladdr", peer2_mac, "dev", "fic-main2", "nud", "permanent")
    run("nsenter", "--net=/run/netns/fic-forward", "ip", "-6", "neigh", "replace", "fd00:200:2::1", "lladdr", router2_mac, "dev", "fic-fwd-link", "nud", "permanent")
    forward_server = subprocess.Popen(["nsenter", "--net=/run/netns/fic-forward", "python3", "-u", "-c", SERVER])
    def check_forward(expected):
        for address in ["10.200.2.2", "fd00:200:2::2"]:
            client = "import socket;s=socket.socket(%s);s.settimeout(.8);s.connect(('%s',18001));s.sendall(b'x');assert s.recv(1)==b'x'" % (
                "socket.AF_INET6" if ":" in address else "socket.AF_INET", address)
            result = subprocess.run(["nsenter", "--net=/run/netns/fic-peer", "python3", "-c", client], capture_output=True)
            if (result.returncode == 0) != expected:
                for namespace in [None, "fic-peer", "fic-forward"]:
                    prefix = [] if namespace is None else ["nsenter", "--net=/run/netns/" + namespace]
                    print("diagnostic", namespace, run(*prefix, "ip", "-6", "route"), run(*prefix, "ip", "-6", "neigh"), file=sys.stderr)
                print(run("sysctl", "net.ipv6.conf.all.forwarding", "net.ipv6.conf.default.forwarding", "net.ipv6.conf.fic-main.forwarding", "net.ipv6.conf.fic-main2.forwarding"), file=sys.stderr)
            assert (result.returncode == 0) == expected, ("FORWARD", address, result.stderr)
    peer_server = subprocess.Popen(["nsenter", "--net=/run/netns/fic-peer", "python3", "-u", "-c", SERVER])
    local_server = subprocess.Popen(["python3", "-u", "-c", SERVER])
    coordinator = subprocess.Popen([executable, "--kernel-server"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   text=True, bufsize=1)
    def apply(quarantine, exceptions=None):
        coordinator.stdin.write(json.dumps(dict(quarantine=quarantine, exceptions=exceptions or [])) + "\n")
        coordinator.stdin.flush()
        result = json.loads(coordinator.stdout.readline())
        assert result["ok"], result
    try:
        time.sleep(1.5)
        # Foreign table survives every profile change. It does not reject peers.
        run("nft", "add", "table", "inet", "foreign_packet_test")
        apply(False)
        check_forward(True)
        for address in ["10.200.1.2", "fd00:200:1::2"]:
            connect(address, 18000)
            connect(address, 18002, udp=True)
        old = socket.create_connection(("10.200.1.2", 18000), timeout=0.8)
        old.settimeout(0.8)
        old.sendall(b"fic-test"); assert old.recv(64) == b"fic-test"
        apply(True)
        check_forward(False)
        for address in ["10.200.1.2", "fd00:200:1::2"]:
            connect(address, 18000, False)
            connect(address, 18002, False, udp=True)
            connect(address, 53, False, udp=True)
        old.sendall(b"blocked")
        try:
            assert not old.recv(64), "unallowed established flow survived"
        except TimeoutError:
            pass
        old.close()
        connect("127.0.0.1", 18000)
        connect("::1", 18000)
        # Input without an exception is blocked; OUTPUT-only tests are insufficient.
        client = "import socket; s=socket.socket();s.settimeout(.8);s.connect(('10.200.1.1',18001));s.sendall(b'x');assert s.recv(1)==b'x'"
        result = subprocess.run(["nsenter", "--net=/run/netns/fic-peer", "python3", "-c", client], capture_output=True)
        assert result.returncode != 0, "unpermitted INPUT succeeded"
        exceptions = [rule("outgoing", "10.200.1.2", 18001),
                      rule("outgoing", "10.200.1.2", 18002, "udp"),
                      rule("outgoing", "fd00:200:1::2", 18001),
                      rule("outgoing", "fd00:200:1::2", 18002, "udp"),
                      rule("incoming", "10.200.1.2", 18001),
                      rule("incoming", "fd00:200:1::2", 18001)]
        apply(True, exceptions)
        check_forward(False)
        run("ip", "-6", "neigh", "flush", "dev", "fic-main")
        run("nsenter", "--net=/run/netns/fic-peer", "ip", "-6", "neigh", "flush", "dev", "fic-peer-link")
        for address in ["10.200.1.2", "fd00:200:1::2"]:
            connect(address, 18001)
            connect(address, 18002, udp=True)
            connect(address, 18000, False)
            connect(address, 53, False, udp=True)
        run("nsenter", "--net=/run/netns/fic-peer", "python3", "-c", client)
        client6 = client.replace("socket.socket()", "socket.socket(socket.AF_INET6)").replace("10.200.1.1", "fd00:200:1::1")
        run("nsenter", "--net=/run/netns/fic-peer", "python3", "-c", client6)
        apply(False)
        check_forward(True)
        for address in ["10.200.1.2", "fd00:200:1::2"]:
            connect(address, 18000)
            connect(address, 53, udp=True)
        run("nft", "list", "table", "inet", "foreign_packet_test")
        print("PACKET PASS: IPv4/IPv6 input/output/forward, loopback, old unallowed TCP, TCP/UDP exceptions and replies, DNS deny, ND, NORMAL restoration, foreign table")
    finally:
        coordinator.terminate(); peer_server.terminate(); local_server.terminate(); forward_server.terminate()
        for process in [coordinator, peer_server, local_server, forward_server]: process.wait(timeout=5)
        run("ip", "netns", "delete", "fic-peer")
        run("ip", "netns", "delete", "fic-forward")


if __name__ == "__main__":
    main()
