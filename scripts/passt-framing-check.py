#!/usr/bin/env python3
"""Confirm real passt's `--fd` qemu-socket framing matches the mvm bridge's
assumption: each ethernet frame is prefixed with a 4-byte big-endian length.

Spawns real passt on one end of an AF_UNIX SOCK_STREAM socketpair, sends a
4-byte-BE-framed DHCP DISCOVER (exactly how `gateway_bridge::write_one_frame`
frames it), and asserts passt replies with a 4-byte-BE-framed DHCP OFFER
(read exactly how `read_one_frame` reads it). No KVM, no microVM — passt is
userspace. This is the empirical check behind Plan 141's Passt-arm framing.
"""
import os, socket, struct, subprocess, sys, time

def ip_checksum(b):
    if len(b) % 2:
        b += b"\x00"
    s = sum(struct.unpack(f">{len(b)//2}H", b))
    s = (s & 0xFFFF) + (s >> 16)
    s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

def dhcp_discover(mac=b"\x02\x00\x00\x00\x00\x42"):
    # BOOTP/DHCP DISCOVER
    d = bytes([1, 1, 6, 0]) + struct.pack(">I", 0x12345678)
    d += struct.pack(">HH", 0, 0)            # secs, flags
    d += b"\x00" * 16                         # ciaddr,yiaddr,siaddr,giaddr
    d += mac + b"\x00" * 10                   # chaddr (16)
    d += b"\x00" * 64 + b"\x00" * 128         # sname, file
    d += bytes([0x63, 0x82, 0x53, 0x63])      # magic cookie
    d += bytes([53, 1, 1])                    # opt 53 = DISCOVER
    d += bytes([55, 3, 1, 3, 6])              # opt 55 param request list
    d += bytes([255])                         # end
    d += b"\x00" * (300 - len(d))             # pad
    # UDP 68 -> 67
    udp = struct.pack(">HHHH", 68, 67, 8 + len(d), 0) + d
    # IPv4 0.0.0.0 -> 255.255.255.255, proto 17
    total = 20 + len(udp)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 17, 0,
                     b"\x00\x00\x00\x00", b"\xff\xff\xff\xff")
    ip = ip[:10] + struct.pack(">H", ip_checksum(ip)) + ip[12:]
    # Ethernet: dst broadcast, src mac, IPv4
    return b"\xff" * 6 + mac + b"\x08\x00" + ip + udp

def dhcp_msg_type(frame):
    # eth(14) + ip + udp(8) + bootp ... option 53 after magic cookie
    if len(frame) < 14 + 20 + 8:
        return None
    ihl = (frame[14] & 0x0F) * 4
    udp_off = 14 + ihl
    if frame[14 + 9] != 17:  # proto UDP
        return None
    dhcp = frame[udp_off + 8:]
    if len(dhcp) < 240 or dhcp[236:240] != bytes([0x63, 0x82, 0x53, 0x63]):
        return None
    i = 240
    while i < len(dhcp):
        c = dhcp[i]
        if c == 255:
            break
        if c == 0:
            i += 1
            continue
        ln = dhcp[i + 1]
        if c == 53 and ln >= 1:
            return dhcp[i + 2]
        i += 2 + ln
    return None

def main():
    passt = sys.argv[1] if len(sys.argv) > 1 else "passt"
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    os.set_inheritable(child.fileno(), True)
    proc = subprocess.Popen(
        [passt, "--fd", str(child.fileno()), "-f", "--quiet", "--mtu", "65520"],
        pass_fds=[child.fileno()],
    )
    child.close()
    time.sleep(0.7)  # let passt initialize
    try:
        frame = dhcp_discover()
        parent.sendall(struct.pack(">I", len(frame)) + frame)  # 4-byte BE prefix
        parent.settimeout(6.0)
        deadline = time.time() + 6.0
        buf = b""
        while time.time() < deadline:
            try:
                chunk = parent.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
            # parse 4-byte-BE-framed frames out of the stream
            while len(buf) >= 4:
                n = struct.unpack(">I", buf[:4])[0]
                if n > 65535:
                    print(f"FAIL: implausible frame length {n} -> framing mismatch")
                    return 1
                if len(buf) < 4 + n:
                    break
                f, buf = buf[4:4 + n], buf[4 + n:]
                mt = dhcp_msg_type(f)
                if mt == 2:
                    print("PASS: real passt accepted 4-byte-BE-framed DISCOVER and "
                          "returned a 4-byte-BE-framed DHCP OFFER")
                    return 0
        print("FAIL: no DHCP OFFER seen within timeout (framing or passt config)")
        return 1
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()

if __name__ == "__main__":
    sys.exit(main())
