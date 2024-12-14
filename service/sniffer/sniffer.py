import socket
import sys

import dpkt

from logkit import logger


def packet_handler(buf):
    # Check if IP packet is encapsulated in Ethernet frame
    eth = dpkt.ethernet.Ethernet(buf)
    if not isinstance(eth.data, dpkt.ip.IP):
        return

    # Check if UDP packet is encapsulated in IP packet
    ip = eth.data
    if not isinstance(ip.data, dpkt.udp.UDP):
        return

    # Check if DNS packet is encapsulated in UDP packet
    udp = ip.data
    if udp.dport == 53:
        dns = dpkt.dns.DNS(udp.data)
        if dns.qr == dpkt.dns.DNS_Q and len(dns.qd) > 0:  # Ensure if DNS query
            query = dns.qd[0].name
            logger.info(f"Source port: {udp.sport}, TXID: {dns.id}, Query: {query}")


def main():
    # Logger configuration
    tty = sys.stdout.isatty()
    logger.setup("", True, tty)
    if tty:
        logger.warning("TTY environment detected. Ensure you're running this script in Docker")

    # Sniffer
    logger.notice("Sniffing DNS queries:")
    s2 = socket.socket(  # 2nd OSI layer - Data Link (Ethernet frames)
        socket.AF_PACKET,
        socket.SOCK_RAW,
        socket.ntohs(0x0003)  # Capture everything
    )
    s2.bind(("eth0", 0))  # Bind for listening
    while True:
        buf = s2.recv(0xffff)  # Receive frames
        packet_handler(buf)


if __name__ == "__main__":
    main()
