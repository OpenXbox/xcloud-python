"""
PCAP Parser for XCloud network traffic
"""
import argparse

import dpkt
from construct.lib import containers


containers.setGlobalPrintFullStrings(True)


def packet_filter(filepath):
    with open(filepath, 'rb') as fh:
        for ts, buf in dpkt.pcap.Reader(fh):
            eth = dpkt.ethernet.Ethernet(buf)

            # Make sure the Ethernet data contains an IP packet
            if not isinstance(eth.data, dpkt.ip.IP):
                continue

            ip = eth.data
            if not isinstance(ip.data, dpkt.udp.UDP):
                continue

            yield(ip.data, ts)


def parse_file(pcap_filepath: str) -> None:
    for packet, timestamp in packet_filter(pcap_filepath):
        print(packet, timestamp)


def main():
    parser = argparse.ArgumentParser(
        "XCloud PCAP parser",
        description="PCAP Parser for XCloud network traffic"
    )
    parser.add_argument("filepath", help="Path to PCAP/NG file")
    args = parser.parse_args()

    parse_file(args.filepath)


if __name__ == "__main__":
    main()
