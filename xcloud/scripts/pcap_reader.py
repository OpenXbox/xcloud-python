"""
PCAP Parser for XCloud network traffic
"""
import argparse
import logging

import dpkt
from aiortc import rtp
from aioice import stun
from construct.lib import containers

from ..protocol import packets


logging.basicConfig(level=logging.DEBUG)
containers.setGlobalPrintFullStrings(True)
LOG = logging.getLogger(__name__)

def print_stun(stun: stun.Message) -> None:
    print(f'STUN: {stun}')

def print_rtp(rtp: rtp.RtpPacket) -> None:
    try:
        payload_name = packets.PayloadType(rtp.payload_type)
    except:
        payload_name = '<UNKNOWN>'

    print(f'RTP: {payload_name.name} {rtp}')

PACKET_TYPES = [
    (stun.parse_message, print_stun),
    (rtp.RtpPacket.parse, print_rtp)
]

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
        packet = bytes(packet.data)
        for cls, print_func in PACKET_TYPES:
            try:
                instance = cls(packet)
                print_func(instance)
            except:
                pass
        

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
