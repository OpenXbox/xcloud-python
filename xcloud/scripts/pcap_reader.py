"""
PCAP Parser for XCloud network traffic
"""
import argparse
import logging
from typing import Any, Optional

import dpkt
from aiortc import rtp
from aioice import stun
from construct.lib import containers

from ..protocol import packets, teredo, ipv6


logging.basicConfig(level=logging.DEBUG)
containers.setGlobalPrintFullStrings(True)
LOG = logging.getLogger(__name__)

def get_info_stun(stun: stun.Message) -> None:
    return f'STUN: {stun}'

def get_info_rtp(rtp: rtp.RtpPacket) -> None:
    try:
        payload_name = packets.PayloadType(rtp.payload_type)
    except:
        payload_name = '<UNKNOWN>'

    return f'RTP: {payload_name.name} {rtp} SSRC={rtp.ssrc}'

def get_info_teredo(teredo: teredo.TeredoPacket) -> None:
    info = f'TEREDO: {teredo}'
    if teredo.ipv6.next_header != ipv6.NO_NEXT_HEADER:
        data = teredo.ipv6.data
        if type(data) == bytes:
            raise ValueError(f'TEREDO contains unparsed-subpacket: {data}')
        subpacket_info = get_info_general(data)
        info += f'\n -> TEREDO-WRAPPED: {subpacket_info}'
    return info


PACKET_TYPES = [
    (stun.parse_message, get_info_stun),
    (rtp.RtpPacket.parse, get_info_rtp),
    (teredo.TeredoPacket.parse, get_info_teredo)
]

def get_info_general(packet: Any) -> Optional[str]:
    if isinstance(packet, dpkt.udp.UDP):
        data = bytes(packet.data)
        for cls, info_func in PACKET_TYPES:
            try:
                instance = cls(data)
                info = info_func(instance)
                return info
            except:
                pass
    elif isinstance(packet, bytes):
        return '<RAW BYTES>'
    else:
        return '<UNHANDLED>'

def packet_filter(filepath):
    with open(filepath, 'rb') as fh:
        for ts, buf in dpkt.pcap.Reader(fh):
            eth = dpkt.ethernet.Ethernet(buf)

            # Make sure the Ethernet data contains an IP packet
            if not isinstance(eth.data, dpkt.ip.IP):
                continue

            ip = eth.data
            subpacket = ip.data
            if not isinstance(subpacket, dpkt.udp.UDP):
                continue

            yield(subpacket, ts)


def parse_file(pcap_filepath: str) -> None:
    for packet, timestamp in packet_filter(pcap_filepath):
        info = get_info_general(packet)
        if info:
            print(info)

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
