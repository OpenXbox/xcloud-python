"""
PCAP Parser for XCloud network traffic
"""
import argparse
import logging
import struct
from typing import Any, Optional

import dpkt
from hexdump import hexdump
from aiortc import rtp
from aioice import stun
from construct.lib import containers

from ..protocol import packets, teredo, ipv6, srtp_crypto


logging.basicConfig(level=logging.DEBUG)
containers.setGlobalPrintFullStrings(True)
LOG = logging.getLogger(__name__)

class XcloudPcapParser:
    def __init__(self, srtp_key: Optional[str]):
        self.crypto: Optional[srtp_crypto.SrtpContext] = None
        if srtp_key:
            self.outgoing_crypto = srtp_crypto.SrtpContext.from_base64(srtp_key)
            self.incoming_crypto = srtp_crypto.SrtpContext.from_base64(srtp_key)
        self.xbox_mac: Optional[bytes] = None

    @property
    def PACKET_TYPES(self):
        return [
            (stun.parse_message, self.get_info_stun),
            (rtp.RtpPacket.parse, self.get_info_rtp),
            (teredo.TeredoPacket.parse, self.get_info_teredo)
        ]

    def get_info_stun(self, stun: stun.Message, is_client: bool) -> None:
        return f'STUN: {stun}'

    def get_info_rtp(self, rtp: rtp.RtpPacket, is_client: bool) -> None:
        try:
            payload_name = packets.PayloadType(rtp.payload_type)
        except:
            payload_name = '<UNKNOWN>'

        direction = 'OUT -> ' if is_client else '<- IN '
        info_str = f'{direction} RTP: {payload_name.name} {rtp} SSRC={rtp.ssrc}'
        if self.incoming_crypto and self.outgoing_crypto:
            rtp_packet = rtp.serialize()
            try:
                if isinstance(is_client, bool):
                    if is_client:
                        rtp_decrypted = self.outgoing_crypto.decrypt_packet(rtp_packet)
                    else:
                        rtp_decrypted = self.incoming_crypto.decrypt_packet(rtp_packet)
                    info_str += "\n" + hexdump(rtp_decrypted.payload, result='return') + "\n"
                else:
                    info_str += "\n UNKNOWN DIRECTION \n"
            except Exception:
                info_str += "\n DECRYPTION FAILED \n"
        return info_str

    def get_info_teredo(self, teredo: teredo.TeredoPacket, is_client: bool) -> None:
        info = f'TEREDO: {teredo}'
        if teredo.ipv6.next_header != ipv6.NO_NEXT_HEADER:
            data = teredo.ipv6.data
            if type(data) == bytes:
                raise ValueError(f'TEREDO contains unparsed-subpacket: {data}')
            subpacket_info = self.get_info_general(data)
            info += f'\n -> TEREDO-WRAPPED: {subpacket_info}'
        return info

    def get_info_general(self, packet: Any, is_client: bool) -> Optional[str]:
        if isinstance(packet, dpkt.udp.UDP):
            data = bytes(packet.data)
            for cls, info_func in self.PACKET_TYPES:
                try:
                    instance = cls(data)
                    info = info_func(instance, is_client)
                    return info
                except:
                    pass
        elif isinstance(packet, bytes):
            return '<RAW BYTES>'
        else:
            return '<UNHANDLED>'

    def packet_filter(self, filepath):
        with open(filepath, 'rb') as fh:
            for ts, buf in dpkt.pcap.Reader(fh):
                eth = dpkt.ethernet.Ethernet(buf)

                # Make sure the Ethernet data contains an IP packet
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue

                ip = eth.data
                if not isinstance(ip.data, dpkt.udp.UDP):
                    continue

                # Check packet direction (client/host)
                if not self.xbox_mac and ip.data.sport == 3074:
                    self.xbox_mac = eth.src
                
                if self.xbox_mac:
                    is_client = (eth.src == self.xbox_mac)
                else:
                    is_client = None

                yield(ip, ts, is_client)


    def parse_file(self, pcap_filepath: str) -> None:
        for packet, timestamp, is_client in self.packet_filter(pcap_filepath):
            info = self.get_info_general(packet.data, is_client)
            if info:
                print(info)

def main():
    parser = argparse.ArgumentParser(
        "XCloud PCAP parser",
        description="PCAP Parser for XCloud network traffic"
    )
    parser.add_argument("filepath", help="Path to PCAP/NG file")
    parser.add_argument("--key", "-k", help="SRTP key")
    args = parser.parse_args()

    pcap_parser = XcloudPcapParser(args.key)
    pcap_parser.parse_file(args.filepath)


if __name__ == "__main__":
    main()
