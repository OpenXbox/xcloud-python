"""
PCAP Parser for XCloud network traffic
"""
import argparse
import logging
import struct
from typing import Any, Optional, Generator

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
            self.crypto = srtp_crypto.SrtpContext.from_base64(srtp_key)

    @property
    def PACKET_TYPES(self):
        return [
            (stun.parse_message, self.get_info_stun),
            (rtp.RtpPacket.parse, self.get_info_rtp),
            (teredo.TeredoPacket.parse, self.get_info_teredo)
        ]

    def get_info_stun(self, stun: stun.Message) -> None:
        return f'STUN: {stun}'

    def brute_force_nonce(self, nonce_orig: bytes) -> Generator:
        for byte1 in range(0, 0xFF):
            for byte2 in range(0, 0xFF):
                nonce_transform = b''.join([nonce_orig[:5], struct.pack('!B', byte1), nonce_orig[6:11], struct.pack('!B', byte2)])
                yield nonce_transform

    def get_info_rtp(self, rtp: rtp.RtpPacket) -> None:
        try:
            payload_name = packets.PayloadType(rtp.payload_type)
        except:
            payload_name = '<UNKNOWN>'

        info_str = f'RTP: {payload_name.name} {rtp} SSRC={rtp.ssrc}'
        if self.crypto:
            rtp_packet_serialized = rtp.serialize()
            rtp_header, rtp_data = rtp_packet_serialized[:12], rtp_packet_serialized[12:]
            nonce_orig = self.crypto.session_keys.nonce_key[2:]
            for nonce_transformed in self.brute_force_nonce(nonce_orig):
                try:
                    decrypted = self.crypto._decrypt(self.crypto.decryptor_ctx, nonce_transformed, rtp_data, rtp_header)
                    info_str += "\n" + hexdump(decrypted, result='return') + "\n"
                except Exception:
                    pass
        return info_str

    def get_info_teredo(self, teredo: teredo.TeredoPacket) -> None:
        info = f'TEREDO: {teredo}'
        if teredo.ipv6.next_header != ipv6.NO_NEXT_HEADER:
            data = teredo.ipv6.data
            if type(data) == bytes:
                raise ValueError(f'TEREDO contains unparsed-subpacket: {data}')
            subpacket_info = self.get_info_general(data)
            info += f'\n -> TEREDO-WRAPPED: {subpacket_info}'
        return info

    def get_info_general(self, packet: Any) -> Optional[str]:
        if isinstance(packet, dpkt.udp.UDP):
            data = bytes(packet.data)
            for cls, info_func in self.PACKET_TYPES:
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

    def packet_filter(self, filepath):
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


    def parse_file(self, pcap_filepath: str) -> None:
        for packet, timestamp in self.packet_filter(pcap_filepath):
            info = self.get_info_general(packet)
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
