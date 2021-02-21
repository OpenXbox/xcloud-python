import os
from dataclasses import dataclass, field
from struct import pack, unpack, unpack_from
from typing import Any, List, Optional, Tuple, Union
from ipaddress import IPv4Address, IPv6Address

from . import ipv6

TEREDO_PORT = 3544
TEREDO_HEADER_LENGTH = 22


@dataclass
class TeredoEndpoint:
    teredo_server_ipv4: IPv4Address
    flags: int
    udp_port: int
    client_pub_ipv4: IPv4Address


def convert_teredo_addr_to_endpoint(
    teredo_addr: bytes
) -> TeredoEndpoint:
    """
    0x00-0x04 Prefix                // 32 bits
    0x04-0x08 Teredo server IPv4    // 32 bits
    0x08-0x0A Flags                 // 16 bits
    0x0A-0x0C UDP Port              // 16 bits
    0x0C-0x10 Client public IPv4    // 32 bits

    Client IP address and UDP port are obfuscated / inverted 
    """
    addr = IPv6Address(teredo_addr)
    teredo_tuple = addr.teredo
    if not teredo_tuple:
        raise ValueError('Not a teredo address')

    prefix, server_ipv4, flags, udp_port, client_ipv4 = \
        unpack('!IIHHI', teredo_addr)
    
    # Deobfuscate/invert client address and port
    client_ipv4 ^= 0xFFFFFFFF
    udp_port ^= 0xFFFF

    # Convert IP addresses to object
    server_ipv4 = IPv4Address(server_ipv4)
    client_ipv4 = IPv4Address(client_ipv4)
    
    assert server_ipv4 == teredo_tuple[0]
    assert client_ipv4 == teredo_tuple[1]

    return TeredoEndpoint(
        teredo_server_ipv4=server_ipv4,
        flags=flags,
        udp_port=udp_port,
        client_pub_ipv4=client_ipv4
    )

class TeredoPacket:
    def __init__(
        self,
        ipv6_base: ipv6.IPv6Packet,
        src_teredo: TeredoEndpoint,
        dst_teredo: TeredoEndpoint
    ) -> None:
        self.ipv6 = ipv6_base
        self.src_teredo = src_teredo
        self.dst_teredo = dst_teredo

    def __repr__(self) -> str:
        return (
            f"TeredoPacket(IPv6={self.ipv6}, SRC={self.src_teredo}, DST={self.dst_teredo})"
        )

    @classmethod
    def parse(cls, data: bytes):
        if len(data) < TEREDO_HEADER_LENGTH:
            raise ValueError(
                f"Teredo packet length is less than {TEREDO_HEADER_LENGTH} bytes"
            )
        base = ipv6.IPv6Packet.parse(data)
        src_teredo = convert_teredo_addr_to_endpoint(base.src)
        dst_teredo = convert_teredo_addr_to_endpoint(base.dst)
        return cls(base, src_teredo, dst_teredo)
        
