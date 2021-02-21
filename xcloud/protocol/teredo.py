import os
from dataclasses import dataclass, field
from struct import pack, unpack, unpack_from
from typing import Any, List, Optional, Tuple, Union

from . import ipv6

TEREDO_PORT = 3544
TEREDO_HEADER_LENGTH = 22

class TeredoPacket:
    def __init__(
        self,
        ipv6_base: ipv6.IPv6Packet
    ) -> None:
        self.ipv6 = ipv6_base

    def __repr__(self) -> str:
        return (
            f"TeredoPacket(IPv6={self.ipv6})"
        )

    @classmethod
    def parse(cls, data: bytes):
        if len(data) < TEREDO_HEADER_LENGTH:
            raise ValueError(
                f"Teredo packet length is less than {TEREDO_HEADER_LENGTH} bytes"
            )
        base = ipv6.IPv6Packet.parse(data)
        return cls(base)
        
