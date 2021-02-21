import dpkt
from typing import Any
from enum import Enum

NO_NEXT_HEADER = 59

class IPv6Packet:
    def __init__(
        self,
        ipv6_base: dpkt.ip6.IP6
    ) -> None:
        self.ipv6_base = ipv6_base
    
    @property
    def version(self) -> int:
        return self.ipv6_base.v
    
    @property
    def traffic_cls(self) -> int:
        return self.ipv6_base.fc
    
    @property
    def flow_label(self) -> int:
        return self.ipv6_base.flow
    
    @property
    def payload_len(self) -> int:
        return self.ipv6_base.plen

    @property
    def next_header(self) -> int:
        return self.ipv6_base.nxt

    @property
    def hop_limit(self) -> int:
        return self.ipv6_base.hlim

    @property
    def src(self) -> bytes:
        return self.ipv6_base.src
    
    @property
    def dst(self) -> bytes:
        return self.ipv6_base.dst

    @property
    def data(self) -> Any:
        return self.ipv6_base.data

    def __repr__(self):
        return (
            f"IPv6Packet(V={self.version}, SRC={self.src}, DST={self.dst}, PLEN={self.payload_len} NEXT={self.next_header} HLIM={self.hop_limit})"
        )

    @classmethod
    def parse(cls, data: bytes):
        ipv6_base = dpkt.ip6.IP6(data)
        if ipv6_base.v != 6:
            raise ValueError(
                f'Invalid IP version: Not 6'
            )
        return cls(ipv6_base)