import dpkt

class IPv6Packet:
    def __init__(
        self,
        ipv6_base: dpkt.ip6.IP6
    ) -> None:
        self.ipv6_base = ipv6_base
    
    @property
    def data(self) -> bytes:
        return self.ipv6_base.data

    def __repr__(self):
        return (
            f"IPv6Packet(V={self.ipv6_base.v}, SRC={self.ipv6_base.src}, DST={self.ipv6_base.dst}, PLEN={self.ipv6_base.plen} NEXT={self.ipv6_base.nxt} HLIM={self.ipv6_base.hlim}) DATA={self.data}"
        )

    @classmethod
    def parse(cls, data: bytes):
        ipv6_base = dpkt.ip6.IP6(data)
        if ipv6_base.v != 6:
            raise ValueError(
                f'Invalid IP version: Not 6'
            )
        return cls(ipv6_base)