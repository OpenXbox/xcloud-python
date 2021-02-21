from binascii import unhexlify
from xcloud.protocol import teredo

def test_teredo_convert(teredo_packet: bytes):
    parsed = teredo.TeredoPacket.parse(teredo_packet)
    
    # Ipv6
    assert parsed.ipv6.version == 6
    assert parsed.ipv6.traffic_cls == 0x00
    assert parsed.ipv6.flow_label == 0x00
    assert parsed.ipv6.payload_len == 0x00
    assert parsed.ipv6.next_header == 59 # No next header
    assert parsed.ipv6.hop_limit == 21
    assert parsed.ipv6.src == unhexlify('20010000338c24f41c38f3fdd2f3c93d')
    assert parsed.ipv6.dst == unhexlify('20010000338c24f4043b30e3d2f3c93d')

    # Teredo source
    assert parsed.src_teredo.udp_port == 3074
    assert parsed.src_teredo.flags == 0x1c38
    assert str(parsed.src_teredo.teredo_server_ipv4) == '51.140.36.244'
    assert str(parsed.src_teredo.client_pub_ipv4) == '45.12.54.194'

    # Teredo destination
    assert parsed.dst_teredo.udp_port == 53020
    assert parsed.dst_teredo.flags == 0x43b
    assert str(parsed.dst_teredo.teredo_server_ipv4) == '51.140.36.244'
    assert str(parsed.dst_teredo.client_pub_ipv4) == '45.12.54.194'


