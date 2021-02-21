from typing import Dict, Tuple
import os
import pytest
from binascii import unhexlify

from xcloud.protocol import srtp_crypto

@pytest.fixture(scope='session')
def test_data() -> Dict[str, bytes]:
    data = {}
    data_path = os.path.join(os.path.dirname(__file__), 'data')
    for f in os.listdir(data_path):
        with open(os.path.join(data_path, f), 'rb') as fh:
            data[f] = fh.read()

    return data

@pytest.fixture(scope='session')
def teredo_packet() -> bytes:
    """
    Teredo IPv6 over UDP tunneling
    Internet Protocol Version 6, Src: 2001:0:338c:24f4:1c38:f3fd:d2f3:c93d, Dst: 2001:0:338c:24f4:43b:30e3:d2f3:c93d
    0110 .... = Version: 6
    .... 0000 0000 .... .... .... .... .... = Traffic Class: 0x00 (DSCP: CS0, ECN: Not-ECT)
        .... 0000 00.. .... .... .... .... .... = Differentiated Services Codepoint: Default (0)
        .... .... ..00 .... .... .... .... .... = Explicit Congestion Notification: Not ECN-Capable Transport (0)
    .... .... .... 0000 0000 0000 0000 0000 = Flow Label: 0x00000
    Payload Length: 0
    Next Header: No Next Header for IPv6 (59)
    Hop Limit: 21
    Source Address: 2001:0:338c:24f4:1c38:f3fd:d2f3:c93d
    Destination Address: 2001:0:338c:24f4:43b:30e3:d2f3:c93d
    [Source Teredo Server IPv4: 51.140.36.244]
    [Source Teredo Port: 3074]
    [Source Teredo Client IPv4: 45.12.54.194]
    [Destination Teredo Server IPv4: 51.140.36.244]
    [Destination Teredo Port: 53020]
    [Destination Teredo Client IPv4: 45.12.54.194]
    """
    return unhexlify(
        '6000000000003b1520010000338c24f41c38f3fdd2f3c93d20010000'
        '338c24f4043b30e3d2f3c93d01049eb8960803080000c0a889db0c02'
    )

@pytest.fixture(scope='session')
def session_id() -> str:
    return 'ED309CA5-F87C-439D-A429-63F417B552FA'

@pytest.fixture(scope='session')
def ice_credentials_client() -> Tuple[str, str]:
    return ('m99KewV+44E=', 'AneALie0L4P2tpvbh76nremwgQrT12/R3UYTG5VmUJ8=')

@pytest.fixture(scope='session')
def ice_credentials_host() -> Tuple[str, str]:
    return ('5yUsZtOzQ+w=', 'bWpvx/cXTk3/IeadJHO4T19W/OZopsbn0MwTAZqZu8w=')

@pytest.fixture(scope='session')
def srtp_key() -> str:
    return 'RdHzuLLVGuO1aHILIEVJ1UzR7RWVioepmpy+9SRf'

@pytest.fixture(scope='session')
def crypto_context(srtp_key: str) -> srtp_crypto.MsSrtpCrypto:
    return srtp_crypto.MsSrtpCrypto(srtp_key)