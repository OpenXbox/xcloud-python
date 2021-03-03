import pytest
import binascii
from xcloud.protocol import srtp_crypto

def test_decrypt(test_data: dict, crypto_context: srtp_crypto.SrtpContext):
    rtp_packet_raw = test_data['rtp_connection_probing.bin']
    rtp_header, rtp_body = rtp_packet_raw[:12], rtp_packet_raw[12:]

    plaintext = crypto_context.decrypt(rtp_body, aad=rtp_header)
    with pytest.raises(Exception):
        # Skip 1 byte of "additional data" to ensure invalid data
        crypto_context.decrypt(rtp_body, aad=rtp_header[1:])

    assert plaintext is not None

def test_init_master_keys(srtp_key: str):
    from_base64 = srtp_crypto.SrtpMasterKeys.from_base64(srtp_key)
    null_keys = srtp_crypto.SrtpMasterKeys.null_keys()
    dummy_keys = srtp_crypto.SrtpMasterKeys.dummy_keys()

    assert len(from_base64.master_key) == 0x10
    assert len(from_base64.master_salt) == 0x0E

    assert null_keys is not None
    assert dummy_keys is not None

def test_derive_session_keys(srtp_key: str):
    session_keys = srtp_crypto.SrtpContext.from_base64(srtp_key).session_keys

    assert binascii.hexlify(session_keys.crypt_key) == b'45eaf77f1262638cf5d3ad0db5838d1d'
    assert binascii.hexlify(session_keys.auth_key) == b'd03d6382e1fec9480feb65e603c81e48'
    assert binascii.hexlify(session_keys.salt_key) == b'dad2a3c84f32ff7dbca6802ea223'
