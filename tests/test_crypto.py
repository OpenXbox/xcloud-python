import pytest
import binascii
from xcloud.protocol import srtp_crypto

def test_decrypt(test_data: dict, crypto_context: srtp_crypto.SrtpContext):
    rtp_packet_raw = test_data['rtp_connection_probing.bin']

    plaintext = crypto_context.decrypt_packet(rtp_packet_raw)
    with pytest.raises(Exception):
        # Skip 1 byte of "additional data" to ensure invalid data
        crypto_context.decrypt(rtp_packet_raw[:-1])

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

def test_ping_packet_signing_static():
    # full udp payload: ffff010000000000d0c87bfa07d4e7fc9909d96e3cb3977d5232bbb391932236d56411f82d103bd5
    # srtp_key: 19J859/D70mZNfu9tEUdxgUVVMbRDkV/L2LavviX

    master_key = binascii.unhexlify('d7d27ce7dfc3ef499935fbbdb4451dc6')
    salt = binascii.unhexlify('ffff')
    data_to_sign =  binascii.unhexlify('00000000')

    ping_key = srtp_crypto.SrtpContext._get_ping_key(
        master_key=master_key,
        salt_bytes=salt,
        hash_algo=srtp_crypto.DigestType.SHA256
    )

    ping_signing_ctx = srtp_crypto.SrtpContext._create_keyed_hasher(
        ping_key, srtp_crypto.KeyedHashAlgorithm.HMAC_SHA256
    )

    ping_signing_ctx.update(data_to_sign)
    signature = ping_signing_ctx.finalize()

    assert binascii.hexlify(ping_key) == b'9dda3a76d9e73b41ad8b37881e9d5af973271573d2fd3783dd6650b9840afb94'
    assert len(signature) == 0x20
    assert binascii.hexlify(signature) == b'd0c87bfa07d4e7fc9909d96e3cb3977d5232bbb391932236d56411f82d103bd5'

def test_ping_packet_signing():
    # full udp payload: ffff010000000000d0c87bfa07d4e7fc9909d96e3cb3977d5232bbb391932236d56411f82d103bd5

    srtp_key = '19J859/D70mZNfu9tEUdxgUVVMbRDkV/L2LavviX'
    salt = binascii.unhexlify('ffff')
    data_to_sign =  binascii.unhexlify('00000000')

    ctx = srtp_crypto.SrtpContext.from_base64(srtp_key)
    ping_signing_ctx = ctx.get_ping_signer(salt)

    ping_signing_ctx.update(data_to_sign)
    signature = ping_signing_ctx.finalize()

    assert len(signature) == 0x20
    assert binascii.hexlify(signature) == b'd0c87bfa07d4e7fc9909d96e3cb3977d5232bbb391932236d56411f82d103bd5'