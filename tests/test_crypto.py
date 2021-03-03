from xcloud.protocol import srtp_crypto

def test_decrypt(test_data: dict, crypto_context: srtp_crypto.SrtpContext):
    rtp_packet_raw = test_data['rtp_connection_probing.bin']

    rtp_header, rtp_body = rtp_packet_raw[:12], rtp_packet_raw[12:]
    plaintext = crypto_context.decrypt(rtp_body, aad=rtp_header)

    print(plaintext)
    assert plaintext is not None

def test_init_master_keys(srtp_key: str):
    from_base64 = srtp_crypto.SrtpMasterKeys.from_base64(srtp_key)
    null_keys = srtp_crypto.SrtpMasterKeys.null_keys()
    dummy_keys = srtp_crypto.SrtpMasterKeys.dummy_keys()

    assert len(from_base64.key1_buf) == 0x10
    assert from_base64.key1_len == 0x10
    assert len(from_base64.key2_buf) == 0x0E
    assert from_base64.key2_len == 0x0E

    assert null_keys is not None
    assert dummy_keys is not None
