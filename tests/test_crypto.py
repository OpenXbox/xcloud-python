from xcloud.protocol import srtp_crypto

def test_decrypt(test_data: dict, crypto_context: srtp_crypto.MsSrtpCrypto):
    rtp_packet_raw = test_data['rtp_connection_probing.bin']
    plaintext = crypto_context.decrypt_raw(rtp_packet_raw)

    print(plaintext)
    assert plaintext is not None
