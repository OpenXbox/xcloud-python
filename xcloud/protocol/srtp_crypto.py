import base64
import struct
from enum import Enum
from typing import List, Optional
from dataclasses import dataclass

from aiortc.rtp import RtpPacket

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class TransformDirection(Enum):
    Encrypt = 0
    Decrypt = 1

class SrtpMasterKeys:
    MASTER_KEY_SIZE = 30
    DUMMY_KEY = (
        b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
        b'\x10\x11\x12\x13'
    )

    def __init__(self, master_key: bytes):
        assert len(master_key) == SrtpMasterKeys.MASTER_KEY_SIZE
        self.key1_buf = master_key[:0x10]
        self.key1_len = len(self.key1_buf)
        self.key1_counter = 0

        self.key2_buf = master_key[0x10:]
        self.key2_len = len(self.key2_buf)
        self.key2_counter = 0
    
    @classmethod
    def from_base64(cls, master_key_b64: str):
        return cls(base64.b64decode(master_key_b64))
    
    @classmethod
    def null_keys(cls):
        return cls(SrtpMasterKeys.MASTER_KEY_SIZE * b'\x00')
    
    @classmethod
    def dummy_keys(cls):
        dummy_key = SrtpMasterKeys.DUMMY_KEY[:0x10] + SrtpMasterKeys.DUMMY_KEY[:0x0E]
        return cls(dummy_key)

@dataclass
class SrtpSessionKey:
    buf: bytes
    len: int
    tag: bytes

    def __init__(self, key: bytes):
        self.buf = key
        self.len = len(key)
        self.tag = 1

class SrtpSessionKeys:
    def __init__(self, session_keys: List[SrtpSessionKey]):
        assert len(session_keys) == 3
        self.session_key_1 = session_keys[0]
        self.session_key_2 = session_keys[1]
        self.session_key_3 = session_keys[2]
    
    @property
    def aes_gcm_key(self) -> bytes:
        return self.session_key_1.buf
    
    @property
    def nonce_key(self) -> bytes:
        return self.session_key_3.buf

class SrtpContext:
    _backend = default_backend()

    def __init__(self, master_keys: SrtpMasterKeys):
        """
        MS-SRTP context
        """
        self.master_keys = master_keys
        self.session_keys = SrtpContext._derive_session_keys(
            self.master_keys.key1_buf, self.master_keys.key2_buf
        )

        # Set-up GCM crypto instances
        self.decryptor_ctx = SrtpContext._init_gcm_cryptor(self.session_keys.aes_gcm_key)
        self.decryptor_ctx = SrtpContext._init_gcm_cryptor(self.session_keys.aes_gcm_key)
    
    @classmethod
    def from_base64(cls, master_key_b64: str):
        return cls(
            SrtpMasterKeys.from_base64(master_key_b64)
        )
    
    @classmethod
    def from_bytes(cls, master_key: bytes):
        return cls(
            SrtpMasterKeys(master_key)
        )

    @staticmethod
    def _derive_single_key(input_key: bytes, bitmask: int = 0) -> bytes:
        keysize = len(input_key)
        keyout = bytearray(b'\x00' * 16)

        if keysize >= 14:
            keysize = 14

        if keysize:
            keyout[13] = input_key[keysize - 1]
            if keysize != 1:
                keyout[12] = input_key[keysize - 2]
                if keysize >= 3:
                    key_index = 0
                    for _ in range(2, keysize):
                        keyout[key_index + 11] = input_key[key_index + keysize - 3]
                        key_index = key_index - 1

        if keysize <= 13:
            null_count = 14 - keysize
            for i in range(0, null_count):
                keyout[i] = 0

        for index in range(14, 16):
            keyout[index] = 0
        
        if bitmask:
            len_before_xor = len(keyout)
            value_to_xor = struct.unpack_from('<I', keyout, 4)[0]
            value_to_xor ^= bitmask
            keyout = keyout[:4] + struct.pack('<I', value_to_xor) + keyout[8:]
            assert len(keyout) == len_before_xor
        return keyout

    @staticmethod
    def _crypt_ctr_oneshot(key: bytes, iv: bytes, plaintext: bytes, max_bytes: Optional[int] = None):
        """
        Encrypt data with AES-CTR (one-shot)
        """
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
        encryptor = cipher.encryptor()
        cipher_out = encryptor.update(plaintext) + encryptor.finalize()
        if max_bytes:
            # Trim to desired output
            cipher_out = cipher_out[:max_bytes]
        return cipher_out

    @staticmethod
    def _derive_session_keys(key1: bytes, key2: bytes) -> SrtpSessionKeys:
        session1 = SrtpContext._derive_single_key(key2)
        session2 = SrtpContext._derive_single_key(key2, 0x1000000)
        session3 = SrtpContext._derive_single_key(key2, 0x2000000)
  
        session1 = SrtpContext._crypt_ctr_oneshot(key1, session1, b'\x00' * 16)
        session2 = SrtpContext._crypt_ctr_oneshot(key1, session2, b'\x00' * 16)
        session3 = SrtpContext._crypt_ctr_oneshot(key1, session3, b'\x00' * 16, max_bytes=14)

        return SrtpSessionKeys([
            SrtpSessionKey(session1),
            SrtpSessionKey(session2),
            SrtpSessionKey(session3)
        ])

    @staticmethod
    def _init_gcm_cryptor(key: bytes) -> AESGCM:
        return AESGCM(key)

    @staticmethod
    def _decrypt(ctx: AESGCM, nonce: bytes, data: bytes, aad: bytes) -> bytes:
        return ctx.decrypt(nonce, data, aad)

    @staticmethod
    def _encrypt(ctx: AESGCM, nonce: bytes, data: bytes, aad: bytes) -> bytes:
        return ctx.encrypt(nonce, data, aad)

    def _get_transformed_nonce(self, transform_direction: TransformDirection) -> bytes:
        # Skip first 2 bytes of Nonce key
        nonce = bytearray(self.session_keys.nonce_key[2:])
        # TODO: Implement transform logic
        # FIXME: Just tranforming the Nonce to a known value for
        #        our single test packet
        nonce[-1] = nonce[-1] + 1

        return nonce

    def decrypt(self, data: bytes, aad: bytes) -> bytes:
        nonce = self._get_transformed_nonce(TransformDirection.Decrypt)
        return SrtpContext._decrypt(self.decryptor_ctx, nonce, data, aad)
    
    def encrypt(self, data: bytes, aad: bytes) -> RtpPacket:
        nonce = self._get_transformed_nonce(TransformDirection.Encrypt)
        return SrtpContext._encrypt(self.decryptor_ctx, nonce, data, aad)
