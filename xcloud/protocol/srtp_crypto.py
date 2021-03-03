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
    MASTER_KEY_SIZE = 16
    MASTER_SALT_SIZE = 14
    DUMMY_KEY = (
        b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
        b'\x10\x11\x12\x13'
    )

    def __init__(self, master_key: bytes, master_salt: bytes):
        assert len(master_key) == SrtpMasterKeys.MASTER_KEY_SIZE
        assert len(master_salt) == SrtpMasterKeys.MASTER_SALT_SIZE

        self._master_key = master_key
        self._master_key_id = 0

        self._master_salt = master_salt
        self._master_salt_id = 0
    
    @classmethod
    def from_base64(cls, master_bytes_b64: str):
        decoded = base64.b64decode(master_bytes_b64)
        return cls(
            decoded[:SrtpMasterKeys.MASTER_KEY_SIZE],
            decoded[SrtpMasterKeys.MASTER_KEY_SIZE:]
        )
    
    @classmethod
    def null_keys(cls):
        return cls(
            SrtpMasterKeys.MASTER_KEY_SIZE * b'\x00',
            SrtpMasterKeys.MASTER_SALT_SIZE * b'\x00',
        )
    
    @classmethod
    def dummy_keys(cls):
        return cls(
            SrtpMasterKeys.DUMMY_KEY[:SrtpMasterKeys.MASTER_KEY_SIZE],
            SrtpMasterKeys.DUMMY_KEY[:SrtpMasterKeys.MASTER_SALT_SIZE]
        )
    
    @property
    def master_key(self) -> bytes:
        return self._master_key

    @property
    def master_key_id(self) -> int:
        return self._master_key_id

    @property
    def master_salt(self) -> bytes:
        return self._master_salt

    @property
    def master_salt_id(self) -> int:
        return self._master_salt_id

class SrtpSessionKeys:
    SRTP_CRYPT = 0
    SRTP_AUTH = 1
    SRTP_SALT = 2
    # Max count of keys
    SRTP_SESSION_KEYS_MAX = 3

    def __init__(self, crypt_key: bytes, auth_key: bytes, salt_key: bytes):
        self._crypt_key = crypt_key
        self._auth_key = auth_key
        self._salt_key = salt_key
    
    @classmethod
    def from_list(cls, session_keys: List[bytes]):
        assert len(session_keys) == SrtpSessionKeys.SRTP_SESSION_KEYS_MAX
        return cls(
            session_keys[SrtpSessionKeys.SRTP_CRYPT],
            session_keys[SrtpSessionKeys.SRTP_AUTH],
            session_keys[SrtpSessionKeys.SRTP_SALT]
        )

    @property
    def crypt_key(self) -> bytes:
        return self._crypt_key
    
    @property
    def auth_key(self) -> bytes:
        return self._auth_key

    @property
    def salt_key(self) -> bytes:
        return self._salt_key

class SrtpContext:
    _backend = default_backend()

    def __init__(self, master_keys: SrtpMasterKeys):
        """
        MS-SRTP context
        """
        self.master_keys = master_keys
        self.session_keys = SrtpContext._derive_session_keys(
            self.master_keys.master_key, self.master_keys.master_salt
        )

        # Set-up GCM crypto instances
        self.decryptor_ctx = SrtpContext._init_gcm_cryptor(self.session_keys.crypt_key)
        self.decryptor_ctx = SrtpContext._init_gcm_cryptor(self.session_keys.crypt_key)
    
    @classmethod
    def from_base64(cls, master_bytes_b64: str):
        return cls(
            SrtpMasterKeys.from_base64(master_bytes_b64)
        )
    
    @classmethod
    def from_bytes(cls, master_key: bytes, master_salt: bytes):
        return cls(
            SrtpMasterKeys(master_key, master_salt)
        )

    @staticmethod
    def _derive_single_key(input_key: bytes, key_index: int = 0) -> bytes:
        keysize = len(input_key)
        keyout = bytearray(b'\x00' * 16)

        if keysize >= 14:
            keysize = 14

        if keysize:
            keyout[13] = input_key[keysize - 1]
            if keysize != 1:
                keyout[12] = input_key[keysize - 2]
                if keysize >= 3:
                    pos = 0
                    for _ in range(2, keysize):
                        keyout[pos + 11] = input_key[pos + keysize - 3]
                        pos -= 1

        if keysize <= 13:
            null_count = 14 - keysize
            for i in range(0, null_count):
                keyout[i] = 0

        for index in range(14, 16):
            keyout[index] = 0
        
        if key_index:
            len_before_xor = len(keyout)
            value_to_xor = struct.unpack_from('<I', keyout, 4)[0]
            value_to_xor ^= (key_index * 0x1000000)
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
    def _derive_session_keys(master_key: bytes, master_salt: bytes) -> SrtpSessionKeys:
        tmp1 = SrtpContext._derive_single_key(master_salt, SrtpSessionKeys.SRTP_CRYPT)
        tmp2 = SrtpContext._derive_single_key(master_salt, SrtpSessionKeys.SRTP_AUTH)
        tmp3 = SrtpContext._derive_single_key(master_salt, SrtpSessionKeys.SRTP_SALT)
  
        crypt_key = SrtpContext._crypt_ctr_oneshot(master_key, tmp1, b'\x00' * 16)
        auth_key = SrtpContext._crypt_ctr_oneshot(master_key, tmp2, b'\x00' * 16)
        salt_key = SrtpContext._crypt_ctr_oneshot(master_key, tmp3, b'\x00' * 16, max_bytes=14)

        return SrtpSessionKeys(crypt_key, auth_key, salt_key)

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
        nonce = bytearray(self.session_keys.salt_key[2:])
        # TODO: Implement transform logic
        # FIXME: Just tranforming the Nonce to a known value for
        #        our single test packet
        nonce[-1] += 1

        return nonce

    def decrypt(self, data: bytes, aad: bytes) -> bytes:
        nonce = self._get_transformed_nonce(TransformDirection.Decrypt)
        return SrtpContext._decrypt(self.decryptor_ctx, nonce, data, aad)
    
    def encrypt(self, data: bytes, aad: bytes) -> RtpPacket:
        nonce = self._get_transformed_nonce(TransformDirection.Encrypt)
        return SrtpContext._encrypt(self.decryptor_ctx, nonce, data, aad)
