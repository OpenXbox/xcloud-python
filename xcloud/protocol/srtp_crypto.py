import base64
import struct
from enum import Enum
from typing import List, Optional
from dataclasses import dataclass

from aiortc.rtp import RtpPacket

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import utils

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
        self.roc = 0
        self.seq = 0

        self.master_keys = master_keys
        self.session_keys = SrtpContext._derive_session_keys(
            self.master_keys.master_key, self.master_keys.master_salt
        )

        # Set-up GCM crypto instances
        self.crypto_ctx = SrtpContext._init_gcm_cryptor(self.session_keys.crypt_key)
    
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
    def _derive_single_key(master_key, master_salt, key_index: int = 0, max_bytes: int = 16, pkt_i=0, key_derivation_rate=0):
        '''SRTP key derivation, https://tools.ietf.org/html/rfc3711#section-4.3'''

        assert len(master_key) == 128 // 8
        assert len(master_salt) == 112 // 8
        salt = utils.bytes_to_int(master_salt)

        DIV = lambda x, y: 0 if y == 0 else x // y
        prng = lambda iv: SrtpContext._crypt_ctr_oneshot(
            master_key, utils.int_to_bytes(iv, 16), b'\x00' * 16, max_bytes=max_bytes
        )
        r = DIV(pkt_i, key_derivation_rate)  # pkt_i is always 48 bits
        derive_key_from_label = lambda label: prng(
            (salt ^ ((label << 48) + r)) << 16)
        
        return derive_key_from_label(key_index)

    @staticmethod
    def _derive_session_keys(master_key: bytes, master_salt: bytes) -> SrtpSessionKeys:
        crypt_key = SrtpContext._derive_single_key(master_key, master_salt, SrtpSessionKeys.SRTP_CRYPT)
        auth_key = SrtpContext._derive_single_key(master_key, master_salt, SrtpSessionKeys.SRTP_AUTH)
        salt_key = SrtpContext._derive_single_key(master_key, master_salt, SrtpSessionKeys.SRTP_SALT, max_bytes=14)

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

    @staticmethod
    def packet_index(roc, seq):
        return seq + (roc << 16)

    @staticmethod
    def _calc_iv(salt, ssrc, pkt_i):
        salt = utils.bytes_to_int(salt)
        iv = ((ssrc << (48)) + pkt_i) ^ salt
        return utils.int_to_bytes(iv, 12)
    
    def _crypt_packet(self, rtp_packet: bytes, encrypt: bool) -> RtpPacket:
        rtp_header = rtp_packet[:12]
        parsed = RtpPacket.parse(rtp_packet)
        
        if parsed.sequence_number < self.seq:
            self.roc += 1
        self.seq = parsed.sequence_number
        pkt_i = SrtpContext.packet_index(self.roc, self.seq)
        iv = SrtpContext._calc_iv(self.session_keys.salt_key[2:], parsed.ssrc, pkt_i)

        if encrypt:
            transformed_payload = SrtpContext._encrypt(self.crypto_ctx, iv, parsed.payload, rtp_header)
        else:
            transformed_payload = SrtpContext._decrypt(self.crypto_ctx, iv, parsed.payload, rtp_header)

        parsed.payload = transformed_payload
        return parsed

    def encrypt_packet(self, rtp_packet: bytes) -> RtpPacket:
        return self._crypt_packet(rtp_packet, True)

    def decrypt_packet(self, rtp_packet: bytes) -> RtpPacket:
        return self._crypt_packet(rtp_packet, False)