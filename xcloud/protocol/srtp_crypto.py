import base64
from aiortc.rtp import RtpPacket

class MsSrtpCrypto:
    def __init__(self, master_key: str):
        try:
            master_key = base64.b64decode(master_key)
        except Exception:
            raise ValueError('Master key is not base64-decodable')
        
        self.master_key = master_key
    
    def decrypt(self, rtp_data: RtpPacket) -> RtpPacket:
        raise NotImplementedError('Decryption not implemented')

    def decrypt_raw(self, data: bytes) -> RtpPacket:
        packet = RtpPacket.parse(data)
        return self.decrypt(packet)
    
    def encrypt(self, rtp_data: RtpPacket) -> RtpPacket:
        raise NotImplementedError('Encryption not implemented')
