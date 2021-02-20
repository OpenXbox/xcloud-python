from enum import Enum
from construct import Struct, this, Int32ul, Int64ul, PrefixedArray, Bytes, Array

"""
Payload types
"""


class PayloadType(Enum):
    MuxDCTChannelRangeDefault = 0x23
    MuxDCTChannelRangeEnd = 0x3f
    BaseLinkControl = 0x60
    MuxDCTControl = 0x61
    FECControl = 0x62
    SecurityLayerCtrl = 0x63
    URCPControl = 0x64
    UDPKeepAlive = 0x65
    UDPConnectionProbing = 0x66
    URCPDummyPacket = 0x68
    MockUDPDctCtrl = 0x7f


"""
Video Channel
"""


class VideoControlFlags:
    LAST_DISPLAYED_FRAME = 0x01
    LOST_FRAMES = 0x02
    QUEUE_DEPTH = 0x04
    STOP_STREAM = 0x08
    START_STREAM = 0x10
    REQUEST_KEYFRAMES = 0x20
    LAST_DISPLAYED_FRAME_RENDERED = 0x80
    SMOOTH_RENDERING_SETTINGS_SENT = 0x1000


video_format = Struct(
)


video_server_handshake = Struct(
    'protocol_version' / Int32ul,
    'screen_width' / Int32ul,
    'screen_height' / Int32ul,
    'reference_timestamp' / Int64ul,
    'formats' / PrefixedArray(Int32ul, video_format)
)


video_client_handshake = Struct(
    'initial_frame_id' / Int32ul,
    'requested_format' / video_format
)


video_control = Struct(
    'flags' / Int32ul,  # see VideoControlFlags
    'last_displayed_frame' / Int32ul,  # if(flags << 31)
    'last_displayed_frame_rendered' / Int32ul,  # if(flags & 0x80)
    'lost_frames' / Array(2, Int32ul),  # if (flags & 2)
    'queue_depth' / Int32ul,  # if(flags & 4)
)


video_data = Struct(
    'flags' / Int32ul,
    'frame_id' / Int32ul,
    'timestamp' / Int32ul,
    'metadata_size' / Int32ul,
    'data_size' / Int32ul,
    'offset' / Int32ul,
    'data' / Bytes(this.data_size)
)


class QosControlFlags:
    REINITIALIZE = 0x1


qos_server_policy = Struct(
    'schema_version' / Int32ul,
    'policy_length' / Int32ul,
    'fragment_count' / Int32ul,
    'offset' / Int32ul,
    'fragment_size' / Int32ul
)


qos_server_handshake = Struct(
    'protocol_version' / Int32ul,
    'min_supported_client_version' / Int32ul
)


qos_client_policy = Struct(
    'schema_version' / Int32ul
)


qos_client_handshake = Struct(
    'protocol_version' / Int32ul,
    'initial_frame_id' / Int32ul
)


qos_control = Struct(
    'flags' / Int32ul
)


qos_data = Struct(
    'flags' / Int32ul,
    'frame_id' / Int32ul,
    # TBD
)


"""
Control Protocol
"""


class ControlProtocolMessageOpCode(Enum):
    Auth = 0x1
    AuthComplete = 0x2
    Config = 0x3
    ControllerChange = 0x4
    Config2 = 0x6
