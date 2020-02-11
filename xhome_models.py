from enum import Enum
from typing import List, Optional
from pydantic import BaseModel


class StreamSetupState(str, Enum):
    Provisioning = 'Provisioning'
    Provisioned = 'Provisioned'


class RegionCloudServer(BaseModel):
    name: str
    baseUri: str
    networkTestHostname: Optional[str]
    isDefault: bool
    poolIds: Optional[str]
    systemUpdateGroups: Optional[str]
    fallbackPriority: int


class CloudEnvironment(BaseModel):
    Name: str
    AuthBaseUri: Optional[str]


class ClientCloudSettings(BaseModel):
    Environments: List[CloudEnvironment]


class OfferingSettings(BaseModel):
    allowRegionSelection: bool
    regions: List[RegionCloudServer]
    clientCloudSettings: ClientCloudSettings


class XHomeLoginResponse(BaseModel):
    offeringSettings: OfferingSettings
    market: str
    gsToken: str
    tokenType: str
    durationInSeconds: int


class StreamSessionResponse(BaseModel):
    sessionId: str
    sessionPath: str
    state: StreamSetupState


class StreamErrorDetails(BaseModel):
    code: Optional[str]
    message: Optional[str]


class StreamStateResponse(BaseModel):
    state: StreamSetupState
    detailedSessionState: int
    errorDetails: StreamErrorDetails


class StreamSRtpData(BaseModel):
    key: str


class StreamServerDetails(BaseModel):
    ipAddress: str
    port: int
    ipV4Address: Optional[str]
    ipV4Port: int
    ipV6Address: Optional[str]
    ipV6Port: int
    iceExchangePath: Optional[str]
    stunServerAddress: Optional[str]
    srtp: StreamSRtpData


class StreamConfig(BaseModel):
    keepAlivePulseInSeconds: int
    serverDetails: StreamServerDetails


class StreamICEConfig(BaseModel):
    candidates: str
