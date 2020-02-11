from typing import Optional, List
from pydantic import BaseModel
from enum import Enum

"""
Responses
"""


class ConsoleType(str, Enum):
    XboxOne = 'XboxOne'
    XboxOneS = 'XboxOneS'
    XboxOneSDigital = 'XboxOneSDigital'
    XboxOneX = 'XboxOneX'
    XboxSeriesS = 'XboxSeriesS'
    XboxSeriesX = 'XboxSeriesX'


class PowerState(str, Enum):
    Unknown = 'Unknown'
    On = 'On'
    Off = 'Off'
    ConnectedStandby = 'ConnectedStandby'
    SystemUpdate = 'SystemUpdate'


class PlaybackState(str, Enum):
    Unknown = 'Unknown'
    Playing = 'Playing'
    Paused = 'Paused'
    Stopped = 'Stopped'


class ErrorCode(str, Enum):
    OK = 'OK'
    CurrentConsoleNotFound = 'CurrentConsoleNotFound'
    RemoteManagementDisabled = 'RemoteManagementDisabled'
    XboxDataNotFound = 'XboxDataNotFound'
    XboxNotPaired = 'XboxNotPaired'


class OpStatus(str, Enum):
    Paused = 'Paused'
    OffConsoleError = 'OffConsoleError'
    Pending = 'Pending'
    TimedOut = 'TimedOut'
    Error = 'Error'
    Succeeded = 'Succeeded'


class SmartglassApiStatus(BaseModel):
    errorCode: str
    errorMessage: Optional[str]


class StorageDevice(BaseModel):
    storageDeviceId: str
    storageDeviceName: str
    isDefault: bool
    totalSpaceBytes: float
    freeSpaceBytes: float


class SmartglassConsole(BaseModel):
    id: str
    name: str
    consoleType: ConsoleType
    powerState: PowerState
    consoleStreamingEnabled: bool
    digitalAssistantRemoteControlEnabled: bool
    remoteManagementEnabled: bool
    storageDevices: Optional[List[StorageDevice]]


class SmartglassConsoleList(BaseModel):
    agentUserId: Optional[str]
    result: List[SmartglassConsole]
    status: SmartglassApiStatus


class SmartglassConsoleStatus(BaseModel):
    powerState: PowerState
    consoleStreamingEnabled: bool
    digitalAssistantRemoteControlEnabled: bool
    remoteManagementEnabled: bool

    focusAppAumid: str
    isTvConfigured: bool
    loginState: Optional[str]
    playbackState: PlaybackState
    powerState: PowerState

    storageDevices: Optional[List[StorageDevice]]
    status: SmartglassApiStatus


class InstalledPackage(BaseModel):
    oneStoreProductId: Optional[str]
    titleId: int
    aumid: Optional[str]
    lastActiveTime: Optional[str]
    isGame: bool
    name: Optional[str]
    contentType: str
    instanceId: str
    storageDeviceId: str
    uniqueId: str
    legacyProductId: Optional[str]
    version: int
    sizeInBytes: int
    installTime: str
    updateTime: Optional[str]
    parentId: Optional[str]


class InstalledPackagesList(BaseModel):
    result: List[InstalledPackage]
    status: SmartglassApiStatus
    agentUserId: Optional[str]


class StorageDevicesList(BaseModel):
    deviceId: str
    result: List[StorageDevice]
    status: SmartglassApiStatus


class OpStatusNode(BaseModel):
    operationStatus: OpStatus
    opId: str
    originatingSessionId: str
    command: str
    succeeded: bool
    consoleStatusCode: Optional[int]
    xccsErrorCode: Optional[ErrorCode]
    hResult: Optional[int]
    message: Optional[str]


class OperationStatusResponse(BaseModel):
    opStatusList: List[OpStatusNode]
    status: SmartglassApiStatus


class CommandDestination(BaseModel):
    id: str
    name: str
    powerState: PowerState
    remoteManagementEnabled: bool
    consoleStreamingEnabled: bool
    consoleType: ConsoleType
    wirelessWarning: Optional[str]
    outOfHomeWarning: Optional[str]


class CommandResponse(BaseModel):
    result: Optional[str]
    uiText: Optional[str]
    destination: CommandDestination
    userInfo: Optional[str]
    opId: str
    status: SmartglassApiStatus


"""
Requests
"""


class VolumeDirection(str, Enum):
    Up = "Up"
    Down = "Down"


class InputKeyType(str, Enum):
    Guide = "Guide"
    Menu = "Menu"
    View = "View"
    A = "A"
    B = "B"
    X = "X"
    Y = "Y"
    Up = "Up"
    Down = "Down"
    Left = "Left"
    Right = "Right"


class MediaCommand(str, Enum):
    Pause = "Pause"
    Play = "Play"
    Previous = "Previous"
    Next = "Next"
