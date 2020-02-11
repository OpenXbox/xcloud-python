from enum import Enum


class XalUserAgents(str, Enum):
    Android_GamestreamingPreview = 'XAL Android 2019.07.20190801.001'
    iOS_XboxBetaTestflight = 'XAL iOS 2020.07.20200714.000'


class XalAppId(str, Enum):
    Android_GamestreamingPreview = '000000004825e41d'
    iOS_XboxBetaTestflight = '000000004415494b'


class XalRedirectUri(str, Enum):
    OAuth20_Desktop = 'https://login.live.com/oauth20_desktop.srf'
    iOS_XboxBetaTestflight = 'ms-xal-000000004415494b://auth'


class XalTitleId(str, Enum):
    Android_GamestreamingPreview = ''
    iOS_XboxBetaTestflight = '177887386'


class XalDeviceType(str, Enum):
    iOS = 'iOS'
    Android = 'Android'
    Win32 = 'Win32'


class XalQueryDisplay(str, Enum):
    Android = 'android_phone'
    iOS = 'ios_phone'


IOS_XBOXBETA_APP_PARAMS = dict(
    UserAgent=XalUserAgents.iOS_XboxBetaTestflight,
    AppId=XalAppId.iOS_XboxBetaTestflight,
    DeviceType=XalDeviceType.iOS,
    ClientVersion='14.0.1',
    TitleId=XalTitleId.iOS_XboxBetaTestflight,
    RedirectUri=XalRedirectUri.iOS_XboxBetaTestflight,
    QueryDisplay=XalQueryDisplay.iOS
)

ANDROID_GAMESTREAMING_PREVIEW_PARAMS = dict(
    UserAgent=XalUserAgents.Android_GamestreamingPreview,
    AppId=XalAppId.Android_GamestreamingPreview,
    DeviceType=XalDeviceType.Android,
    ClientVersion='8.0.0',
    TitleId=XalTitleId.Android_GamestreamingPreview,
    RedirectUri=XalRedirectUri.OAuth20_Desktop,
    QueryDisplay=XalQueryDisplay.Android
)
