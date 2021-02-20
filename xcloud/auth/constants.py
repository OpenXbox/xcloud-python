from enum import Enum


class XalUserAgents(str, Enum):
    Android_GamestreamingPreview = 'XAL Android 2019.07.20190801.001'
    Android_XboxBetaApp = 'XAL Android 2020.07.20200714.000'
    Android_GamePassBeta = 'XAL Android 2020.07.20200714.000'
    iOS_XboxBetaApp = 'XAL iOS 2020.07.20200714.000'


class XalAppId(str, Enum):
    Android_GamestreamingPreview = '000000004825e41d'
    XboxGamePassBeta = '000000004c20a908'
    XboxBetaApp = '000000004415494b'


class XalRedirectUri(str, Enum):
    OAuth20_Desktop = 'https://login.live.com/oauth20_desktop.srf'
    XboxGamePassBeta = 'ms-xal-public-beta-000000004c20a908://auth'
    XboxBetaApp = 'ms-xal-000000004415494b://auth'


class XalTitleId(str, Enum):
    Android_GamestreamingPreview = ''
    XboxGamePassBeta = '1016898439'
    XboxBetaApp = '177887386'


class XalDeviceType(str, Enum):
    iOS = 'iOS'
    Android = 'Android'
    Win32 = 'Win32'


class XalQueryDisplay(str, Enum):
    Android = 'android_phone'
    iOS = 'ios_phone'


IOS_XBOXBETA_APP_PARAMS = dict(
    UserAgent=XalUserAgents.iOS_XboxBetaApp,
    AppId=XalAppId.XboxBetaApp,
    DeviceType=XalDeviceType.iOS,
    ClientVersion='14.0.1',
    TitleId=XalTitleId.XboxBetaApp,
    RedirectUri=XalRedirectUri.XboxBetaApp,
    QueryDisplay=XalQueryDisplay.iOS
)

ANDROID_XBOXBETA_APP_PARAMS = dict(
    UserAgent=XalUserAgents.Android_XboxBetaApp,
    AppId=XalAppId.XboxBetaApp,
    DeviceType=XalDeviceType.Android,
    ClientVersion='8.0.0',
    TitleId=XalTitleId.XboxBetaApp,
    RedirectUri=XalRedirectUri.XboxBetaApp,
    QueryDisplay=XalQueryDisplay.Android
)

ANDROID_GAMEPASS_BETA_PARAMS = dict(
    UserAgent=XalUserAgents.Android_GamePassBeta,
    AppId=XalAppId.XboxGamePassBeta,
    DeviceType=XalDeviceType.Android,
    ClientVersion='8.0.0',
    TitleId=XalTitleId.XboxGamePassBeta,
    RedirectUri=XalRedirectUri.XboxGamePassBeta,
    QueryDisplay=XalQueryDisplay.Android
)
