import io
import uuid
import time
import asyncio

from common import AppConfiguration

from auth.constants import IOS_XBOXBETA_APP_PARAMS
from auth.models import XalClientParameters, XSTSResponse
from auth.xal_auth import XalAuthenticator
from auth.request_signer import RequestSigner

from smartglass_api import SmartglassApi
from xhomestreaming_api import XHomeStreamingApi

APP_CONFIG_FILE = "appconfig.json"


def choose_console(console_list):
    print('Please choose a console:')
    for index, c in enumerate(console_list.result):
        print(f'{index}) {c.id} - {c.name} - Type: {c.consoleType}')

    choice = int(input('Enter index of target console: '))
    return console_list.result[choice]


async def test_smartglass_api(
    smartglass: SmartglassApi,
    console_liveid: str
):
    console_status = await smartglass.get_console_status(console_liveid)
    print(console_status)

    poweron_resp = await smartglass.command_power_on(console_liveid)
    print(poweron_resp)

    print('Waiting 30 secs')
    time.sleep(30)

    poweroff_resp = await smartglass.command_power_off(console_liveid)
    print(poweroff_resp)


async def test_xhome_streaming(
    config: AppConfiguration,
    console_liveid: str,
):
    xal = XalAuthenticator(
        config.ClientUUID,
        config.XalParameters,
        RequestSigner.from_pem(config.SigningKey)
    )

    print(':: Requesting XSTS Token (RelyingParty: http://gssv.xboxlive.com)')
    gssv_token = await xal.xsts_authorization(
        config.Authorization.DeviceToken,
        config.Authorization.TitleToken.Token,
        config.Authorization.UserToken.Token,
        relying_party='http://gssv.xboxlive.com/'
    )
    await xal.session.aclose()

    xhome_api = XHomeStreamingApi(gssv_token)
    await xhome_api.start_streaming(console_liveid)
    await xhome_api.session.aclose()


async def main():
    """
    Prepare needed values
    """

    try:
        config = AppConfiguration.parse_file(APP_CONFIG_FILE)
    except Exception as e:
        print(f'Failed to parse app configuration! Err: {e}')
        print('Initializing new config...')
        config = AppConfiguration(
            ClientUUID=uuid.uuid4(),
            SigningKey=RequestSigner().export_signing_key(),
            XalParameters=XalClientParameters.parse_obj(
                IOS_XBOXBETA_APP_PARAMS
            )
        )

    # Create request signer
    request_signer = RequestSigner.from_pem(config.SigningKey)

    """
    Authenticate
    """
    if not config.WindowsLiveTokens or not config.Authorization:
        xal = XalAuthenticator(
            config.ClientUUID, config.XalParameters, request_signer
        )
        await xal.auth_flow()

        config.WindowsLiveTokens = xal.windows_live_tokens
        config.Authorization = xal.sisu_authorization_tokens

    """
    Saving app config
    """
    with io.open(APP_CONFIG_FILE, 'wt') as f:
        f.write(config.json(indent=2))

    smartglass = SmartglassApi(
        request_signer,
        config.Authorization.AuthorizationToken
    )

    print(':: Getting console list')
    console_list = await smartglass.get_console_list()
    await smartglass.session.aclose()

    console = choose_console(console_list)
    console_liveid = console.id

    # test_smartglass_api(smartglass, console_liveid)
    await test_xhome_streaming(config, console_liveid)


if __name__ == '__main__':
    asyncio.run(main())
