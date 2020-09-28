import asyncio
from urllib.parse import urljoin

import httpx
import ms_cv

from auth.models import XSTSResponse, XCloudTokenResponse
from common_models import StreamLoginResponse, StreamSessionResponse, \
    StreamStateResponse, StreamConfig, StreamSetupState
from xcloud_models import TitlesResponse, TitleWaitTimeResponse

USER_AGENT_ANDROID = '{"conn":{"cell":{"carrier":"congstar","mcc":"262","mnc":"01","networkDetail":"{\"ci\":\"unknown\",\"pci\":\"unknown\",\"rat\":\"unknown\",\"signalStrengthDbm\":\"-2147483648\",\"pilotPowerSignalQuality\":\"-2147483648\",\"snr\":\"-2147483648\"}","roaming":"NotRoaming","strengthPct":100},"type":"Wifi","wifi":{"freq":5300,"strengthDbm":-60,"strengthPct":88}},"dev":{"hw":{"make":"Google","model":"Pixel 3a"},"os":{"name":"Android","ver":"11-RP1A.200720.009-30"}}}'


class XCloudApi:
    def __init__(
        self,
        gssv_token: XSTSResponse,
        xcloud_token: XCloudTokenResponse,
        user_agent: str = USER_AGENT_ANDROID
    ):
        self.session = httpx.AsyncClient()
        self.session.headers.update({
            'X-MS-Device-Info': user_agent,
            'User-Agent': user_agent
        })

        self.cv = ms_cv.CorrelationVector()
        self.gssv_xsts_token = gssv_token
        self.xcloud_token = xcloud_token

    async def _do_login(self) -> StreamLoginResponse:
        url = 'https://publicpreview.gssv-play-prod.xboxlive.com/v2/login/user'
        headers = {
            'MS-CV': self.cv.increment()
        }
        post_body = {
            'offeringId': 'xgpubeta',
            'token': self.gssv_xsts_token.authorization_header_value
        }
        resp = await self.session.post(url, headers=headers, json=post_body)
        resp.raise_for_status()
        return StreamLoginResponse.parse_obj(resp.json())

    async def _get_titles(
        self,
        base_url: str,
        count: int = 25,
        continuation_token: str = None
    ) -> TitlesResponse:
        url = urljoin(base_url, '/v1/titles')
        headers = {
            'MS-CV': self.cv.increment()
        }
        query_params = {
            'mr': count
        }
        if continuation_token:
            query_params.update({'ct': continuation_token})

        resp = await self.session.get(url, headers=headers, params=query_params)
        resp.raise_for_status()
        return TitlesResponse.parse_obj(resp.json())

    async def _get_titles_2(
        self,
        base_url: str,
        count: int = 25,
        continuation_token: str = None
    ) -> TitlesResponse:
        url = urljoin(base_url, '/v1/titles/mru')
        headers = {
            'MS-CV': self.cv.increment()
        }
        query_params = {
            'mr': count
        }
        if continuation_token:
            query_params.update({'ct': continuation_token})

        resp = await self.session.get(url, headers=headers, params=query_params)
        resp.raise_for_status()
        return TitlesResponse.parse_obj(resp.json())

    async def _fetch_wait_time(
        self,
        base_url: str,
        title_id: str
    ) -> TitleWaitTimeResponse:
        url = urljoin(base_url, f'/v1/waittime/{title_id}')
        headers = {
            'MS-CV': self.cv.increment()
        }
        resp = await self.session.get(url, headers=headers)
        resp.raise_for_status()
        return TitleWaitTimeResponse.parse_obj(resp.json())

    async def _request_stream(
        self, base_url: str, title_id: str
    ) -> StreamSessionResponse:
        url = urljoin(base_url, '/v5/sessions/cloud/play')
        headers = {
            'MS-CV': self.cv.increment()
        }
        json_body = {
            "fallbackRegionNames": ["WestEurope", "UKSouth", "UKWest"],
            "serverId": "",
            "settings": {
                "enableTextToSpeech": False,
                "locale": "de-DE",
                "nanoVersion": "V3",
                "timezoneOffsetMinutes": 120,
                "useIceConnection": False
            },
            "systemUpdateGroup": "",
            "titleId": title_id
        }
        resp = await self.session.post(url, json=json_body, headers=headers)
        resp.raise_for_status()
        return StreamSessionResponse.parse_obj(resp.json())

    async def _get_session_state(
        self, base_url: str, session_path: str
    ) -> StreamStateResponse:
        url = urljoin(base_url, session_path + '/state')
        headers = {
            'MS-CV': self.cv.increment()
        }
        resp = await self.session.get(url, headers=headers)
        resp.raise_for_status()
        return StreamStateResponse.parse_obj(resp.json())

    async def _connect_to_session(
        self, base_url: str, session_path: str, xcloud_token: str
    ) -> bool:
        url = urljoin(base_url, session_path + '/connect')
        headers = {
            'MS-CV': self.cv.increment()
        }
        json_body = {
            'userToken': xcloud_token
        }
        resp = await self.session.post(url, json=json_body, headers=headers)
        resp.raise_for_status()
        return resp.status_code == 202  # ACCEPTED

    async def _get_stream_config(
        self, base_url: str, session_path: str
    ) -> StreamConfig:
        url = urljoin(base_url, session_path + '/configuration')
        headers = {
            'MS-CV': self.cv.increment()
        }
        resp = await self.session.get(url, headers=headers)
        resp.raise_for_status()
        return StreamConfig.parse_obj(resp.json())

    async def start_streaming(self):
        print(':: CLOUD GS - Logging in ::')
        login_data = await self._do_login()

        print(':: Updating http authorization header ::')
        self.session.headers.update(
            {'Authorization': f'Bearer {login_data.gsToken}'}
        )

        print(':: Filtering for default server ::')
        base_url = None
        for server in login_data.offeringSettings.regions:
            if server.isDefault:
                base_url = server.baseUri
                break

        titles = await self._get_titles(base_url, count=25)
        gametitle = titles.results[0]
        print(f':: Chose Game: {gametitle}')

        wait_time = await self._fetch_wait_time(base_url, gametitle.titleId)
        print(f':: Estimated wait time for provisioning: {wait_time}')

        stream_session = await self._request_stream(base_url, gametitle.titleId)
        print(f':: Stream session {stream_session}')

        print(':: Waiting for stream')
        while True:
            state = await self._get_session_state(base_url, stream_session.sessionPath)
            print(state.state)
            if state.state == StreamSetupState.ReadyToConnect:
                print(':: Connecting to stream')
                success = await self._connect_to_session(
                    base_url, stream_session.sessionPath, self.xcloud_token.lpt
                )
                if not success:
                    print(':: Failed to connect to session')
                    return
            elif state.state == StreamSetupState.Provisioned:
                break

            await asyncio.sleep(1)

        print(':: Requesting config')
        config = await self._get_stream_config(base_url, stream_session.sessionPath)

        print(f':: Config: {config}')
