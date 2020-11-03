import asyncio
import json
import time
from urllib.parse import urljoin

import ms_cv

import aiohttp
from auth.models import XSTSResponse
from ice import ICEHandler

from streaming_models import StreamLoginResponse, StreamSessionResponse, \
    StreamStateResponse, StreamConfig, StreamICEConfig

USER_AGENT_IOS = '{"conn":{"cell":{"carrier":"","mcc":"","mnc":"","networkDetail":"","roaming":"Unknown","strengthPct":-1},"type":"Wifi","wifi":{"freq":-2147483648,"strengthDbm":-2147483648,"strengthPct":-1}},"dev":{"hw":{"make":"Apple","model":"iPad6,11"},"os":{"name":"iOS","ver":"14.0.1 (Build 18A393)"}}}'
USER_AGENT_ANDROID = '{"conn":{"cell":{"carrier":"","mcc":"unknown","mnc":"unknown","strengthPct":0},"type":"Wifi","wifi":{"freq":2417,"strengthDbm":-47,"strengthPct":100}},"dev":{"hw":{"make":"amzn","model":"Fire"},"os":{"name":"Android","ver":"7.1.2-NJH47F-25"}}}'


class XHomeStreamingApi:
    def __init__(
        self,
        gssv_token: XSTSResponse,
        user_agent: str = USER_AGENT_IOS
    ):
        self.session = aiohttp.ClientSession()
        self.cv = ms_cv.CorrelationVector()

        self.user_agent = user_agent
        self.gssv_xsts_token = gssv_token

    @property
    def headers(self):
        return {
            'MS-CV': self.cv.increment(),
            'X-MS-Device-Info': self.user_agent,
            'User-Agent': self.user_agent
        }

    async def _do_login(self, offering_id: str = 'xhome') -> StreamLoginResponse:
        url = 'https://xhome.gssv-play-prod.xboxlive.com/v2/login/user'
        post_body = {
            'offeringId': offering_id,
            'token': self.gssv_xsts_token.authorization_header_value
        }
        resp = await self.session.post(url, headers=self.headers, json=post_body)
        resp.raise_for_status()
        return StreamLoginResponse.parse_obj(resp.json())

    async def _request_stream(
        self, base_url: str, console_liveid: str
    ) -> StreamSessionResponse:
        url = urljoin(base_url, '/v4/sessions/home/play')
        json_body = {
            "fallbackRegionNames": [],
            "serverId": console_liveid,
            "settings": {
                "enableTextToSpeech": False,
                "locale": "en-US",
                "nanoVersion": "V3",
                # TODO: how is timezoneOffsetMinutes defined?
                "timezoneOffsetMinutes": 6088401280,
                "useIceConnection": True
            },
            "systemUpdateGroup": "",
            "titleId": ""
        }

        resp = await self.session.post(url, json=json_body, headers=self.headers)
        resp.raise_for_status()
        return StreamSessionResponse.parse_obj(resp.json())

    async def _get_session_state(
        self, base_url: str, session_path: str
    ) -> StreamStateResponse:
        url = urljoin(base_url, session_path + '/state')
        resp = await self.session.get(url, headers=self.headers)
        resp.raise_for_status()
        return StreamStateResponse.parse_obj(resp.json())

    async def _get_stream_config(
        self, base_url: str, session_path: str
    ) -> StreamConfig:
        url = urljoin(base_url, session_path + '/configuration')
        resp = await self.session.get(url, headers=self.headers)
        resp.raise_for_status()
        return StreamConfig.parse_obj(resp.json())

    async def _set_ice(
        self, base_url: str, ice_path: str, local_ice_config: str
    ) -> bool:
        url = urljoin(base_url, ice_path)
        json_body = {
            "candidates": local_ice_config
        }
        resp = await self.session.post(url, json=json_body, headers=self.headers)
        resp.raise_for_status()
        return resp.status == 202  # ACCEPTED

    async def _get_ice(
        self, base_url: str, ice_path: str
    ) -> StreamICEConfig:
        url = urljoin(base_url, ice_path)
        resp = await self.session.get(url, headers=self.headers)
        resp.raise_for_status()
        return StreamICEConfig.parse_obj(resp.json())

    async def _stop_stream(
        self, base_url: str, session_path: str
    ) -> bool:
        url = urljoin(base_url, session_path)
        resp = await self.session.delete(url, headers=self.headers)
        resp.raise_for_status()
        return resp.status == 202  # ACCEPTED

    async def _handle_ice_negotiation(
        self, base_url: str, ice_exchange_path: str
    ):
        ice_handler = ICEHandler()
        local_ice_config: dict = await ice_handler.generate_local_config()

        local_candidates = json.dumps(local_ice_config, indent=2)
        print(local_candidates)

        print(':: Setting ICE data')
        success = await self._set_ice(base_url, ice_exchange_path, local_candidates)
        if not success:
            print('Failed to set ICE data')
            return

        print(':: Getting ICE data')
        ice_data = await self._get_ice(base_url, ice_exchange_path)
        print(f'ICE Config: {ice_data}')

        candidates: str = ice_data.candidates
        candidates: dict = json.loads(candidates)
        remote_candidates, remote_params = ice_handler.parse_remote_config(candidates)

        for rc in remote_candidates:
            ice_handler.transport.addRemoteCandidate(rc)

        # End adding
        ice_handler.transport.addRemoteCandidate(None)

        await ice_handler.transport.start(remote_params)
        await asyncio.sleep(5)
        await ice_handler.transport.stop()

    async def start_streaming(self, console_liveid: str):
        print(':: HOME GS - Logging in ::')
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

        if not base_url:
            print(f'No default server found in login response: {login_data}')
            return

        print(f':: Using server {base_url}')

        print(':: Requesting stream')
        stream_session_info = await self._request_stream(base_url, console_liveid)

        print(':: Waiting for provisioning')
        state = 'Provisioning'
        while state == 'Provisioning':
            resp = await self._get_session_state(base_url, stream_session_info.sessionPath)
            state = resp.state
            time.sleep(1)

        print(':: Getting stream config')
        config = await self._get_stream_config(base_url, stream_session_info.sessionPath)
        print(f':: Stream config: {config}')

        if config.serverDetails.iceExchangePath:
            print(':: Handling ICE negotiation')
            await self._handle_ice_negotiation(
                base_url, config.serverDetails.iceExchangePath
            )

        print(':: Closing stream again')
        await self._stop_stream(base_url, stream_session_info.sessionPath)


