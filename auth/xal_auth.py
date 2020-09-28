""""
SISU Authentication
"""
import os
import logging
import uuid
import base64
import hashlib
import asyncio
import httpx
from urllib import parse
from typing import Optional

import ms_cv
from auth.signed_session import SignedSession
from auth.request_signer import RequestSigner
from auth.models import SisuAuthenticationResponse, SisuAuthorizationResponse, \
    WindowsLiveTokenResponse, XADResponse, XalClientParameters, XSTSResponse, \
    XCloudTokenResponse
from auth.constants import XalDeviceType

log = logging.getLogger('auth')


class XalAuthenticator(object):
    def __init__(
        self,
        client_id: uuid.UUID,
        xal_client: XalClientParameters,
        request_signer: RequestSigner = None
    ):
        self.client_id = client_id
        self.client_data: XalClientParameters = xal_client

        self.session = SignedSession(request_signer)
        self.session.headers.update({
            'User-Agent': self.client_data.UserAgent
        })

        self.cv = ms_cv.CorrelationVector()

        self.windows_live_tokens: Optional[WindowsLiveTokenResponse] = None
        self.sisu_authorization_tokens: Optional[SisuAuthorizationResponse] = None
        self._endpoints = None

    async def fetch_endpoints(self) -> dict:
        if not self._endpoints:
            self._endpoints = (await self._get_endpoints()).json()
        return self._endpoints

    @staticmethod
    def get_random_bytes(length) -> bytes:
        return os.urandom(length)

    @staticmethod
    def generate_code_verifier() -> str:
        # https://tools.ietf.org/html/rfc7636
        code_verifier = base64.urlsafe_b64encode(
            XalAuthenticator.get_random_bytes(32)
        ).decode().rstrip('=')
        assert len(code_verifier) >= 43 and len(code_verifier) <= 128

        return code_verifier

    @staticmethod
    def get_code_challenge_from_code_verifier(code_verifier: str) -> str:
        code_challenge = hashlib.sha256(code_verifier.encode()).digest()
        # Base64 urlsafe encoding WITH stripping trailing '='
        code_challenge = base64.urlsafe_b64encode(
            code_challenge
        ).decode().rstrip('=')

        return code_challenge

    @staticmethod
    def generate_random_state() -> str:
        state = str(uuid.uuid4()).encode()
        # Base64 urlsafe encoding WITHOUT stripping trailing '='
        return base64.b64encode(state).decode()

    async def _get_endpoints(self) -> httpx.Response:
        url = 'https://title.mgt.xboxlive.com/titles/default/endpoints'
        headers = {
            'x-xbl-contract-version': '1'
        }
        params = {
            'type': 1
        }
        return await self.session.get(url, headers=headers, params=params)

    async def _get_device_token(self) -> httpx.Response:
        # Proof of posession: https://tools.ietf.org/html/rfc7800

        client_uuid = str(self.client_id)

        if self.client_data.DeviceType == XalDeviceType.Android:
            # {decf45e4-945d-4379-b708-d4ee92c12d99}
            client_uuid = "{%s}" % client_uuid
        else:
            # iOS
            # DECF45E4-945D-4379-B708-D4EE92C12D99
            client_uuid = client_uuid.upper()

        url = 'https://device.auth.xboxlive.com/device/authenticate'
        headers = {
            'x-xbl-contract-version': '1',
            'MS-CV': self.cv.get_value()
        }
        post_body = {
            'RelyingParty': 'http://auth.xboxlive.com',
            'TokenType': 'JWT',
            'Properties': {
                'AuthMethod': 'ProofOfPossession',
                'Id': client_uuid,
                'DeviceType': self.client_data.DeviceType,
                'Version': self.client_data.ClientVersion,
                'ProofKey': self.session.request_signer.proof_field
            }
        }

        request = self.session.build_request('POST', url, headers=headers, json=post_body)
        return await self.session.send_signed(request)

    async def _do_sisu_authentication(
        self,
        device_token_jwt: str,
        code_challenge: str,
        state: str
    ) -> httpx.Response:
        url = 'https://sisu.xboxlive.com/authenticate'
        headers = {
            'x-xbl-contract-version': '1',
            'MS-CV': self.cv.increment()
        }
        post_body = {
            'AppId': self.client_data.AppId,
            'TitleId': self.client_data.TitleId,
            'RedirectUri': self.client_data.RedirectUri,
            'DeviceToken': device_token_jwt,
            'Sandbox': 'RETAIL',
            'TokenType': 'code',
            'Offers': [
                'service::user.auth.xboxlive.com::MBI_SSL'
            ],
            'Query': {
                'display': self.client_data.QueryDisplay,
                'code_challenge': code_challenge,
                'code_challenge_method': 'S256',
                'state': state
            }
        }

        request = self.session.build_request('POST', url, headers=headers, json=post_body)
        return await self.session.send_signed(request)

    async def __oauth20_token_endpoint(
        self, json_body: dict
    ) -> httpx.Response:
        url = 'https://login.live.com/oauth20_token.srf'
        headers = {
            'MS-CV': self.cv.increment()
        }

        # NOTE: No signature necessary
        request = self.session.build_request(
            'POST', url, headers=headers, data=json_body
        )
        return await self.session.send(request)

    async def _exchange_code_for_token(
        self,
        authorization_code: str,
        code_verifier: str
    ) -> httpx.Response:
        post_body = {
            'client_id': self.client_data.AppId,
            'code': authorization_code,
            'code_verifier': code_verifier,
            'grant_type': 'authorization_code',
            'redirect_uri': self.client_data.RedirectUri,
            'scope': 'service::user.auth.xboxlive.com::MBI_SSL'
        }

        return await self.__oauth20_token_endpoint(post_body)

    async def exchange_refresh_token_for_xcloud_transfer_token(
        self,
        refresh_token_jwt: str
    ) -> XCloudTokenResponse:
        post_body = {
            'client_id': self.client_data.AppId,
            'refresh_token': refresh_token_jwt,
            'grant_type': 'refresh_token',
            'scope': 'service::http://Passport.NET/purpose::PURPOSE_XBOX_CLOUD_CONSOLE_TRANSFER_TOKEN'
        }

        resp = await self.__oauth20_token_endpoint(post_body)
        resp.raise_for_status()
        return XCloudTokenResponse.parse_obj(resp.json())

    async def _refresh_token(self, refresh_token_jwt: str) -> httpx.Response:
        post_body = {
            'client_id': self.client_data.AppId,
            'refresh_token': refresh_token_jwt,
            'grant_type': 'refresh_token',
            'redirect_uri': self.client_data.RedirectUri,
            'scope': 'service::user.auth.xboxlive.com::MBI_SSL'
        }

        return await self.__oauth20_token_endpoint(post_body)

    async def _do_sisu_authorization(
        self,
        sisu_session_id: str,
        access_token_jwt: str,
        device_token_jwt: str
    ) -> httpx.Response:
        url = 'https://sisu.xboxlive.com/authorize'
        headers = {
            'MS-CV': self.cv.increment()
        }
        post_body = {
            'AccessToken': f't={access_token_jwt}',
            'AppId': self.client_data.AppId,
            'DeviceToken': device_token_jwt,
            'Sandbox': 'RETAIL',
            'SiteName': 'user.auth.xboxlive.com',
            'SessionId': sisu_session_id,
            'ProofKey': self.session.request_signer.proof_field
        }

        request = self.session.build_request('POST', url, headers=headers, json=post_body)
        return await self.session.send_signed(request)

    async def xsts_authorization(
        self,
        device_token_jwt: str,
        title_token_jwt: str,
        user_token_jwt: str,
        relying_party: str
    ) -> XSTSResponse:
        url = 'https://xsts.auth.xboxlive.com/xsts/authorize'
        headers = {
            'x-xbl-contract-version': '1',
            'MS-CV': self.cv.increment()
        }
        post_body = {
            'RelyingParty': relying_party,
            'TokenType': 'JWT',
            'Properties': {
                'SandboxId': 'RETAIL',
                'DeviceToken': device_token_jwt,
                'TitleToken': title_token_jwt,
                'UserTokens': [
                    user_token_jwt
                ]
            }
        }

        request = self.session.build_request('POST', url, headers=headers, json=post_body)
        resp = await self.session.send_signed(request)
        resp.raise_for_status()
        return XSTSResponse.parse_obj(resp.json())

    async def device_auth(self) -> XADResponse:
        print('::: DEVICE TOKEN AUTHENTICATION :::')
        resp = await self._get_device_token()
        assert resp.status_code == 200,\
            f'Invalid response for GET_DEVICE_TOKEN: {resp.status_code}'

        resp = XADResponse.parse_raw(resp.content)
        print(f'Device Token: {resp.Token}')
        return resp

    async def sisu_authentication(
        self,
        device_token: str,
        code_challenge: str,
        state: str
    ) -> (SisuAuthenticationResponse, str):
        print('::: SISU AUTHENTICATION :::')
        resp = await self._do_sisu_authentication(device_token, code_challenge, state)
        assert resp.status_code == 200,\
            f'Invalid response for DO_SISU_AUTHENTICATION: {resp.status_code}'

        session_id = resp.headers['X-SessionId']
        print('SISU Session Id: {}'.format(session_id))

        resp = SisuAuthenticationResponse.parse_raw(resp.content)
        return resp, session_id

    async def auth_flow(self):
        device_token_resp = await self.device_auth()

        code_verifier = self.generate_code_verifier()
        code_challenge = self.get_code_challenge_from_code_verifier(code_verifier)
        state = self.generate_random_state()

        sisu_authenticate_resp, sisu_session_id = \
            await self.sisu_authentication(device_token_resp.Token, code_challenge, state)

        redirect_uri = input(
            (f'Continue auth with the following URL: '
             f'{sisu_authenticate_resp.MsaOauthRedirect}.\n\n'
             f'Provide redirect URI:')
        )

        if not redirect_uri.startswith(self.client_data.RedirectUri):
            print('Wrong data passed as redirect URI')
            return None

        query_params = dict(
            parse.parse_qsl(parse.urlsplit(redirect_uri).query)
        )

        resp_authorization_code = query_params['code']
        resp_state = query_params['state']

        if resp_state != state:
            print('Response with non-matching state received')
            return None

        tokens = await self._exchange_code_for_token(resp_authorization_code, code_verifier)
        assert tokens.status_code == 200,\
            f'Invalid response for EXCHANGE_CODE_FOR_TOKENS: {tokens.status_code}'
        tokens = WindowsLiveTokenResponse.parse_raw(tokens.content)

        print('::: SISU AUTHORIZATION :::')
        sisu_authorization = await self._do_sisu_authorization(
            sisu_session_id,
            tokens.access_token,
            device_token_resp.Token
        )
        assert sisu_authorization.status_code == 200, 'Invalid response for DO_SISU_AUTHORIZATION'

        sisu_authorization_resp = SisuAuthorizationResponse.parse_raw(
            sisu_authorization.content
        )

        print('Device Token: {}'.format(sisu_authorization_resp.DeviceToken))
        print('User Token: {}'.format(sisu_authorization_resp.UserToken.Token))
        print('Authorization Token: {}'.format(sisu_authorization_resp.AuthorizationToken.Token))
        print('Userhash: {}'.format(sisu_authorization_resp.AuthorizationToken.Userhash))

        self.windows_live_tokens = tokens
        self.sisu_authorization_tokens = sisu_authorization_resp
