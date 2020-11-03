"""
Signed Session

A wrapper around aiohttp's ClientSession which transparently calculates the "Signature" header.
"""

import asyncio
import aiohttp
from yarl import URL
from auth.request_signer import RequestSigner


class SignedSession(aiohttp.ClientSession):
    def __init__(self, request_signer=None):
        super().__init__()
        self.request_signer = request_signer or RequestSigner()

    @classmethod
    def from_pem_signing_key(cls, pem_string: str):
        request_signer = RequestSigner.from_pem(pem_string)
        return cls(request_signer)

    def _prepare_signed_request(
        self,
        request: aiohttp.ClientRequest
    ) -> aiohttp.ClientRequest:
        path_and_query = request.url.raw_path
        authorization = request.headers.get('Authorization', '')

        body = b''
        for byte in request.stream:
            body += byte

        signature = self.request_signer.sign(
            method=request.method,
            path_and_query=path_and_query,
            body=body,
            authorization=authorization
        )

        request.headers['Signature'] = signature
        return request

    async def send_signed(
        self, method: str, url: URL, raise_for_status=True, *args, **kwargs
    ) -> aiohttp.ClientResponse:
        """
        Shorthand for prepare signed + send
        """
        # FIXME!
        #prepared = self._prepare_signed_request(request)
        #return await prepared.send(self.connector)
        resp = await self.request(method, url, **kwargs)
        if raise_for_status:
            resp.raise_for_status()
        return resp