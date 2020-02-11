import asyncio
import httpx
import ms_cv


class XCloudApi:
    def __init__(self):
        self.session = httpx.AsyncClient()
        self.cv = ms_cv.CorrelationVector()

    async def do_login(self, xtoken_jwt):
        url = 'https://publicpreview.gssv-play-prod.xboxlive.com/v2/login/user'
        headers = {
            'User-Agent': '{"conn":{"cell":{"carrier":"","mcc":"unknown","mnc":"unknown","strengthPct":0},"type":"Wifi","wifi":{"freq":2417,"strengthDbm":-47,"strengthPct":100}},"dev":{"hw":{"make":"amzn","model":"Fire"},"os":{"name":"Android","ver":"7.1.2-NJH47F-25"}}}',
            'MS-CV': self.cv.increment()
        }
        post_body = {
            'offeringId': 'publicpreview',
            'token': xtoken_jwt
        }
        return await self.session.post(url, headers=headers, json=post_body)