from pydantic import BaseModel
from typing import Dict, List, Optional


class XADDisplayClaims(BaseModel):
    # {"xdi": {"did": "F.....", "dcs": "0"}}
    xdi: Dict[str, str]


class XADResponse(BaseModel):
    IssueInstant: str
    NotAfter: str
    Token: str
    DisplayClaims: XADDisplayClaims


class XATDisplayClaims(BaseModel):
    xti: Dict[str, str]


class XATResponse(BaseModel):
    IssueInstant: str
    NotAfter: str
    Token: str
    DisplayClaims: XATDisplayClaims


class XAUDisplayClaims(BaseModel):
    xui: List[Dict[str, str]]


class XAUResponse(BaseModel):
    IssueInstant: str
    NotAfter: str
    Token: str
    DisplayClaims: XAUDisplayClaims


class XSTSDisplayClaims(BaseModel):
    xui: List[Dict[str, str]]


class XSTSResponse(BaseModel):
    IssueInstant: str
    NotAfter: str
    Token: str
    DisplayClaims: XSTSDisplayClaims

    @property
    def Userhash(self) -> str:
        return self.DisplayClaims.xui[0]["uhs"]

    @property
    def authorization_header_value(self) -> str:
        return f'XBL3.0 x={self.Userhash};{self.Token}'


class SisuAuthenticationResponse(BaseModel):
    MsaOauthRedirect: str
    MsaRequestParameters: Dict[str, str]


class SisuAuthorizationResponse(BaseModel):
    DeviceToken: str
    TitleToken: XATResponse
    UserToken: XAUResponse
    AuthorizationToken: XSTSResponse
    WebPage: str
    Sandbox: str
    UseModernGamertag: Optional[bool]


class WindowsLiveTokenResponse(BaseModel):
    token_type: str
    expires_in: int
    scope: str
    access_token: str
    refresh_token: str
    user_id: str


class XCloudTokenResponse(BaseModel):
    lpt: str
    refresh_token: str
    user_id: str


class XalClientParameters(BaseModel):
    UserAgent: str
    AppId: str
    DeviceType: str
    ClientVersion: str
    TitleId: str
    RedirectUri: str
    QueryDisplay: str
