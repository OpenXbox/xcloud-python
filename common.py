from typing import Optional

from pydantic import BaseModel, UUID4
from auth.models import SisuAuthorizationResponse, WindowsLiveTokenResponse,\
    XalClientParameters


class AppConfiguration(BaseModel):
    ClientUUID: UUID4
    XalParameters: XalClientParameters
    WindowsLiveTokens: Optional[WindowsLiveTokenResponse]
    Authorization: Optional[SisuAuthorizationResponse]
    SigningKey: str
