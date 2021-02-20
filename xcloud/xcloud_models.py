from typing import List, Optional
from pydantic import BaseModel


class TitleSupportedTab(BaseModel):
    id: str
    tabVersion: str
    layoutVersion: str
    manifestVersion: str


class CloudGameTitleDetails(BaseModel):
    productId: str
    xboxTitleId: Optional[int]
    hasEntitlement: bool
    blockedByFamilySafety: bool
    supportsInAppPurchases: bool
    supportedTabs: Optional[List[TitleSupportedTab]]
    nativeTouch: bool


class CloudGameTitle(BaseModel):
    titleId: str
    details: CloudGameTitleDetails


class TitlesResponse(BaseModel):
    totalItems: Optional[int]
    results: List[CloudGameTitle]
    continuationToken: Optional[str]


class TitleWaitTimeResponse(BaseModel):
    estimatedProvisioningTimeInSeconds: int
    estimatedAllocationTimeInSeconds: int
    estimatedTotalWaitTimeInSeconds: int