from typing import List, Optional
from pydantic import BaseModel


class CloudGameTitleDetails(BaseModel):
    productId: str
    xboxTitleId: int
    hasEntitlement: bool
    blockedByFamilySafety: bool
    supportsInAppPurchases: bool
    supportedTabs: Optional[str]
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