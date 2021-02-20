import uuid
import json
from xcloud.common import AppConfiguration

def test_appconfig(test_data: dict):
    appconfig = test_data["appconfig_no_tokens.json"].decode('utf-8')
    appconfig = json.loads(appconfig)

    config = AppConfiguration(**appconfig)
    
    assert config.SigningKey.startswith("-----BEGIN EC PRIVATE KEY-----\nMH")
    assert config.WindowsLiveTokens is None
    assert config.XalParameters is not None
    assert config.ClientUUID == uuid.UUID("78af29d1-7572-4861-9ce2-1cd99830b9e7")
    assert config.XalParameters.AppId == "000000004415494b"