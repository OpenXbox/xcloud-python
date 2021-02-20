from typing import Dict
import os
import pytest

@pytest.fixture(scope='session')
def test_data() -> Dict[str, bytes]:
    data = {}
    data_path = os.path.join(os.path.dirname(__file__), 'data')
    for f in os.listdir(data_path):
        with open(os.path.join(data_path, f), 'rb') as fh:
            data[f] = fh.read()

    return data