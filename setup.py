#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name='xcloud',
    version='0.1.0',
    description='XCloud Gamestreaming library for python',
    author='tuxuser',
    author_email='noreply@openxbox.org',
    url='https://github.com/OpenXbox/xcloud-python',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'xcloud-pcap-reader=xcloud.scripts.pcap_reader:main',
            'xcloud-client=xcloud.scripts.client:main'
        ]
    },
    install_requires=[
        "ecdsa",
        "ms_cv",
        "pydantic",
        "httpx",
        "aiortc",
        "construct",
        "dpkt"
    ]
)
