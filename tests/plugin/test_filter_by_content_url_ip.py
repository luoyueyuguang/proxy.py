# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""

import pytest
from proxy.plugin.filter_by_content_url_ip import FilterByContentUrlIpPlugin
from types import SimpleNamespace

class DummyRequest:
    def __init__(self, host, path, body=None):
        self.host = host
        self.path = path
        self.body = body

class DummyClient:
    def __init__(self, addr):
        self.addr = addr

@pytest.fixture
def plugin():
    flags = SimpleNamespace(filter_content_url_ip_config='proxy/plugin/filter_content_url_ip.json')
    client = DummyClient(('192.168.1.100', 12345))
    return FilterByContentUrlIpPlugin('uid', flags, client, None)

def test_block_url(plugin):
    req = DummyRequest('test.com', '/forbidden-url')
    with pytest.raises(Exception):
        plugin.handle_client_request(req)

def test_block_domain(plugin):
    req = DummyRequest('forbidden-domain.com', '/index')
    with pytest.raises(Exception):
        plugin.handle_client_request(req)

def test_block_ip(plugin):
    req = DummyRequest('test.com', '/index')
    with pytest.raises(Exception):
        plugin.handle_client_request(req)

def test_block_content(plugin):
    req = DummyRequest('test.com', '/index', body='forbidden-text')
    with pytest.raises(Exception):
        plugin.handle_client_request(req)
