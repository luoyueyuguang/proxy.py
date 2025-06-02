# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import os
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
def plugin(tmp_path):
    # 创建临时特征库和日志文件
    config_path = tmp_path / "test_feature.json"
    log_path = tmp_path / "feature_learn.log"
    rules = [
        {"type": "url", "pattern": "illegal-url"},
        {"type": "content", "pattern": "illegal-content"}
    ]
    config_path.write_text(str(rules).replace("'", '"'), encoding='utf-8')
    flags = SimpleNamespace(filter_content_url_ip_config=str(config_path))
    FilterByContentUrlIpPlugin.FEATURE_LOG_PATH = str(log_path)
    client = DummyClient(('1.2.3.4', 12345))
    return FilterByContentUrlIpPlugin('uid', flags, client, None)

def test_illegal_url_learn(plugin, tmp_path):
    req = DummyRequest('test.com', '/illegal-url')
    with pytest.raises(Exception):
        plugin.handle_client_request(req)
    # 检查日志文件
    log_path = tmp_path / "feature_learn.log"
    assert log_path.exists()
    with open(log_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    assert any('url' in line and 'illegal-url' in line for line in lines)

def test_upgrade_feature_library(plugin, tmp_path):
    # 模拟多次出现同一特征
    log_path = tmp_path / "feature_learn.log"
    for _ in range(5):
        with open(log_path, 'a', encoding='utf-8') as f:
            f.write('content\tillegal-learned\n')
    plugin.upgrade_feature_library()
    # 检查特征库已升级
    config_path = tmp_path / "test_feature.json"
    with open(config_path, 'r', encoding='utf-8') as f:
        rules = f.read()
    assert 'illegal-learned' in rules
