# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    .. spelling::

       ip
"""
import re
import json
import logging
import os
import urllib.request
from typing import Any, Dict, List, Optional
from ..http import httpStatusCodes
from ..http.proxy import HttpProxyBasePlugin
from ..common.flag import flags
from ..http.parser import HttpParser
from ..common.utils import text_
from ..http.exception import HttpRequestRejected

logger = logging.getLogger(__name__)

flags.add_argument(
    '--filter-content-url-ip-config',
    type=str,
    default='',
    help='过滤内容/URL/IP/域名的json配置文件路径',
)

#增加从远程URL更新黑名单的功能
flags.add_argument(
    '--update-blacklist-from-url',
    type=str,
    default='',
    help='从指定网址下载黑名单并合并到本地特征库，支持简单文本或json格式',
)

class FilterByContentUrlIpPlugin(HttpProxyBasePlugin):
    """统一过滤插件：支持对文本内容、URL、域名、IP进行过滤，并支持自学习升级特征库。"""
    FEATURE_LOG_PATH = 'proxy/plugin/feature_learn.log'  # 可自定义路径

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.rules: List[Dict[str, Any]] = []
        # self.config_path = self.flags.filter_content_url_ip_config
        # if self.config_path:
        #     with open(self.config_path, 'r', encoding='utf-8') as f:
        #         self.rules = json.load(f)
        self.config_path = flags.filter_content_url_ip_config
        if self.config_path and os.path.exists(self.config_path):
            with open(self.config_path, 'r', encoding='utf-8') as f:
                try:
                    self.rules = json.load(f)
                except json.JSONDecodeError as e:
                    logger.error(f"加载特征库失败: {e}")
                    self.rules = []
        else:
            logger.warning(f"特征库配置文件不存在或无法读取: {self.config_path}")
            self.rules = []
        # 如果指定了远程黑名单URL，则尝试更新本地特征库
        self.update_blacklist_from_url(flags.update_blacklist_from_url) if flags.update_blacklist_from_url else None

    def _log_illegal_feature(self, rule_type: str, value: str):
        # 记录被拦截的非法特征，供后续人工或自动分析升级特征库
        with open(self.FEATURE_LOG_PATH, 'a', encoding='utf-8') as f:
            f.write(f'{rule_type}\t{value}\n')

    def _match(self, rule_type: str, value: str) -> bool:
        for rule in self.rules:
            if rule.get('type') == rule_type:
                pattern = rule.get('pattern')
                if pattern and re.search(pattern, value, re.IGNORECASE):
                    logger.info(f"Blocked by {rule_type} rule: {pattern}")
                    self._log_illegal_feature(rule_type, value)
                    return True
        return False

    def upgrade_feature_library(self):
        # 简单自学习：将日志中出现频率高的特征自动加入特征库
        if not os.path.exists(self.FEATURE_LOG_PATH):
            return
        from collections import Counter
        with open(self.FEATURE_LOG_PATH, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        features = [line.strip().split('\t', 1) for line in lines if '\t' in line]
        counter = Counter(tuple(f) for f in features)
        # 只自动加入出现超过3次的特征
        new_rules = []
        for (rule_type, value), count in counter.items():
            if count > 3 and not any(r.get('type') == rule_type and r.get('pattern') == value for r in self.rules):
                new_rules.append({'type': rule_type, 'pattern': value})
        if new_rules and self.config_path:
            self.rules.extend(new_rules)
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(self.rules, f, ensure_ascii=False, indent=2)
            logger.info(f"自学习已将{len(new_rules)}条新特征加入特征库")

    def handle_client_request(self, request: HttpParser) -> Optional[HttpParser]:
        # 过滤URL
        url = f"{text_(request.host)}{text_(request.path)}"
        if self._match('url', url):
            raise HttpRequestRejected(status_code=httpStatusCodes.I_AM_A_TEAPOT, reason=b'Blocked by URL rule')
        # 过滤域名
        if self._match('domain', text_(request.host)):
            raise HttpRequestRejected(status_code=httpStatusCodes.I_AM_A_TEAPOT, reason=b'Blocked by domain rule')
        # 过滤IP
        if self._match('ip', text_(self.client.addr[0])):
            raise HttpRequestRejected(status_code=httpStatusCodes.I_AM_A_TEAPOT, reason=b'Blocked by IP rule')
        # 过滤请求内容
        if request.body and self._match('content', text_(request.body)):
            raise HttpRequestRejected(status_code=httpStatusCodes.I_AM_A_TEAPOT, reason=b'Blocked by content rule')
        return request

    def handle_upstream_chunk(self, chunk: memoryview) -> memoryview:
        # 过滤响应内容
        if self._match('content', chunk.tobytes().decode(errors='ignore')):
            logger.info('Blocked by content rule in response')
            return memoryview(b'')
        return chunk

    def update_blacklist_from_url(self, url: str):
        """从指定网址下载黑名单并合并到本地特征库。支持简单文本或json格式。"""
        try:
            with urllib.request.urlopen(url, timeout=10) as response:
                content = response.read().decode('utf-8')
            # 尝试解析为json，否则按每行一个特征处理
            try:
                remote_rules = json.loads(content)
                if isinstance(remote_rules, list):
                    for rule in remote_rules:
                        if rule not in self.rules:
                            self.rules.append(rule)
                else:
                    logger.warning('远程黑名单不是list格式，忽略')
            except Exception:
                # 按每行一个域名或IP，加入domain黑名单
                for line in content.splitlines():
                    line = line.strip()
                    if line and not any(r.get('type') == 'domain' and r.get('pattern') == line for r in self.rules):
                        self.rules.append({'type': 'domain', 'pattern': line})
            # 保存到本地配置
            if self.config_path:
                with open(self.config_path, 'w', encoding='utf-8') as f:
                    json.dump(self.rules, f, ensure_ascii=False, indent=2)
            logger.info('已从远程更新黑名单')
        except Exception as e:
            logger.error(f'更新黑名单失败: {e}')
