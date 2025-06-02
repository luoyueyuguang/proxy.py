# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import time
import logging
from threading import Lock
from typing import Any, Dict, Optional
from ..http import httpStatusCodes
from ..http.proxy import HttpProxyBasePlugin
from ..common.flag import flags
from ..http.parser import HttpParser
from ..http.exception import HttpRequestRejected

logger = logging.getLogger(__name__)

flags.add_argument(
    '--max-daily-seconds',
    type=int,
    default=3600,
    help='每个IP每天最大可用秒数，默认3600秒(1小时)',
)
flags.add_argument(
    '--max-session-seconds',
    type=int,
    default=600,
    help='单次连接最大时长(秒)，默认600秒(10分钟)',
)

class LimitTimeByIpPlugin(HttpProxyBasePlugin):
    """限时上网和超时下线插件：为每个IP限制每日累计时长和单次连接时长。"""
    _ip_usage: Dict[str, Dict[str, Any]] = {}
    _lock = Lock()

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._session_start = time.time()

    def _check_time_limit(self, ip: str) -> None:
        now = time.time()
        today = time.strftime('%Y-%m-%d', time.localtime(now))
        with self._lock:
            usage = self._ip_usage.setdefault(ip, {})
            if usage.get('date') != today:
                usage['date'] = today
                usage['seconds'] = 0
            session_seconds = now - self._session_start
            # 检查单次连接超时
            if session_seconds > self.flags.max_session_seconds:
                logger.warning(f"IP {ip} session timeout.")
                raise HttpRequestRejected(status_code=httpStatusCodes.REQUEST_TIMEOUT, reason=b'Session timeout, offline')
            # 检查每日累计时长
            if usage['seconds'] + session_seconds > self.flags.max_daily_seconds:
                logger.warning(f"IP {ip} daily time exceeded.")
                raise HttpRequestRejected(status_code=httpStatusCodes.FORBIDDEN, reason=b'Daily time exceeded, offline')
            # 预留：可在连接关闭时将 session_seconds 累加到 usage['seconds']

    def handle_client_request(self, request: HttpParser) -> Optional[HttpParser]:
        ip = self.client.addr[0] if self.client and self.client.addr else 'unknown'
        self._check_time_limit(ip)
        return request
