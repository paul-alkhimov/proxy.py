# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2020-present by Abhinav Singh, P.Alkhimov and contributors.
    :license: BSD, see LICENSE for more details.
"""
from typing import Optional, Any
import logging
from ldap3 import Server, Connection, ALL
import base64
import configparser

from ..common.utils import bytes_

from ..http.exception import ProxyAuthenticationFailed
from ..http.parser import HttpParser
from ..http.proxy import HttpProxyBasePlugin

logger = logging.getLogger(__name__)


class LdapAuthenticationPlugin(HttpProxyBasePlugin):
    """Drop traffic if needed after checking user's credentials with LDAP."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        if 'optional' in kwargs and kwargs['optional']:
            self.filename = kwargs['optional'][0]
        else:
            raise ProxyAuthenticationFailed(
                'Cannot init LDAP plugin without config. Profide the config file name after a colon: "plugin:filename"')

    def before_upstream_connection(self, request: HttpParser) -> Optional[HttpParser]:
        ldap_config = configparser.ConfigParser()
        ldap_config.read(self.filename)
        # if LDAP us provided, it is checked, otherwise user is allowed
        if ldap_config.get('ldap', 'Server'):
            if b'proxy-authorization' not in request.headers:
                raise ProxyAuthenticationFailed()
            plainUser, plainPassword = base64.b64decode(bytes_(
                request.headers[b'proxy-authorization'][1]).decode().split()[1]).decode('utf8').split(":")
            logger.info('LDAP auth: user=%s, password=%s',
                        plainUser, plainPassword)
            try:
                ldap_server = Server(ldap_config.get(
                    'ldap', 'Server'), get_info=ALL)
                ldap_conn = Connection(
                    ldap_server, ldap_config.get('ldap', 'Root'), ldap_config.get('ldap', 'Secret'), auto_bind=True)
                # stub check, to be clarified
                what = ldap_config.get('ldap', 'What')
                if ldap_conn.search(ldap_config.get('ldap', 'Where'), what):
                    logger.info("LDAP auth: %s is found", what)
                else:
                    logger.warning("LDAP auth: %s is not found", what)
                    raise ProxyAuthenticationFailed()
            except Exception:
                logger.warning("LDAP auth failed to connect to LDAP server")
                raise ProxyAuthenticationFailed()
        else:
            if b'proxy-authorization' in request.headers:
                logger.warning("LDAP source is required, but not provided")
                raise ProxyAuthenticationFailed()
        return request

    def handle_client_request(self, request: HttpParser) -> Optional[HttpParser]:
        return request

    def handle_upstream_chunk(self, chunk: memoryview) -> memoryview:
        return chunk

    def on_upstream_connection_close(self) -> None:
        pass
