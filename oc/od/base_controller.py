#!/usr/bin/env python3
#
# Software Name : abcdesktop.io
# Version: 0.2
# SPDX-FileCopyrightText: Copyright (c) 2020-2021 Orange
# SPDX-License-Identifier: GPL-2.0-only
#
# This software is distributed under the GNU General Public License v2.0 only
# see the "license.txt" file for more details.
#
# Author: abcdesktop.io team
# Software description: cloud native desktop service
#
import logging
import ipaddress
import re
import hmac

from fastapi import APIRouter, HTTPException, Request
from netaddr import IPNetwork, IPAddress

import oc.logging
from oc.cherrypy import (
    getclientipaddr,
    getclienthttp_header,
    getxforwardedfor,
    getproxy_ipaddr_from_xforwardedfor_header,
)
from oc.od.services import services

logger = logging.getLogger(__name__)


@oc.logging.with_logger()
class BaseController(APIRouter):

    def __init__(self, config=None, **router_kwargs):
        class_filter = r"^(\w+)Controller$"
        self.controllerprefix = re.match(class_filter, self.__class__.__name__).group(1).lower()

        # Initialise l'APIRouter avec le préfixe et le tag du contrôleur
        router_kwargs.setdefault("prefix", f"/{self.controllerprefix}")
        router_kwargs.setdefault("tags", [self.controllerprefix])
        super().__init__(**router_kwargs)

        # by default a controller is enabled even if config is not set
        self.enable = True
        self.config = config

        self.ipnetworklistfilter = None
        self.requestsallowed = None
        self.apikey = None
        self.database_acl = []

        if isinstance(config, dict):
            self.init_ipfilter()
            self.requestsallowed = config.get("requestsallowed")
            self.enable = config.get("enable", True)
            self.apikey = config.get("apikey")
            self.database_acl = config.get("database_acl", [])

    # ------------------------------------------------------------------
    def getlambdaroute(self, routecontenttype: dict, defaultcontenttype: str, request: Request):
        """Sélectionne le handler selon l'en-tête Accept de la requête."""
        accepts_header = request.headers.get("Accept", "") if request else ""
        routecontenttypekeys = routecontenttype.keys()
        for part in accepts_header.split(","):
            accept_content_type = part.split(";")[0].strip().lower()
            if accept_content_type in routecontenttypekeys:
                return routecontenttype[accept_content_type]
        return routecontenttype.get(defaultcontenttype)

    def overwrite_requestpermission_ifnotset(self, method: str, permission: bool) -> None:
        if isinstance(self.requestsallowed, dict):
            if self.requestsallowed.get(method) is None:
                self.requestsallowed[method] = permission
        else:
            self.requestsallowed = {method: permission}

    def init_ipfilter(self):
        if not isinstance(self.config, dict):
            return
        ipfilterlist = self.config.get("permitip")
        if not isinstance(ipfilterlist, list):
            return
        self.ipnetworklistfilter = []
        for ipfilter in ipfilterlist:
            try:
                ipnetwork = IPNetwork(ipfilter)
            except Exception as e:
                self.logger.error(f"invalid value={ipfilter} type={type(ipfilter)}, skipping error {e}")
                continue
            self.ipnetworklistfilter.append(ipnetwork)

    def required_controller_security_check(self, request: Request, ipAddr: str = None) -> None:
        if not isinstance(ipAddr, str):
            ipAddr = getclientipaddr(request)
        if self.isban_ip(request, ipAddr):
            raise HTTPException(status_code=401, detail="ip address is banned")
        if self.isspoofed_proxyxforwardedfor(request):
            self.fail_ip(request, ipAddr)
            raise HTTPException(status_code=401, detail="spoofed X-Forwarded-For header detected")

    def validate_env(self, request: Request):
        """Valide l'environnement de la requête (auth + ban).
        Retourne (auth, user, roles) ou lève HTTPException(401).
        """
        if self.isban_ip(request):
            raise HTTPException(status_code=401, detail="ip address is banned")
        if self.isspoofed_proxyxforwardedfor(request):
            self.fail_ip(request)
            raise HTTPException(status_code=401, detail="spoofed X-Forwarded-For header detected")
        if not services.auth.isauthenticated:
            self.fail_ip(request)
            raise HTTPException(status_code=401, detail="user is not authenticated")
        if not services.auth.isidentified:
            self.fail_ip(request)
            raise HTTPException(status_code=401, detail="user is not identified")

        user = services.auth.user
        auth = services.auth.auth
        roles = services.auth.roles

        if self.isban_login(user.userid):
            raise HTTPException(status_code=401, detail="user is banned")

        return (auth, user, roles)

    def fail_ip(self, request: Request, ipAddr: str = None):
        if not isinstance(ipAddr, str):
            ipAddr = getclientipaddr(request)
        services.fail2ban.fail_ip(ipAddr)

    def fail_login(self, login: str):
        self.logger.debug("")
        return services.fail2ban.fail_login(login)

    def isban_ip(self, request: Request, ipAddr: str = None) -> bool:
        if not isinstance(ipAddr, str):
            ipAddr = getclientipaddr(request)
        isban = services.fail2ban.isban(ipAddr, collection_name=services.fail2ban.ip_collection_name)
        if isban:
            self.logger.info(f"isban {ipAddr} return {isban}")
        return isban

    def isban_login(self, login: str) -> bool:
        isban = services.fail2ban.isban(login, collection_name=services.fail2ban.login_collection_name)
        if isban:
            self.logger.info(f"isban {login} return {isban}")
        return isban

    def isspoofed_proxyxforwardedfor(self, request: Request) -> bool:
        bReturn = True
        try:
            if not getxforwardedfor(request):
                return False
            proxies = getproxy_ipaddr_from_xforwardedfor_header(request)
            if len(proxies) == 0:
                return False
            if len(oc.od.settings.ip_network_trusted_proxy_cidr) == 0:
                return False
            for proxy in proxies:
                for network in oc.od.settings.ip_network_trusted_proxy_cidr:
                    if IPAddress(proxy) in network:
                        return False
            return True
        except Exception as e:
            self.logger.error(e)
        return bReturn

    def is_ipsource_private(self, request: Request) -> bool:
        bReturn = False
        try:
            remote_ip = getclientipaddr(request)
            if remote_ip:
                myipaddr = ipaddress.ip_address(remote_ip)
                bReturn = myipaddr.is_private
        except Exception as e:
            self.logger.error(e)
        return bReturn

    def is_apikey(self, request: Request) -> bool:
        self.logger.debug("")
        bReturn = False
        apikey = getclienthttp_header(request, "X-API-Key") or getclienthttp_header(request, "X-Api-Key")
        if apikey is None:
            return bReturn
        for k in self.apikey:
            bReturn = hmac.compare_digest(k, apikey)
            if bReturn:
                break
        return bReturn

    def raise_http_error_message(self, error_message: str, status: int = 403):
        self.logger.error(error_message)
        raise HTTPException(status_code=status, detail=error_message)

    def is_permit_request(self, request: Request):
        if not self.enable:
            self.raise_http_error_message("403.10 - Invalid configuration")

        is_api_filter = self.apifilter(request)
        is_ip_filter = self.ipfilter(request)
        if not is_api_filter or not is_ip_filter:
            if not is_ip_filter:
                self.raise_http_error_message("403.7 - IP address access denied")
            if not is_api_filter:
                self.raise_http_error_message("403.1 - Execute access forbidden")

        if isinstance(self.requestsallowed, dict):
            path = request.url.path if request else ""
            arg = path.split("/")
            if len(arg) < 3:
                self.raise_http_error_message("403.12 - Mapper denied access. Invalid request")
            request_info = arg[2]
            is_allowed = self.requestsallowed.get(request_info)
            if is_allowed is False:
                self.raise_http_error_message("403.8 - Site access denied")

    def apifilter(self, request: Request) -> bool:
        """apifilter
            check if the request apikey is in the permitted apikey list
            if no apikey list is set, return True
        Returns:
            bool: True if the request apikey is in the permitted apikey list or no list is set
        """
        self.logger.debug('')
        if isinstance(self.apikey, list):
            return self.is_apikey(request)
        # if no apikey list is set, return True
        return True

    def ipfilter(self, request: Request) -> bool:
        self.logger.debug("")
        if not isinstance(self.ipnetworklistfilter, list):
            return True
        ipclient = getclientipaddr(request)
        if isinstance(ipclient, str):
            for ipnetwork in self.ipnetworklistfilter:
                if IPAddress(ipclient) in ipnetwork:
                    self.logger.debug(f"ipsource {ipclient} is permitted in network {ipnetwork}")
                    return True
        return False


# Import deferred to avoid circular import
import oc.od.settings  # noqa: E402
