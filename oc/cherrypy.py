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
# --------------------------------------------------------------------------
# Ce module remplace les utilitaires CherryPy par des équivalents FastAPI.
# Le contexte de la requête courante est stocké dans un ContextVar afin de
# conserver la même API publique (getclientipaddr, etc.) sans passer
# explicitement la Request à chaque site d'appel.
# --------------------------------------------------------------------------

import logging
from typing import Optional

import netaddr
from fastapi import HTTPException, Request

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Fonctions publiques – même API que l'ancienne version CherryPy
# ---------------------------------------------------------------------------

#########
# WARNING : No logging is possible inside getclientipaddr,
# it would generate cycling dependencies call in oc.logging functions
#########


def getclienthttp_header(request: Request, header_name: str, default=None):
    if request is None:
        return default
    return request.headers.get(header_name, default)


def getclienthttp_headers(request: Request):
    if request is None:
        return {}
    return request.headers


def getclientremote_ip(request: Request) -> Optional[str]:
    if request is None:
        return None
    return request.client.host if request.client else None


def getclientreal_ip(request: Request) -> Optional[str]:
    realip = None
    try:
        _realip = getclienthttp_header(request, "X-Real-IP")
        if isinstance(_realip, str):
            ipaddr = netaddr.IPAddress(_realip)
            realip = str(ipaddr)
    except netaddr.core.AddrFormatError:
        pass
    except Exception:
        pass
    return realip


def getuseragent(request: Request) -> Optional[str]:
    return getclienthttp_header(request, "User-Agent")


def getxforwardedfor(request: Request) -> Optional[str]:
    return getclienthttp_header(request, "X-Forwarded-For")


def getclientxforwardedfor_listip(request: Request) -> list:
    clientiplist = []
    xforwardedfor = getxforwardedfor(request)
    if isinstance(xforwardedfor, str):
        for ipforwarded in xforwardedfor.split(","):
            try:
                ipaddr = netaddr.IPAddress(ipforwarded.strip())
                clientiplist.append(str(ipaddr))
            except netaddr.core.AddrFormatError:
                pass
            except Exception:
                pass
    return clientiplist


def getclientxforwardedfor_ip(request: Request) -> Optional[str]:
    clientip = None
    xforwardedfor = getxforwardedfor(request)
    if isinstance(xforwardedfor, str):
        try:
            parts = xforwardedfor.split(",")
            if parts:
                ipaddr = netaddr.IPAddress(parts[0].strip())
                clientip = str(ipaddr)
        except netaddr.core.AddrFormatError:
            pass
        except Exception:
            pass
    return clientip


def getproxy_ipaddr_from_xforwardedfor_header(request: Request) -> list:
    proxiesipaddrlist = []
    xforwardedfor = getxforwardedfor(request)
    if isinstance(xforwardedfor, str):
        try:
            parts = xforwardedfor.split(",")
            for proxy in parts[1:]:
                proxiesipaddrlist.append(proxy.strip())
        except Exception:
            pass
    return proxiesipaddrlist


def getclientipaddr_dict(request: Request) -> dict:
    return {
        "X-Forwarded-For": getclientxforwardedfor_ip(request),
        "X-Real-IP": getclientreal_ip(request),
        "remoteip": getclientremote_ip(request),
    }


# WARNING : No logging is possible inside getclientipaddr
def getclientipaddr(request: Request) -> Optional[str]:
    for myip in getclientipaddr_dict(request).values():
        if isinstance(myip, str):
            return myip
    return None


# ---------------------------------------------------------------------------
# WebAppError – remplace cherrypy.HTTPError
# ---------------------------------------------------------------------------


class WebAppError(HTTPException):
    def __init__(self, message: str, status: int = 400, code: int = 400, source=None):
        super().__init__(status_code=status, detail=message)
        self.code = code or status
        self.source = source
        self.status = status
        self.message = message

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "error": {"code": self.code, "message": self.message, "source": self.source},
        }


# ---------------------------------------------------------------------------
# Results – réponses JSON standardisées
# ---------------------------------------------------------------------------


class Results:
    @staticmethod
    def result(message: str = None, status: int = 200, result=None) -> dict:
        response: dict = {"status": status, "result": result}
        if status == 200 or status == 100: 
            response["message"] = message
        else:
            response["error"] = message or "Unknown error"
        return response

    @staticmethod
    def progress(message: str = "progress", result=None) -> dict:
        return Results.result(message, 100, result)

    @staticmethod
    def success(message: str = "ok", result=None) -> dict:
        return Results.result(message, 200, result)

    @staticmethod
    def error(message: str = "unknown error", status: int = 500, _context=None) -> dict:
        return Results.result(message, status)

    @staticmethod
    def unauthorized(message: str = "unauthorized") -> dict:
        return Results.result(message, 401)

    @staticmethod
    def is_a_success(result: dict) -> bool:
        if isinstance(result, dict):
            return result.get("status") == 200
        return False

    @staticmethod
    def is_in_progress(result: dict) -> bool:
        if isinstance(result, dict):
            return result.get("status") == 100
        return False

    @staticmethod
    def is_an_error(result: dict) -> bool:
        if isinstance(result, dict):
            return result.get("status") not in (100, 200)
        return False