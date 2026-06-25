#!/usr/bin/env python3
#
# Software Name : abcdesktop.io
# Version: 0.2
# SPDX-FileCopyrightText: Copyright (c) 2020-2021 Orange
# SPDX-License-Identifier: GPL-2.0-only
#
import json
import logging
from typing import Any
import urllib
from urllib import response
import ua_parser 
from collections.abc import AsyncIterable, Iterable
from pydantic import BaseModel
from fastapi import Depends, Request, Response
from fastapi.exceptions import HTTPException
from fastapi.sse import EventSourceResponse, ServerSentEvent

import oc.logging
import oc.od.composer
import oc.od.settings as settings
import oc.i18n
from oc.auth.authservice import AuthInfo, AuthUser, AuthRoles
from oc.cherrypy import Results
from oc.od.base_controller import BaseController
from oc.od.services import services

logger = logging.getLogger(__name__)


class ResultItem(BaseModel):
    status: int
    message: str | None
    result: dict | None

@oc.logging.with_logger()
class ComposerController(BaseController):
    """Description: Composer Controller"""

    def __init__(self, config_controller=None):
        super().__init__(config_controller)
        self.add_api_route("/ocrun",                   self.ocrun,                   methods=["POST"])
        self.add_api_route( path="/launchdesktop",     endpoint=self.launchdesktop,  dependencies=[Depends(self.live_jsonl_headers)],methods=["POST"], response_class=EventSourceResponse)
        self.add_api_route("/list_applications_by_phase", self.list_applications_by_phase, methods=["POST"])
        self.add_api_route("/getlogs",                 self.getlogs,                 methods=["POST"])
        self.add_api_route("/stopcontainer",           self.stopcontainer,           methods=["POST"])
        self.add_api_route("/logcontainer",            self.logcontainer,            methods=["POST"])
        self.add_api_route("/envcontainer",            self.envcontainer,            methods=["POST"])
        self.add_api_route("/removecontainer",         self.removecontainer,         methods=["POST"])
        self.add_api_route("/listcontainer",           self.listcontainer,           methods=["POST"])
        self.add_api_route("/refreshdesktoptoken",     self.refreshdesktoptoken,     methods=["POST"])
        self.add_api_route("/getdesktopdescription",   self.getdesktopdescription,   methods=["POST"])
        self.add_api_route("/getuserapplist",          self.getuserapplist,          methods=["POST"])
        self.add_api_route("/listsecrets",             self.listsecrets,             methods=["POST"])
        self.add_api_route("/finddesktop",             self.finddesktop,             methods=["POST"])
        self.add_api_route("/getapplist",              self.getapplist,              methods=["POST"])


    async def live_jsonl_headers(self, response:Response) -> Response:
        # response.headers["Cache-Control"] = "no-cache"
        response.headers["X-Accel-Buffering"] = "no"
        return response


    def LocaleSettingsLanguage(self, user: dict, request: Request) -> None:
        accept_language = request.headers.get("Accept-Language") if request else None
        locale = oc.i18n.detectLocale(accept_language, oc.od.settings.supportedLocales)
        user["locale"] = locale

    async def ocrun(self, request: Request) -> dict:
        self.logger.debug("")
        (auth, user, roles) = self.validate_env(request)
        try:
            args = await request.json()
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"invalid parameters: {e}")
        if not isinstance(args, dict):
            raise HTTPException(status_code=400, detail="invalid parameters")
        appname = args.get("image")
        if not isinstance(appname, str) or len(appname) == 0:
            raise HTTPException(status_code=400, detail="invalid image parameters")
        self.LocaleSettingsLanguage(user, request)
        result = await oc.od.composer.openapp(auth, user, args)
        if not isinstance(result, dict):
            raise HTTPException(status_code=400, detail="ocrun error")
        return Results.success(result=result)

    async def launchdesktop(self, request: Request )-> AsyncIterable[ ResultItem ]:
    # async def launchdesktop(self, request: Request, response: Response = Depends(live_jsonl_headers))-> AsyncIterable[ ResultItem ]:
    # async def launchdesktop(self, request: Request)-> AsyncIterable[ ServerSentEvent ]:
        self.logger.debug("")
        (auth, user, roles) = self.validate_env(request)
        self.logger.debug("launchdesktop:LocaleSettingsLanguage")
        self.LocaleSettingsLanguage(user, request)
        args = {}

        #try:
        #    args = await request.json()
        #except Exception as e:
        #    raise HTTPException(status_code=400, detail=f"invalid parameters: {e}")
        
        # response.headers["Cache-Control"] = "no-cache"
        # response.headers["X-Accel-Buffering"] = "no"

        if not isinstance(args, dict):
            raise HTTPException(status_code=400, detail="invalid parameters")
        
        #yield ServerSentEvent(comment="stream of item updates")
        resultitem = None
        launchdesktop_events = self._launchdesktop(auth, user, roles, args, request)
        i=0
        async for item in launchdesktop_events:
            self.logger.debug(f"launchdesktop:yield_{i} {item}")
            if isinstance(item, dict):
                resultitem=ResultItem(status=item.get("status"), message=item.get("message"), result=item.get("result"))
                if Results.is_a_success(item):
                    await launchdesktop_events.aclose()
                if Results.is_in_progress(item): 
                    # yield ServerSentEvent(data=resultitem, event="item_update", id=str(i), retry=5000)
                    yield resultitem
                if Results.is_an_error(item):
                    await launchdesktop_events.aclose()
            else:
                resultitem=ResultItem(status=500, message="unknown error", result=None)
            i=i+1
        
        # yield ServerSentEvent(data=resultitem, event="item_update", id=str(i), retry=5000)
        yield resultitem


    async def list_applications_by_phase(self, request: Request) -> list:
        (auth, user, roles) = self.validate_env(request)
        try:
            args = await request.json()
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"invalid parameters: {e}")
        if not isinstance(args, dict):
            raise HTTPException(status_code=400, detail="invalid parameters")
        phase = args.get("phase")
        if not isinstance(phase,str) or phase not in ["Running", "Terminated", "Waiting", "Completed", "Succeeded"]:
            raise HTTPException(status_code=400, detail="invalid args parameters")
        return await oc.od.composer.list_applications_by_phase(auth, user, phase)

    async def getlogs(self, request: Request) -> dict:
        self.logger.debug("")
        (auth, user, roles) = self.validate_env(request)
        logs = await oc.od.composer.logdesktop(auth, user)
        return Results.success(result=logs)

    async def stopcontainer(self, request: Request) -> dict:
        self.logger.debug("")
        (auth, user, roles) = self.validate_env(request)
        try:
            args = await request.json()
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"invalid parameters: {e}")
        if not isinstance(args, dict):
            raise HTTPException(status_code=400, detail="invalid parameters")
        containerid = args.get("containerid")
        if not isinstance(containerid, str):
            raise HTTPException(status_code=400, detail="invalid containerid parameters")
        podname = args.get("podname")
        if not isinstance(podname, str):
            return Results.error(message="invalid parameter podname")
        result = await oc.od.composer.stopContainerApp(auth, user, podname, containerid)
        if result:
            return Results.success(result=result)
        raise HTTPException(status_code=400, detail="failed to stop container")

    async def logcontainer(self, request: Request) -> dict:
        self.logger.debug("")
        (auth, user, roles) = self.validate_env(request)
        try:
            args = await request.json()
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"invalid parameters: {e}")
        if not isinstance(args, dict):
            raise HTTPException(status_code=400, detail="invalid parameters")
        podname = args.get("podname")
        if not isinstance(podname, str):
            return Results.error(message="invalid parameter podname")
        containerid = args.get("containerid")
        if not isinstance(containerid, str):
            raise HTTPException(status_code=400, detail="invalid parameters containerid")
        result = await oc.od.composer.logContainerApp(auth, user, podname, containerid)
        if result is not None:
            return Results.success(result=result)
        raise HTTPException(status_code=400, detail="failed to get log container")

    async def envcontainer(self, request: Request) -> dict:
        self.logger.debug("")
        (auth, user, roles) = self.validate_env(request)
        try:
            args = await request.json()
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"invalid parameters: {e}")
        if not isinstance(args, dict):
            raise HTTPException(status_code=400, detail="invalid parameters")
        containerid = args.get("containerid")
        if not isinstance(containerid, str):
            raise HTTPException(status_code=400, detail="invalid parameters")
        podname = args.get("podname")
        if not isinstance(podname, str):
            return Results.error(message="invalid parameter podname")
        result = await oc.od.composer.envContainerApp(auth, user, podname, containerid)
        if not result:
            raise HTTPException(status_code=500, detail="failed to get log container")
        return Results.success(result=result)

    async def removecontainer(self, request: Request) -> dict:
        self.logger.debug("")
        (auth, user, roles) = self.validate_env(request)
        try:
            args = await request.json()
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"invalid parameters: {e}")
        if not isinstance(args, dict):
            raise HTTPException(status_code=400, detail="invalid parameters")
        containerid = args.get("containerid")
        if not isinstance(containerid, str):
            raise HTTPException(status_code=400, detail="invalid parameter containerid")
        podname = args.get("podname")
        if not isinstance(podname, str):
            return Results.error(message="invalid parameter podname")
        result = await oc.od.composer.removeContainerApp(auth, user, podname, containerid)
        if isinstance(result, bool):
            return Results.success(result=result) if result else Results.error("failed to remove container")
        raise HTTPException(status_code=400, detail="failed to remove container")

    async def listcontainer(self, request: Request) -> dict:
        self.logger.debug("")
        (auth, user, roles) = self.validate_env(request)
        result = await oc.od.composer.listContainerApps(auth, user)
        return Results.success(result=result)

    async def refreshdesktoptoken(self, request: Request) -> Response:
        self.logger.debug("")
        (auth, user, roles) = self.validate_env(request)
        desktop = await oc.od.composer.finddesktop(authinfo=auth, userinfo=user)
        if not isinstance(desktop, oc.od.desktop.ODDesktop):
            raise HTTPException(status_code=400, detail="finddesktop does not return a desktop object")
        if not oc.od.desktop.isdesktopreachabled(desktop):
            raise HTTPException(status_code=400, detail="Your desktop is unreachable")
        jwtdesktoptoken = services.jwtdesktop.encode(desktop.internaluri)
        result = Results.success(result={"authorization": jwtdesktoptoken, "expire_in": services.jwtdesktop.exp()})
        return Response(
            content=json.dumps(result).encode("utf-8"),
            media_type="application/json;charset=utf-8",
            headers={"Cache-Control": "no-cache, private", "X-Content-Type-Options": "nosniff"},
        )

    async def getdesktopdescription(self, request: Request) -> dict:
        self.logger.debug("")
        self.is_permit_request(request)
        self.required_controller_security_check(request)
        (auth, user, roles) = self.validate_env(request)
        webclient_ip_addr = oc.cherrypy.getclientremote_ip(request)
        result = await oc.od.composer.getdesktopdescription(auth, user, webclient_ip_addr)
        if not isinstance(result, dict):
            raise HTTPException(status_code=400, detail="failed to getdesktopdescription")
        return Results.success(result=result)

    async def getuserapplist(self, request: Request) -> dict:
        self.logger.debug("")
        (auth, user, roles) = self.validate_env(request)
        userappdict = {}
        appdict = services.apps.user_appdict(auth, filtered_public_attr_list=True)
        defaultappdict = services.apps.default_appdict(auth, settings.get_default_appdict(), filtered_public_attr_list=True)
        userappdict.update(defaultappdict)
        userappdict.update(appdict)
        userapplist = list(userappdict.values())
        return Results.success(result=userapplist)

    async def listsecrets(self, request: Request) -> dict:
        (auth, user, roles) = self.validate_env(request)
        secrets = await oc.od.composer.listAllSecretsByUser(auth, user)
        return Results.success(result=list(secrets))

    async def finddesktop(self, request: Request) -> dict:
        (auth, user, roles) = self.validate_env(request)
        desktop = await oc.od.composer.finddesktop(authinfo=auth, userinfo=user)
        return Results.success(result=desktop)

    async def getapplist(self, request: Request) -> dict:
        (auth, user, roles) = self.validate_env(request)
        return Results.success(result=services.apps.get_json_applist())

    async def _launchdesktop(self, auth: AuthInfo, user: AuthUser, roles: AuthRoles, args: dict, request: Request):
        self.logger.debug("")
        
        # read http headers for accounting and log history data
        args[ 'ABCDESKTOP_WEBCLIENT_SOURCEIPADDR' ] = oc.cherrypy.getclientremote_ip(request)
        args[ 'ABCDESKTOP_WEBCLIENT_USERAGENT_OS_FAMILY' ] = self.get_webclient_os_family(request) # parse_user_agent_os_family()
    
        desktop_events = oc.od.composer.opendesktop(auth, user, roles, args)
        async for desktop in desktop_events:
            if not isinstance(desktop, oc.od.desktop.ODDesktop):
                if isinstance(desktop, str):
                    if desktop.startswith("e."):
                        await desktop_events.aclose()
                        yield Results.error(message=desktop)
                    else:
                        yield Results.progress(message=desktop)
                else:
                    await desktop_events.aclose()
                    yield Results.error(message="e.Desktop creation failed")
            elif not oc.od.desktop.isdesktopreachabled(desktop):
                await desktop_events.aclose()
                if await oc.od.composer.removedesktop(auth, user) is True:
                    yield Results.error(message="e.Your desktop is unreachabled. Delete desktop done.")
                else:
                    error_msg = oc.od.desktop.getunreachablemessage(desktop)
                    yield Results.error(message=f"Your desktop previous was unreachable. {error_msg}. Please try to reload again.")
            else:
                jwtdesktoptoken = services.jwtdesktop.encode(desktop.internaluri)
                target = desktop.ipAddr
                if desktop.websocketrouting == "bridge":
                    target = desktop.websocketroute
                expire_in = services.jwtdesktop.exp()
                target_ip = self.get_target_ip_route(target, desktop.websocketrouting, request)
                yield Results.success(result={
                    "target_ip": target_ip,
                    "vncpassword": desktop.vncPassword,
                    "authorization": jwtdesktoptoken,
                    "websocketrouting": desktop.websocketrouting,
                    "websockettcpport": oc.od.settings.desktop_pod["graphical"].get("tcpport"),
                    "expire_in": expire_in,
                })


    def get_target_ip_route(self, target: str, websocketrouting: str, request: Request) -> str:
        http_origin = request.headers.get("Origin") if request else None
        http_host   = request.headers.get("Host") if request else None
        http_requested_host = str(request.url) if request else ""

        route = None
        url = urllib.parse.urlparse(http_requested_host)
        route = url.hostname

        if websocketrouting == "default_host_url":
            try:
                myhosturl = oc.od.settings.default_host_url or http_origin
                url = urllib.parse.urlparse(myhosturl)
                route = url.hostname
            except Exception as e:
                self.logger.error(e)
        elif websocketrouting == "bridge":
            route = target
        elif websocketrouting == "http_origin":
            if http_origin is not None:
                try:
                    url = urllib.parse.urlparse(http_origin)
                    route = url.hostname
                except Exception as e:
                    self.logger.error(e)
        elif websocketrouting == "http_host":
            try:
                url = urllib.parse.urlparse(http_host)
                route = url.hostname
            except Exception as e:
                self.logger.error(e)

        self.logger.debug(f"Route websocket to: {route}")
        return route


    def get_webclient_os_family(self,request:Request):
        desktop_theme = oc.od.settings.desktop.get('theme')
        if isinstance(desktop_theme, str):
            if desktop_theme == 'autodetect':
                desktop_theme = self.parse_user_agent_os_family(request)
        return desktop_theme

    def parse_user_agent_os_family(self,request:Request)->str:
        os_family = None # default value as fallback
        try:
            user_agent = oc.cherrypy.getuseragent(request)
            if isinstance(user_agent, str):
                user_agent = user_agent[:512]  # guard against pathological UA strings
            ua_parsed = ua_parser.parse(user_agent)
            if isinstance( ua_parsed, ua_parser.core.Result):
                os_family = ua_parsed.os.family.replace(' ', '').lower()
            # Mac OS/X -> macosx
            # Linux -> linux
            # Windows -> windows
        except Exception as e:
            logger.error(e)
        return os_family


import oc.od.desktop  # noqa: E402 (deferred to avoid circular import)
