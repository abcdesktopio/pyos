#!/usr/bin/env python3
#
# Software Name : abcdesktop.io
# Version: 0.2
# SPDX-FileCopyrightText: Copyright (c) 2020-2021 Orange
# SPDX-License-Identifier: GPL-2.0-only
#
import json
import logging

from fastapi import HTTPException, Request, Response

import oc.logging
import oc.od.settings
from oc.cherrypy import Results
from oc.od.services import services
from oc.od.base_controller import BaseController

logger = logging.getLogger(__name__)


@oc.logging.with_logger()
class CoreController(BaseController):
    """Description: Core Controller"""

    def __init__(self, config_controller=None):
        super().__init__(config_controller)
        self.version_data = self.get_current_version_from_file()
        self.add_api_route("/getkeyinfo",    self.getkeyinfo,    methods=["POST"])
        self.add_api_route("/getmessageinfo", self.getmessageinfo, methods=["POST"])
        self.add_api_route("/version",       self.version,       methods=["GET"])

    async def getkeyinfo(self, request: Request) -> dict:
        """Return the key id if key is set in configuration file."""
        try:
            arguments = await request.json()
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"invalid parameters: {e}")
        
        if not isinstance(arguments, dict):
            return {}
        provider = arguments.get("provider")
        if not isinstance(provider, str):
            return {}

        id = None
        callbackurl = None

        if provider == "colors":
            id = oc.od.settings.desktop.get("defaultbackgroundcolors")
        elif provider == "menuconfig":
            id = oc.od.settings.menuconfig
        elif provider == "geolocation":
            id = oc.od.settings.geolocation
        elif provider == "zoom":
            id = oc.od.settings.desktop.get("zoom")
        elif provider == "tipsinfo":
            id = oc.od.settings.tipsinfoconfig
        elif provider == "welcomeinfo":
            id = oc.od.settings.welcomeinfoconfig
        elif provider == "imagenotificationconfig":
            id = oc.od.settings.imagenotificationconfig
        elif provider == "features_permissions_executeclasses":
            if "read" in oc.od.settings.desktop.get("features_permissions", []):
                id = oc.od.settings.executeclasses
        return {"id": id, "callbackurl": callbackurl}

    def handler_messageinfo_json(self, messageinfo) -> Response:
        data = Results.success(message=messageinfo)
        result_str = json.dumps(data) + "\n"
        return Response(content=result_str.encode("utf-8"), media_type="application/json;charset=utf-8")

    def handler_messageinfo_text(self, messageinfo) -> Response:
        result_str = messageinfo + "\n"
        return Response(
            content=result_str.encode("utf-8"),
            media_type="text/text;charset=utf-8",
            headers={"Cache-Control": "no-cache, private"},
        )

    async def getmessageinfo(self, request: Request) -> Response:
        (auth, user, roles) = self.validate_env(request)
        lambdaroute = b""
        routecontenttype = {
            "text/plain": self.handler_messageinfo_text,
            "application/json": self.handler_messageinfo_json,
        }
        try:
            message = services.messageinfo.popflush(user.userid)
            lambdaroute = self.getlambdaroute(routecontenttype, defaultcontenttype="application/json", request=request)(message)
        except Exception as e:
            self.logger.error(f"getmessageinfo error {e}")
        return lambdaroute

    def get_current_version_from_file(self) -> dict:
        version_file = "version.json"
        version_data = {"date": "undefined", "commit": "undefined"}
        try:
            with open(version_file) as json_file:
                version_data = json.load(json_file)
        except Exception as e:
            logger.error(f"Error loading version information from {version_file}: {e}")
        return version_data

    async def version(self, request: Request) -> dict:
        self.validate_env(request)
        return self.version_data
