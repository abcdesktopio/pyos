#!/usr/bin/env python3
#
# Software Name : abcdesktop.io
# SPDX-FileCopyrightText: Copyright (c) 2020-2021 Orange
# SPDX-License-Identifier: GPL-2.0-only
#
import logging

from fastapi import Request

import oc.logging
import oc.od.user
from oc.cherrypy import Results
from oc.od.services import services
from oc.od.base_controller import BaseController

logger = logging.getLogger(__name__)


@oc.logging.with_logger()
class UserController(BaseController):

    def __init__(self, config_controller=None):
        super().__init__(config_controller)
        self.add_api_route("/getlocation", self.getlocation, methods=["POST"])
        self.add_api_route("/whoami", self.whoami, methods=["POST"])

    async def getlocation(self, request: Request) -> dict:
        (auth, user, roles) = self.validate_env(request)
        location = await oc.od.user.getlocation(auth, request)
        return Results.success(result=location)

    async def whoami(self, request: Request) -> dict:
        self.required_controller_security_check(request)
        auth = None
        user = None
        roles = None
        if services.auth.isauthenticated and services.auth.isidentified:
            user = services.auth.user
            auth = services.auth.auth
            roles = services.auth.roles
        userinfo = await oc.od.user.whoami(auth, user)
        return userinfo
