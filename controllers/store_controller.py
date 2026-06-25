#!/usr/bin/env python3
#
# Software Name : abcdesktop.io
# SPDX-FileCopyrightText: Copyright (c) 2020-2021 Orange
# SPDX-License-Identifier: GPL-2.0-only
#
import logging

from fastapi import Request
from fastapi.exceptions import HTTPException

import oc.logging
from oc.od.services import services
from oc.cherrypy import Results
from oc.od.base_controller import BaseController

logger = logging.getLogger(__name__)


@oc.logging.with_logger()
class StoreController(BaseController):

    def __init__(self, config_controller=None):
        super().__init__(config_controller)
        self.wrapped_key = (config_controller or {}).get("wrapped_key", {})
        self.databasename = "profiles"
        self.add_api_route("/set", self.set, methods=["POST"])
        self.add_api_route("/get", self.get, methods=["POST"])
        self.add_api_route("/getcollection", self.getcollection, methods=["POST"])

    async def set(self, request: Request) -> dict:
        (auth, user, roles) = self.validate_env(request)
        try:
            arguments = await request.json()
        except Exception as e:
            return Results.error(message=f"invalid parameters: {e}")
        if not isinstance(arguments, dict):
            return Results.error(message="invalid parameters")
        userid = user.userid
        key = arguments.get("key")
        value = arguments.get("value")
        if all([userid, key]):
            if services.datastore.set_document_value_in_collection(self.databasename, userid, key, value) is True:
                return Results.success()
        return Results.error(message="invalid parameters")

    async def get(self, request: Request) -> dict:
        (auth, user, roles) = self.validate_env(request)
        try:
            arguments = await request.json()
        except Exception as e:
            return Results.error(message=f"invalid parameters: {e}")
        if not isinstance(arguments, dict):
            return Results.error(message="invalid parameters")
        userid = user.userid
        key = arguments.get("key")
        if all([userid, key]):
            value = services.datastore.get_document_value_in_collection(self.databasename, userid, key)
            return Results.success(result=value)
        return Results.error(message="invalid parameters")

    async def getcollection(self, request: Request) -> dict:
        (auth, user, roles) = self.validate_env(request)
        try:
            arguments = await request.json()
        except Exception as e:
            return Results.error(message=f"invalid parameters: {e}")
        if not isinstance(arguments, dict):
            return Results.error(message="invalid parameters")
        userid = user.userid
        collection = services.datastore.get_document_collection(self.databasename, userid)
        return Results.success(result=collection)
