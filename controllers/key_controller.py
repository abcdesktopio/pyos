#!/usr/bin/env python3
#
# Software Name : abcdesktop.io
# SPDX-FileCopyrightText: Copyright (c) 2020-2021 Orange
# SPDX-License-Identifier: GPL-2.0-only
#
import logging

from fastapi import Request, Response
from fastapi.exceptions import HTTPException

import oc.logging
import oc.od.services
from oc.od.base_controller import BaseController

logger = logging.getLogger(__name__)


@oc.logging.with_logger()
class KeyController(BaseController):

    def __init__(self, config_controller=None):
        super().__init__(config_controller)
        self.add_api_route("/key", self.key, methods=["GET"])

    async def key(self, request: Request, format: str = "rsa", length: int = 1024) -> Response:
        """Return a jwt with public key in payload."""
        self.is_permit_request(request)
        if length not in [2048, 4096]:
            raise HTTPException(status_code=400, detail="invalid length parameter")
        jwt = oc.od.services.services.keymanager.encode(length=length)
        return Response(content=jwt, media_type="application/jwt")
