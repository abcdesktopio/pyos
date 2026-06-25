#!/usr/bin/env python3
#
# Software Name : abcdesktop.io
# SPDX-FileCopyrightText: Copyright (c) 2020-2021 Orange
# SPDX-License-Identifier: GPL-2.0-only
#
import json
import logging

from fastapi import Request, Response

import oc.logging
import oc.od.services
import oc.auth.namedlib
from oc.od.base_controller import BaseController

logger = logging.getLogger(__name__)


@oc.logging.with_logger()
class AccountingController(BaseController):

    def __init__(self, config_controller=None):
        super().__init__(config_controller)
        self.add_api_route("/metrics", self.metrics, methods=["GET"])

    async def metrics(self, request: Request, format: str = "ebnf") -> Response:
        """Return metrics. Default format is ebnf."""
        self.is_permit_request(request)
        if format == "json":
            return await self.dump_tojson()
        else:
            return await self.dump_toebnf()

    async def dump_toebnf(self) -> Response:
        output = ""
        message = await oc.od.services.services.accounting.todict()
        if isinstance(message, dict):
            for counter_name, v in message.items():
                if isinstance(v, dict):
                    for ka in v:
                        if counter_name in ["container", "image"]:
                            datatype = oc.auth.namedlib.normalize_containername(ka)
                        else:
                            datatype = ka
                        output += f'pyos_{counter_name}_total{{{counter_name}="{datatype}"}} {v.get(ka)}\n'
                if isinstance(v, str):
                    output += f"# {counter_name} pyos_counter\n"
                    output += f"pyos_{counter_name}_total {v}\n"
        return Response(content=output.encode("utf8"), media_type="text/plain;charset=utf-8")

    async def dump_tojson(self) -> Response:
        message = await oc.od.services.services.accounting.todict()
        return Response(content=json.dumps(message).encode("utf8"), media_type="application/json;charset=utf-8")
