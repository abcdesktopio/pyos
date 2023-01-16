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
import cherrypy		

from oc.cherrypy import Results
from oc.od.services import services
import oc.od.user
from oc.od.base_controller import BaseController

logger = logging.getLogger(__name__)

@oc.logging.with_logger()
class UserController(BaseController):

    def __init__(self, config_controller=None):
        super().__init__(config_controller)

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def getinfo(self):
        """ Method return information from user token give as arguments parameters
        """
        arguments = cherrypy.request.json
        try:
            return services.auth.getuserinfo(arguments.get('token_provider'), arguments.get('token'))
        except Exception:
            return {'userid': None, 'name': None}

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def getlocation(self):
        self.logger.debug('')
        (auth, user) = self.validate_env() 
        location = oc.od.user.getlocation( auth )
        return Results.success(result=location)

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def whoami(self):
        self.logger.debug('')  
        auth = None
        user = None
        # same has super().validate_env 
        # but do not fail or ban ipaddr
        if services.auth.isauthenticated and services.auth.isidentified:
            user = services.auth.user
            auth = services.auth.auth
        userinfo = oc.od.user.whoami( auth, user )
        return userinfo