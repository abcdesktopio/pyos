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

# Desktop.io lib
import oc.logging
from oc.od.base_controller import BaseController

logger = logging.getLogger(__name__)

@cherrypy.tools.allow(methods=['GET'])
@cherrypy.config(**{ 'tools.auth.on': False })
@oc.logging.with_logger()
class KeyController(BaseController):

    def __init__(self, config_controller=None):
        super().__init__(config_controller)

    # key request is protected by is_permit_request()
    @cherrypy.expose
    def key(self, format='rsa', length='1024'):
        ''' return a jwt with public key in payload'''
        length = int( length )
        self.is_permit_request()       
        jwt = oc.od.services.services.keymanager.encode( length=length)
        cherrypy.response.headers['Content-Type'] = 'application/jwt'
        return jwt