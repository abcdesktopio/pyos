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
# 

import logging
import cherrypy

from oc.od.apps import ODApps
from oc.od.base_controller import BaseController
import oc.od.composer
import oc.od.services
import oc.cherrypy
import oc.logging
import distutils.util

logger = logging.getLogger(__name__)

@cherrypy.tools.allow(methods=['GET'])
@cherrypy.config(**{ 'tools.auth.on': False })
class ManagerController(BaseController):

    '''
        Description: Manager Controller 
    '''

    def __init__(self, config_controller=None):
        super().__init__(config_controller)

    # buildapplist request is protected by is_permit_request()
    @cherrypy.expose
    @cherrypy.tools.json_out()
    def buildapplist(self):
        self.is_permit_request()
        cherrypy.response.notrace = True
        # True to force an application list refresh
        return ODApps.cached_applist(True)

    # updateactivedirectorysite request is protected by is_permit_request()
    @cherrypy.expose
    @cherrypy.tools.json_out()
    def updateactivedirectorysite(self):
        ''' update activedirectory cached site and subnet cached data '''
        self.is_permit_request() 
        cherrypy.response.notrace = True
        return oc.od.services.services.update_locator()
        

    # garbagecollector request is protected by is_permit_request()
    @cherrypy.expose
    @cherrypy.tools.json_out()
    def garbagecollector(self, expirein, force=False):
        ''' garbage collector remove all user containers not connected created since more than expirein time
            expirein:   value in second
            force:      boolean False by default, garbage even if user is connected
            to remove all user containers run garbagecollector(expirein=0, force=True)
        '''
        self.is_permit_request()
        cherrypy.response.notrace = True

        if expirein is None :
            # 400 - Invalid parameters Bad Request
            raise cherrypy.HTTPError(status=400)

        nexpirein = None
        try:
            nexpirein = int( expirein )
            if type(force) is str:
                # convert str parameter to bool type
                force = distutils.util.strtobool( force )
        except Exception:
            pass # test force type and nexpirein type are done next line      

        # check if nexpirein is a integer value 
        if type(nexpirein) is not int or type(force) is not bool:
            # 400 - Invalid parameters Bad Request
            raise cherrypy.HTTPError(status=400)        
        
        # remove all disconnected container
        garbaged = oc.od.composer.garbagecollector( expirein=nexpirein, force=force )

        return garbaged