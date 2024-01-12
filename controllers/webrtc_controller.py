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
import oc.od.settings
import oc.od.composer
import oc.od.webrtc 

from oc.cherrypy import Results
from oc.od.base_controller import BaseController

logger = logging.getLogger(__name__)

@oc.logging.with_logger()
@cherrypy.config(**{ 'tools.auth.on': True })
class WebRTCController(BaseController):

    def __init__(self, config_controller=None):
        super().__init__(config_controller)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def coturn_rtcconfiguration( self ):
        self.logger.debug('')
        self.validate_env() # make sure thah the user is authenticated
        rtc_configuration = oc.od.webrtc.coturn_rtcconfiguration()
        return Results.success( result=rtc_configuration )

'''
# Previous code with janus 

from oc.od.desktop import ODDesktop
from oc.od.services import services

    def rtp_stream( self, action=lambda x: x):
        self.logger.debug('')
        (auth, user ) = self.validate_env()
        if not oc.od.settings.webrtc.get('enable') :
            raise cherrypy.HTTPError( 400, message='WebRTC is disabled in configuration file')
        if services.webrtc is None:
            raise cherrypy.HTTPError( 400, message='no WebRTC configuration found')
        desktop = oc.od.composer.finddesktop( authinfo=auth, userinfo=user ) 
        if not isinstance( desktop, ODDesktop):               
            self.logger.error( "desktop is not found")
            raise cherrypy.HTTPError( 400, message='desktop not found')
        stream = action( desktop.name )
        return Results.success(result=stream)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def get_stream(self):
        self.logger.debug('')
        if services.webrtc is None :
            raise cherrypy.HTTPError( 400, message='WebRTC is disabled in configuration file')
        else:
            # get_stream create or get a previous created stream
            stream = self.rtp_stream( services.webrtc.get_stream )
            return stream
            
    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def destroy_stream(self):
        self.logger.debug('')
        if services.webrtc is None :
            raise cherrypy.HTTPError( 400, message='WebRTC is disabled in configuration file')
        else:
            return self.rtp_stream( services.webrtc.destroy_stream )
'''