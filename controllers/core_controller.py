﻿#
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
import oc.od.settings
from oc.od.services import services 
from oc.od.base_controller import BaseController
import oc.od.janus

import oc.lib


logger = logging.getLogger(__name__) 

class CoreController(BaseController):

    '''
        Description: Core Controller 
    '''

    def __init__(self, config_controller=None):
        super().__init__(config_controller)

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def getkeyinfo(self):
        """ Return the key id if key is set in configuration file
            Return the client id for OAuth
            Return True is active direcotry configucation provider is set
        """
        arguments = cherrypy.request.json

        # do not report error message 
        # ignore the message and send an empty response
        if not isinstance( arguments, dict ):
            return {}

        provider = arguments.get('provider')
        if not isinstance(provider,str):
            return {}	

        id = None           # value to return 
        callbackurl = None  # reserved for futur usage 
         
        if provider == 'colors' :
            id = oc.od.settings.desktop['defaultbackgroundcolors']

        elif provider == 'menuconfig':            
            id = oc.od.settings.desktop['menuconfig']

        elif provider == 'tracker' :
            import oc.od.tracker
            id = oc.od.tracker.jiraclient().isenable()

        elif provider == 'webrtc':
            id = isinstance( services.webrtc, oc.od.janus.ODJanusCluster )

        return { 'id': id, 'callbackurl': callbackurl }


    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def getmessageinfo(self):     
        
        try:
            (auth, user ) = self.validate_env()
        except Exception as e:
            logger.error( e )
            return Results.error( message=str(e) )
        
        message = ''
        
        if isinstance( user, oc.auth.authservice.AuthUser ): 
            message = services.messageinfo.popflush(user.userid)

        return Results.success(message,result={'message':message})
