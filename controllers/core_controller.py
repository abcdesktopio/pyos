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
import json

import oc.od.janus
import oc.od.tracker
import oc.logging
import oc.lib

from oc.od.settings import tipsinfoconfig, desktop, menuconfig, welcomeinfoconfig
from oc.od.janus import ODJanusCluster
from oc.cherrypy import Results
from oc.od.services import services 
from oc.od.base_controller import BaseController

logger = logging.getLogger(__name__) 

@oc.logging.with_logger()
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
            id = desktop.get('defaultbackgroundcolors')
        elif provider == 'menuconfig':    
            id = menuconfig
        elif provider == 'geolocation':    
            id = oc.od.settings.geolocation
        elif provider == 'executeclasses':    
            id = oc.od.settings.executeclasses.items()
        elif provider == 'tracker' :
            id = oc.od.tracker.jiraclient().isenable()
        elif provider == 'zoom':
            id = oc.od.settings.desktop.get('zoom')
        elif provider == 'tipsinfo':
            id = tipsinfoconfig
        elif provider == 'welcomeinfo':
            id = welcomeinfoconfig
        elif provider == 'webrtc.configuration':
            id = oc.od.settings.webrtc.get('rtc_configuration')
        elif provider == 'webrtc.rtc_constraints':
            id = oc.od.settings.webrtc.get('rtc_constraints')
        elif provider == 'webrtc.enable':
            id = oc.od.settings.webrtc.get('enable')

        return { 'id': id, 'callbackurl': callbackurl }


    def handler_messageinfo_json(self, messageinfo):
        cherrypy.response.headers[ 'Content-Type'] = 'application/json;charset=utf-8'
        data = Results.success(message=messageinfo)
        # convert data as str
        result_str = json.dumps( data ) + '\n'
        # encode with charset=utf-8
        return result_str.encode('utf-8')

    def handler_messageinfo_text(self, messageinfo):
        cherrypy.response.headers[ 'Content-Type'] = 'text/text;charset=utf-8'
        cherrypy.response.headers[ 'Cache-Control'] = 'no-cache, private'
        result_str = messageinfo + '\n'
        return result_str.encode('utf-8')


    @cherrypy.expose
    @cherrypy.tools.json_in()
    def getmessageinfo(self):     
        (_, user ) = self.validate_env()
        message = services.messageinfo.popflush(user.userid)
        routecontenttype = {
            'text/plain':  self.handler_messageinfo_text,
            'application/json': self.handler_messageinfo_json 
        }
        return self.getlambdaroute( routecontenttype, defaultcontenttype='application/json' )( message )
