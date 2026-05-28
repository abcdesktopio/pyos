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
import oc.logging

import oc.od.settings
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
        self.version_data = self.get_current_version_from_file()

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def getkeyinfo(self)->dict:
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
            id = oc.od.settings.desktop.get('defaultbackgroundcolors')
        elif provider == 'menuconfig':    
            id = oc.od.settings.menuconfig
        elif provider == 'geolocation':    
            id = oc.od.settings.geolocation
        elif provider == 'zoom':
            id = oc.od.settings.desktop.get('zoom')
        elif provider == 'tipsinfo':
            id = oc.od.settings.tipsinfoconfig
        elif provider == 'welcomeinfo':
            id = oc.od.settings.welcomeinfoconfig
        elif provider == 'imagenotificationconfig':
            id = oc.od.settings.imagenotificationconfig
        elif provider == 'features_permissions_executeclasses' :
            if 'read' in oc.od.settings.desktop.get('features_permissions',[]):
                id = oc.od.settings.executeclasses
        return { 'id': id, 'callbackurl': callbackurl }


    def handler_messageinfo_json(self, messageinfo)->bytes:
        cherrypy.response.headers[ 'Content-Type'] = 'application/json;charset=utf-8'
        data = Results.success(message=messageinfo)
        # convert data as str
        result_str = json.dumps( data ) + '\n'
        # encode with charset=utf-8
        return result_str.encode('utf-8')

    def handler_messageinfo_text(self, messageinfo)->bytes:
        cherrypy.response.headers[ 'Content-Type'] = 'text/text;charset=utf-8'
        cherrypy.response.headers[ 'Cache-Control'] = 'no-cache, private'
        result_str = messageinfo + '\n'
        return result_str.encode('utf-8')

    @cherrypy.expose
    @cherrypy.tools.json_in()
    def getmessageinfo(self)->bytes:

        # can raise exception
        (auth, user, roles) = self.validate_env()

        lambdaroute = b'' # default return empty string
        # route content type to handler
        routecontenttype = { 
            'text/plain': self.handler_messageinfo_text, 
            'application/json': self.handler_messageinfo_json 
        }
        try:
            message = services.messageinfo.popflush(user.userid)
            lambdaroute = self.getlambdaroute( routecontenttype, defaultcontenttype='application/json' )( message )
        except Exception as e:
            self.logger.error( f"getmessageinfo error {e}" )
        return lambdaroute
    

    def get_current_version_from_file(self)->dict:
        """get_current_version_from_file read version.json file in current directory with date and commit information
        """
        version_file = 'version.json'
        version_data = { 'date': 'undefined', 'commit': 'undefined' }
        try:
            # The input encoding should be UTF-8, UTF-16 or UTF-32.
            with open(version_file) as json_file:
                version_data = json.load(json_file)
        except Exception as e:  
            logger.error( f"Error loading version information from {version_file}: {e}" )
        return version_data
    
    @cherrypy.expose
    @cherrypy.tools.json_out()
    # @cherrypy.tools.json_in()
    def version(self):
        """version

        Returns:
            dict: content of version.json file in current directory
        """
        # can raise exception
        self.validate_env()
        return self.version_data