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

import sys
import logging
import json
import os
import cherrypy # web framework 
from cherrypy._cpdispatch import Dispatcher

import oc.logging
import oc.cherrypy
import oc.od.settings as settings
import oc.od.services as services

# Load logging config ASAP !
oc.logging.configure( config_or_path=oc.od.settings.defaultConfigurationFilename, is_cp_file=True)
logger = logging.getLogger(__name__)

# define virtual path used 
# app_virtual_path is for application
# img_virtual_path is for icon static file
app_virtual_path = '/API' 
img_virtual_path = '/img'

# define each configration for API
# app_config is the core servive
# img_config is a dummy app used to serve icon static file 

# Allow (partial) case-insensivity in URLs
class APIDispatcher(Dispatcher):
    def __call__(self, path_info):
        return Dispatcher.__call__(self, path_info.lower()) 

def api_handle_error():
    ex_type, ex, ex_tb = sys.exc_info()
    
    status = 0
    result = None
    if isinstance(ex, oc.cherrypy.WebAppError):
        status = ex.status
        result = ex.to_dict()
    else:
        status = 500 
        message = 'Internal server error'
        if ex:
            message = message + ':' + str(ex)
        result = { 'status': 500, 'message':message }

    cherrypy.response.headers['Content-Type'] = 'application/json'
    cherrypy.response.status = status 
    cherrypy.response.body = cherrypy._json.encode(result)


def api_build_error(status, message, traceback, version):
    ex_type, ex, ex_tb = sys.exc_info()

    if isinstance(ex, oc.cherrypy.WebAppError):
        cherrypy.response.status = ex.status
        result = ex.to_dict()
    else:
        result = { 'status': cherrypy.response.status, 'status_message':status, 'message':message }

    cherrypy.response.headers['Content-Type'] = 'application/json'
    return cherrypy._json.encode(result)



def img_handle_404_application(status, message, traceback, version):
    ''' if the image icone file does not exist      '''
    ''' return img/app/application-default-icon.svg '''
    curdir = os.getcwd()
    path = os.path.join(curdir, 'img/app', 'application-default-icon.svg')
    # overwrite 404 to 200 
    # if status is 404 then body is not aways display
    cherrypy.response.status = 200
    cherrypy.response.message = 'OK'
    return cherrypy.lib.static.serve_file(path, content_type='image/svg+xml')


#
# img class to serve static files 
# for example icon files for applications
@cherrypy.config(**{ 
    'tools.staticdir.on' : True, 
    'tools.staticdir.dir': '/var/pyos/img', # relative path not allowed
    'tools.allow.methods': [ 'GET' ],  # HTTP GET only for images 
    'error_page.404'    : img_handle_404_application
})
class IMG(object):
    def __init__(self):
        """ init IMG static files
        """

#
# main API class 
@oc.logging.with_logger()
@cherrypy.config(**{ 
    'request.error_response': api_handle_error,
    'error_page.default': api_build_error,
    'tools.trace_request.on': True,
    'tools.trace_response.on': True,
    'tools.add_response_result.on': True,
    # 'tools.allow_origin.on': True,
    'tools.allow.on': True,
    'tools.allow.methods': [ 'POST' ]  # POST for API, GET for OAuth 2.0 response by OAuth provider
})

class API(object):
   
    def __init__(self, config_controllers):
        """ init API Router

        Args:
            config_controllers (dict): dict controller config
            each config_controllers is the controller name
        """
        oc.cherrypy.Tools.create_controllers(self, 'controllers', config_controllers=config_controllers ) 

    @staticmethod
    @cherrypy.tools.register('before_handler')
    def trace_request():
        if hasattr(cherrypy.request, 'json'):
            # if request is an auth request
            if cherrypy.request.path_info == '/auth/auth' :
                # auth may contains password data
                # do not log password data 
                # copy dict cherrypy.request.json to keep it unchanged
                jsonhidendata = cherrypy.request.json.copy()
                # replace password data by XXXXXXXXXXXXX in jsonhidendata object
                jsonhidendata['password'] = 'XXXXXXXXXXX'
                # log data message with the hidden passord value
                logger.info('%s %s', cherrypy.request.path_info, jsonhidendata )
            else:
                logger.info('%s %s', cherrypy.request.path_info, cherrypy.request.json)
        else:
            logger.info(cherrypy.request.path_info)

    @staticmethod    
    @cherrypy.tools.register('on_end_request')
    def trace_response():   
        #
        # do not trace the response if cherrypy.response.notrace is set
        if hasattr(cherrypy.response, 'notrace'):
            return
        
        message = str(cherrypy.request.result) if hasattr(cherrypy.request, 'result') else str(cherrypy.response.body)
        # message = message.encode("ascii","ignore")
        logger.info('%s %s', cherrypy.request.path_info, message)
    
    
    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.allow(methods=['GET', 'POST']) 
    def version(self):
        """
            return the pyos build information as json format
        """
        data = { 'date': 'undefined', 'commit': 'undefined' }
        try:
            with open('version.json') as json_file:
                data = json.load(json_file)
        except Exception as e:
            logger.error( str(e))
        return data
     
    @cherrypy.expose
    @cherrypy.tools.allow(methods=['GET'])
    def healthcheck(self):
        return "OK"  

def run_server():   
    logger.info("Starting cherrypy service...")
    # update config for cherrypy
    cherrypy.config.update(settings.defaultConfigurationFilename)    
    settings.config['/']['request.dispatch'] = APIDispatcher() # can't be set with @cherrypy.config decorator
    # set auth tools
    cherrypy.tools.auth = services.services.auth
    # set /API
    cherrypy.tree.mount( API(settings.controllers), app_virtual_path, settings.config )
    # set /IMG
    cherrypy.tree.mount(IMG(), img_virtual_path, config={} ) # no config for img, use class config
    # start cherrypy engine
    cherrypy.engine.start()
    # infite loop
    logger.info("Waiting for requests...")
    cherrypy.engine.block()

def main(argv):
    # Load config file od.config
    settings.init()    
    # Init services 
    services.init()
    # Let's run
    run_server()

if __name__ == "__main__":
    main(sys.argv[1:])
