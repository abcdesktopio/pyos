#!/usr/bin/env python3.8
#
# Software Name : abcdesktop.io
# Version: 0.2
# SPDX-FileCopyrightText: Copyright (c) 2020-2022 Orange
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
from cherrypy.process import plugins

import oc.logging
import oc.cherrypy
import oc.od.settings as settings
import oc.od.services as services

# Load logging config ASAP !
oc.logging.configure( config_or_path=settings.get_configuration_file_name(), is_cp_file=True)
logger = logging.getLogger(__name__)

# define each configration for API
# app_config is the core service
# img_config is file service to send icon static file 

# Allow (partial) case-insensivity in URLs
class APIDispatcher(Dispatcher):
    def __call__(self, path_info):
        return Dispatcher.__call__(self, path_info.lower()) 

def api_handle_error():
    _ex_type, ex, _ex_tb = sys.exc_info()
    
    status = 500
    message = None
    if isinstance(ex, oc.cherrypy.WebAppError):
        status = ex.status
        message = ex.to_dict()
    else:
        if hasattr( ex, 'code' ):   
            status = ex.code
        for m in [ 'reason', 'message', '_message', 'description', 'args' ]:
            if hasattr( ex, m ):
                message = getattr( ex, m )
                if isinstance( message, list) or isinstance( message, tuple):
                    message = message[0]
                if isinstance( message, str) and len(message) > 0:
                    break
    # message is ALWAYS a str
    if not isinstance(message, str ):
        message = 'Internal api server error'

    # return error dict json 
    result = { 'status': status, 'message':message, 'exception':str(ex) }
    build_error = json.dumps( result ) + '\n'
    cherrypy.response.headers['Content-Type'] = 'application/json;charset=utf-8'
    cherrypy.response.status = status 
    cherrypy.response.body = build_error.encode('utf-8')


def api_build_error(status, message, traceback, version):
    _ex_type, ex, _ex_tb = sys.exc_info()

    if isinstance(ex, oc.cherrypy.WebAppError):
        cherrypy.response.status = ex.status
        result = ex.to_dict()
        log_result = result
    else:
        result = {
            'status': cherrypy.response.status,  
            'message':message 
        }
        log_result = { 'status': cherrypy.response.status,  'message':message, 'traceback':str(traceback), 'version':version }
    if cherrypy.config.get('tools.log_full.on'):
        logger.info( log_result )
    build_error = json.dumps( result ) + '\n'
    cherrypy.response.headers['Content-Type'] = 'application/json'
    return build_error.encode('utf-8')




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

        message = b''
        if isinstance( cherrypy.response.body, list):
            for m in cherrypy.response.body:
                message = message + m.rstrip(b' ')
            message = message.rstrip(b' \n')

        if isinstance( message, str):
            # drop message too long
            # OSError: [Errno 90] Message too long
            message = message[:4096] # suppose to be 4096

        # message = message.encode("ascii","ignore")
        logger.info(f"{cherrypy.request.path_info} {message}")
    
    
    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.allow(methods=['GET', 'POST']) 
    def version(self):
        """
            return the pyos build information as json format
            load json data file version.json in current directory
        """
        data = { 'date': 'undefined', 'commit': 'undefined' }
        try:
            # The input encoding should be UTF-8, UTF-16 or UTF-32.
            json_file = open('version.json')
            data = json.load(json_file)
            json_file.close()
        except Exception as e:
            logger.error( e )
        return data

    @cherrypy.expose
    @cherrypy.tools.allow(methods=['GET','POST'])
    def healthz(self):
        # disable trace response in log
        cherrypy.response.notrace = True
        # return OK i'm fine
        return "OK"  
    
class ODCherryWatcher(plugins.SimplePlugin):
    """ signal thread to stop when cherrypy stop"""
    def start(self):
        logger.debug( "ODCherryWatcher start events, skipping" )
        oc.od.services.services.start()

    def stop(self):
        logger.debug("ODCherryWatcher is stopping. Stopping runnging thread")
        oc.od.services.services.stop()


def run_server():   
    logger.info("Starting cherrypy service...")
    # update config for cherrypy
    cherrypy.config.update(settings.get_configuration_file_name())  
    # cherrypy.config['/']
    # APIConfig = { '/': { 'request.dispatch': APIDispatcher() } }
    # settings.config['/']['request.dispatch'] = APIDispatcher() # can't be set with @cherrypy.config decorator
    # set auth tools
    cherrypy.tools.auth = services.services.auth
    # set /API
    cherrypy.tree.mount( API(settings.controllers), '/API', settings.config )
    # set /IMG
    cherrypy.tree.mount( IMG(), '/img', config=
                        { '/img': { 'tools.staticdir.on' : True, 
                                    'tools.staticdir.dir': '/var/pyos/img', # relative path not allowed
                                    'tools.allow.methods': [ 'GET' ],  # HTTP GET only for images 
                                    'error_page.404'     : img_handle_404_application # overwrite 404 to default icon
                                    } } )

    odthread_watcher = ODCherryWatcher(cherrypy.engine)
    odthread_watcher.subscribe()

    # start cherrypy engine
    cherrypy.engine.start()

    # infite loop
    logger.info("Waiting for requests.")
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
