#!/usr/bin/env python3
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
from cherrypy.process.plugins import SignalHandler

import oc.logging
import oc.cherrypy
import oc.od.settings as settings
import oc.od.services as services

logger = logging.getLogger(__name__)
version_data = { 'date': 'undefined', 'commit': 'undefined' }

# define each configration for API
# app_config is the core service
# img_config is file service to send icon static file 

def api_handle_error():
    _ex_type, ex, _ex_tb = sys.exc_info()
    
    status = 500
    message = None
    
    if hasattr( ex, 'code' ):   
        status = ex.code
    elif hasattr( ex, 'status' ):   
        status = ex.status

    for m in [ 'reason', 'message', '_message', 'description', 'args' ]:
        if hasattr( ex, m ):
            message = getattr( ex, m )
            if isinstance( message, (list,tuple) ):
                message = message[0]
            if isinstance( message, str) and len(message) > 0:
                break
            
    # message is ALWAYS a str
    if not isinstance(message, str ):
        message = 'Internal api server error'

    # return error dict json 
    # result = { 'status': status, 'message':message, 'exception':str(ex) }
    result = { 'status': status, 'message':message }
    build_error = json.dumps( result ) + '\n'
    cherrypy.response.headers['Content-Type'] = 'application/json;charset=utf-8'
    cherrypy.response.status = status 
    cherrypy.response.body = build_error.encode('utf-8')


def api_build_error(status, message:str, traceback:str, version:str)->str:
    result =     { 'status': cherrypy.response.status, 'message':message }
    # 'exception': str(ex), 'traceback':str(traceback),'version':version
    log_result = { 'status': cherrypy.response.status, 'message':message }
    logger.error(message, exc_info=True)
    build_error = json.dumps( result ) + '\n'
    cherrypy.response.headers['Content-Type'] = 'application/json'
    return build_error.encode('utf-8')


def img_handle_404_application(status, message, traceback, version):
    """img_handle_404_application overwrite 404 to default icon
        return 'img/app/application-default-icon.svg' content 
        using cherrypy.lib.static.serve_file

    Args:
        status (_type_): _description_
        message (_type_): _description_
        traceback (_type_): _description_
        version (_type_): _description_

    Returns:
        _type_: _description_
    """
    ''' if the image icon file does not exist      '''
    ''' return img/app/application-default-icon.svg '''
    curdir = os.getcwd()
    path = os.path.join(curdir, 'img/app', 'application-default-icon.svg')
    # overwrite 404 to 200
    # if status is 404 then body is not aways display
    cherrypy.response.status = 200
    cherrypy.response.message = 'OK'
    return cherrypy.lib.static.serve_file(path, content_type='image/svg+xml')

#
# main API class 
@oc.logging.with_logger()
@cherrypy.config(**{ 
    'server.shutdown_timeout': 5,
    'request.error_response': api_handle_error,
    'request.body.maxbytes': 2097152, # 2M must be greater than the default applist size 1763525 Bytes https://raw.githubusercontent.com/abcdesktopio/images/refs/heads/main/appLists/appList.4.4.json 
    'error_page.default': api_build_error,
    'tools.trace_request.on': True,
    'tools.trace_response.on': True,
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
        """ trace request """
        json_data = None
        if  hasattr(cherrypy.request, 'json'):
            # copy dict cherrypy.request.json to keep it unchanged
            json_data = cherrypy.request.json
            # auth may contains password data do not log password data 
            # cherrypy.request.path_info in [ '/auth/auth', '/auth/autologin', '/auth/logmein' ]
            json_data = cherrypy.request.json
            if  isinstance(cherrypy.request.json, dict):
                
                # hide authorization data in log message if exist in cherrypy.request.json['result']['authorization']
                # {"status": 200, "result": {"authorization": "eyJ.......-uVvWw", "expire_in": 420}, "message": "ok"}
                if cherrypy.request.json.get('result', {}).get('authorization'):
                    json_data = cherrypy.request.json.copy()
                    json_data['result']['authorization'] = 'XXXXXXXXXXX'
            
                # check if password data exist in cherrypy.request.json 
                # and if it exist, replace it by XXXXXXXXXXXXX in log message
                # logmessage is the message to log with hidden password value
                if cherrypy.request.json.get('password'):
                    json_data = cherrypy.request.json.copy()
                    # replace password data by XXXXXXXXXXXXX in jsonhidendata object
                    json_data['password'] = 'XXXXXXXXXXX'
        
        logmessage = cherrypy.request.path_info
        if json_data is not None:
            logmessage += f" {json_data}"
        # log the request
        logger.info(logmessage)

    @staticmethod    
    @cherrypy.tools.register('on_end_request')
    def trace_response():
        #
        # do not trace the response if cherrypy.response.notrace is set
        if hasattr(cherrypy.response, 'notrace'):
            return

        MAX_LOG_BODY = settings.max_log_body_size
        # get the body of the response and log it, but limit the size to MAX_LOG_BODY bytes
        message = b''
        if isinstance( cherrypy.response.body, list):
            for m in cherrypy.response.body:
                message = message + m.rstrip(b' ')
                if len(message) >= MAX_LOG_BODY:
                    message = message[:MAX_LOG_BODY] + b'...[truncated]'
                    break
            message = message.rstrip(b' \n')

        logmessage = f"{cherrypy.request.path_info} {message}"
        logger.info(logmessage)
    
    
    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.allow(methods=['GET']) 
    def version(self):
        """version
            Keep this code for compatibility with old version of od.py, 
            but for security reason, do not return real version information in /version API, 
            ALWAYS return { 'date': None, 'commit': None }
            Please use /user/version API to get real version information, this API is protected by authentication and authorization check
        Returns:
            dict: content of version.json file in current directory
        """
        return { 'date': None, 'commit': None }

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.allow(methods=['GET']) 
    def openapi(self):
        """openapi

        Returns:
            load json data file openapi.json in current directory
            return {} if error
        """
        data = {}
        try:
            # The input encoding should be UTF-8, UTF-16 or UTF-32.
            with open('openapi.json') as json_file:
                data = json.load(json_file)
        except Exception as e:  
            logger.error( f"Error loading openapi information from openapi.json: {e}" )
        return data
    

    @cherrypy.expose
    @cherrypy.tools.allow(methods=['GET','POST'])
    def healthz(self):
        # disable trace response in log
        cherrypy.response.notrace = True
        return "OK"  
    
    
class ODCherryWatcher(plugins.SimplePlugin):
    """ signal thread to stop when cherrypy stop"""
    def start(self):
        if isinstance( oc.od.services.services, oc.od.services.ODServices ):
            logger.debug( "ODCherryWatcher start events" )
            oc.od.services.services.start()

    def stop(self):
        logger.debug("ODCherryWatcher is stopping. Stopping running threads")
        if isinstance( oc.od.services.services, oc.od.services.ODServices  ):
            oc.od.services.services.stop()

def handler_SIGNAL( signal:str, **signum )->None:
    logger.warning(f"*** Received signal {signal}, stopping cherrypy engine and services {len(signum)}")
    cherrypy.engine.exit()

def handler_SIGQUIT( **signum ): handler_SIGNAL( 'SIGQUIT', **signum )
def handler_SIGINT ( **signum ): handler_SIGNAL( 'SIGINT' , **signum )
def handler_SIGTERM( **signum ): handler_SIGNAL( 'SIGTERM', **signum )
def handler_SIGSTOP( **signum ): handler_SIGNAL( 'SIGSTOP', **signum )

def run_server():
    logger.info("Starting cherrypy service...")
    # update config for cherrypy with the od.config file
    cherrypy.config.update(settings.get_configuration_file_name())
    logger.debug(f"cherrypy.config.update({settings.get_configuration_file_name()}) done")  

    # signal handler 
    signalhandler = SignalHandler(cherrypy.engine)
    signalhandler.handlers['SIGTERM'] = handler_SIGTERM
    signalhandler.handlers['SIGQUIT'] = handler_SIGQUIT
    signalhandler.handlers['SIGINT'] = handler_SIGINT
    # signalhandler.handlers['SIGSTOP'] = handler_SIGSTOP
    signalhandler.subscribe()
    
    # set auth tools
    cherrypy.tools.auth = services.services.auth
    # set /API
    cherrypy.tree.mount( API(settings.controllers), '/API', settings.config )
    # create ODCherryWatcher to subscribe start and stop
    odthread_watcher = ODCherryWatcher(cherrypy.engine)
    odthread_watcher.subscribe()
    # start cherrypy engine
    cherrypy.engine.start()
    # infite loop
    logger.info("Waiting for requests.")
    cherrypy.engine.block()


def main(argv):
    # Load logging config
    oc.logging.configure( config_or_path=settings.get_configuration_file_name(), is_cp_file=True)
    # Init settings and load config file od.config
    settings.init()
    # Init services 
    services.init()
    # Let's run
    run_server()

if __name__ == "__main__":
    main(sys.argv[1:])

# In od.py, register a before_handler tool
# MAX_REQUESTS_PER_WINDOW=1000
# WINDOW_SECONDS=60
# @cherrypy.tools.register('before_handler')
# def rate_limit():
#    ip = oc.cherrypy.getclientipaddr()
#    key = f"rl:{ip}"
#    count = services.sharecache.get(key) or 0
#    if int(count) > MAX_REQUESTS_PER_WINDOW:
#        raise cherrypy.HTTPError(429, "Too Many Requests")
#    services.sharecache.set(key, int(count) + 1, expire=WINDOW_SECONDS)

