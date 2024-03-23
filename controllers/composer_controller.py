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
import datetime

import oc.lib
import oc.od.acl
import oc.od.settings as settings

import oc.od.composer 
import oc.i18n
import oc.auth.jwt
import urllib

from oc.od.services import services

from oc.cherrypy import Results
from oc.od.base_controller import BaseController


logger = logging.getLogger(__name__)


@oc.logging.with_logger()
@cherrypy.config(**{ 'tools.auth.on': True })
class ComposerController(BaseController):

    '''
        Description: Composer Controller 
    '''

    def __init__(self, config_controller=None):
        super().__init__(config_controller)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def ocrun(self):
        self.logger.debug('')
        (auth, user ) = self.validate_env()
        args = cherrypy.request.json
        if not isinstance(args, dict):
            raise cherrypy.HTTPError( status=400, message='invalid parameters')

        # appname must exists
        appname = args.get('image')
        if not isinstance(appname, str) or not appname:
            raise cherrypy.HTTPError( status=400, message='invalid image parameters')

        # add lang to user dict
        self.LocaleSettingsLanguage( user )
        # open the app
        result = oc.od.composer.openapp( auth, user, args )
        if not isinstance( result, dict):
             raise cherrypy.HTTPError( status=400, message='ocrun error')
        return Results.success(result=result)
        
       
    
    def LocaleSettingsLanguage( self, user ):
        # add current locale from http Accept-Language to AuthUser 
        locale = oc.i18n.detectLocale(cherrypy.request.headers.get('Accept-Language'), oc.od.settings.supportedLocales)
        user['locale'] = locale

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def launchdesktop(self):
        # increase timeout when creating the first user pod
        cherrypy.response.timeout = 300
        self.logger.debug('launchdesktop:validate_env')
        (auth, user ) = self.validate_env()
        # add lang to user dict   
        self.logger.debug('launchdesktop:LocaleSettingsLanguage')
        self.LocaleSettingsLanguage( user )
        self.logger.debug('launchdesktop:_launchdesktop')
        result = self._launchdesktop(auth, user, cherrypy.request.json)
        return result

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def getlogs(self):
        self.logger.debug('')
        (auth, user ) = self.validate_env()
        logs = oc.od.composer.logdesktop(auth, user)
        return Results.success(result=logs)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def stopcontainer(self):
        self.logger.debug('')
        (auth, user ) = self.validate_env()
        args = cherrypy.request.json
        if type(args) is not dict:
            return cherrypy.HTTPError( status=400, message='invalid args parameters')

        containerid = args.get('containerid')
        if not isinstance( containerid, str):      
            return cherrypy.HTTPError( status=400, message='invalid containerid parameters')
        
        podname = args.get('podname')
        if not isinstance( podname, str) :
            return Results.error( message='invalid parameter podname')
        result = oc.od.composer.stopContainerApp(auth, user, podname, containerid)
        if result :
            return Results.success(result=result)
        raise cherrypy.HTTPError( status=400, message='failed to stop container')

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def logcontainer(self):
        self.logger.debug('')
        (auth, user ) = self.validate_env()
        args = cherrypy.request.json
        if not isinstance( args, dict):
            return cherrypy.HTTPError( status=400, message='invalid parameters')

        podname = args.get('podname')
        if not isinstance( podname, str) :
            return Results.error( message='invalid parameter podname')

        containerid = args.get('containerid')
        if not isinstance( containerid, str) :   
            return cherrypy.HTTPError( status=400, message='invalid parameters containerid')
        
        result = oc.od.composer.logContainerApp(auth, user, podname, containerid)
        if result is not None:            
            return Results.success(result=result)
        raise cherrypy.HTTPError( status=400, message='failed to get log container')


    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def envcontainer(self):
        self.logger.debug('')
        (auth, user ) = self.validate_env()
        args = cherrypy.request.json
        if not isinstance( args, dict):
            raise cherrypy.HTTPError( status=400, message='invalid parameters' )

        containerid = args.get('containerid')
        if not isinstance( containerid, str) :    
            raise cherrypy.HTTPError( status=400, message='invalid parameters' )
        
        podname = args.get('podname')
        if not isinstance( podname, str) :
            return Results.error( message='invalid parameter podname')
        
        result = oc.od.composer.envContainerApp(auth, user, podname, containerid)
        if not result:
            raise cherrypy.HTTPError( status=500, message='failed to get log container')
        return Results.success(result=result)
    
    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def removecontainer(self):
        self.logger.debug('')
        (auth, user ) = self.validate_env()
        args = cherrypy.request.json
        if not isinstance( args, dict):
            return cherrypy.HTTPError( status=400, message='invalid parameters' )

        containerid = args.get('containerid')
        if not isinstance( containerid, str):
            return cherrypy.HTTPError( status=400, message='invalid parameter containerid')
        
        podname = args.get('podname')
        if not isinstance( podname, str):
            return cherrypy.HTTPError( message='invalid parameter podname')
        
        result = oc.od.composer.removeContainerApp(auth, user, podname, containerid)
        if isinstance(result, bool):
            if result is True:
                return Results.success(result=result)
            else:
                return Results.error('failed to remove container')
        raise cherrypy.HTTPError( status=400, message='failed to remove container')


    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def listcontainer(self):
        self.logger.debug('')
        (auth, user ) = self.validate_env()
        result = oc.od.composer.listContainerApp(auth, user)
        return Results.success(result=result)

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def refreshdesktoptoken(self):
        self.logger.debug('')
        (auth, user ) = self.validate_env()
        desktop = oc.od.composer.finddesktop(authinfo=auth, userinfo=user)

        # check desktop object
        if not isinstance(desktop, oc.od.desktop.ODDesktop):
            raise cherrypy.HTTPError( status=400, message='finddesktop does not return a desktop object')  

        # check desktop object
        if not isinstance(desktop, oc.od.desktop.ODDesktop):
            raise cherrypy.HTTPError( status=400, message='finddesktop does not return a desktop object')          
        if not oc.od.desktop.isdesktopreachabled( desktop ):
            raise cherrypy.HTTPError( status=400, message='Your desktop is unreachable')
   
        # build new jwtdesktop
        jwtdesktoptoken = services.jwtdesktop.encode( desktop.internaluri )
        self.logger.info(f"jwttoken is {desktop.internaluri} -> {jwtdesktoptoken}" )

        # add no-cache nosniff HTTP headers
        cherrypy.response.headers[ 'Cache-Control'] = 'no-cache, private'
        # disable content or MIME sniffing which is used to override response Content-Type headers 
        # to guess and process the data using an implicit content type
        # is this case the content-type is json 
        cherrypy.response.headers[ 'X-Content-Type-Options'] = 'nosniff'

        return Results.success(result={
                'authorization' : jwtdesktoptoken,  # the desktop.ipAddr encrypted
                'expire_in'     : services.jwtdesktop.exp() # jwt TTL
        })



    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def getdesktopdescription(self):
        self.logger.debug('')
        # check if request is allowed, raise an exception if deny
        self.is_permit_request()
        # check if user is authenticated and identified, raise an exception if not
        (auth, user ) = self.validate_env()
        result = oc.od.composer.getdesktopdescription(auth, user)
        if not isinstance( result, dict ):
            raise cherrypy.HTTPError( status=400, message='failed to getdesktopdescription')
        return Results.success(result=result)


    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def getuserapplist(self):
        self.logger.debug('')
        
        (auth, user ) = self.validate_env()
        userappdict = {}
        # list all applications allowed for this user (auth)
        appdict = services.apps.user_appdict( auth, filtered_public_attr_list=True)
        # list all default application from the config file allowed for this user (auth)
        defaultappdict= services.apps.default_appdict( auth, settings.get_default_appdict(), filtered_public_attr_list=True )
        # user application list is the default applist + the user application list
        # add defaultappdict 
        # defaultappdict id the first one to get filemanager as first entry if in dock 
        userappdict.update( defaultappdict )
        # add appdict
        userappdict.update( appdict )
        # return value is a list, convert dict to list
        userapplist = list( userappdict.values() )
        # return succes data 
        return Results.success(result=userapplist)    
        
    def _launchdesktop(self, auth, user, args):
        self.logger.debug('')

        #
        # embeded inside a try/catch to make sure that we call 
        # services.messageinfo.stop(user.userid) 
        # in all case
        # if an exception occurs 
        # raise it again
        #
        try:
            # read the user ip source address for accounting and log history data
            webclient_sourceipaddr = oc.cherrypy.getclientipaddr()
            args[ 'WEBCLIENT_SOURCEIPADDR' ] = webclient_sourceipaddr

            # open a new desktop
            desktop = oc.od.composer.opendesktop( auth, user, args ) 

            # safe check for desktop type
            if not isinstance(desktop, oc.od.desktop.ODDesktop):  
                # an error occurs  
                if isinstance(desktop, str):     
                    return Results.error(message=desktop)
                else:
                    return Results.error(message='Desktop creation failed')

            # safe desktop reachable check 
            if not oc.od.desktop.isdesktopreachabled( desktop ) :   
                # a desktop exists but is unreachable
                # decide to trash it
                services.messageinfo.push(user.userid, 'e.Your desktop is unreachabled. Delete desktop process is starting') 
                if oc.od.composer.removedesktop( auth, user ) is True:        
                    services.messageinfo.push(user.userid, 'e.Delete desktop done.')
                error_msg = oc.od.desktop.getunreachablemessage( desktop )
                return Results.error( message=f"Your desktop previous was unreachable. {error_msg}. Please reload try again.")
                                     

            # build a jwt token with desktop.internaluri
            jwtdesktoptoken = services.jwtdesktop.encode( desktop.internaluri )
            # self.logger.info('jwttoken is %s -> %s ', desktop.internaluri, jwtdesktoptoken )
            # self.logger.info('Service is running on node %s', str(desktop.nodehostname) )
            
            # build an accounting data
            datadict={  **user,
                        'provider':     auth.providertype,
                        'date':         datetime.datetime.utcnow().isoformat(),
                        'useragent':    cherrypy.request.headers.get('User-Agent', None),
                        'ipaddr':       webclient_sourceipaddr,
                        'node':         desktop.nodehostname,
                        'type':         'desktop'
            }
            # store the accouting data in collectionname 'loginHistory'
            services.datastore.addtocollection( databasename='loginHistory', 
                                                collectionname=user.userid, 
                                                datadict=datadict)

            target = desktop.ipAddr

            if desktop.websocketrouting == 'bridge':
                target = desktop.websocketroute
            
            expire_in = services.jwtdesktop.exp() 
            target_ip = self.get_target_ip_route( target, desktop.websocketrouting )
            return Results.success(result={
                'target_ip'     :   target_ip,
                'vncpassword'   :   desktop.vncPassword,
                'authorization' :   jwtdesktoptoken, # contains desktop.uri (ipaddr)   
                'websocketrouting': desktop.websocketrouting,
                'websockettcpport': oc.od.settings.desktop_pod['graphical'].get('tcpport'),
                'expire_in'     :   expire_in             
            })

        except Exception as e:
            self.logger.error( e )
            raise e
        finally:
            services.messageinfo.stop(user.userid) # Stop message info log


    def get_target_ip_route(self, target, websocketrouting ):  
        """[get_target_ip_route]
        
            return hostname how to reach the websocket from HTTP web browser to docker container
        Args:
            target_ip ([str]): [target ip destination of the user container ]

        Returns:
            [str]: [hostname to reach the websocket container]
        """ 
        
        http_requested_host = cherrypy.url()
        http_origin = cherrypy.request.headers.get('Origin', None)
        http_host   = cherrypy.request.headers.get('Host', None)
        # self.logger.debug(locals())

        route = None

        # set default value as fallback
        # to pass exception
        url = urllib.parse.urlparse(http_requested_host)
        route = url.hostname

        # Now do the route
        if websocketrouting == 'default_host_url':
            try:
                myhosturl = oc.od.settings.default_host_url or http_origin
                url = urllib.parse.urlparse(myhosturl)
                route = url.hostname
            except Exception as e:
                self.logger.error('failed: %s', e)

        elif websocketrouting == 'bridge':
            route = target

        elif websocketrouting == 'http_origin':
            if http_origin is not None:
                try:
                    # use the origin url to connect to
                    url = urllib.parse.urlparse(http_origin)
                    route = url.hostname
                except Exception as e:
                    self.logger.error('Errror: %s', e)

        elif websocketrouting == 'http_host':
            try:
                # use the origin url to connect to
                url = urllib.parse.urlparse(http_host)
                route = url.hostname
            except Exception as e:
                self.logger.error('Errror: %s', e)

        self.logger.debug('Route websocket to: %s', route)
        return route

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def listsecrets(self):    
        (auth, user ) = self.validate_env()
        # list secrets
        secrets = oc.od.composer.listAllSecretsByUser(auth, user)
        list_secrets = list( secrets )
        return Results.success(result=list_secrets)
