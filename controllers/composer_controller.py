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
        logger.debug('')
        
        try:
            (auth, user ) = self.validate_env()
            args = cherrypy.request.json
            if not isinstance(args, dict):
                return Results.error( message='invalid parameters' )

            # appname must exists
            appname = args.get('image')
            if not isinstance(appname, str):
                return Results.error('Missing parameter image')

            # add lang to user dict
            self.LocaleSettingsLanguage( user )
            # open the app
            result = oc.od.composer.openapp( auth, user, args )
            return Results.success(result=result)

        except Exception as e:
            logger.error( e )
            return Results.error( message=str(e) )
        
       
    
    def LocaleSettingsLanguage( self, user ):
        # add current locale from http Accept-Language to AuthUser 
        locale = oc.i18n.detectLocale(cherrypy.request.headers.get('Accept-Language'), oc.od.settings.supportedLocales)
        user['locale'] = locale

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def launchmetappli(self):

        try:
            (auth, user ) = self.validate_env()
        except Exception as e:
            logger.error( e )
            return Results.error( message=str(e) )
        
        if type(cherrypy.request.json) is not dict:
            return Results.error( message='invalid parameters' )

        args = cherrypy.request.json.copy()
        appname = args.get('app')
        appargs = args.get('args')
        querystring = args.get('querystring')
        if not appname:
            return Results.error('Missing parameters app')

        # decode appargs URL decode string
        if type(appargs) is str:
            args['args'] = urllib.parse.unquote( appargs )
        
        if querystring :
            datadict = urllib.parse.parse_qs( querystring )
            keyname  = datadict.get('keyname')
            metadata = datadict.get('metadata')
            if type(keyname) is list and len(keyname) > 0:
                keyname=keyname[0]            
            if type(metadata) is list and len(metadata) > 0:
                metadata=metadata[0]     

            # check if metadata is an encrypted metadata
            if type(keyname) is str and type(metadata) is str:
                if len(keyname) > 0 and len(metadata)>0 :
                    # keyname exists and execmetadata exists
                    metadata = services.keymanager.decode( keyname=keyname, enc_data=metadata )
                    if metadata is None :
                        return Results.error( message='invalid encrypted execmetadata parameters' )
            args['metadata'] = metadata

        logger.info('Metappli : %s %s', str(appname), str(appargs))

        # add lang to user dict
        self.LocaleSettingsLanguage( user )
     
        return self._launchdesktop(auth, user, args)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def launchdesktop(self):
        logger.debug('')
        try:
            (auth, user ) = self.validate_env()
            # add lang to user dict   
            self.LocaleSettingsLanguage( user )
            return self._launchdesktop(auth, user, cherrypy.request.json)

        except Exception as e:
            logger.error( e )
            return Results.error( message=str(e) )

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def getlogs(self):
        try:
            (auth, user ) = self.validate_env()
        except Exception as e:
            logger.error( e )
            return Results.error( message=str(e) )
        
        logs = oc.od.composer.logdesktop(auth, user)
        if logs :            
            return Results.success(result=logs)
        return Results.error('failed to read log')

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def stopcontainer(self):
        
        try:
            (auth, user ) = self.validate_env()
        except Exception as e:
            logger.error( e )
            return Results.error( message=str(e) )

        args = cherrypy.request.json
        if type(args) is not dict:
            return Results.error( message='invalid parameters' )

        containerid = args.get('containerid')
        if type( containerid ) is not str:      
            return Results.error( message='invalid parameter containerid')
        
        result = oc.od.composer.stopContainerApp(auth, user, containerid)
        if result :            
            return Results.success(result=result)
        return Results.error('failed to stop container')

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def logcontainer(self):
        try:
            (auth, user ) = self.validate_env()
        except Exception as e:
            logger.error( e )
            return Results.error( message=str(e) )

        args = cherrypy.request.json
        if type(args) is not dict:
            return Results.error( message='invalid parameters' )

        containerid = args.get('containerid')
        if type( containerid ) is not str:      
            return Results.error( message='invalid parameter containerid')
        
        result = oc.od.composer.logContainerApp(auth, user, containerid)
        if result is not None:            
            return Results.success(result=result)
        return Results.error('failed to get log container')


    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def envcontainer(self):
        try:
            (auth, user ) = self.validate_env()
        except Exception as e:
            logger.error( e )
            return Results.error( message=str(e) )

        args = cherrypy.request.json
        if type(args) is not dict:
            return Results.error( message='invalid parameters' )

        containerid = args.get('containerid')
        if type( containerid ) is not str:      
            return Results.error( message='invalid parameter containerid')
        
        result = oc.od.composer.envContainerApp(auth, user, containerid)
        if result is not None:            
            return Results.success(result=result)
        return Results.error('failed to get log container')

    
    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def removecontainer(self):
        try:
            (auth, user ) = self.validate_env()
        except Exception as e:
            logger.error( e )
            return Results.error( message=str(e) )

        args = cherrypy.request.json
        if type(args) is not dict:
            return Results.error( message='invalid parameters' )

        containerid = args.get('containerid')
        if type( containerid ) is not str:      
            return Results.error( message='invalid parameter containerid')
        
        result = oc.od.composer.removeContainerApp(auth, user, containerid)
        if result is not None:            
            return Results.success(result=result)
        return Results.error('failed to remove container')


    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def listcontainer(self):
        try:
            (auth, user ) = self.validate_env()
            result = oc.od.composer.listContainerApp(auth, user)
            if type(result) is list:     
                return Results.success(result=result)
            else:
                return Results.error('failed to read container list')
        except Exception as e:
            logger.error( e )
            return Results.error( message=str(e) )       


    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def refreshdesktoptoken(self):
        logger.debug('')
        try:
            (auth, user ) = self.validate_env()

            appname = None
            args = cherrypy.request.json
            if isinstance(args, dict):
                appname = args.get('app')

            desktop = oc.od.composer.finddesktop_quiet(authinfo=auth, userinfo=user, appname=appname) 
            # check desktop object
            if not isinstance(desktop, oc.od.desktop.ODDesktop):                
                return Results.error('finddesktop_quiet return None object')
            if not hasattr(desktop, 'internaluri') :
                return Results.error('finddesktop_quiet return invalid desktop object')
            if desktop.internaluri is None:                
                return Results.error('finddesktop_quiet return desktop.internaluri is None, unreachable')
            
            # build new jwtdesktop
            jwtdesktoptoken = services.jwtdesktop.encode( desktop.internaluri )
            logger.info('jwttoken is %s -> %s ', desktop.internaluri, jwtdesktoptoken )

            return Results.success(result={
                    'authorization' : jwtdesktoptoken,  # the desktop.ipAddr encrypted
                    'expire_in'     : services.jwtdesktop.exp() # jwt TTL
            })

        except Exception as e:
            logger.error( e )
            return Results.error( message=str(e) )

    
    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def getuserapplist(self):
        logger.debug('')
        try:
            (auth, user ) = self.validate_env()
            userappdict = {}
            # list all applications allowed for this user (auth)
            appdict = services.apps.user_appdict( auth, filtered_public_attr_list=True)
            # list all default application from the config file allowed for this user (auth)
            defaultappdict= services.apps.default_appdict( auth, settings.get_default_appdict(), filtered_public_attr_list=True )

            # user application list is the default applist + the user application list
            # add defaultappdict 
            # defaultappdict id the first one to get filemanager as first entry if in 
            userappdict.update( defaultappdict )
            # add appdict
            userappdict.update( appdict )


            # return value is a list
            # convert dict to list
            userapplist = list( userappdict.values() )
            # return succes data 
            return Results.success(result=userapplist)    
        except Exception as e:
            logger.error( e )
            return Results.error( message=str(e) )
        
    def removedesktop(self, auth, user, args ):  
        logger.debug('')              
        services.accounting.accountex('desktop', 'remove')
        try:
            (auth, user ) = self.validate_env()
            remove = oc.od.composer.removedesktop(auth, user, args)
            return Results.success(result=remove)
        except Exception as e:
            logger.error( e )
            return Results.error( message=str(e) )
        

    def _launchdesktop(self, auth, user, args):

        try:
            appname = args.get('app')
            
            # read the user ip source address for accounting and log history data
            webclient_sourceipaddr = oc.cherrypy.getclientipaddr()
            args[ 'WEBCLIENT_SOURCEIPADDR' ] = webclient_sourceipaddr

            # open a new desktop
            desktop = oc.od.composer.opendesktop( auth, user, args ) 

            # safe check for desktop type
            if not isinstance(desktop, oc.od.desktop.ODDesktop):                
                return Results.error('Desktop creation failed')

            # safe check for futur desktop.internaluri usage 
            if not hasattr( desktop, 'internaluri') or desktop.internaluri is None:                
                return Results.error('Desktop URI is None, creation failed')
            
            # build a jwt token with desktop.internaluri
            jwtdesktoptoken = services.jwtdesktop.encode( desktop.internaluri )
            # logger.info('jwttoken is %s -> %s ', desktop.internaluri, jwtdesktoptoken )
            # logger.info('Service is running on node %s', str(desktop.nodehostname) )
            
            # set cookie for a optimized load balacing http request
            # if loadbalancing support cookie persistance routing
            # cookie name is abcdesktop_host
            # match the worker node hostname to recieve next http request on this node
            if isinstance(desktop.nodehostname, str):
                oc.lib.setCookie( oc.od.settings.routehostcookiename, desktop.nodehostname, path='/' )

            # accounting data
            datadict={  **user,
                        'provider':     auth.providertype,
                        'date':         datetime.datetime.utcnow().isoformat(),
                        'useragent':    cherrypy.request.headers.get('User-Agent', None),
                        'ipaddr':       webclient_sourceipaddr,
                        'node':         desktop.nodehostname,
                        'type':         'desktop'
            } 

            if type(appname) is str:
                datadict['type'] = 'metappli'
                datadict['app']  = appname
           
            services.datastore.addtocollection( databasename=user.userid, 
                                                collectionname='loginHistory', 
                                                datadict=datadict)

            target = desktop.ipAddr
            if desktop.websocketrouting is None:
                desktop.websocketrouting = oc.od.settings.websocketrouting

            if desktop.websocketrouting == 'bridge':
                target = desktop.websocketroute
            

            expire_in = services.jwtdesktop.exp() 

            target_ip = self.get_target_ip_route( target, desktop.websocketrouting )

            return Results.success(result={
                'target_ip'     :   target_ip,
                'vncpassword'   :   desktop.vncPassword,
                'authorization' :   jwtdesktoptoken, # contains desktop.uri (ipaddr)   
                'websocketrouting': desktop.websocketrouting,
                'websockettcpport': oc.od.settings.desktopservicestcpport['x11server'],
                'expire_in'     :   expire_in             
            })

        except Exception as e:
            logger.error( str(e) )
            return Results.error( message=str(e) )

        finally:
            if hasattr( user, 'userid'): 
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
        # logger.debug(locals())

        route = None

        # set default value as fallback
        # to pass exception
        url = urllib.parse.urlparse(http_requested_host)
        route = url.hostname

        # Now do the route
        if websocketrouting == 'default_host_url':
            try:
                myhosturl = oc.od.settings.default_host_url
                if myhosturl is None:
                    myhosturl = http_origin
                logger.debug('Use %s', myhosturl)
                url = urllib.parse.urlparse(myhosturl)
                route = url.hostname
            except Exception as e:
                logger.error('failed: %s', e)

        elif websocketrouting == 'bridge':
            route = target

        elif websocketrouting == 'http_origin':
            if http_origin is not None:
                try:
                    # use the origin url to connect to
                    url = urllib.parse.urlparse(http_origin)
                    route = url.hostname
                except Exception as e:
                    logger.error('Errror: %s', e)

        elif websocketrouting == 'http_host':
            try:
                # use the origin url to connect to
                url = urllib.parse.urlparse(http_host)
                route = url.hostname
            except Exception as e:
                logger.error('Errror: %s', e)

        logger.info('Route websocket to: %s', route)
        return route

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def listsecrets(self):
        try:
            (auth, user ) = self.validate_env()
            # list secrets
            secrets = oc.od.composer.listAllSecretsByUser( auth, user)
            list_secrets = list( secrets )
            return Results.success(result=list_secrets)
        except Exception as e:
            logger.error( e )
            return Results.error( message=str(e) )