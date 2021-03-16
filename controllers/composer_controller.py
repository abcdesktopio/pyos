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
        except Exception as e:
            logger.error( e )
            return Results.error( message=str(e) )
        
        args = cherrypy.request.json
        if type(args) is not dict:
            return Results.error( message='invalid parameters' )

        # appname must exists
        appname = args.get('image')
        if type(appname) is not str:
            return Results.error('Missing parameter image')

        # add lang to user dict
        self.LocaleSettingsLanguage( user )
        try:                       
            result = oc.od.composer.openapp( auth, user, args )
        except Exception as e:
            return Results.error(str(e))
            
        return Results.success(result=result)
    
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

        preferednodehostname = cherrypy.request.headers.get('Prefered-Nodename')
        self.logger.debug('cherrypy.request.headers.get(Prefered-Nodename) = %s ', str(preferednodehostname))
        
        # add lang to user dict
        self.LocaleSettingsLanguage( user )
     
        return self._launchdesktop(preferednodehostname, auth, user, args)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def launchdesktop(self):

        try:
            (auth, user ) = self.validate_env()
        except Exception as e:
            logger.error( e )
            return Results.error( message=str(e) )

        # add lang to user dict   
        self.LocaleSettingsLanguage( user )
        
        preferednodehostname = services.auth.user.get('nodehostname')
        if preferednodehostname is None:
            self.logger.debug('services.auth.nodehostname is None')    
            preferednodehostname = cherrypy.request.headers.get('Prefered-Nodename')    

        self.logger.debug('cherrypy.request.headers.get(Prefered-Nodename) = %s ', str(preferednodehostname))
        
        return self._launchdesktop(preferednodehostname, auth, user, cherrypy.request.json)

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
        except Exception as e:
            logger.error( e )
            return Results.error( message=str(e) )       

        result = oc.od.composer.listContainerApp(auth, user)
        if type(result) is list:     
            return Results.success(result=result)
        return Results.error('failed to read container list')

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def refreshdesktoptoken(self):
        logger.debug('')
        try:
            (auth, user ) = self.validate_env()
        except Exception as e:
            logger.error( e )
            return Results.error( message=str(e) )

        appname = None
        args = cherrypy.request.json
        if type(args) is dict:
            appname = args.get('app')

        preferednodehostname = services.auth.user.get('nodehostname')
        if preferednodehostname is None:
            self.logger.debug('services.auth.nodehostname is None')    
            preferednodehostname = cherrypy.request.headers.get('Prefered-Nodename') 

        desktop = oc.od.composer.finddesktop_quiet(authinfo=auth, userinfo=user, appname=appname) 
        if desktop is None:                
            return Results.error('refreshdesktoptoken failed')
        
        # This case should only exist if a desktop is running twice on the same host
        # twice mode standalone in docker mode and kubernetes mode
        if desktop.internaluri is None:                
            return Results.error('refreshdesktoptoken Desktop internaluri is None, unreachable')
        
        # build new jwtdesktop
        jwtdesktoptoken = services.jwtdesktop.encode( desktop.internaluri )
        logger.info('jwttoken is %s -> %s ', desktop.internaluri, jwtdesktoptoken )

        return Results.success(result={
                'authorization' : jwtdesktoptoken,                   # desktop.ipAddr
                'expire_in'      : services.jwtdesktop.exp()
        })


    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def getuserapplist(self):
        logger.debug('')
        try:
            (auth, user ) = self.validate_env()
        except Exception as e:
            logger.error( e )
            return Results.error( message=str(e) )
        
        # list all applications allowed for this user (auth)
        applist = services.apps.user_applist( auth )

        # get the default application list from the config file
        userapplist = settings.get_default_applist()
        userapplist += applist
        
        return Results.success(result=userapplist)  
    
    def removedesktop(self, auth, user, args ):                
        services.accounting.accountex('desktop', 'remove')
        logger.debug('')
        try:
            (auth, user ) = self.validate_env()
        except Exception as e:
            logger.error( e )
            return Results.error( message=str(e) )
        
        return oc.od.composer.removedesktop(auth, user, args)

    def _launchdesktop(self, preferednodehostname, auth, user, args):

        nodehostname = preferednodehostname
        appname = args.get('app')
        messageinfo = services.messageinfo.start(user.userid, 'Looking for your desktop')

        try:
            ipaddr = oc.cherrypy.getclientipaddr()
            args[ 'usersourceipaddr' ] = ipaddr
            desktop = oc.od.composer.opendesktop( nodehostname, auth, user, args ) 
            if desktop is None:                
                return Results.error('Desktop creation failed')
            
            if desktop.internaluri is None:                
                return Results.error('Desktop URI is None, creation failed')
            
            # update internal dns entry
            # only if we use an external direct access
            # desktop_fqdn = services.internaldns.update_dns( desktop.id, desktop.ipAddr)
            # logger.info('New entry is dns %s->%s ', desktop_fqdn, desktop.ipAddr ) 

            # In kubernetes mode change the desktop.ipAddr
            # to IpAddr.desktop.abcdesktop.svc.cluster.local
            # example 
            # If th Pod IPAddr is 10-1-1-85
            # 10-1-1-85.desktop.abcdesktop.svc.cluster.local
            # desktoptarget = self.build_desktop_internal_fqdn( desktop.ipAddr )

            jwtdesktoptoken = services.jwtdesktop.encode( desktop.internaluri )
            logger.info('jwttoken is %s -> %s ', desktop.internaluri, jwtdesktoptoken )
            logger.info('Service is running on node %s', str(desktop.nodehostname) )
            
            # set cookie for a better loadbalacing
            if desktop.nodehostname is not None:
                oc.lib.setCookie( 'abchost', desktop.nodehostname )

            datadict={  **user,
                        'provider': auth.providertype,
                        'date': datetime.datetime.utcnow().isoformat(),
                        'useragent': cherrypy.request.headers.get('User-Agent', None),
                        'ipaddr': ipaddr,
                        'node': desktop.nodehostname
            } 

            if appname :
                datadict['type'] = 'metappli'
                datadict['app']  = appname
            else:
                datadict['type'] = 'desktop'
            
            
            services.datastore.addtocollection( databasename=user.userid, 
                                                collectionname='loginHistory', 
                                                datadict=datadict)
            expire_in = services.jwtdesktop.exp() 

            return Results.success(result={
                'target_ip'     :   oc.lib.get_target_ip_route(desktop.ipAddr),
                'vncpassword'   :   desktop.vncPassword,
                'authorization' :   jwtdesktoptoken,                    # contains desktop.uri (ipaddr)   
                'websocketrouting': oc.od.settings.websocketrouting,
                'websockettcpport': oc.od.settings.desktopservicestcpport['x11server'],
                'expire_in'     :   expire_in             
            })
        finally:
            messageinfo.stop() # Stop message info log