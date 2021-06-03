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

from oc.od.base_controller import BaseController
from oc.cherrypy import Results 
from oc.od.services import services
import oc.od.composer 
import oc.lib


logger = logging.getLogger(__name__)

@cherrypy.config(**{ 'tools.auth.on': True })
@cherrypy.tools.auth(allow_anonymous=True)

# To protect agains CSRF all method must use @cherrypy.tools.json_in()
# except for autologin pure http form POST request
@oc.logging.with_logger()
class AuthController(BaseController):

    '''
        Description: Authentification Controller 
    '''

    def __init__(self, config_controller=None):
        super().__init__(config_controller)

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def getauthconfig(self):
        """
        Get the authentification configuration.

        Args:
            None

        Returns:
            The authentification configuration json

        """
        return services.auth.getclientdata()

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def isauthenticated(self):
        """
        Return a result object with auth status 

        Args:
            None

        Returns:
            Results object if user is authenticated

        """
        return Results.success(result=services.auth.isauthenticated)
    

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def disconnect(self):
        """
            Disconnect a connected user, 
            remove ONLY all cookies (by setting empty value)
            Keep desktop running
        Args:
            None


        Returns:
            JSON Results
        """
        bReturn = None
        if services.auth.isidentified:
            # Always remove all http cookies
            services.auth.logout()
            bReturn = Results.success()
        else:
            bReturn = Results.error( message='invalid user credentials' )  
        return bReturn

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def logout(self, redirect_uri=None):
        """
        Logout a connected user, remove the desktop
        only if anonymous remove all homedir data
        Args:
            redirect_uri (str): redirect uri 

        Returns:
            JSON Results

        """
        bReturn = None
        args = cherrypy.request.json
        if services.auth.isidentified:
            bReturn = None
            user = services.auth.user
            auth = services.auth.auth  
            # remove the pod/container          
            if oc.od.composer.removedesktop(auth, user, args) is False:
                bReturn = Results.error( message='removedesktop failed' )

            # Always remove removeCookie
            oc.lib.removeCookie( oc.od.settings.routehostcookiename )

            # Always call logout auth services 
            services.auth.logout() 
            
            if bReturn is None:
                bReturn = Results.success()

        else:
            bReturn = Results.error( message='invalid user credentials' )
        
        return bReturn
            
    def build_redirecthtmlpage(self,jwt_user_token):
        # do not use cherrypy.HTTPRedirect
        # READ  https://stackoverflow.com/questions/4694089/sending-browser-cookies-during-a-302-redirect
        # Safari does not support Sending browser cookies during a 302 redirect correctly
        # This is typical in an OAuth2 flow:
        #
        # OAuth2 id provider (GitHub, Facebook, Google) redirects browser back to your app
        # Your app's callback URL verifies the authorization and sets login cookies,
        # then redirects again to the destination URL
        # Your destination URL loads without any cookies set.
        # For reasons I haven't figured out yet, some cookies from request 2 are ignored while others are not. 
        # However, if request 2 returns a HTTP 200 with a Refresh header (the "meta refresh" redirect), cookies are set properly by request 3.
        #
        # empty html page to fix HTTP redirect cookie bug with safari
        loginScreencss_url = oc.od.settings.default_host_url + '/css/css-dist/loginScreen.css'
        oauth_html_refresh_page = '<html dir="ltr" lang="en">\
                    <head>\
                    <title>abcdesktop.io</title>\
                    <link rel="stylesheet" href="' + loginScreencss_url + '" type="text/css" />\
                    <script type="text/javascript"> \
                        var jwt_user_token="' +  jwt_user_token + '"; \
                        var default_host_url="' +  oc.od.settings.default_host_url + '"; \
                    </script> \
                    <script type="text/javascript" src="/js/jwtstorage.js"></script> \
                </head> \
                <body>  \
                    <div id="loginScreen">Reloading</div>\
                </body>\
            </html>'
        
        return oauth_html_refresh_page

    @cherrypy.expose
    @cherrypy.tools.allow(methods=['GET'])
    def oauth(self, **params):
        response = services.auth.login(**params)
        if response.success:
            oc.od.composer.prepareressources( response.result.auth, response.result.user )
            jwt_user_token = services.auth.update_token( auth=response.result.auth, user=response.result.user, roles=response.result.roles, expire_in=None )
            oauth_html_refresh_page = self.build_redirecthtmlpage( jwt_user_token )
            cherrypy.response.headers[ 'Refresh' ] = '5; url=' + oc.od.settings.default_host_url
            return oauth_html_refresh_page
        else:
            logger.error( 'auth error %s', str(response.reason) )
            return response.reason

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def auth(self):
        """
        authentificate a user with json http request parameters 
        Args:
            None use implicit json http 

        Returns:
            JSON Result
            Results success 
            if success 
                set auth jwt cookie
                result={'userid': response.result.user.userid,
                                        'name': response.result.user.name,
                                        'provider': response.result.auth.providertype,       
                                        'expire_in': expire_in }
                return Results.success
            else
                raise cherrypy.HTTPError(400) invalid parameters
                raise cherrypy.HTTPError(401) invalid credentials
        """
        self.logger.debug('auth call')
        cherrypy.response.timeout = 180
        args = cherrypy.request.json

        # services.auth.isauthenticated is False

        if not isinstance(args, dict):
            raise cherrypy.HTTPError(400)

        # Check if provider is set            
        if not args.get('provider'): 
            raise cherrypy.HTTPError(400)

        # do login
        self.logger.info( 'event:start services.auth.login' )
        response = services.auth.login(**args)
        self.logger.info( 'event:stop services.auth.login' )
        if not response.success:    
            services.accounting.accountex('login', 'failed')
            raise cherrypy.HTTPError(401, response.reason)

        services.accounting.accountex('login', 'success')
        services.accounting.accountex('login', response.result.auth.providertype )
        

        # if the user have to access authenticated external ressources 
        # this is the only one request which contains users credentials       
        # Build now auth secret for postponed usage    
        oc.od.composer.prepareressources( response.result.auth, response.result.user )

        self.logger.info( 'event:start oc.od.settings.jwt_config_user' )
        expire_in = oc.od.settings.jwt_config_user.get('exp')    
        jwt_user_token = services.auth.update_token( auth=response.result.auth, user=response.result.user, roles=response.result.roles, expire_in=expire_in )
        self.logger.info( 'event:stop oc.od.settings.jwt_config_user' )

        return Results.success( message="Authentication successful", 
                                result={'userid': response.result.user.userid,
                                        'jwt_user_token': jwt_user_token,
                                        'name': response.result.user.name,
                                        'provider': response.result.auth.providertype,       
                                        'expire_in': expire_in      
                                })


    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def labels(self):
        """[summary]

        Returns:
            [json]: [Results array of labels if auth set]
        """
        self.logger.debug('')
        res = None
        if services.auth.isidentified:
            auth = services.auth.auth
            labels = [] 
            if auth.data and isinstance( auth.data.get('labels'), dict) :
                for k in auth.data.get('labels').keys():
                    labels.append( str(k) )
            res = Results.success( result=labels) 
        else:
            res = Results.error( message='invalid user credentials' )
        return res

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    # @cherrypy.tools.allow(methods=['GET']) 
    def buildsecret(self):
        self.logger.debug('')
     
        cherrypy.response.timeout = 180
        args = cherrypy.request.json

        if not isinstance(args, dict):
            raise cherrypy.HTTPError(400)

        # Check if password is set
        password = args.get('password')
        if not isinstance(password, str):
            raise cherrypy.HTTPError(400, 'Bad request invalid password parameter')

        try:
            (auth, user ) = self.validate_env()

            # build a login dict arg object with provider set to AD
            args_login = {  'userid'  : user.userid,
                            'password': password
            }

            response = services.auth.su( source_provider_name=auth.provider, arguments=args_login)  
            if not response.success:                
                raise cherrypy.HTTPError(401, response.reason)

            oc.od.composer.prepareressources( response.result.auth, response.result.user )
            expire_in = oc.od.settings.jwt_config_user.get('exp')    
            jwt_user_token = services.auth.update_token( auth=response.result.auth, user=response.result.user, roles=response.result.roles, expire_in=expire_in )
            
            return Results.success( message="Authentication successful", 
                                    result={'userid': response.result.user.userid,
                                            'name': response.result.user.name,
                                            'jwt_user_token': jwt_user_token,
                                            'provider': response.result.auth.providertype,       
                                            'expire_in': expire_in      
                                    })

        except Exception as e:
            logger.error( e )
            return Results.error( message=str(e) )
        
     

    @cherrypy.expose
    @cherrypy.tools.allow(methods=['POST','GET'])
    # Pure HTTP Form request
    def autologin(self, login=None, provider='anonymous', password=None):
        self.logger.debug('')

        if oc.od.settings.services_http_request_denied.get(self.autologin.__name__) is True:
            raise cherrypy.HTTPError(400, 'request is denied by configfile')

        #if not isinstance(login,str):
        #    raise cherrypy.HTTPError(400, 'Bad request invalid login parameter')

        # password is an optionnal value but must be a str if set
        if password is not None and not isinstance(password,str) :
            raise cherrypy.HTTPError(400, 'Bad request invalid password parameter')

        if isinstance(provider,str) is False:
            raise cherrypy.HTTPError(400, 'Bad request invalid provider parameter')
        
        # build a login dict arg object with provider set to AD
        args_login = {  'manager':  None,
                        'password': password,
                        'provider': provider,
                        'userid':   login,
                        'auto':     True
        }
        
        # do login        
        response = services.auth.login(**args_login)
        if not response.success:                
            raise cherrypy.HTTPError(401, response.reason)

        oc.od.composer.prepareressources( response.result.auth, response.result.user )
        expire_in = oc.od.settings.jwt_config_user.get('exp')    
        jwt_user_token = services.auth.update_token( auth=response.result.auth, user=response.result.user, roles=response.result.roles, expire_in=expire_in )
        oauth_html_refresh_page = self.build_redirecthtmlpage( jwt_user_token )
        cherrypy.response.headers[ 'Refresh' ] = '5; url=' + oc.od.settings.default_host_url
        return oauth_html_refresh_page

        


    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def login(self):
        #
        # this request could take a while and 
        # takes up to 180s
        #  
        cherrypy.response.timeout = 180

        # get params from json request
        args = cherrypy.request.json

        # only authenticated request are allowed
        if not services.auth.isauthenticated:            
            raise cherrypy.HTTPError(401)

        # get auth and user object from the http request 
        auth = services.auth.auth
        user = services.auth.user

        # push a start message to the message info database
        services.messageinfo.start(user.userid, 'Authentication successful %s' % user.name)   

        # launch the user desktop 
        return self.root.composer._launchdesktop( auth, user, args)


    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def refreshtoken(self):
        
        if services.auth.isidentified:
            user = services.auth.user
            auth = services.auth.auth
            expire_in = oc.od.settings.jwt_config_user.get('exp')    
            jwt_user_token = services.auth.update_token( auth=auth, user=user, roles=None, expire_in=expire_in )
            services.accounting.accountex('login', 'refreshtoken')
            return Results.success( 'Authentication successful %s' % user.name, 
                                    {   'expire_in': expire_in,
                                        'jwt_user_token': jwt_user_token } )
     
        return Results.error(message='Invalid user')