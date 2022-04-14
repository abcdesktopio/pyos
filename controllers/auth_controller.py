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
import chevron

from cryptography import x509
from cryptography.hazmat.backends import default_backend


import urllib.parse

from oc.od.base_controller import BaseController
from oc.cherrypy import Results, getclientipaddr 
from oc.od.services import services
import oc.od.composer 
from oc.lib import removeCookie
import oc.od.settings



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
    redirect_page_local_filename = 'redirect.mustache.html'

    def __init__(self, config_controller=None):
        self.logger.info( 'config_controller=%s', config_controller )
        super().__init__(config_controller)
        try:
            self.oauth_html_redirect_page = oc.lib.load_local_file(filename=AuthController.redirect_page_local_filename)
        except Exception as e:
            self.logger.error( 'FATAL ERROR %s file is missing', AuthController.redirect_page_local_filename)
            self.logger.error( 'http auth request will failed')
            self.logger.error( e )
            raise ValueError( 'missing file ' + AuthController.redirect_page_local_filename)


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
        
        if services.auth.isidentified:
            bReturn = None
            user = services.auth.user
            auth = services.auth.auth  
            # remove the pod/container          
            if oc.od.composer.removedesktop(auth, user) is False:
                bReturn = Results.error( message='removedesktop failed' )

            # Always removeCookie routehostcookiename
            removeCookie( oc.od.settings.routehostcookiename )

            # Always call logout auth services 
            services.auth.logout() 
            
            if bReturn is None:
                bReturn = Results.success()

        else:
            bReturn = Results.error( message='invalid user credentials' )
        
        return bReturn
            
    def build_redirecthtmlpage(self, jwt_user_token):
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
        mustache_dict = {   'loginScreencss_url': '../../css/css-dist/loginScreen.css',
                            'jwt_user_token': str(jwt_user_token),
                            'default_host_url' : '/' 
        }
        oauth_html_refresh_page = chevron.render( self.oauth_html_redirect_page, mustache_dict )
        return oauth_html_refresh_page

    @cherrypy.expose
    @cherrypy.tools.allow(methods=['GET'])
    def oauth(self, **params):
        # overwrite auth params to prevent manager changes
        # for security reasons
        params['manager'] = 'external'
        response = services.auth.login(**params)

        # can raise excetion 
        self.checkloginresponseresult( response )  

        # prepare ressources
        oc.od.composer.prepareressources( response.result.auth, response.result.user )

        # create auth token
        jwt_user_token = services.auth.update_token( auth=response.result.auth, user=response.result.user, roles=response.result.roles, expire_in=None )
        
        # redirect user html
        oauth_html_refresh_page = self.build_redirecthtmlpage( jwt_user_token )
        cherrypy.response.headers[ 'Refresh' ] = '5; url=' + oc.od.settings.default_host_url
        return oauth_html_refresh_page


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
                result={    'userid': response.result.user.userid,
                            'name': response.result.user.name,
                            'provider': response.result.auth.providertype,       
                            'expire_in': expire_in 
                }
                return Results.success
            else
                raise cherrypy.HTTPError(400) invalid parameters
                raise cherrypy.HTTPError(401) invalid credentials
        """
        self.logger.debug('auth call')
        cherrypy.response.timeout = 180
        args = cherrypy.request.json

        if not isinstance(args, dict):
            raise cherrypy.HTTPError(400)

        # ipsource
        ipsource = getclientipaddr()
        http_attribut_to_force_auth_prelogin = cherrypy.request.headers.get(services.prelogin.http_attribut_to_force_auth_prelogin)
        # if the request need a prelogin
        if services.prelogin.enable and ( services.prelogin.request_match(ipsource) or http_attribut_to_force_auth_prelogin ) :
            userid = args.get('userid')
            if not isinstance(userid, str):
                self.logger.error( 'invalid auth parameters userid %s', type(userid) )
                if isinstance( services.prelogin.prelogin_url_redirect_on_error, str ):
                    raise cherrypy.HTTPRedirect( services.prelogin.prelogin_url_redirect_on_error )
                else:     
                    raise cherrypy.HTTPError(401, 'invalid auth parameters')

            # read the provider name
            provider_name = args.get('provider')
            # look for a provider object using the provider name
            if isinstance(provider_name, str):
                provider = services.auth.findprovider( provider_name )
                # if the provider exists and is a ODAdAuthProvider
                if isinstance( provider, oc.auth.authservice.ODAdAuthProvider ):
                    # look for a provider object using the provider name
                    # add the domain ad prefix
                    userid = provider.getadlogin(userid)
                    self.logger.info( 'userid rewrite as %s', userid )

            loginsessionid = args.get('loginsessionid')
            if not isinstance(loginsessionid, str):
                self.logger.error( 'invalid auth parameters loginsessionid %s', type(loginsessionid) )
                if isinstance( services.prelogin.prelogin_url_redirect_on_error, str ):
                    raise cherrypy.HTTPRedirect( services.prelogin.prelogin_url_redirect_on_error )
                else:     
                    raise cherrypy.HTTPError(401, 'invalid auth parameters, request must use a prelogin session')

            prelogin_verify = services.prelogin.prelogin_verify(sessionid=loginsessionid, userid=userid)
            if not prelogin_verify:
                # todo: black list the ip source ?
                self.logger.error( 'SECURITY WARNING prelogin_verify failed invalid ipsource=%s auth parameters userid %s', ipsource, userid )
                if isinstance( services.prelogin.prelogin_url_redirect_on_error, str ):
                    raise cherrypy.HTTPRedirect( services.prelogin.prelogin_url_redirect_on_error )
                else:     
                    raise cherrypy.HTTPError(401, 'invalid auth request, verify failed')

        # do login
        # Check if provider is set   
        provider = args.get('provider')         
        if provider is None and services.auth.is_default_metalogin_provider(): 
            # no provider set 
            # use metalogin provider by default
            self.logger.info( 'auth is using metalogin provider' )
            response = services.auth.metalogin(**args)
        elif isinstance(provider, str ):
            self.logger.info( 'provider set to %s, use login provider', args.get('provider') )
            response = services.auth.login(**args)
        else:
            self.logger.info( 'ValueError provider excepet str get %s ', str(type(provider)) )
            raise cherrypy.HTTPError(400, 'Bad provider parameter')
        self.logger.info( 'login done' )

        # can raise excetion 
        self.checkloginresponseresult( response )  
        
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

            # can raise excetion 
            self.checkloginresponseresult( response, msg='su' )  
                        
            # prepare ressources
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
    def prelogin(self,userid=None):
        self.logger.debug( cherrypy.request.headers )
        ipsource = getclientipaddr()
        self.logger.debug('prelogin request from ip source %s', ipsource)
        
        if not services.prelogin.enable:
            self.logger.error('prelogin is disabled, but request ask for prelogin from %s', ipsource)
            raise cherrypy.HTTPError(400, 'Configuration file error, service is disabled')

        if not services.prelogin.request_match( ipsource ):
            self.logger.error('prelogin invalid network source error ipsource=%s', ipsource)
            raise cherrypy.HTTPError(400, 'Invalid network source error')
        
        # if http request has services.prelogin.http_attribut
        # use services.prelogin.http_attribut value has userid
        if isinstance( services.prelogin.http_attribut, str) :
            http_userid = cherrypy.request.headers.get(services.prelogin.http_attribut)
            if isinstance( http_userid, str ):
                userid = http_userid
        
        if not isinstance( userid, str) or len(userid) == 0:
            self.logger.error('prelogin invalid userid parameter format')
            raise cherrypy.HTTPError(400, 'invalid userid request parameter')

        # if the param id url quoted
        # always decode it 
        self.logger.info('prelogin request raw param userid=%s', userid)
        userid = urllib.parse.unquote(userid)
        self.logger.info('prelogin decoded param userid=%s', userid)

        # build html response
        html_data = services.prelogin.prelogin_html( userid=userid )
        if html_data is None:
            self.logger.error('prelogin_html failed')
            raise cherrypy.HTTPError(400, 'Configuration file error, invalid prelogin_url')

        cherrypy.response.headers['Content-Type'] = 'text/html;charset=utf-8'
        return html_data.encode('utf-8')

    @cherrypy.expose
    @cherrypy.tools.allow(methods=['POST','GET'])
    # Pure HTTP Form request
    def autologin(self, login=None, provider=None, password=None):
        self.logger.debug('')

        # check if autologin is enabled
        if oc.od.settings.services_http_request_denied.get(self.autologin.__name__, True) is True:
            raise cherrypy.HTTPError(400, 'request is denied by configfile')

        # login must be set and must be a str
        if not isinstance(login,str):
            raise cherrypy.HTTPError(400, 'Bad request invalid login parameter')

        # password is an optionnal value but must be a str if set
        if password is not None:
            if not isinstance(password,str) :
                raise cherrypy.HTTPError(400, 'Bad request invalid password parameter')

        # build a login dict arg object with provider set to AD
        args_login = {  'manager':  'explicit',
                        'password': password,
                        'provider': provider,
                        'userid':   login,
                        'auto':     True
        }
        
        # do login with dict params
        response = services.auth.login(**args_login)

        # can raise exception 
        self.checkloginresponseresult( response )  

        oc.od.composer.prepareressources( response.result.auth, response.result.user )

        expire_in = oc.od.settings.jwt_config_user.get('exp')    
        jwt_user_token = services.auth.update_token( auth=response.result.auth, user=response.result.user, roles=response.result.roles, expire_in=expire_in )
        oauth_html_refresh_page = self.build_redirecthtmlpage( jwt_user_token )
        cherrypy.response.headers[ 'Refresh' ] = '5; url=' + oc.od.settings.default_host_url
        return oauth_html_refresh_page


    @cherrypy.expose
    @cherrypy.tools.allow(methods=['POST','GET'])
    # Pure HTTP Form request
    def logmein(self, provider=None, userid=None ):

        ipsource = getclientipaddr()
        self.logger.debug('logmein request from ip source %s', ipsource)
        
        if not services.logmein.enable:
            self.logger.error('logmein is disabled, but request ask for logmein from %s', ipsource)
            raise cherrypy.HTTPError(400, 'logmein configuration file error, service is disabled')

        if not services.logmein.request_match( ipsource ):
            self.logger.error('logmein invalid network source error ipsource=%s', ipsource)
            raise cherrypy.HTTPError(400, 'logmein invalid network source error')

        # use the userid in querystring parameter
        if services.logmein.permit_querystring:
            if isinstance(userid, str) and len(userid) > 0:
                userid = urllib.parse.unquote(userid)
        
        # if the http header name is defined in configuration file
        # the header name must exist in the http request else raise error
        if isinstance( services.logmein.http_attribut, str):
            cert = cherrypy.request.headers.get(services.logmein.http_attribut)
            # if the http header name exixsts in the current http request
            if isinstance( cert, str ):
                strcert = urllib.parse.unquote( cert )
                self.logger.info('read cert:' + strcert  )
                # update the certificat format if not begin with -----BEGIN CERTIFICATE-----
                if not strcert.startswith('-----BEGIN') :
                    strcert = '-----BEGIN CERTIFICATE-----\n' + strcert + '\n-----END CERTIFICATE-----'
                    self.logger.info('changed cert:' + strcert  )
                
                # only to debug cert format
                # f = open('user.cer')
                # strcert = f.read( )
                # f.close()

                cert_info = x509.load_pem_x509_certificate( strcert.encode(), default_backend() )
                self.logger.debug('logmein certificat subject data %s', str(cert_info.subject) )

                cert_info_data = None
                for oid in services.logmein.oid_query_list :
                    try:
                        self.logger.debug('cert get oid %s', str(oid))
                        cert_info_data = cert_info.subject.get_attributes_for_oid(oid)[0].value
                        if isinstance( cert_info_data, str ) and len( cert_info_data ) > 0:
                            userid = cert_info_data
                            self.logger.info('cert read user=%s', str(cert_info_data))
                            break
                    except Exception as e:
                        self.logger.error('cert read %s', str(e))

        if not isinstance(userid, str) :
            self.logger.error('invalid userid parameter' )
            raise cherrypy.HTTPError(400, 'logmein invalid user parameter')
        
        if len(userid) == 0:
            self.logger.error('invalid userid parameter' )
            raise cherrypy.HTTPError(400, 'logmein invalid user parameter')

        self.logger.info('start login(provider=%s, manager=implicit, userid=%s)', str(provider), str(userid))
        response = services.auth.login( provider=provider, manager='implicit', userid=userid )
        
        # can raise excetion 
        self.checkloginresponseresult( response )

        # prepare ressources
        oc.od.composer.prepareressources( response.result.auth, response.result.user )

        jwt_user_token = services.auth.update_token( auth=response.result.auth, user=response.result.user, roles=response.result.roles, expire_in=None )
        oauth_html_refresh_page = self.build_redirecthtmlpage( jwt_user_token )
        cherrypy.response.headers[ 'Content-Type'] = 'text/html;charset=utf-8'
        cherrypy.response.headers[ 'Refresh' ] = '5; url=' + oc.od.settings.default_host_url
        return oauth_html_refresh_page


    def checkloginresponseresult( self, response, msg='login' ):
        # check auth response
        if not isinstance( response, oc.auth.authservice.AuthResponse ):
            self.logger.error( f"services auth.{msg} does not return oc.auth.authservice.AuthResponse object" )
            raise cherrypy.HTTPError(401, f"services auth.{msg} does not return oc.auth.authservice.AuthResponse")  

        if not response.success:
            self.logger.error( "services auth.login does not return %s", str(response.reason) )
            raise cherrypy.HTTPError(401, str(response.reason) )  


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