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
import oc.od.settings
import json



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
            self.logger.error( f"FATAL ERROR {AuthController.redirect_page_local_filename} file is missing")
            self.logger.error( f"http auth request will failed {e}" )
            raise cherrypy.HTTPError( status=401, message=f"missing file {AuthController.redirect_page_local_filename}")


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
            Disconnect a connected user
            Keep desktop running
        Args:
            None
        Returns:
            JSON Results
        """
        self.logger.debug('disconnect')
        result = None
        url = '/'
        if services.auth.isidentified:
            # nothing to do
            # keep dekstop running
            services.auth.logout(provider=services.auth.auth.provider, authinfo=services.auth.auth )
            result = Results.success( result = {'url': url} )
        else:
            self.logger.error('user try to logout, but user is not identified')
            result = Results.error( message='invalid user credentials', result = {'url': url}  )  
        return result

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
        response = None
        url = '/'
        if services.auth.isidentified:
            # remove the pod/container          
            removedesktop = oc.od.composer.removedesktop(services.auth.auth, services.auth.user)
            if removedesktop is True:
                response = Results.success( result = {'url': url} )
            else:
                response = Results.error( message='removedesktop failed' )
                response['result'] = { 'url': url } # always add a url in result to logout

            # Always call logout auth services 
            # nothing to do
            services.auth.logout( provider=services.auth.auth.provider, authinfo=services.auth.auth ) 

        else:
            response = Results.error( message='invalid user credentials' )
            response['result'] = { 'url': url } # always add a url in result to logout

        return response
            
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

        # can raise excetion 
        self.isban_ip()

        # overwrite auth params to prevent manager changes
        # for security reasons
        params['manager'] = 'external' # oauth MUST force an 'external' manager 
        response = services.auth.login(**params)

        # can raise excetion 
        self.checkloginresponseresult( response )  

        # prepare ressources
        # can raise Exception
        oc.od.composer.prepareressources( authinfo=response.result.auth, userinfo=response.result.user )

        # create auth token
        jwt_user_token = services.auth.update_token( auth=response.result.auth, user=response.result.user, roles=response.result.roles )
        
        # redirect user html page
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
        self.logger.debug('auth call start')
        cherrypy.response.timeout = 180

        self.logger.debug( f"dump http header request {cherrypy.request.headers} ")
       
        args = cherrypy.request.json
        if not isinstance(args, dict):
            raise cherrypy.HTTPError( status=401, message='invalid parameters')

        # read user's client ipsource
        ipsource = getclientipaddr()

        # can raise excetion 
        self.isban_ip(ipsource)

        # if force_auth_prelogin
        http_attribut_to_force_auth_prelogin = cherrypy.request.headers.get(services.prelogin.http_attribut_to_force_auth_prelogin)
        self.logger.debug( f"dump http_attribut_to_force_auth_prelogin http.header[{services.prelogin.http_attribut_to_force_auth_prelogin}] = {http_attribut_to_force_auth_prelogin}" )
        # if the request need a prelogin
        if services.prelogin.enable and ( services.prelogin.request_match(ipsource) or http_attribut_to_force_auth_prelogin ) :
            self.logger.debug(f"the request need a prelogin services.prelogin.enable={services.prelogin.enable}")
            userid = args.get( 'userid' )
            self.logger.debug( f"auth {services.prelogin.http_attribut}={userid}" )
            if not isinstance(userid, str):
                self.logger.error( f"invalid auth parameters {services.prelogin.http_attribut} type={type(userid)}" )
                raise cherrypy.HTTPError( status=401, message='invalid auth parameters, request must use set userid' )

            loginsessionid = args.get('loginsessionid')
            if not isinstance(loginsessionid, str) or len(loginsessionid)==0:
                self.logger.error( f"invalid auth parameters loginsessionid type={type(loginsessionid)}" )
                raise cherrypy.HTTPError( status=401, message='invalid auth parameters, request must use a prelogin session' )

            prelogin_verify = services.prelogin.prelogin_verify(sessionid=loginsessionid, userid=userid)
            if not prelogin_verify:
                self.logger.debug(f"prelogin_verify is false sessionid={loginsessionid}, userid={userid}")
                self.logger.error(f"SECURITY WARNING prelogin_verify failed invalid ipsource={ipsource} auth parameters userid={userid}" )
                self.fail_ip( ipsource ) # ban the ipsource addr
                raise cherrypy.HTTPError( status=401, message='invalid auth request, verify prelogin request failed' )

        # do login
        # Check if provider is set   
        provider = args.get('provider')         
        if provider is None and services.auth.is_default_metalogin_provider(): 
            # no provider set 
            # use metalogin provider by default
            self.logger.info( 'auth is using metalogin provider' )
            # can raise exception 
            response = services.auth.metalogin(**args)
        elif isinstance(provider, str ) and len(provider) > 0:
            self.logger.info( f"provider set to {provider}, use login provider" )
            # can raise exception 
            response = services.auth.login(**args)
        else:
            self.logger.info( f"ValueError provider expect str get {type(provider)}" )
            raise cherrypy.HTTPError( status=401, message='missing provider parameter')

        self.logger.debug( 'login done' )

        # checkloginresponseresult can raise exception 
        self.logger.debug( 'login checkloginresponseresult' )
        self.checkloginresponseresult( response )  
        
        services.accounting.accountex('login', 'success')
        services.accounting.accountex('login', response.result.auth.providertype )
        
        # can raise excetion   
        try:
            self.logger.debug( 'login prepareressources' )
            oc.od.composer.prepareressources( authinfo=response.result.auth, userinfo=response.result.user )
        except Exception as e:
            return Results.error( status=401, message='failed to prepare ressources ' + str(e) )
        

        expire_in = oc.od.settings.jwt_config_user.get('exp')    
        jwt_user_token = services.auth.update_token( auth=response.result.auth, user=response.result.user, roles=response.result.roles )

        return Results.success( message=response.reason, 
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
            res = Results.success( result=auth.get_labels() ) 
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

        
        (auth, user ) = self.validate_env()

        # build a login dict arg object with provider set to AD
        args_login = {  
            'userid'  : user.userid,
            'password': password
        }

        response = services.auth.su( source_provider_name=auth.provider, arguments=args_login)  

        # can raise excetion 
        self.checkloginresponseresult( response, msg='su' )  
                    
        # prepare ressources
        oc.od.composer.prepareressources( authinfo=response.result.auth, userinfo=response.result.user )

        # compute new user jwt token   
        jwt_user_token = services.auth.update_token( auth=response.result.auth, user=response.result.user, roles=response.result.roles )
        
        return Results.success( message="Authentication successful", 
                                result={'userid': response.result.user.userid,
                                        'name': response.result.user.name,
                                        'jwt_user_token': jwt_user_token,
                                        'provider': response.result.auth.providertype,       
                                        'expire_in':  oc.od.settings.jwt_config_user.get('exp')      
                                })

    @cherrypy.expose
    @cherrypy.tools.allow(methods=['POST','GET'])
    # Pure HTTP Form request
    def prelogin(self,userid=None):
        self.logger.debug( f"dump http header request {cherrypy.request.headers} ")
        ipsource = getclientipaddr()
        self.logger.debug('prelogin request from ip source %s', ipsource)
        
        # can raise exception 
        self.isban_ip(ipsource)

        if not services.prelogin.enable:
            self.logger.error("prelogin service is disabled in configuration file")
            raise cherrypy.HTTPError(400, "prelogin service is disabled in configuration file")

        http_attribut_to_force_auth_prelogin = cherrypy.request.headers.get(services.prelogin.http_attribut_to_force_auth_prelogin)
        self.logger.debug( f"read http_attribut_to_force_auth_prelogin http.header[{services.prelogin.http_attribut_to_force_auth_prelogin}] = {http_attribut_to_force_auth_prelogin}" )
        
        # if the request need a prelogin
        is_http_attribut_exist = isinstance(http_attribut_to_force_auth_prelogin, str)
        is_ipsource_match = services.prelogin.request_match( ipsource )
        self.logger.debug( f"{services.prelogin.http_attribut_to_force_auth_prelogin} type={type(http_attribut_to_force_auth_prelogin)} value={http_attribut_to_force_auth_prelogin} is_http_attribut_exist={is_http_attribut_exist} is_ipsource_match={is_ipsource_match}")
        if not is_http_attribut_exist and not is_ipsource_match:
            self.logger.error(f"prelogin invalid network source error ipsource={ipsource} is_http_attribut {services.prelogin.http_attribut_to_force_auth_prelogin} exist={is_http_attribut_exist} is_ipsource_match={is_ipsource_match}")
            self.fail_ip( ipsource ) # ban ipsource addr
            raise cherrypy.HTTPError(400, 'prelogin service is denied, invalid request parameters')
        
        # if http request has services.prelogin.http_attribut
        # use services.prelogin.http_attribut value has userid
        # overwrite userid parameter
        if isinstance( services.prelogin.http_attribut, str):
            http_userid = cherrypy.request.headers.get(services.prelogin.http_attribut)
            self.logger.debug( f"read http attribut http_userid={http_userid}")
            if isinstance( http_userid, str ):
                # overwrite userid with http header value
                userid = http_userid

        if not isinstance(userid, str) or len(userid) == 0:
            self.logger.error(f"prelogin invalid userid={userid} parameter type={type(userid)}")
            raise cherrypy.HTTPError(400, 'invalid userid request parameter')

        # if the param id url quoted
        # always decode it 
        self.logger.info(f"prelogin request raw param userid={userid}")
        userid = urllib.parse.unquote(userid)
        self.logger.info(f"prelogin decoded param userid={userid}")

        # build html response
        html_data = services.prelogin.prelogin_html( userid=userid )
        if not isinstance(html_data, str) or len(html_data) == 0 :
            self.logger.error('prelogin_html fetch {services.prelogin.prelogin_url} failed')
            raise cherrypy.HTTPError(400, 'Configuration file error, prelogin url fetch failed')

        cherrypy.response.headers['Cache-Control'] = 'no-cache, private'
        cherrypy.response.headers['Content-Type'] = 'text/html; charset=utf-8'
        return html_data.encode('utf-8')

    @cherrypy.expose
    @cherrypy.tools.allow(methods=['POST','GET'])
    # Pure HTTP Form request
    def autologin(self, login=None, provider=None, password=None):
        self.logger.debug('')
   
        # can raise exception 
        self.isban_ip()

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

        oc.od.composer.prepareressources( authinfo=response.result.auth, userinfo=response.result.user )

        jwt_user_token = services.auth.update_token( auth=response.result.auth, user=response.result.user, roles=response.result.roles )
        oauth_html_refresh_page = self.build_redirecthtmlpage( jwt_user_token )
        cherrypy.response.headers[ 'Refresh' ] = '5; url=' + oc.od.settings.default_host_url
        return oauth_html_refresh_page


    def handler_logmein_json(self, jwt_user_token):
        cherrypy.response.headers[ 'Content-Type'] = 'application/json;charset=utf-8'
        jwt_user = { 'jwt_user_token': jwt_user_token }
        result_jwt = Results.success( 'login success', result=jwt_user)
        # convert result_jwt as str
        result_str = json.dumps( result_jwt ) + '\n'
        # encode with charset=utf-8
        return result_str.encode('utf-8')

    def handler_logmein_html(self,jwt_user_token):
        oauth_html_refresh_page = self.build_redirecthtmlpage( jwt_user_token )
        cherrypy.response.headers[ 'Content-Type'] = 'text/html;charset=utf-8'
        cherrypy.response.headers[ 'Cache-Control'] = 'no-cache, private'
        cherrypy.response.headers[ 'Refresh' ] = '5; url=' + oc.od.settings.default_host_url
        return oauth_html_refresh_page 

    def handler_logmein_text(self, jwt_desktop):
        cherrypy.response.headers[ 'Content-Type'] = 'text/text;charset=utf-8'
        cherrypy.response.headers[ 'Cache-Control'] = 'no-cache, private'
        result_str = jwt_desktop + '\n'
        return result_str.encode('utf-8')


    @cherrypy.expose
    @cherrypy.tools.allow(methods=['POST','GET'])
    # Pure HTTP Form request
    def logmein(self, provider=None, userid=None, format='deprecated' ):

        ipsource = getclientipaddr()
        self.logger.debug('logmein request from ip source %s', ipsource)

        # can raise exception 
        self.isban_ip(ipsource)
        
        if not services.logmein.enable:
            self.logger.error('logmein is disabled, but request ask for logmein from %s', ipsource)
            raise cherrypy.HTTPError(400, 'logmein configuration file error, service is disabled')

        if not services.logmein.request_match( ipsource ):
            self.logger.error('logmein invalid network source error ipsource=%s', ipsource)
            services.fail2ban.fail( ipsource, services.fail2ban.ip_collection_name )
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
        
        # can raise excetion if an error occurs
        self.checkloginresponseresult( response )

        # prepare ressources
        oc.od.composer.prepareressources( authinfo=response.result.auth, userinfo=response.result.user )

        jwt_user_token = services.auth.update_token( auth=response.result.auth, user=response.result.user, roles=response.result.roles  )

        routecontenttype = {    
            'text/html': self.handler_logmein_html, 
            'application/json': self.handler_logmein_json,
            'text/plain':  self.handler_logmein_text 
        }

        return self.getlambdaroute( routecontenttype, defaultcontenttype='text/html' )( jwt_user_token )


    def checkloginresponseresult( self, response, msg='login' ):
        # check auth response
        if not isinstance( response, oc.auth.authservice.AuthResponse ):
            error = f"services auth.{msg} does not return AuthResponse object"
            self.logger.error( error )
            raise cherrypy.HTTPError(401, message=error)  

        # if it's an error
        # this section code should never occurs
        if not response.success:
            message = None
            for m in [ 'reason', 'message', '_message']:
                if hasattr( response, m ):
                    message = getattr( response, m )
                    break

            self.logger.error( f"services auth.login error {message}" )
            raise cherrypy.HTTPError(401, message )  


    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def login(self):
        # 
        # this request launchdesktop a desktop
        # this request could take a while and takes up to 180s
        #
        cherrypy.response.timeout = 180
        # can raise exception 
        self.isban_ip()
        # get params from json request
        args = cherrypy.request.json
        # can raise exception
        (auth, user ) = self.validate_env()
        # push a start message to database cache info
        services.messageinfo.start( user.userid, "b.Launching desktop")
        # launch the user desktop 
        return self.root.composer._launchdesktop( auth, user, args)


    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def refreshtoken(self):
        self.logger.debug('')
        # no params from json request
        # args = cherrypy.request.json
        # can raise exception
        (auth, user) = self.validate_env()
        # update token
        jwt_user_token = services.auth.update_token( auth=auth, user=user, roles=None )
        # add no-cache nosniff HTTP headers
        cherrypy.response.headers[ 'Cache-Control'] = 'no-cache, private'
        # disable content or MIME sniffing which is used to override response Content-Type headers 
        # to guess and process the data using an implicit content type
        cherrypy.response.headers[ 'X-Content-Type-Options'] = 'nosniff'
        # return new token
        return Results.success( 
            "Refresh token success", 
            { 'expire_in': oc.od.settings.jwt_config_user.get('exp'), 'jwt_user_token': jwt_user_token } )