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
import time

# ldap import
import ldap
import ldap.filter
from   ldap.controls import SimplePagedResultsControl
from   distutils.version import LooseVersion
import platform
import chevron  # for citrix All_Regions.ini

# OAuth lib
from requests_oauthlib import OAuth2Session
import requests

import json
import urllib
import urllib.parse 
import urllib.request

import copy
import base64
from threading import Thread, Lock
from collections import OrderedDict

import cherrypy
from oc.cherrypy import getclientipaddr
from netaddr import IPNetwork, IPAddress
import os
import subprocess
import time

import oc.logging
import oc.pyutils as pyutils
import oc.od.resolvdns
import oc.auth.jwt
import oc.od.acl

import tempfile
import uuid

logger = logging.getLogger(__name__)

#
# defined some AuthenticationError
class AuthenticationError(Exception):
    def __init__(self,message='Something went bad',code=500):
        self.message = message
        self.code = code

class InvalidCredentialsError(AuthenticationError):
    def __init__(self,message='Invalid credentials',code=401):
        self.message = message
        self.code = code

class AuthenticationFailureError(AuthenticationError):
    def __init__(self,message='Authentication failed',code=401):
        self.message = message
        self.code = code

class ExternalAuthError(AuthenticationError):
    def __init__(self,message='Authentication failure',code=500):
        self.message = message
        self.code = code 

class AuthenticationDenied(AuthenticationError):
    def __init__(self,message='Authentication denied by security policy',code=401):
        self.message = message
        self.code = code

class ExternalAuthLoginError(ExternalAuthError):
    def __init__(self,message='Log-in failed',code=401):
        self.message = message
        self.code = code

class ExternalAuthUserError(ExternalAuthError):
    def __init__(self,message='Fetch user info failed',status=401):
        self.message = message
        self.code = status

#
# define AuthRoles
class AuthRoles(dict):
    def __init__(self,entries):
        if type(entries) is dict:
            super().__init__(entries)

    def __getattr__(self, name):
        return self.get(name)

    def __getitem__(self, key):
        return getattr(self, key, None)

# define AuthUser      
class AuthUser(dict):
    def __init__(self,entries):
        if type(entries) is dict:
            super().__init__(entries)

    def __getattr__(self, name):
        return self.get(name)

    def __getitem__(self, key):
        return getattr(self, key, None)
        
#
# define AuthInfo
class AuthInfo(object):
    def __init__(self, provider=None, providertype=None, token=None, type='Bearer', expires_in=None, protocol=None, data={}, claims={}):
        self.provider = provider
        self.providertype = providertype
        self.protocol = protocol
        self.token = token
        self.type = type
        self.expires_in = expires_in
        self.data = data
        self.claims = claims

    def __getitem__(self, key):
        return getattr(self, key, None)

    def get(self, key):
        return self[key]

    def isValid(self):
        bReturn = False
        try:
            bReturn = not not (self.provider and self.token)            
        except Exception:
            pass
        return bReturn
    
    def markAuthDoneFromPreviousToken(self, already_done=True):
        self.token = already_done

    def isPreviousAuth(self):        
        if type(self.token) is bool:
            return True
        if type(self.token) is str:
            return False
        raise ValueError('Invalid token value type')

    def todict( self ):
        """[todict]
            convert AuthInfo public data to dict
        Returns:
            [dict]: AuthInfo to dict 
        """
        mydict = {   
            'provider' :    self.provider,
            'providertype': self.providertype,
            'protocol':     self.protocol,
            'type':         self.type,
            'data':         self.data 
        } 
        return mydict  
    
    

    
class AuthResponse(object):
    def __init__(self, manager=None, success=False, result=None, reason='', error=None, code=200, redirect_to='/', claims={}):
        self.manager = manager
        self.success = success
        self.result = result
        self.error = error
        self.reason = reason
        self.claims = claims
        self.mgr = None 
        self.redirect_to = redirect_to
       
        
class AuthCache(object):
    NotSet  = object()

    def __init__(self, dict_token=None):
        self.reset()
        if type(dict_token) is dict:
            self.setuser( dict_token.get('user'))
            self.setauth( dict_token.get('auth'))            
            self.setroles( dict_token.get('roles'))

    def markAuthDoneFromPreviousToken(self):
        self._auth.markAuthDoneFromPreviousToken()

    def reset(self):
        self._user = AuthCache.NotSet
        self._roles = AuthCache.NotSet        
        self._auth = AuthInfo()

    @property 
    def user(self):
        return self._user
    
    def setuser( self, valuedict ):
        self._user = AuthUser( valuedict )

    def isValidUser(self):
        return self._user != AuthCache.NotSet and not(not self._user.userid)
            
    def isValidRoles(self):
        return self._roles != AuthCache.NotSet            

    def isValidAuth(self):
        return self._auth.isValid()            

    @property 
    def roles(self):
        return self._roles

    def setroles( self, valuedict ):
        self._roles = AuthRoles( valuedict )
        
    @property 
    def auth(self):
        return self._auth   
    
    def setauth( self, valuedict ):
        self._auth = AuthInfo(  provider=valuedict.get('provider'),
                                providertype=valuedict.get('providertype'), 
                                token=valuedict.get('token'), 
                                type=valuedict.get('type'), 
                                expires_in=valuedict.get('expires_in'), 
                                protocol=valuedict.get('protocol'), 
                                data=valuedict.get('data'), 
                                claims=valuedict.get('claims') )

@oc.logging.with_logger()
class ODAuthTool(cherrypy.Tool):

    abcdesktop_auth_token_cookie_name = 'abcdesktop_token'

    def parse_auth_request(self):
        authcache = None
        token = oc.lib.getCookie(ODAuthTool.abcdesktop_auth_token_cookie_name)
        if token :
            # get the dict decoded token
            decoded_token = self.jwt.decode( token )

            # read user, roles, auth
            # Build a cache data to store value from decoded token 
            # into object class AuthCache
            authcache = AuthCache( decoded_token )
            authcache.markAuthDoneFromPreviousToken()
        else:
            authcache = AuthCache()
        return authcache

    @property
    def current(self):
        # check if we can use cached request data 
        # to prevent decode twice update the request object 
        # by adding the cherrypy.request.odauthcache attribut
        if not hasattr(cherrypy.request, 'odauthcache') :  
            # attr is not found
            # parse_auth_request() will decode the cookie token 
            cherrypy.request.odauthcache = self.parse_auth_request()                
        return cherrypy.request.odauthcache 

    @property
    def user(self):
        return self.current.user

    @property
    def nodehostname(self): 
        return self.current.user.nodehostname
 
    @property
    def roles(self):
        return self.current.roles
        
    @property
    def auth(self):
        return self.current.auth

    @property
    def provider(self):
        return self.current.auth.provider

    @property
    def providertype(self):
        return self.current.auth.providertype

    @property
    def token(self):
        return self.current.auth.token

    @property
    def isauthenticated(self):  
        return self.current.isValidAuth()
    
    @property
    def isidentified(self):
        is_valid_auth = self.current.isValidAuth()
        if  is_valid_auth:
            is_valid_user = self.current.isValidUser()
            if  is_valid_user:
                return True
        return False
        
        # return self.current.isValidAuth() and self.current.isValidUser()
        

    def __init__(self, redirect_url, jwt_config, config):
        super().__init__('before_handler', self.authorize)
        self.redirect_url = redirect_url        
        self.managers = {}
        self.jwt = oc.auth.jwt.ODJWToken( jwt_config )
        
        for name,cfg in config.items():
            try:
                # skip the entry if not enabled
                if not cfg.get('enabled', True): 
                    continue
                logger.info( 'Adding Auth manager %s', name)
                self.managers[name] = self.createmanager(name,cfg)
            except Exception as e:
                self.logger.exception(e)

    def createmanager(self, name, config):
        cls = None
        if name == 'external':
            cls = ODExternalAuthManager 
        elif name == 'explicit':
            cls = ODExplicitAuthManager  
        elif name == 'implicit':
            cls = ODImplicitAuthManager
        else:
            cls = oc.pyutils.get_class(config.get('class', name))
        return cls(name, config)
 
    def findmanager(self, providername, managername=None):
        if managername: 
            return self.getmanager(managername, True)

        if providername:
            provider = self.findprovider(providername)
            if provider: 
                return provider.manager

        raise AuthenticationFailureError('Authentication manager not found: mangaer=%s provider=%s' % (managername,providername))

    def getmanager(self, name, raise_error=False):
        if not name: 
            if raise_error: 
                raise AuthenticationFailureError('Invalid authentication manager name')
            return None

        manager = self.managers.get(name)
        if not manager: 
            if raise_error: 
                raise  AuthenticationFailureError('Undefined authentication manager: %s' % name)
            return None

        return manager

    def findprovider(self, name):
        for mgr in self.managers.values():
            for pdr in mgr.providers.values():
                if pdr.name == name: 
                    return pdr
        return None

    def getclientdata(self):
       return { 'managers': list(map(lambda m: m.getclientdata(), self.managers.values())) }
    
    def update_token( self, auth, user, roles, expire_in ):        
        
        # remove unused data
        # jwt_token is a cookie and must be less than 4096 Bytes
        # call reducetoToken() for auth, user, roles
        # compute the jwt token
       
        auth_data_reduce = {}
        if auth.data.get('domain') :
            auth_data_reduce.update( { 'domain': auth.data.get('domain') } )
        if auth.data.get('dn'):
            auth_data_reduce.update( { 'dn': auth.data.get('dn') } )
        if auth.data.get('labels'):
            auth_data_reduce.update( { 'labels': auth.data.get('labels') } )

        jwt_auth_reduce = { 'provider': auth.provider, 'providertype': auth.providertype, 'data': auth_data_reduce }
        jwt_user_reduce = { 'name': user.get('name'), 'userid': user.get('userid'), 'nodehostname': user.get('nodehostname') }
        # role is not set 
        jwt_role_reduce = {} 

        jwt_token = self.jwt.encode( jwt_auth_reduce, jwt_user_reduce, jwt_role_reduce )

        # save the jwt into cookie data
        self.updatecookies( jwt_token=jwt_token, expire_in=expire_in )
        return jwt_token 

        
        
    def compiledcondition( self, condition, user, roles ):        
        def isPrimaryGroup(user, primaryGroupID):
            # primary group id is uniqu for
            if user.get('primaryGroupID') == primaryGroupID:  
                return True
            return False

        def isHttpHeader( headerdict ):
            if type(headerdict) is not dict:
                logger.warning('invalid value type http header %s, dict is expected in rule', type(headerdict) )
                return False  

            for header in headerdict.keys():
                headervalue = cherrypy.request.headers.get(header)
                if headervalue != headerdict[header] :
                    return False
            return True

        def isBoolean( value ):
            if type(value) is not bool:
                logger.warning('invalid value type boolean %s, bool is expected in rule', type(value) )
                return False  

            if value is True: return True
            return False

        def isMemberOf(roles, groups) :
            if type(roles) is not list:  
                roles = [roles]
            if type(groups) is not list: 
                groups = [groups]
            for m in roles:
                for g in groups:
                    logger.debug('isMemberOf %s, %s', m, g)
                    if m.lower().startswith(g.lower()):
                        return True
            return False

        def isinNetwork( ipsource, network ):
            if IPAddress(ipsource) in IPNetwork( network ):
                return True
            return False

        logger.info('condition %s ', condition )
        compiled_result = False
        if type(condition) is not dict :
            return False

        expected    = condition.get('expected')
        if type(expected) is not bool:
            logger.warning('invalid value type %s bool is expected in rule', type(expected) )
   
        # DO not change with lambda 
        # this is not a dummy code
        # this is readable code for human
        #
        always = condition.get('boolean')
        if type(always) is bool:
            result     = isBoolean( always )
            if result == condition.get( 'expected'):
                compiled_result = True

        httpheader = condition.get('httpheader')
        if type(httpheader) is dict:
            result     = isHttpHeader( httpheader )
            if result == condition.get( 'expected'):
                compiled_result = True

        memberOf = condition.get('memberOf')
        if type(memberOf) is str:
            result     = isMemberOf( roles, memberOf )
            if result == condition.get( 'expected'):
                compiled_result = True

        network = condition.get('network')
        if type(network) is str:
            ipsource = getclientipaddr()
            result = isinNetwork( ipsource, network )
            if result == condition.get( 'expected'):
                compiled_result = True

        primaryGroup = condition.get('primarygroupid')
        if type(primaryGroup) is str:
            result = isPrimaryGroup( user, primaryGroup )
            if result == condition.get( 'expected'):
                compiled_result = True

        return compiled_result

    def compiledrule( self, name, rule, user, roles ):        

        if type(rule) is not dict :
            return False
       
        conditions  = rule.get('conditions')   
        expected    = rule.get('expected')
        if type(expected) is not bool:
            logger.warning('invalid value type %s bool is expected in rule', type(expected) )

        results = []
        for condition in conditions :
            results.append( self.compiledcondition(condition, user, roles) )
            
        if len(results) == 0:
            return False

        compiled_result = True
        for r in results:
            compiled_result = r and compiled_result

        result = compiled_result == expected 
       
        return result


    def compiledrules( self, rules, user, roles ):
        # 
        # 'rule-ship':   {  'conditions' : { 'memberOf': [  'cn=ship_crew,ou=people,dc=planetexpress,dc=com'] },
        #                   'expected' : True,
        #                   'label': 'ship' },
        #
        # 'rule-addressip': {   'conditions'    : { 'network': [ '1.2.3.4/32'] },
        #                       'expected'      : True,
        #                       'label'         : 'home' } 
        #
        # 'rule-double': {  'conditions' : {   'network': [ '1.2.3.4/32'],
        #                                      'memberOf': [ 'cn=ship_crew,ou=people,dc=planetexpress,dc=com'] },
        #                   'expected' : True,
        #                   'label': 'groupshipandip' },
        #
        # 'rule-notnetwork': {  'conditions' : {    'network': [ '80.0.0.0/8'],
        #                                            'memberOf': [ 'cn=ship_crew,ou=people,dc=planetexpress,dc=com'] },
        #                       'expected' : False,
        #                       'label': 'noinnet' }
        #

        buildcompiledrules = {}
        for name in rules.keys():
            try:
                compiled_result = self.compiledrule( name, rules.get(name), user, roles )
                if compiled_result is True:
                    k = rules.get(name).get('label')
                    if k is not None:
                        buildcompiledrules[ k ] = rules.get('load')
            except Exception as e:
                self.logger.error( 'rules %s compilation failed %s, skipping rule', name, e)
            
        return buildcompiledrules


    
    def login(self, provider, manager=None, **arguments):        
        response = AuthResponse(self)
        try:
            mgr = self.findmanager(provider, manager)
            result = mgr.authenticate(provider, **arguments)
            if not result:
                raise AuthenticationFailureError('No authentication token provided')
            
            claims, auth = result
            if not auth :
                raise AuthenticationFailureError('No authentication provided')
            self.logger.info( 'mgr.authenticate provider=%s token success', provider) 
            
            # uncomment this line only to see password in clear text format
            # logger.debug( 'mgr.getuserinfo arguments=%s', arguments)            
            user = mgr.getuserinfo(provider, auth, **arguments)
            if user is None:
                raise AuthenticationFailureError('User data not found')
            self.logger.info( 'mgr.getuserinfo provider=%s success', provider)
            
            
            # uncomment this line only to see password in clear text format
            # logger.debug( 'mgr.getroles arguments=%s', arguments)            
            roles = mgr.getroles(provider, auth, **arguments)
            if roles is None:
                raise AuthenticationFailureError('User roles not found')
            
            auth = mgr.finalize(provider, auth, **arguments)

            # if the mgr is an explicit mgr then add the claims for next usage 
            # for example domain, username, password are used by desktop cifs driver
            # claims contains raw user credentials 
            # add claims to auth only if credentials are need to get access to external ressources                        
            if mgr.name == 'explicit':
                auth.claims = claims  

            # if the auth has data and rules request
            # then compile data using rules
            # and runs the rules to get associated labels
            auth.data['labels'] = {}
            if auth.get('data') and auth.data.get('rules'):
                auth.data['labels'] = self.compiledrules( auth.data.get('rules'), user, roles )
                self.logger.info( 'compiled rules get labels %s', auth.data['labels'] )

            if not oc.od.acl.ODAcl().isAllowed( auth, mgr.getprovider(provider).acls ):
                raise AuthenticationDenied( 'Access is denied by security policy')
            
            myauthcache = AuthCache( { 'auth': vars(auth), 'user': user, 'roles': roles } ) 
            response.success = True     
            response.mgr = mgr       
            response.reason = 'Authentication successful'                            
            response.result = myauthcache           
            
        except Exception as e:
            if isinstance(e,AuthenticationError):
                response.reason = e.message
                response.code = e.code
            else:
                response.reason = str(e) # default value
                if hasattr( e, 'args'):
                    # try to extract the desc value 
                    if isinstance(e.args, tuple) and len(e.args) > 0:
                        try:
                            response.reason = e.args[0].get('desc',str(e))
                        except:
                            pass
                
                response.code = e.code if hasattr( e, 'code') else 500
                
            response.error = e
            
        return response

    def authenticate(self, provider,  manager=None, **arguments):
        return self.findmanager(provider, manager).authenticate(provider, **arguments)

    def getuserinfo(self, provider, authinfo, manager=None, **arguments):
        return self.findmanager(provider, manager).getuserinfo(provider, authinfo, **arguments)

    def getroles(self, provider, authinfo, manager=None, **arguments):
        return self.findmanager(provider, manager).getroles(provider, authinfo, **arguments)

    def finalize(self, provider, authinfo, manager=None, **arguments):
        return self.findmanager(provider, manager).finalize(provider, authinfo, **arguments)

    def authorize(self, allow_anonymous=False, allow_authentified=True):        
        self.logger.debug('')

        # reset cache data
        if allow_anonymous is True: 
            return

        if not self.provider or not self.providertype:
            self.raise_unauthorized('Invalid token')
        
        is_unauthorized = not allow_authentified
        if is_unauthorized is True:
            self.raise_unauthorized()       

    def logout(self):
        self.clearcookies()

    def raise_unauthorized(self, message='Unauthorized'):
        raise cherrypy.HTTPError(401, message)
    
    def updatecookies(self, jwt_token, expire_in=None):
        """[updatecookies]
            set cookie abcdesktop_token value jwt_token
        Args:
            jwt_token ([jwt]): [jwt token]
            expire_in ([type], optional): [description]. Defaults to None.
        """
        if jwt_token:            
            self.logger.debug( 'setCookie abcdesktop_token len %d', len(jwt_token) )
            oc.lib.setCookie(   name=ODAuthTool.abcdesktop_auth_token_cookie_name, 
                                value=jwt_token, 
                                path='/API', 
                                expire_in=expire_in)

    def clearcookies(self):
        """[clearcookies]
            remore the abcdesktop_token path '/API'
        """
        oc.lib.removeCookie(    ODAuthTool.abcdesktop_auth_token_cookie_name,
                                '/API')             
        
          
@oc.logging.with_logger()
class ODAuthManagerBase(object):
    def __init__(self, name, config):
        self.name = name
        self.providers = OrderedDict()
        self.initproviders(config)

    def initproviders(self, config):
        for name,cfg in config.get('providers',{}).items():
            try:
                if not cfg.get('enabled', True): 
                    continue
                logger.info( 'Adding provider name %s ', name )
                provider = self.createprovider(name, cfg)
                if provider is not None: 
                    self.providers[name] = provider    
            except Exception as e:
                logger.exception(e) 

    def authenticate(self, provider, **arguments):
        return self.getprovider(provider, True).authenticate(**arguments)

    def getuserinfo(self, provider, token, **arguments):
        return self.getprovider(provider, True).getuserinfo(token, **arguments)

    def getroles(self, provider, authinfo, **arguments):
        return self.getprovider(provider, True).getroles(authinfo, **arguments)

    def finalize(self, provider, authinfo, **arguments):
        return self.getprovider(provider, True).finalize(authinfo, **arguments)
    
    def createprovider(self, name, config):
        return ODAuthProviderBase(self, name, config)

    def getprovider(self, name, raise_error=False):
        if not name: 
            if raise_error: 
                raise AuthenticationFailureError('Invalid authentication provider name')
            return None
        
        pdr = self.providers.get(name)
        if not pdr: 
            if raise_error: 
                raise AuthenticationFailureError('Undefined authentication provider: %s' % name)
            return None

        return pdr

    def getclientdata(self):
        return {
            'name': self.name,
            'providers': list(map(lambda p: p.getclientdata(), self.providers.values()))
        }

    
class ODExternalAuthManager(ODAuthManagerBase):
    def __init__(self, name, config):
        super().__init__(name, config)

    def createprovider(self, name, config):
        return ODExternalAuthProvider(self, name, config)


class ODExplicitAuthManager(ODAuthManagerBase):
    def __init__(self, name, config):
        super().__init__(name, config)
        self.show_domains = config.get('show_domains', False)
        self.default_domain = config.get('default_domain', None)

        if self.default_domain not in self.providers:
            self.default_domain = list(self.providers.values())[0].name if len(self.providers) else None

    def createprovider(self, name, config):
        domain = config.get('domain')
        if domain:
            return ODAdAuthProvider(self, name, config)
        else:
            return ODLdapAuthProvider(self, name, config)

    def getclientdata(self):
        data = super().getclientdata()
        data['default_domain'] = self.default_domain
        data['show_domains'] = self.show_domains
        return data

    def authenticate(self, provider, userid=None, password=None, **params):
        if userid and not provider:
            arr = userid.split('\\', 1)
            userid,provider = tuple(arr) if len(arr) > 1 else (None, userid)
            if not provider: 
                provider = self.default_domain

        if not userid or not password or not provider: 
            raise InvalidCredentialsError('Missing credential (userid or password or domain)')

        return self.getprovider(provider, True).authenticate(userid, password)


class ODImplicitAuthManager(ODAuthManagerBase):
    def __init__(self, name, config):
        super().__init__(name, config)

    def createprovider(self, name, config):
        return ODImplicitAuthProvider(self, name, config)


class ODRoleProviderBase(object):
    def getroles(self, authinfo, **params):
        return []

    def isinrole(self, token, role, **params):
        return role.casefold() in (n.casefold() for n in self.getroles(token))


class ODAuthProviderBase(ODRoleProviderBase):
    def __init__(self, manager, name, config):
        self.name = name
        self.manager = manager
        self.type = config.get('type', self.name)
        self.displayname = config.get('displayname',  self.name) 
        self.caption = config.get('caption', self.displayname )
        policies = config.get('policies', {} )
        self.acls  = policies.get('acls')
        self.rules = policies.get('rules')


    def authenticate(self, **params):
        raise NotImplementedError()

    def getuserinfo(self, authinfo, **params):
        raise NotImplementedError()

    def getclientdata(self):
        return { 
            'name': self.name, 
            'caption': self.caption, 
            'displayname': self.displayname
        }

    def finalize(self, token, **params):
        return token


# Implement OAuth 2.0 AuthProvider

@oc.logging.with_logger()
class ODExternalAuthProvider(ODAuthProviderBase):
    def __init__(self, manager, name, config):
        super().__init__(manager, name, config)
        self.displayname = config.get('displayname')
        self.encoding = config.get('encoding', 'utf-8')
        self.client_id = config.get('client_id')
        self.client_secret = config.get('client_secret')
        self.scope = config.get('scope')

        self.basic_auth = config.get('basic_auth', False) is True
        self.userinfo_auth = config.get('userinfo_auth', False) is True
        self.type = config.get('type', 'oauth')
        self.userinfomap = config.get('userinfomap')
       
        self.authorization_base_url = config.get('authorization_base_url')
        self.token_url = config.get('token_url')
        self.redirect_uri_prefix = config.get('redirect_uri_prefix')
        self.redirect_uri_querystring = config.get('redirect_uri_querystring')
        self.redirect_uri = self.redirect_uri_prefix + '?' + self.redirect_uri_querystring
        self.userinfo_url = config.get('userinfo_url')

    def getclientdata(self):
        data = super().getclientdata()
        oauthsession = OAuth2Session( self.client_id, scope=self.scope, redirect_uri=self.redirect_uri)
        authorization_url, state = oauthsession.authorization_url( self.authorization_base_url ) 
        data['dialog_url']  = authorization_url
        data['state']       = state
        return data

    def authenticate(self, code=None, **params):
        oauthsession = OAuth2Session( self.client_id, scope=self.scope, redirect_uri=self.redirect_uri)
        authorization_response = self.redirect_uri_prefix + '?' + cherrypy.request.query_string
        token = oauthsession.fetch_token( self.token_url, client_secret=self.client_secret, authorization_response=authorization_response )
        self.logger.debug( 'provider %s type %s return token %s', self.name,  self.type, str(token) )
        data = (    {}, 
                    AuthInfo( provider=self.name, providertype=self.type, token=oauthsession, protocol='oauth') )
        return data


    def getuserinfo(self, authinfo, **params):

        # retrieve the token object from the previous authinfo 
        oauthsession = authinfo.token 

        # Check if token type is OAuth2Session
        if not isinstance(oauthsession,OAuth2Session) :
            raise ExternalAuthError( message='authinfo is an invalid oauthsession object')

        userinfo = None
        if self.userinfo_auth is True and oauthsession.authorized is True:
            userinfo = oauthsession.get(self.userinfo_url)

        if isinstance(userinfo, requests.models.Response) and userinfo.ok is True :
            jsondata = userinfo.content.decode(userinfo.encoding or self.encoding ) 
            data = json.loads(jsondata)
            userinfo = self.parseuserinfo( data )
        return userinfo
        
  
    def parseuserinfo(self, jsondata):        
        if self.userinfomap:
            user = {}
            all = self.userinfomap.get('*')
            if all=='*':
                user = jsondata
            elif all is not None:
                user[all] = jsondata
            
            for k,v in self.userinfomap.items():
                if k=='*': 
                    continue
                user[k] = pyutils.get_setting(jsondata, v)
        else:
            user = jsondata

        userid = user.get('userid') or jsondata.get('id') or jsondata.get('sub', '')
        userid = str(userid) # make sure always use string 
        name   = user.get('name') or user.get('lastname') or userid
        user['userid'] = oc.auth.namedlib.normalize_name(userid) 
        user['name']   = name
        return user

    def finalize(self, authinfo, **params):   
        # retrieve the token object from the previous authinfo 
        oauthsession = authinfo.token 
        # Check if type is OAuth2Session
        if not isinstance(oauthsession,OAuth2Session) :
            authinfo.token = None
        return authinfo

# ODImplicitAuthProvider is an Anonymous AuthProvider
class ODImplicitAuthProvider(ODAuthProviderBase):
    def __init__(self, manager, name, config):
        super().__init__(manager, name, config)
        self.userid = config.get('userid', self.name)
        self.username = config.get('username', self.name)
        self.userinfo = copy.deepcopy(config.get('userinfo', {}))

    def getuserinfo(self, authinfo, **params):

        userid = authinfo.token

         # Check if token type is dict
        if not isinstance(userid,str) :
            raise ExternalAuthError( message='authinfo is an invalid str object')
    
        user = copy.deepcopy(self.userinfo)
        user['name']   = self.username   # static value always 'Anonymous'
        user['userid'] = userid          # set previously by authenticate str(uuid.uuid4())
        return user

    def authenticate(self, **params):
        userid = str(uuid.uuid4())
        return ({}, AuthInfo( self.name, self.type, userid, data={ 'userid': userid }))

    

LDAP24API = LooseVersion(ldap.__version__) >= LooseVersion('2.4')

@oc.logging.with_logger()
class ODLdapAuthProvider(ODAuthProviderBase,ODRoleProviderBase):

    # Check if we're using the Python "ldap" 2.4 or greater API
    
    LDAP_PAGE_SIZE = 8  # LDAP PAGE QUERY

    class Query(object):
        def __init__(self, basedn, scope=ldap.SCOPE_SUBTREE, filter=None, attrs=None ):
            self.scope = scope
            self.basedn = basedn
            self.filter = filter
            self.attrs = attrs            

    def __init__(self, manager, name, config={}):
        logger.info('')
        super().__init__(manager, name, config)
        self.type = 'ldap'

        logger.debug('LooseVersion:LDAP24API=%s', str(LDAP24API) )

        self.auth_type  = config.get('auth_type', 'bind')
        serviceaccount = config.get('serviceaccount', { 'login':None, 'password':None } )
        if type(serviceaccount) is dict:
            self.userid = serviceaccount.get('login')
            self.password = serviceaccount.get('password')
        
        self.users_ou = config.get('users_ou', config.get('basedn') ) 
        self.servers = config.get('servers', []) 
        self.timeout = config.get('timeout', 20)
        self.secure = config.get('secure', False) is True
        self.useridattr = config.get('useridattr', 'cn')
        self.useruidattr = config.get('useruidattr', 'uid')
        self.domain = config.get('domain')
        self.kerberos_realm = config.get('kerberos_realm')
        self.kerberos_krb5_conf = config.get('krb5_conf')
        self.kerberos_ktutil = config.get('ktutil', '/usr/bin/ktutil') # change to /usr/sbin/ktutil on macOS
        self.kerberos_kinit  = config.get('kinit', '/usr/bin/kinit') # change to /usr/sbin/kinit on macOS
        # auth_protocol is a dict of auth protocol, will be injected inside the container
        self.auth_protocol = config.get('auth_protocol', { 'ntlm': False, 'cntlm': False, 'kerberos': False, 'citrix': False} )
        # if ldif is not set (None) 
        # add ldif user information auth_protocol to inform that this object contains ldif data 
        if self.auth_protocol.get('ldif') is None:
            self.auth_protocol['ldif'] = True

        self.citrix_all_regions  = config.get('citrix_all_regions' )
        self.exec_timeout = config.get('exec_timeout', 10)
        self.kerb_ccname = config.get('kerb_ccname','/tmp/krb5cc_4096')
        self.tls_require_cert = config.get( 'tls_require_cert', False)

        # query users
        self.user_query = self.Query(
            config.get('basedn'), 
            config.get('scope', ldap.SCOPE_SUBTREE),
            config.get('filter', '(&(objectClass=inetOrgPerson)(cn=%s))'), 
            config.get('attrs'))

        # query groups
        self.group_query = self.Query(
            config.get('group_basedn', self.user_query.basedn),
            config.get('group_scope', self.user_query.scope),
            config.get('group_filter', "(&(objectClass=Group)(cn=%s))"),
            config.get('group_attrs'))

    @staticmethod
    def create_controls(pagesize):
        """Create an LDAP control with a page size of "pagesize"."""
        # Initialize the LDAP controls for paging. Note that we pass ''
        # for the cookie because on first iteration, it starts out empty.
        if LDAP24API:
            return SimplePagedResultsControl(True, size=pagesize, cookie='')
        else:
            return SimplePagedResultsControl(ldap.LDAP_CONTROL_PAGE_OID, True, (pagesize, ''))

    @staticmethod 
    def get_pctrls(serverctrls):
        """Lookup an LDAP paged control object from the returned controls."""
        # Look through the returned controls and find the page controls.
        # This will also have our returned cookie which we need to make
        # the next search request.
        if LDAP24API:
            return [c for c in serverctrls
                    if c.controlType == SimplePagedResultsControl.controlType]
        else:
            return [c for c in serverctrls
                    if c.controlType == ldap.LDAP_CONTROL_PAGE_OID]

    @staticmethod
    def set_cookie(lc_object, pctrls, pagesize):
        """Push latest cookie back into the page control."""
        if LDAP24API:
            cookie = pctrls[0].cookie
            lc_object.cookie = cookie
            return cookie
        else:
            est, cookie = pctrls[0].controlValue
            lc_object.controlValue = (pagesize, cookie)
            return cookie

    @staticmethod
    def issafeLdapAuthCommonName(cn):
        ''' return True id cn is safe for LDAP Query '''
        for c in cn:
            # filter permit char
            permitchar = c.isalnum() or c == '-' or c == ' '
            if not permitchar:
                return False
        return True

    def validate(self, userid, password, **params):

        userdn = None

        if self.auth_type not in ['kerberos', 'bind']:
            raise AuthenticationError('auth_type must be kerberos or bind ')

        if self.auth_type == 'kerberos':
            # do kerberos auth 
            if not self.krb5_validate( userid, password ):
               raise AuthenticationError('kerberos auth failed')

            # run ldap query using the service account
            # self.userid and self.password define the service account
            if self.userid and self.password :
                conn = self.getconnection( self.userid, self.password)
                try:
                    userdn = self.getuserdn(conn, userid)
                finally:            
                    conn.unbind()

        # do bind ldap auth
        if self.auth_type == 'bind':
            # validate can raise exception 
            self.bind_validate(userid, password)

            conn = self.getconnection(userid, password)
            try:
                userdn = self.getuserdn(conn, userid)
            finally:            
                conn.unbind()
    
        return userdn

    def authenticate(self, userid, password, **params):

        # validate can raise exception 
        # like invalid credentials
        userdn = self.validate(userid, password)   

        data = {    'userid': userid, 
                    'dn': userdn,
                    'environment': self.createauthenv(userid, password),
                    'rules':  self.rules }
        
        return (    {   'userid': userid, 
                        'password': password }, 
                        AuthInfo(self.name, self.type, userid, data=data, protocol=self.auth_protocol) )

    def krb5_validate(self, userid, password):
        if type(userid) is not str or len(userid) < 1 :
            raise AuthenticationError('user can not be an empty string')

        if len(userid) > 256 :
            raise AuthenticationError('user length must be less than 256 characters')

        if type(password) is not str or len(password) < 1 :
            raise AuthenticationError('password can not be an empty string')

        # kerberos password length Limit.
        # Maximum number of characters supported for plain-text krb5-password config is 256
        if len(password) > 256 :
            raise AuthenticationError('password length must be less than 256 characters')

        if type(self.kerberos_krb5_conf) is not str:
            raise AuthenticationError('invalid krb5 configuration file')

        cmd = [ self.kerberos_kinit, userid]
        my_env = os.environ.copy()
        my_env['KRB5_CONFIG'] = self.kerberos_krb5_conf
        process = subprocess.run(cmd, input=password.encode(),  env=my_env )
        success = process.returncode
        return not bool(success)
        

    def bind_validate(self, userid, password):
        ''' validate userid and password, using bind to ldap server '''
        ''' validate can raise execptions '''
        ''' for example if all ldap servers are down or ''' 
        ''' if credentials are invalid ''' 
        # uncomment this line may dump password in clear text 
        # logger.debug(locals())


        # LDAP by itself doesn't place any restriction on the username
        # especially as LDAP doesn't really specify which attribute qualifies as the username.
        # The DN is similarly unencumbered.
        # set max value to 256
        if type(userid) is not str or len(userid) < 1 :
            raise AuthenticationError('user can not be an empty string')
        if len(userid) > 256 :
            raise AuthenticationError('user length must be less than 256 characters')

        if type(password) is not str or len(password) < 1 :
            raise AuthenticationError('password can not be an empty string')

        # LDAP BIND password length Limit.
        # Maximum number of characters supported for plain-text bind-password config is 63
        if len(password) > 64 :
            raise AuthenticationError('password length must be less than 64 characters')

        conn = self.getconnection(userid, password)
        conn.unbind()
        return True
   
    def getuserinfo(self, authinfo, **params):        
        # uncomment this line may dump password in clear text 
        # logger.debug(locals())
        token = authinfo.token 
        q = self.user_query
        userinfo = self.search_one(q.basedn, q.scope, ldap.filter.filter_format(q.filter, [token]), q.attrs, **params)
        if userinfo:
            # Add always userid entry, make sure this entry exists
            userinfo['userid'] = userinfo.get(self.useruidattr)
            # Add always name entry
            userinfo['name'] = userinfo.get(self.useridattr)
        return userinfo

    def isinrole(self, token, role, **params):
        ldap_bind_userid     = params.get( 'userid', self.userid )
        ldap_bind_password   = params.get( 'password', self.password )    
        conn = self.getconnection(ldap_bind_userid, ldap_bind_password)
        try:
            groupdn = self.getgroupdn(conn, role)
            if not groupdn: 
                return False
            filter = ldap.filter.filter_format('(&'+self.user_query.filter+'(memberOf=%s))', [token,groupdn])
            return self.search(conn, self.user_query.basedn, self.user_query.scope, filter, ['cn'], True) is not None
        finally:
            if ldap_bind_userid: 
                conn.unbind()

    def getroles(self, authinfo, **params):    
        token = authinfo.token            
        q = self.user_query
        result = self.search_one(q.basedn, q.scope, ldap.filter.filter_format(q.filter, [token]), ['memberOf'], **params)
        # return [dn.split(',',2)[0].split('=',2)[1] for dn in result['memberOf']] if result else []
        memberOf = result.get('memberOf', [] )
        return memberOf

    def getuserdnldapconnection(self, userid):
        # rewrite the userid with full dn
        # format cn=Hubert J. Farnsworth,ou=people,dc=planetexpress,dc=com
        escape_userid = ldap.filter.escape_filter_chars(userid)
        if len(escape_userid) != len( userid ):
            self.logger.debug( 'WARNING ldap.filter.escape_filter_chars activated' )
            self.logger.debug( 'value=%s escaped by ldap.filter.escape_filter_chars as value=%s', userid, escape_userid )
        return self.useridattr + '=' + escape_userid + ',' + self.users_ou

    def getconnection(self, userid, password):
        servers = self.servers.copy()
        for i in range(len(self.servers)):
            try:                
                server = self.servers[i] 
                logger.info( 'ldap connecting to %s', server)
                time_start = time.time()
                conn = self.initconnection(server)
                if userid:
                    userdn = self.getuserdnldapconnection(userid)
                    conn.simple_bind_s(userdn, password)
                    time_done = time.time()
                    elapsed = time_done - time_start
                    logger.info( 'ldap connected to %s in %d s', server, int(elapsed))
                    return conn
            # Only choose another LDAP server if SERVER_DOWN, TIMEOUT or TIMELIMIT_EXCEED
            except (ldap.SERVER_DOWN, ldap.TIMEOUT, ldap.TIMELIMIT_EXCEEDED) as e:
                servers.append(servers.pop(i))
                logger.exception(e)
            # else do not except the execption now
            # the exception is excepted by caller 
            # #  except Exception as e:
            # #      logger.exception('')
            # #      raise e
            finally:
                self.servers = servers

        raise AuthenticationError('Can not contact LDAP servers, all servers are unavailable')

    def initconnection(self, server):
        protocol = 'ldaps' if self.secure else 'ldap'
        ldap_url = protocol + '://' + server        
        logger.info( 'ldap.initialize to %s', ldap_url)
       
        if self.tls_require_cert is False:
            # TLS: hostname does not match CN peer cetificate
            # if we use a VIP with bad CN for example
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)

        conn = ldap.initialize(ldap_url)        
        conn.protocol_version = 3
        conn.set_option(ldap.OPT_REFERRALS, 0)
        conn.set_option(ldap.OPT_NETWORK_TIMEOUT, self.timeout)
        conn.set_option(ldap.OPT_TIMEOUT, self.timeout)  
        return conn

    def search_all(self, basedn, scope, filter=None, attrs=None, **params):
        ldap_bind_userid     = params.get( 'userid', self.userid )
        ldap_bind_password   = params.get( 'password', self.password )        
        conn = self.getconnection(ldap_bind_userid, ldap_bind_password)
        try:
            return self.search(conn, basedn, scope, filter, attrs, False)
        finally:  
            logger.debug( 'search_all conn.unbind()')          
            conn.unbind()

    def search_one(self, basedn, scope, filter=None, attrs=None, **params):                
        ldap_bind_userid     = params.get( 'userid', self.userid )
        ldap_bind_password   = params.get( 'password', self.password )        
        conn = self.getconnection(ldap_bind_userid, ldap_bind_password)
        try:
            return self.search(conn, basedn, scope, filter, attrs, True)
        finally:
            if ldap_bind_userid: 
                conn.unbind()

    def search(self, conn, basedn, scope, filter=None, attrs=None, one=False):
        logger.debug(locals())
        withdn = attrs is not None and 'dn' in (a.lower() for a in attrs)
        entries = []
        time_start = time.time()
        results = conn.search_s(basedn, scope, filter, attrs)
        for dn, entry in results: 
            if not dn: 
                continue
            for k,v in entry.items(): 
                entry[k] = self.decodeValue(k,v)
            if withdn: 
                entry['dn'] = dn
            if one: 
                return entry
            entries.append(entry)
        time_done = time.time()
        elapsed = time_done - time_start
        self.logger.info( 'ldap search_s %s %s take %d ', basedn, str(filter), int(elapsed) )
        return entries if not one else None 

    def getuserdn(self, conn, id):
        return self.getdn(conn, self.user_query, id)

    def getgroupdn(self, conn, id):
        return self.getdn(conn, self.group_query, id)

    def getdn(self, conn, query, id):
        result = self.search(conn, query.basedn, query.scope, ldap.filter.filter_format(query.filter, [id]), ['distinguishedName'], True)
        return result['distinguishedName'] if result else None

    def decodeValue(self, name, value):
        if not isinstance(value, list): 
            return value

        items = [] 
        for item in value:
            if type(item) is bytes: # try to translate bytes to str using decode
                try:
                    item = item.decode('utf-8')
                except Exception as e:
                    # raw binary data
                    # Could be an raw binary JPEG data
                    logger.warning('Attribute %s not decoded as utf-8, use raw data type: %s exception:%s', name, type(item), e)
            items.append(item)

        return items[0] if len(items) == 1 else items

    def createauthenv(self, userid, password):
        default_authenv = {}

        try: 
            if self.auth_protocol.get('kerberos') is True:
                default_authenv.update( { 'kerberos' : {    'PRINCIPAL'   : userid,
                                                            'REALM' : self.kerberos_realm,
                                                            **self.generateKerberosKeytab( userid, password ) }
                } )
            
            if self.auth_protocol.get('ntlm') is True :
                default_authenv.update( { 'ntlm' : {    'NTLM_USER'   : userid,
                                                        'NTLM_DOMAIN' : self.domain,
                                                        **self.generateNTLMhash(password) } 
                } )

            if self.auth_protocol.get('cntlm') is True :
                default_authenv.update( { 'cntlm' : {   'NTLM_USER'   : userid,
                                                        'NTLM_DOMAIN' : self.domain,
                                                        **self.generateCNTLMhash( userid, password, self.domain) } 
                } )

            if self.auth_protocol.get('citrix') is True :
                default_authenv.update( { 'citrix' : {  **self.generateCitrixAllRegionsini ( userid, password, self.domain) } 
                } )

        except Exception as e:
            self.logger.error('Failed: %s', e)

        return default_authenv
    
    def _pagedAsyncSearch( self, conn, basedn, filter, attrlist, scope=ldap.SCOPE_SUBTREE, sizelimit=0):
        logger.debug('_pagedAsyncSearch %s %s %s', basedn, filter, attrlist)

        if conn is None:
            raise RuntimeError('conn is not established')   

        # Create the page control to work from
        lc = self.create_controls(self.LDAP_PAGE_SIZE)
        objArray = {}
        while True:
            try:
                msgid = conn.search_ext( basedn, scope, filter, attrlist, serverctrls=[lc])
            except ldap.LDAPError as e:
                logger.error( '_pagedAsyncSearch:Could not pull LDAP results: %s', e)
                return objArray
            except ldap.TIMEOUT as e:
                logger.error('_pagedAsyncSearch: LDAP TIMEOUT %s', e)
                return objArray

            # Pull the results from the search request
            try:
                rtype, rdata, rmsgid, serverctrls = conn.result3(msgid)
            except ldap.LDAPError as e:
                logger.error( '_pagedAsyncSearch: Could not pull LDAP results: %s', e)
                return objArray

            # Each "rdata" is a tuple of the form (dn, attrs), where dn is
            # a string containing the DN (distinguished name) of the entry,
            # and attrs is a dictionary containing the attributes associated
            # with the entry. The keys of attrs are strings, and the associated
            # values are lists of strings.
            # objArray[ dn ]=
            for dn, attrs in rdata:
                objArray[dn] = attrs

            # Get cookie for next request
            pctrls = self.get_pctrls(serverctrls)
            if not pctrls:
                logger.warning('_pagedAsyncSearch Warning: Server ignores RFC 2696 control.')
                break

            # Ok, we did find the page control, yank the cookie from it and
            # insert it into the control for our next search. If however there
            # is no cookie, we are done!
            cookie = self.set_cookie(lc, pctrls, self.LDAP_PAGE_SIZE)
            if not cookie:
                break

        return objArray


    def generateKerberosKeytab(self, principal, password ):
        self.logger.info('')
        keytab = {}
        #
        # source https://support.microsoft.com/en-us/help/327825/problems-with-kerberos-authentication-when-a-user-belongs-to-many-grou
        # 
        # The token has a fixed maximum size (MaxTokenSize). Transport protocols such as remote procedure call (RPC) and HTTP rely on the MaxTokenSize value when they allocate buffers for authentication operations. MaxTokenSize has the following default value, depending on the version of Windows that builds the token:
        # 
        # Windows Server 2008 R2 and earlier versions, and Windows 7 and earlier versions: 12,000 bytes
        # Windows Server 2012 and later versions, and Windows 8 and later versions: 48000 bytes
        # Generally, if the user belongs to more than 120 universal groups, the default MaxTokenSize value does not create a large enough buffer to hold the information. The user cannot authenticate and may receive an "out of memory" message. Additionally, Windows may not be able to apply Group Policy settings for the user.
        keytab = {}  # default return value
 
        def removekoutputfile( koutputfilename ):
            try :
                os.unlink( koutputfilename )
            except Exception as e:
                self.logger.error('failed to delete tmp file: %s %s', koutputfilename, e)

        ''' ktutil
			addent -password -p username@MYDOMAIN.COM -k 1 -e RC4-HMAC
			- enter password for username -
			wkt username.keytab
			q
		'''
        if not all([principal, password ]):
            self.logger.error('makekeytab invalid parameters ')
            return None

        if type(self.kerberos_krb5_conf) is not str:
            self.logger.error('invalid krb5.conf file option')
            return None

        if type(self.kerberos_ktutil) is not str:
            self.logger.error('invalid ktutil file option')
            return None

        koutputfilename = '/tmp/' + oc.auth.namedlib.normalize_name( principal ) + '.keytab'

        userPrincipalName = principal + '@' + self.kerberos_realm
        inputs = [  'addent -password -p ' + userPrincipalName + ' -k 1 -e RC4-HMAC',
                    password,
                    'wkt ' + koutputfilename,
                    'q']

        returncode = None
        try:
            self.logger.info('makekeytab Popen ' + str(self.kerberos_ktutil))
            # You can override the default location by setting the environment variable KRB5_CONFIG.
            my_env = os.environ.copy()
            my_env['KRB5_CONFIG'] = self.kerberos_krb5_conf
            proc = subprocess.Popen(self.kerberos_ktutil, stdin=subprocess.PIPE, env=my_env )
            for p in inputs:
                # Only for troubleshooting password show in clear text
                # self.logger.info('ocad:makekeytab send args to stdin ' +
                # str(p) )
                ewl = p.encode()
                proc.stdin.write(ewl)
                proc.stdin.write(b'\n')
            proc.stdin.close()

            returncode = proc.wait( self.exec_timeout )

        except Exception as e:
            self.logger.error( 'command %s failed %s', self.kerberos_ktutil, e)
            removekoutputfile( koutputfilename )
            return keytab

       
        self.logger.info(str(self.kerberos_ktutil) + ' return code: ' + str(returncode))
        if returncode == 0:
            try:
                koutputfile = open( koutputfilename, mode='rb' )
                keytabdata = koutputfile.read() 
                koutputfile.close()

                kbr5conf_file =  open( self.kerberos_krb5_conf )
                krb5conf = kbr5conf_file.read() 
                kbr5conf_file.close()
                keytab = { 'keytab' : keytabdata, 'krb5.conf': krb5conf }  
            except Exception as e:
                self.logger.error('read keytab file %s error: %s', koutputfilename, str(e))
        else:
                self.logger.info('failed to run %s return code %s', self.kerberos_ktutil, str(returncode))
    
        # clean tmp filename
        removekoutputfile( koutputfilename )

        return keytab


    def generateNTLMhash(self, password):
        self.logger.debug('Generatin NTLM hashes')
        '''
            const char* const args[] = {
                "ntlm_auth",
                        "--helper-protocol", "ntlmssp-client-1",
                        "--use-cached-creds",
                        "--username", username,
        '''
        hashes = {}
        if  type(password) is not str :
            self.logger.error('Invalid parameters')
            return hashes
        try:
            # Linux: Linux
            # Mac: Darwin
            # Windows: Windows
            #  export NTLM_PASSWORD=letmein 
            # ./ntlm_auth.Linux 
            #   NTLM_KEY=cymZ2Dmnb2SIZNcBLcftpxpXeN/R
            #   NTLM_LM_HASH=Ln/q/IOboZwit2M0mNPpSRpXeN/R
            #   NTLM_NT_HASH=zedCmtWbMxseNoIypiOomxpXeN/R

            command = 'oc/auth/ntlm/ntlm_auth.' + platform.system()
            ret,out = pyutils.execproc( command=command, 
                                        environment= {'NTLM_PASSWORD': password}, 
                                        timeout=self.exec_timeout)
            if ret != 0:
                raise RuntimeError('Command ntlm_auth returned error code: %s' % ret)
            self.logger.info( 'Running %s', command )
            for line in out:
                # parse string format
                # NTLM_KEY=v8+pDkRc41i8weIufYRhVBPSv=dqM
                self.logger.info( 'Parsing %s', line )
                try:
                    nv = line.index('=') # read the first entry of 
                    hashes[ line[ 0 : nv ] ] = line[ nv+1 : ]
                except Exception as e:
                    # Index if found otherwise raises an exception if str is not found
                    # by pass line 
                    self.logger.error('Failed: %s', e)
            self.logger.debug('NTLM hashes: %s', hashes)
        except Exception as e:
            self.logger.error('Failed: %s', e)

        return hashes

    def generateCitrixAllRegionsini(self, user, password, domain ):
        if type(self.citrix_all_regions) is str:
            # read https://www.citrix.com/content/dam/citrix/en_us/documents/downloads/citrix-receiver/linux-oem-guide-13-1.pdf
            self.logger.debug('Generating file All_Regions.ini for citrix-receiver')
            data = chevron.render( self.citrix_all_regions, {'user': user, 'password': password, 'domain': domain })
            hashes = { 'All_Regions.ini' : data }
            return hashes

    def generateCNTLMhash(self, user, password, domain ):
        self.logger.debug('Generating CNTLM hashes')
        hashes = {}

        cntlm_command = '/usr/sbin/cntlm'

        if  type(user) is not str or \
            type(password) is not str or \
            type(domain) is not str :
            self.logger.error('CNTLM missing parameters, CNTLM hashes has been disabled')
            return hashes

        if not os.path.isfile(cntlm_command):
            self.logger.error('command %s not found CNTLM hashes has been disabled', cntlm_command )
            return hashes

        try:
            password = password + '\n'
            ret,out = pyutils.execproc( [ cntlm_command, '-H', '-u', user, '-d', domain ], input=password, timeout=self.exec_timeout)
            if ret!=0:
                raise RuntimeError('Command cntml returned error code: %s' % ret)

            # Output is :
            # Password: 
            # PassLM          24996FE06B4235F061EEE95D1308178F
            # PassNT          11C803BC30FD15CCA7D19566C0F2940C
            # PassNTLMv2      A4236B8CB1F37A826FAD328283258FF5    # Only for user 'testuser', domain 'corp-uk'
            for line in out:
                nv = line.split(' ')
                # remove empty entries
                datalist = [x for x in nv if x] 
                if len(datalist)<2: 
                    continue # Bad entry
                key = datalist[0]
                value = datalist[1]
                # Do not add empty key or value 
                if len(key)>0 and len(value)>0:
                    key = 'CNTLM_' + key.upper()  
                    hashes[key] = value
            self.logger.debug('CNTLM hashes: %s', hashes)
        except Exception as e:
            self.logger.error('Failed: %s', e)

        return hashes


 



@oc.logging.with_logger()
class ODAdAuthProvider(ODLdapAuthProvider):
    INVALID_CHARS = ['"', '/', '[', ']', ':', ';', '|', '=', ',', '+', '*', '?', '<', '>'] #'\\'
    DEFAULT_ATTRS = ['distinguishedName', 'dn', 'displayName', 'sAMAccountName', 'name', 'cn', 'homeDrive', 'homeDirectory', 'profilePath', 'memberOf', 'proxyAddresses', 'userPrincipalName', 'primaryGroupID']

    def __init__(self, manager, name, config):
        super().__init__(manager, name, config)
        self.type = 'activedirectory'
        self.useridattr = config.get('useridattr', 'sAMAccountName')
        self.domain_fqdn = config.get('domain_fqdn')
        self.domain = config.get('domain', self.domain_fqdn.split('.',1)[0] if self.domain_fqdn else self.name)
        self.query_dcs = config.get('query_dcs', False) is True
        self.dcs_list_maxage = config.get('dcs_list_maxage', 3600)
        self.dcs_list_lastupdated = 0
        self.refreshdcs_lock = None
        self.servers = config.get('servers') or []
        self.user_query.filter = config.get('filter', '(&(objectClass=user)(sAMAccountName=%s))')
        self.user_query.attrs = config.get('attrs', ODAdAuthProvider.DEFAULT_ATTRS)
        self.group_query.filter = config.get('group_filter', "(&(objectClass=group)(cn=%s))")
        self.recursive_search = config.get('recursive_search', False) is True


        if self.query_dcs:
            if not self.domain_fqdn: 
                raise ValueError("Property 'domain_fqdn' not set, cannot query domain controllers list")
            self.refreshdcs_lock = Lock()
            self.refreshdcs()

        elif len(self.servers)==0:
            if not self.domain_fqdn: 
                raise ValueError("Properties 'domain_fqdn' and 'servers' not set , cannot define domain FQD as fallback (VIP) address")
            self.servers = [ self.domain_fqdn ]
        if len(self.servers)==0:
            raise RuntimeError('Empty list of domain controllers')

        # query sites
        self.printer_query = self.Query(
            basedn=config.get('printer_printerdn', 'OU=Applications,' + config.get('basedn') ),
            scope=config.get('printer_scope', ldap.SCOPE_SUBTREE),
            filter=config.get('printer_filter', '(objectClass=printQueue)'),
            attrs=config.get('printer_attrs',
                                [ 'cn', 'uNCName', 'location', 'driverName', 'driverVersion', 'name', 
                                  'portName', 'printColor', 'printerName', 'printLanguage', 'printSharename',
                                  'serverName', 'shortServerName', 'url', 'printMediaReady'
                                  'printBinNames',              # multiple values
                                  'printMediaSupported',        # multiple values
                                  'printOrientationsSupported'  # multiple values
                                ]
                            ) )
            
            
        # query printer
        self.site_query = self.Query(
            basedn=config.get('site_subnetdn', 'CN=Subnets,CN=Sites,CN=Configuration,' + config.get('basedn') ),
            scope=config.get('site_scope', ldap.SCOPE_SUBTREE),
            filter=config.get('site_filter', '(objectClass=subnet)'),
            attrs=config.get('site_attrs',['cn', 'siteObject', 'location']) )

    def getuserdnldapconnection(self, userid):
        return userid
        
    def getadlogin( self, userid ):
        adlogin = None
        if self.domain:
            adlogin = self.domain + '\\' + userid
        else:
            adlogin = userid
        return adlogin

    def authenticate(self, userid, password, **params):
        if not self.issafeAdAuthusername(userid) or not self.issafeAdAuthpassword(password):
            raise InvalidCredentialsError('Unsafe credentials')
       
        # authenticate can raise exception 
        userdn = super().validate(userid, password)
    
        data = { 
            'userid': userid, 
            'domain': self.domain, 
            'ad_domain': self.domain,
            'dn': userdn,
            'environment': self.createauthenv(userid, password),
            'rules':  self.rules
        }

        return (
            { 'userid': userid, 'password': password, 'domain': self.domain },
            AuthInfo(self.name, self.type, userid, data=data, protocol=self.auth_protocol)
        )

    def getuserinfo(self, authinfo, **params):
        token = authinfo.token 
        userinfo = super().getuserinfo(token, **params)
    
        if userinfo:
            # Add always userid entry
            # overwrite value from standard LDAP server
            # useridattr should be 'sAMAccountName'
            userinfo['userid'] = userinfo.get(self.useridattr)
            # homeDirectory
            path = userinfo.get('homeDirectory') 
            if path: 
                userinfo['homeDirectory'] = path.replace('\\','/')
            # profilePath
            profilePath = userinfo.get('profilePath')
            if profilePath: 
                userinfo['profilePath'] = path.replace('\\','/')
        return userinfo

    
    def isinrole(self, token, role, **params):
        if not self.recursive_search:
            return super().isinrole(token, role, **params)

        ldap_bind_userid     = params.get( 'userid', self.userid )
        ldap_bind_password   = params.get( 'password',self.password )                
        conn = self.getconnection(ldap_bind_userid, ldap_bind_password)
        try:
            groupdn = self.getgroupdn(conn, role)
            if not groupdn: 
                return False
            filter = ldap.filter.filter_format('(&'+self.user_query.filter+'(memberOf:1.2.840.113556.1.4.1941:=%s))', [token,groupdn])
            return self.search(conn, self.user_query.basedn, self.user_query.scope, filter, ['cn'], True) is not None
        finally:
            if self.userid: 
                conn.unbind()

    def getroles(self, authinfo, **params):
        token = authinfo.token 
        if not self.recursive_search:
            return super().getroles(authinfo, **params)

        ldap_bind_userid     = params.get( 'userid', self.userid )
        ldap_bind_password   = params.get( 'password',self.password )        
        
        conn = self.getconnection(ldap_bind_userid, ldap_bind_password)
        try:
            userdn = self.getuserdn(conn, token)
            if not userdn: 
                return []
            return [entry['cn'] for entry in self.search(conn, self.group_query.basedn, ldap.SCOPE_SUBTREE, '(member:1.2.840.113556.1.4.1941:=%s)' % userdn, ['cn'])]
        finally:
            if self.userid: 
                conn.unbind()

    
    def issafeAdAuthusername(self, username):
        ''' protect against injection       '''
        ''' return True if username is safe '''
        if not isinstance(username, str): 
            return False
        # username len must be more than 0 and less than 20 chars lens
        if len(username) < 1 or len(username) > 20:
            return False    
        for c in username:
            if c in ODAdAuthProvider.INVALID_CHARS: 
                return False
            if ord(c) < 32: 
                return False
        return True

    def issafeAdAuthpassword(self, password):
        ''' protect against injection       '''
        ''' return True if password is safe '''
        if not isinstance(password, str): 
            return False
        # password len must be more than 0 and less than 255 chars lens
        if len(password) < 1 or len(password) > 255:
            return False
        for c in password:
            if ord(c) < 32: 
                return False
        return True

    def refreshdcs(self):
        if not self.refreshdcs_lock.acquire(False): 
            return
        try:
            ldap_tcp_domain = '_ldap._tcp.' + self.domain_fqdn            
            self.logger.info("Refreshing domain controllers list - %s", ldap_tcp_domain)
            self.servers = oc.od.resolvdns.ODResolvDNS.resolv( fqdn_name=ldap_tcp_domain, query_type='SRV' )
            self.dcs_list_lastupdated = time.time()
            self.logger.info("Domain controllers list: %s", str(self.servers) )            
        finally:
            self.refreshdcs_lock.release()

    def isdcslistexpired(self):
        bReturn  =  self.query_dcs and                      \
                    self.dcs_list_maxage and                \
                    not self.refreshdcs_lock.locked() and   \
                    (time.time() - self.dcs_list_lastupdated > self.dcs_list_maxage)
        if bReturn is True:
           logger.debug( 'dcslist has exprired' )
        return bReturn

    def getconnection(self, userid, password):
        if self.isdcslistexpired():
            Thread(target=self.refreshdcs).start() # Start async refresh of DCs list

        adlogin = self.getadlogin(userid)
        return super().getconnection(adlogin, password)

 

    def listprinter( self, filter, **params):
        logger.info('')
        printerlist = []

        userid     = params.get( 'userid', self.userid )
        password   = params.get( 'password',self.password )                
        
        if type(filter) is str:
           filter = '(&' + self.printer_query.filter + filter + ')'
        else:
           filter = self.printer_query.filter
        logger.debug('filter %s', filter)
        try:
            # logger.debug('getconnection')
            conn = self.getconnection( userid, password )
            result = self._pagedAsyncSearch(conn,self.printer_query.basedn, filter, self.printer_query.attrs)
            # logger.debug('result %s', result)
            len_printers = len(result)
            logger.info('query result count:%d %s %s ', len_printers, self.printer_query.basedn, filter )

            for dn in result:
                attrs = result.get(dn)
                # attrs must be a dict
                if type( attrs ) is not dict: 
                    logger.error( 'attrs must be a dict, return data from ldap attrs %s', str(type( attrs )))
                    continue
                myobject = {}             
                for a in self.printer_query.attrs:
                    myobject[a] = self.decodeValue( a, attrs.get(a) )                
                printerlist.append(myobject)
            
        except Exception as e:
            logger.error( e )
        finally:
            conn.unbind()

        return printerlist


    
    def listsite(self, **params):       
        logger.info('')

        dictsite = {}
        len_dictsite = 0
        userid     = params.get( 'userid', self.userid )
        password   = params.get( 'password',self.password )                
        
        if userid is None or password is None:
            logger.info( 'service account not set in config file, listsite return empty site')
            return dictsite

        try:
            logger.debug('getconnection to ldap')
            conn = self.getconnection( userid, password )

            logger.debug('_pagedAsyncSearch %s %s %s ', self.site_query.basedn, self.site_query.filter, self.site_query.attrs)            
            result = self._pagedAsyncSearch(conn, self.site_query.basedn, self.site_query.filter, self.site_query.attrs )            
            # logger.debug('_pagedAsyncSearch return len=%d', len( result ))
            for dn in result:
                attrs = result[dn]

                if attrs is None:
                    logger.info( 'ldap dn=%s has no attrs %s, skipping', str(dn), self.site_query.attrs  )
                    continue

                if type( attrs ) is not dict: 
                    logger.error( 'dn=%s attrs must be a dict, return data from ldap attrs %s', str(dn), str( type( attrs )))
                    continue
                
                entry = {}                
                # translate the 'cn' as 'subnet'     
                entry['subnet'] = self.decodeValue( 'cn', attrs.get('cn') )
                entry['siteObject'] = self.decodeValue( 'siteObject', attrs.get('siteObject') )
                entry['location'] = self.decodeValue( 'location', attrs.get('location') )
                
                if all([ entry.get('subnet'), entry.get('siteObject'), entry.get('location') ]):                       
                    dictsite[ entry.get('subnet') ] = entry
                
            len_dictsite = len( dictsite )
            logger.info('query result count:%d %s %s ', len_dictsite, self.site_query.basedn, self.site_query.filter)

            conn.unbind()

        except Exception as e:
            logger.error( 'LDAP query siteObject error: %s', e )     
        
        if len_dictsite == 0:
           logger.warning('ActiveDirectory has no siteObject defined')
            
        return dictsite