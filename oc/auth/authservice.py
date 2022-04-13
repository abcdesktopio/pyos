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
import cherrypy
import os
import subprocess
import uuid
import time
import mergedeep
import copy
import requests
import json
import crypt


from ldap import filter as ldap_filter
import ldap3
# from ldap3 import Server, Tls, ReverseDnsSetting, SYNC, ALL
# from ldap3.core.exceptions import *


# kerberos import
import gssapi
import base64
import platform
import chevron  # for citrix All_Regions.ini

# OAuth lib
from requests_oauthlib import OAuth2Session

from threading import Lock
from collections import OrderedDict


from oc.cherrypy import getclientipaddr
from netaddr import IPNetwork, IPAddress


import oc.logging
import oc.pyutils as pyutils
import oc.od.resolvdns
import jwt
import oc.auth.jwt
import oc.od.acl
import oc.lib


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

    def merge(self, newroles ):
        if not isinstance( newroles, AuthRoles):
              raise ValueError('merge error invalid roles AuthRoles object type %s', str( type(newroles) ) )
        z = newroles.copy()
        mergedeep.merge( newroles, self, strategy=mergedeep.Strategy.ADDITIVE) 
        return newroles

# define AuthUser      
class AuthUser(dict):
    def __init__(self,entries):
        if type(entries) is dict:
            super().__init__(entries)

    def __getattr__(self, name):
        return self.get(name)

    def __getitem__(self, key):
        return getattr(self, key, None)
    
    def merge(self, newuser ):
        if not isinstance( newuser, AuthUser):
              raise ValueError('merge error invalid user AuthUser object type %s', str( type(newuser) ) )
        mergedeep.merge(newuser, self, strategy=mergedeep.Strategy.ADDITIVE) 
        return newuser

#
# define AuthInfo
class AuthInfo(object):
    def __init__(self, provider=None, providertype=None, token=None, type='Bearer', expires_in=None, protocol=None, data={}, claims={}, conn=None):
        """[summary]

        Args:
            provider ([str], optional): [name of the provider]. Defaults to None.
            providertype ([str], optional): [description]. Defaults to None.
            token ([object], optional): [data to keep between auth]. Defaults to None.
            type (str, optional): [authinfo type]. Defaults to 'Bearer'.
            expires_in ([int], optional): [expire in seconds]. Defaults to None.
            protocol ([str], optional): [description]. Defaults to None.
            data (dict, optional): [description]. Defaults to {}.
            claims (dict, optional): [description]. Defaults to {}.
            conn ([object], optional): [connection object]. Defaults to None.
        """
        self.provider = provider
        self.providertype = providertype
        self.protocol = protocol
        self.token = token
        self.type = type
        self.expires_in = expires_in
        self.data = data
        if not self.data.get('labels'):
            self.data['labels'] = {} # make sure labels always exist as entry dict 
        self.claims = claims
        self.conn = conn

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
    
    def merge( self, newauthinfo ):
        # merge only data object
        if not isinstance( newauthinfo, AuthInfo):
              raise ValueError('merge error invalid AuthInfo object type %s', str(type(newauthinfo)) )
        mergedeep.merge(newauthinfo.data, self.data, strategy=mergedeep.Strategy.ADDITIVE)
        self.data = newauthinfo.data
        return self 

    
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
        """[reset]
            Clear all previous cached data
            set internal cached value to AuthCache.NotSet
        """
        self._user  = AuthCache.NotSet
        self._roles = AuthCache.NotSet        
        self._auth  = AuthInfo()

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
        """[setauth]
            set auth data from a AuthInfo data
            read datas from an AuthInfo and set
            [ 'provider', 'providertype', 'token', 'type', 'expires_in', 'protocol', 'data', 'claims') ]
            it to _auth  AuthCache Object

        Args:
            valuedict ([AuthInfo]): [AuthInfo object]
        """
        self._auth = AuthInfo(  provider=valuedict.get('provider'),
                                providertype=valuedict.get('providertype'), 
                                token=valuedict.get('token'), 
                                type=valuedict.get('type'), 
                                expires_in=valuedict.get('expires_in'), 
                                protocol=valuedict.get('protocol'), 
                                data=valuedict.get('data'), 
                                claims=valuedict.get('claims') )
    
    def merge( self, new_authcache ):
        # read user and roles from another authinfo
        # merge data from new_authcache
        self._user  = self.user.merge(new_authcache._user)
        self._roles = self.roles.merge(new_authcache._roles)
        self._auth  = self.auth.merge(new_authcache._auth)




@oc.logging.with_logger()
class ODAuthTool(cherrypy.Tool):

    # define meta manager and provider name
    manager_metaexplicit_name   = 'metaexplicit'
    provider_metadirectory_name = 'metadirectory'
    # define the list of manager type
    manager_name_list = [ 'external', 'metaexplicit', 'explicit', 'implicit' ]

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

    """   @staticmethod
    def is_kerberos_request():
        # Attempts to authenticate the user if a token was provided

        negotiate = cherrypy.request.headers.get('Authorization')

        if isinstance(negotiate, str) and negotiate.startswith('Negotiate '):
            in_token = base64.b64decode(negotiate[10:])

            creds = None
            ctx = gssapi.SecurityContext(creds=creds, usage='accept')

            out_token = ctx.step(in_token)

            if ctx.complete:
                username = str(ctx.initiator_name)
                logger.debug( 'Negotiate auth -> ' + username )
                return username, out_token

        return None, None 
    """

    def parse_auth_request(self):
        """[parse_auth_request]
            parse a http request
            check if the http request contains the authorization header 'ABCAuthorization'
            add decode jwt data
            return empty AuthCache in case of jwt.exceptions.DecodeError 
            can raise Exception
        Returns:
            [AuthCache]: [return an authcahe can be empty or contains decoded data]
        """
        authcache = AuthCache() # empty Auth
        
        # by default user token use Authorization HTTP Header
        token = cherrypy.request.headers.get('ABCAuthorization', None)
        if isinstance(token, str) and token.startswith( 'Bearer '):
            # remove the 'Bearer ' : len( 'Bearer ') = 7
            token = token[7:] 
            # if there is some data to decode
            if len(token) > 0 : 
                try:
                    # get the dict decoded token
                    # can raise jwt.exceptions.ExpiredSignatureError: Signature has expired
                    decoded_token = self.jwt.decode( token )

                    # read user, roles, auth
                    # Build a cache data to store value from decoded token into an AuthCache object
                    authcache = AuthCache( decoded_token )
                    authcache.markAuthDoneFromPreviousToken()
                except jwt.exceptions.DecodeError as e:
                    logger.error( e )
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

    #@property
    #def nodehostname(self): 
    #    return self.current.user.nodehostname
 
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
        

    def createmanager(self, name, config):
        cls = None
        if name == 'external':
            # use OAuth 2.0 authentification support
            cls = ODExternalAuthManager 
        elif name == 'metaexplicit':
            # use meta direcotry for active directory trust relationship support
            cls = ODExplicitMetaAuthManager  
        elif name == 'explicit':
            # use ldap directory or microsoft active directory support
            cls = ODExplicitAuthManager  
        elif name == 'implicit':
            # dummy anonymous authentificatio support
            cls = ODImplicitAuthManager
        else:
            # for another class extended 
            cls = oc.pyutils.get_class(config.get('class', name))
        logger.info( 'createmanager name=%s %s', name, cls )
        return cls(name, config)
 
    def findmanager(self, providername, managername=None):
        if managername: 
            return self.getmanager(managername, True)

        if providername:
            provider = self.findprovider(providername)
            if provider: 
                return provider.manager

        raise AuthenticationFailureError('Authentication manager not found: manager=%s provider=%s, check your configuration file' % (managername,providername))

    def getmanager(self, name, raise_error=False):
        if not name: 
            if raise_error: 
                raise AuthenticationFailureError('Invalid authentication manager name')
            return None

        manager = self.managers.get(name)
        if not manager: 
            if raise_error: 
                raise AuthenticationFailureError(f"Undefined authentication manager {str(name)}")
            return None

        return manager


    def _findprovider( self, provider_name, manager_name ):
        mgr = self.getmanager(name=manager_name)
        if isinstance( mgr, ODAuthManagerBase) :
            for pdr in mgr.providers.values():
                if pdr.name.upper() == provider_name:
                    return pdr
        return None


    def findprovider(self, provider_name, manager_list_name=None):
        """[findprovider]
            read all manager and find the provider object from the provider name
            return None if not found, provider else
        Args:
            name ([str]): [name of the provider to look for]

        Returns:
            [ODAuthProviderBase]: [instance of  ODAuthProviderBase]
        """
        provider = None
        provider_name = provider_name.upper()

        if isinstance( manager_list_name, str ):
            manager_list_name = [ manager_list_name ]

        if manager_list_name is None:
            # Look for all manager
            manager_list_name = ODAuthTool.manager_name_list

        for manager_name in manager_list_name:
            provider = self._findprovider( provider_name, manager_name )
            if isinstance( provider, ODAuthProviderBase ) : break

        return provider


    def listprovider( self, manager_name):
        """[listprovider]
            list of all providers defined for a specific manager 
        Args:
            manager ([str]): [manager name]

        Returns:
            [list]: [ list of providers defined for the manager ]
        """
        mgr = self.getmanager( manager_name )
        if mgr: 
            return list(mgr.providers.values())
        return None

        
    def getclientdata(self):
       return { 'managers': list(map(lambda m: m.getclientdata(), self.managers.values())) }
    
    def update_token( self, auth, user, roles, expire_in, updatecookies=False ):        
        
        # remove unused data
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

        return jwt_token 

        
        
    def compiledcondition( self, condition, user, roles ):     

        def isPrimaryGroup(user, primaryGroupID):
            # if user is not a dict return False
            if not isinstance(user, dict):
                return False

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

            return value

        def isMemberOf(roles, groups) :
            if type(roles) is not list:  
                roles = [roles]
            if type(groups) is not list: 
                groups = [groups]
            for m in roles:
                # 
                if not isinstance( m, str):
                    continue
                for g in groups:
                    if not isinstance( g, str):
                        continue
                    logger.debug('isMemberOf %s, %s', m, g)
                    if m.lower().startswith(g.lower()):
                        return True
            return False

        def isinNetwork( ipsource, network ):
            if IPAddress(ipsource) in IPNetwork( network ):
                return True
            return False

        def isAttribut(user, attribut, start_with=None, equal=None ):
            # if user is not a dict return False
            if not isinstance(user, dict):
                return False

            if not isinstance( attribut, str ):
                return False
            
            if not isinstance( start_with, str ) and \
               not isinstance( equal, str ):
                return False
                
            try:
                attribut_user_value = str( user.get( attribut ) )
                if start_with :
                    return attribut_user_value.startswith( start_with )
                if equal :
                    return attribut_user_value.__eq__( equal )
            except Exception as e:
                logger.error( str(e) ) 
                return False
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

        memberOf = condition.get('memberOf') or condition.get('memberof')
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
        if primaryGroup is not None:
            # always use 'int' type format
            # from https://docs.microsoft.com/en-us/windows/win32/adschema/a-primarygroupid
            # Ldap-Display-Name	primaryGroupID
            # Size	4 bytes
            if isinstance(primaryGroup,str):
                try:
                    primaryGroup = int(primaryGroup)
                except Exception as e:
                    logger.error(   'invalid primarygroupid type convert value %s to int failed %s',
                                    str(primaryGroup), 
                                    str(e))

            if isinstance(primaryGroup,int):
                result = isPrimaryGroup( user, primaryGroup )
                if result == condition.get( 'expected'):
                    compiled_result = True
            else:
                logger.error( 'invalid primarygroupid type int is expected, get %s', type(primaryGroup) )

        attribut_dict = condition.get('attibut')
        if type(attribut_dict) is dict:
            attribut   = attribut_dict.get( 'attribut')
            startwith  = attribut_dict.get( 'startwith')
            equal      = attribut_dict.get( 'equal')
            result = isAttribut( user, attribut, startwith, equal )
            if result == condition.get('expected'):
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
            r = self.compiledcondition(condition, user, roles)
            logger.debug('compiled_result=%s condition=%s', r, condition)
            results.append( r )
            
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
                        buildcompiledrules[ k ] = rules.get(name).get('load', 'true')
            except Exception as e:
                self.logger.error( 'rules %s compilation failed %s, skipping rule', name, e)
            
        return buildcompiledrules


    def findproviderusingrules(self, manager ):
        provider = None # default value

        # get explicit manager dict
        managers = self.managers.get(manager)
        if not isinstance(managers, ODExplicitAuthManager):
            raise AuthenticationFailureError('No %s authentication manager found', str(manager) )

        # get provider dict for explicit manager
        providers = managers.providers
        if not isinstance(providers, dict):
            raise AuthenticationFailureError('No authentication provider found')

        # get the length of providers dict 
        l = len( providers )
        # if there is only one provider 
        # return the only one 
        if l == 1:
            # return the first value in the dict
            provider = providers[ next(iter(providers)) ] 
            return provider

        # there is more than one provider use rules 
        rules = managers.getrules()
        if not isinstance( rules, dict):
            raise AuthenticationFailureError('No authentication provider can be selected, please defined rules entry')
        
        compiledrules = self.compiledrules( rules, None, None )
        if len(compiledrules) > 0:
            # return the first value in the dict, even if more value matches 
            provider = next(iter(compiledrules.keys()))
        else:
            # no provider found using rules
            # use the default provider with attribut 'default':True 
            for k in providers.keys():
                if providers[k].is_default() is True:
                    provider = k
                    break
                    
        return provider
    

    def get_metalogin_manager_provider( self ):
        # start metalogin check
        # managername and providername are hard coded
        # only one provider providername = 'metadirectory'
        mgr_meta = None
        provider_meta = None
        
        # check if metaexplicit manager exits in config
        mgr_meta = self.managers.get( ODAuthTool.manager_metaexplicit_name )
        if isinstance( mgr_meta, ODExplicitMetaAuthManager):
            # a metamanager exists
            # check if metadirectory provider exits in config
            provider_meta = mgr_meta.providers.get( ODAuthTool.provider_metadirectory_name )
        
        return (mgr_meta, provider_meta)
        


    def is_default_metalogin_provider( self ):
        """[is_default_metalogin_provider]
            check if the managername='metaexplicit' is defined and 
                  if the providername='metadirectory' is defined and
                         providername='metadirectory' as default property to True
        Returns:
            [bool]: [return True if the providername='metadirectory' is defined as default ]
        """
        ( mgr_meta, provider_meta ) = self.get_metalogin_manager_provider()
        if isinstance( provider_meta, ODAdAuthMetaProvider ):
            return provider_meta.is_default()
        return False



    def metalogin(self, provider, manager=None, **arguments): 
        """[metalogin] 
            same as login but use meta directory to select user informations like DOMAIN\SAMAccountName 
            and Kerberos realm
        Args:
            provider_name ([str]): [provider name]
            manager ([str], optional): [manager name]. Defaults to None.
        """

        """
        # Check if the user auth request contains a domain prefix 
        # do not use the meta login process 
        providers_list = self.listprovider( 'explicit' )
        (domain,_) = ODAdAuthProvider.splitadlogin( arguments.get( 'userid') )
        specified_provider = self.findproviderbydomainprefix( providers=providers_list, domain=domain ) 
        if isinstance( specified_provider, ODAdAuthProvider):
            # metadirectory can be an ODAdAuthProvider
            # if the specified_provider is a metadirectory 
            # do not use the specified_provider as auth provider
            if specified_provider.name != 'metadirectory' :
                # do not perform a metalogin
                # run a login with the specified_provider 
                return self.login( provider=specified_provider, manager=manager, **arguments)
        """


        # start metalogin check
        # managername and providername are hard coded
        # only one provider providername = 'metadirectory'
        # managername  = 'metaexplicit'
        # providername = 'metadirectory'
        # check if metalogin manager and provider are defined
        ( mgr_meta, provider_meta ) = self.get_metalogin_manager_provider()
        if mgr_meta is None or provider_meta is None:
            # no metaexplicit manager has been defined
            logger.info( 'skipping metalogin, no metaexplicit manager or no metadirectory provider has been defined')
            return self.login(provider, manager, **arguments)

        # 
        # do authenticate using service account to the metadirectory provider
        #
        try:
            claims, auth = provider_meta.authenticate( provider_meta.userid, provider_meta.password )  
        except Exception as e:
            # no authenticate 
            logger.error( 'skipping metalogin, authenticate failed %s', str(e))
            return self.login(provider, manager, **arguments)

        #
        # find user in metadirectory entries if exists
        #
        metauser = None
        try:
            metauser = provider_meta.getuserinfo( auth, **arguments ) 
        except Exception as e:
            # no user provider has been found
            logger.error( 'skipping metalogin, no metauser getuserinfo  %s', str(e))
            return self.login(provider, manager, **arguments)
        if metauser is None:
            # no user provider has been found
            # an error occurs in meta directory query
            logger.error( 'skipping metalogin, no metauser found' )
            return self.login(provider, manager, **arguments)
       
        roles = provider_meta.getroles( auth, **arguments)
        if not isinstance(roles, list):
            raise AuthenticationFailureError( 'mgr.getroles provider=%s error' %  provider )
        self.logger.debug( 'mgr.getroles provider=%s success', provider)

        # if the provider has rules defined
        # then compile data using rules
        # and runs the rules to get associated labels tag
        if provider_meta.rules:
            auth.data['labels'] = self.compiledrules( provider_meta.rules, metauser, roles )
            self.logger.info( 'compiled rules get labels %s', auth.data['labels'] )

        # check if acl matches with tag
        if not oc.od.acl.ODAcl().isAllowed( auth, provider_meta.acls ):
            raise AuthenticationDenied( 'Access is denied by security policy')
        
        # buid a AuthCache as response result 
        metaauthcache = AuthCache( { 'auth': vars(auth), 'user': metauser, 'roles': roles } ) 

        new_login = metauser.get( provider_meta.join_key_ldapattribut )

        if not isinstance( new_login, str ):
            logger.debug( 'invalid object type %s', provider_meta.join_key_ldapattribut  )
            return self.login(provider, manager, **arguments)

        providers_list = self.listprovider( manager_name='explicit' )
        (new_domain,new_userid) = ODAdAuthProvider.splitadlogin( new_login )
        new_provider = self.findproviderbydomainprefix( providers=providers_list, domain=new_domain ) 

        if new_provider is None:
            logger.error( 'provider %s to authenticate %s is not defined', new_domain, new_userid )
            raise AuthenticationFailureError('Provider %s to authenticate %s is not defined' % (new_domain, new_userid) )
            # return self.login(provider, manager, **arguments)

        logger.info( 'metadirectory translating user auth')
        logger.info( 'metadirectory replay from provider %s->%s', provider_meta.name, new_provider.name )
        logger.info( 'metadirectory replay from user %s->%s', str(arguments.get('userid')) , new_userid )
        logger.info( 'metadirectory replay from domain %s->%s', provider_meta.domain, new_domain )

        # update login with new data from meta directory
        arguments[ 'userid'   ] = new_userid
        arguments[ 'provider' ] = new_provider.name
        arguments[ 'manager'  ] = 'explicit'
          

        userloginresponse = self.login(**arguments)
        # Now merge userloginresponse result 
        if  hasattr( userloginresponse, 'success')  and  \
            userloginresponse.success is True       and  \
            hasattr( userloginresponse, 'result')   and  \
            isinstance( userloginresponse.result, AuthCache ) : 
              
            # merge userloginresponse with metaauthdata
            userloginresponse.result.merge( metaauthcache )

        return userloginresponse


        
    def findproviderbydomainprefix( self, providers, domain ):
        """[summary]
            find a provider using the DOMAIN ActiveDirectory domain name
            return the provider object for this domain
        Args:
            providers ([list]): [list of provider]
            domain ([str]): [ActiveDirectory DOMAIN NAME]

        Returns:
            provider [ODAdAuthProvider]: [provider type ODAdAuthProvider]
            None if not found
        """
        # sanity check
        if not isinstance(domain,str): 
            return None
        # sanity check
        if not isinstance(providers, list):
            return None 

        domain = domain.upper()
        provider = None

        for p in providers:
            if p.domain.upper() == domain :
                logger.info( 'provider.name %s match for domain=%s', p.name, domain) 
                provider = p
                break   
        
        return provider

    def finddefaultprovider( self, providers):
        """[finddefaultprovider]
                return a provider with default property set to True, None if not found or not set
        Args:
            providers ([provider]): [description]

        Returns:
            [provider]: [the default provider, None is not set]
        """
        m = list( filter(lambda p: p.is_default(), providers ))
        default_provider = m[0] if len(m)>0 else None
        return default_provider


    def logintrytofindaprovider( self, manager ):
        # manager must be explicit
        if manager != 'explicit':
            raise AuthenticationFailureError('No authentication provider can be found')
        
        # no provider has been set in the request 
        # try to find a provider using the auth rules
        # manager is 'explicit'
        provider = self.findproviderusingrules(manager) 
        if provider is None:
            # no provider has been found
            # try to parse the login name    
            # manager is 'explicit'     
            providers = self.listprovider(manager_name=manager)           
            provider  = self.finddefaultprovider( providers=providers )
            if provider is None:
                raise AuthenticationFailureError('No authentication default provider can be found')
        return provider



    def login(self, provider, manager=None, **arguments):        

        try:
            auth = None
            response = AuthResponse(self)

            # if provider is None, it must be an explicit manager 
            if provider is None:
                # can raise exception
                # do everythings possible to find one provider
                logger.info( 'provider is None, login try to find a provider using manager=' +  str(manager) )
                provider = self.logintrytofindaprovider( manager )
                
            # look for an auth manager
            mgr = self.findmanager(provider, manager)
                 
            # do authenticate 
            claims, auth = mgr.authenticate(provider, **arguments)
            
            if not isinstance( auth, AuthInfo ):
                raise AuthenticationFailureError('No authentication provided')
            self.logger.debug( 'mgr.authenticate provider=%s success', provider) 
            
            # uncomment this line only to dump password in clear text format
            # logger.debug( 'mgr.getuserinfo arguments=%s', arguments)            
            user = mgr.getuserinfo(provider, auth, **arguments)
            if not isinstance(user, dict ):
                raise AuthenticationFailureError('getuserinfo return None provider=%s', provider)

            userid = user.get('userid')
            if not isinstance(userid, str):
                raise AuthenticationFailureError('getuserinfo return invalid userid provider=%s', provider)

            self.logger.debug( 'mgr.getuserinfo provider=%s success', provider)
            
            # make sure to use the same case sensitive if we change provider
            # user['userid'] = userid.upper()
            
            # uncomment this line only to see password in clear text format
            # logger.debug( 'mgr.getroles arguments=%s', arguments)            
            roles = mgr.getroles(provider, auth, **arguments)
            if not isinstance(roles, list):
                raise AuthenticationFailureError( 'mgr.getroles provider=%s error' %  provider )
            self.logger.debug( 'mgr.getroles provider=%s success', provider)

            # if the mgr is an explicit mgr then add the claims for next usage 
            # for example domain, username, password are used by desktop cifs driver
            # claims contains raw user credentials 
            # add claims to auth only if credentials are need to get access to external ressources                        
            if mgr.name == 'explicit':
                auth.claims = claims  

            # get the provider object
            pdr = mgr.getprovider(provider)

            # if the provider has rules defined
            # then compile data using rules
            # and runs the rules to get associated labels tag
            if pdr.rules:
                auth.data['labels'] = self.compiledrules( pdr.rules, user, roles )
                self.logger.info( 'compiled rules get labels %s', auth.data['labels'] )

            # check if acl matches with tag
            if not oc.od.acl.ODAcl().isAllowed( auth, pdr.acls ):
                raise AuthenticationDenied( 'Access is denied by security policy')
            
            # buid a AuthCache as response result 
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

        finally:
            # call finalize if 
            if auth is not None and hasattr( mgr, 'finalize' ) and callable(mgr.finalize) :
               auth = mgr.finalize(provider, auth, **arguments)

        return response


    def su(self, source_provider_name, arguments):

        # look for the current provider source_provider_name
        source_provider = self.findprovider(source_provider_name)
        if source_provider.explicitproviderapproval is None:
            raise AuthenticationFailureError( 'provider %s has no explicitproviderapproval' %  source_provider.providername )
        
        # read the explicitproviderapproval from the source_provider
        target_provider_name = source_provider.explicitproviderapproval
        target_provider = self.findprovider(target_provider_name)

        # check if provider is a valid object 
        if not isinstance( target_provider, ODAuthProviderBase ):
            raise AuthenticationFailureError( 'provider %s is not approvable' % target_provider_name )
        
        # check if target manager is an explicit manager
        if not isinstance( target_provider.manager, ODExplicitAuthManager ):    
            raise AuthenticationFailureError( 'provider explicitproviderapproval %s must be an explicit Auth Manager ' %  source_provider.explicitproviderapproval )

        # do authenticate 
        response = self.login( provider=target_provider.name, manager=None, **arguments)
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
        """[logout]
        """
        pass
        

    def raise_unauthorized(self, message='Unauthorized'):
        raise cherrypy.HTTPError(401, message)
               
        
          
@oc.logging.with_logger()
class ODAuthManagerBase(object):
    def __init__(self, name, config):
        self.name = name
        self.providers = OrderedDict()
        self.initproviders(config)
        self.rules = config.get('rules')

    def initproviders(self, config):
        for name,cfg in config.get('providers',{}).items():
            if not cfg.get('enabled', True): 
                continue
            logger.info( 'Adding provider name %s ', name )
            provider = self.createprovider(name, cfg)
            try:
                # add only instance ODAuthProviderBase or herited
                self.add_provider( name, provider )    
            except Exception as e:
                logger.exception(e) 

    def add_provider( self, name, provider ):
        """[add_provider]
            add a provider object ODAuthProviderBase in providers dict
        Args:
            name ([str]): [key of the providers dict]
            provider ([ODAuthProviderBase]): [ODAuthProviderBase]
        """
        assert isinstance(name, str) , 'bad provider name parameter'
        assert isinstance(provider, ODAuthProviderBase) , 'bad provider parameters'
        self.providers[name] = provider  
       
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

    def getrules(self):
        return self.rules

    def getprovider(self, name, raise_error=False):
        """[getprovider]
            return a provider from name 
        Args:
            name ([str]): [name of the provider]
            raise_error (bool, optional): [raise error an exception if not exist]. Defaults to False.

        Raises:
            AuthenticationFailureError: ['Invalid authentication provider name']
            AuthenticationFailureError: ['Undefined authentication provider']

        Returns:
            [type]: [description]
        """
        if not isinstance(name, str) : 
            if raise_error: 
                raise AuthenticationFailureError('Invalid authentication provider name')
            return None
        
        pdr = self.providers.get(name)
        # pdr is an instance of ODAuthProviderBase
        if pdr is None: 
            if raise_error: 
                raise AuthenticationFailureError('Undefined authentication provider: %s' % name)
            return None

        return pdr

    def getclientdata(self):
        # list(map(lambda p: p.getclientdata(), self.providers.values()))
        # filter get p.showclientdata == True
        providersmaplist = list( filter( lambda p: p.showclientdata == True, self.providers.values() ) )
        providers = list( map(lambda p: p.getclientdata(), providersmaplist )) 
        return { 'name': self.name, 'providers': providers }


@oc.logging.with_logger()
class ODExternalAuthManager(ODAuthManagerBase):
    def __init__(self, name, config):
        super().__init__(name, config)

    def createprovider(self, name, config):
        return ODExternalAuthProvider(self, name, config)


@oc.logging.with_logger()
class ODExplicitAuthManager(ODAuthManagerBase):
    def __init__(self, name, config):
        super().__init__(name, config)
        self.show_domains = config.get('show_domains', False)
        # look for a default provider
        m = list( filter(lambda p: p.is_default(), self.providers.values()))
        # if multiple provider has default property set to True, choose the first one
        self.default_domain = m[0].name if len(m) > 0 else None

        # else:
        #    self.default_domain 
        #    # no default provider has been defined, use the first one, 
        #    # None is the list is empty
        #    self.default_domain = list(self.providers.values())[0].name if len(self.providers) else None

    def createprovider(self, name, config):
        """[createprovider]
            create an authnetification provider 

        Args:
            name ([str]): [name of the provider]
            config ([dict]): [provider configuration]

        Returns:
            [ODAdAuthProvider or ODLdapAuthProvider]: [if domain is set in config return ODAdAuthProvider else ODLdapAuthProvider]
        """
        # if domain is defined then create an active directory auth provider 
        # else create a LDAP auth provider

        provider = None 
        if self.isActiveDirectory( config ):
            provider = ODAdAuthProvider(self, name, config)
        else:
            provider = ODLdapAuthProvider(self, name, config)
        return provider

    def isActiveDirectory( self, config ) -> bool:
        """[isActiveDirectory]
            True if config is an ActiveDirectory config else False
        Args:
            config ([dict]): [provider configuration]

        Returns:
            bool: [True if config is an ActiveDirectory config else False]
        """
        if config.get('domain'):
            return True
        else:
            return False

    def add_provider( self, name, provider ):
        super().add_provider( name, provider)
        # check the default domain 
        if isinstance( provider, ODAdAuthProvider) and provider.is_default():
            self.default_domain = provider.domain

    def getclientdata(self):
        data = super().getclientdata()
        data['default_domain'] = self.default_domain
        data['show_domains'] = self.show_domains
        return data

    def authenticate(self, provider, userid=None, password=None, **params):
        return self.getprovider(name=provider, raise_error=True).authenticate(userid, password)


@oc.logging.with_logger()
class ODExplicitMetaAuthManager(ODAuthManagerBase):
    def __init__(self, name, config):
        super().__init__(name, config)
        
    def createprovider(self, name, config):
        """[createprovider]
            create an authnetification provider for meta directory
            only active directory is supported 

        Args:
            name ([str]): [name of the provider]
            config ([dict]): [configuration ]

        Returns:
            [ODAdAuthMetaProvider]: [ODAdAuthMetaProvider instance]
        """
        return ODAdAuthMetaProvider(self, name, config)

@oc.logging.with_logger()
class ODImplicitAuthManager(ODAuthManagerBase):
    def __init__(self, name, config):
        super().__init__(name, config)

    def createprovider(self, name, config):
        provider = None
        if config.get('useExplicitIdentityProvider'):
            provider = ODImplicitTLSCLientAdAuthProvider(self, name, config)
        else:
            provider = ODImplicitAuthProvider(self, name, config)
        return provider


@oc.logging.with_logger()
class ODRoleProviderBase(object):
    def getroles(self, authinfo, **params):
        return []

    def isinrole(self, token, role, **params):
        return role.casefold() in (n.casefold() for n in self.getroles(token))

@oc.logging.with_logger()
class ODAuthProviderBase(ODRoleProviderBase):
    def __init__(self, manager, name, config):
        self.name = name
        self.manager = manager
        self.type = config.get('type', self.name)
        self.displayname = config.get('displayname',  self.name) 
        self.caption = config.get('caption', self.displayname )
        policies = config.get('policies', {} )
        self.acls  = policies.get('acl', { 'permit': [ 'all' ] } ) 
        self.rules = policies.get('rules')
        self.default = config.get('default', False )
        self.auth_only = config.get('auth_only', False )
        self.showclientdata = config.get('showclientdata', True )
        self.default_user_if_not_exist = config.get('defaultuser', 'balloon' )
        self.default_passwd_if_not_exist = config.get('defaultpassword', 'lmdpocpetit' )

       
    def authenticate(self, **params):
        raise NotImplementedError()

    def getuserinfo(self, authinfo, **params):
        raise NotImplementedError()

    def getclientdata(self):
        clientdata = { 
            'name': self.name, 
            'caption': self.caption, 
            'displayname': self.displayname
        }
        return clientdata

    def finalize(self, auth, **params):
        return auth

    def is_default( self ):
        return self.default

    def is_serviceaccount_defined( self, config ):
        bReturn = False
        serviceaccount = config.get('serviceaccount')
        if isinstance(serviceaccount, dict):
            serviceaccount_login    =  serviceaccount.get('login')
            serviceaccount_password =  serviceaccount.get('password')
            if isinstance(serviceaccount_login, str) and isinstance(serviceaccount_password, str):
                bReturn = True
        return bReturn
        
    def generateLocalAccount(self, user, password ):
        self.logger.debug('Generating passwd file')
        if not isinstance( user, str ):
            user = self.default_user_if_not_exist
        if not isinstance( password, str ):
            password = self.default_passwd_if_not_exist
        hashes = {}
        hashes['user']= user
        # Shadow
        hashes['sha512'] = crypt.crypt( password, crypt.mksalt(crypt.METHOD_SHA512))
        return hashes

    
    def createauthenv(self, userid, password):
        self.logger.debug('createauthenv')
        dict_hash = self.generateLocalAccount( user=userid, password=password ) 
        default_authenv = { 'localaccount' : { **dict_hash } }
        return default_authenv


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
        # relation ship to allow an external provider to resign as an explicitprovider
        # after login process and pod create
        self.explicitproviderapproval = config.get('explicitproviderapproval') 

    def getclientdata(self):
        data = super().getclientdata()
        oauthsession = OAuth2Session( self.client_id, scope=self.scope, redirect_uri=self.redirect_uri)
        authorization_url, state = oauthsession.authorization_url( self.authorization_base_url ) 
        data['dialog_url']  = authorization_url
        data['explicitproviderapproval'] = self.explicitproviderapproval 
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
            raise ExternalAuthError( message='authinfo is an invalid token oauthsession object')

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
        if isinstance(oauthsession,OAuth2Session) :
            authinfo.token = oauthsession.token 
        return authinfo

# ODImplicitAuthProvider is an Anonymous AuthProvider
class ODImplicitAuthProvider(ODAuthProviderBase):
    def __init__(self, manager, name, config):
        super().__init__(manager, name, config)
        self.userid = config.get('userid', self.name)
        self.username = config.get('username', self.name)
        self.userinfo = copy.deepcopy(config.get('userinfo', {}))
        self.explicitproviderapproval = config.get('explicitproviderapproval') 
        self.dialog_url = config.get( 'dialog_url' )
    

    def getclientdata(self):
        data =  super().getclientdata()
        if self.dialog_url:
            data['dialog_url'] = self.dialog_url
        return data
        
    def getuserinfo(self, authinfo, **params):

        user = copy.deepcopy(self.userinfo)
       
        # Check if token type is str
        if  isinstance(authinfo.token ,str) :
            # anonymous can have a username
            # user name is set has the auth token 
            user['name']   = authinfo.token
            user['userid'] = authinfo.token # take care, it must be uniqu
        else:
            # set default values
            user['name']   = self.username      # anomymous by default
            user['userid'] = str(uuid.uuid4())  # create a user id
            
        return user

    def authenticate(self, userid=None, password=None, **params):
        data = {    'userid': userid, 
                    'environment': self.createauthenv(userid, password)
        }

        return ({}, AuthInfo( self.name, self.type, userid, data=data))


class ODImplicitTLSCLientAuthProvider(ODImplicitAuthProvider):

     def __init__(self, manager, name, config):
        super().__init__(manager, name, config)

     def getuserinfo(self, authinfo, **params):
        user = copy.deepcopy(self.userinfo)
        # anonymous can have a username
        # user name is set has the auth token
        user['name']   = authinfo.token
        user['userid'] = authinfo.token # take care, it must be uniqu
        return user


@oc.logging.with_logger()
class ODLdapAuthProvider(ODAuthProviderBase,ODRoleProviderBase):

    DEFAULT_ATTRS = [ 'cn', 'sn', 'description', 'employeeType', 'givenName', 'jpegPhoto', 'mail', 'ou', 'title', 'uid', 'distinguishedName', 'displayName', 'name', 'memberOf' ]
    class Query(object):
        def __init__(self, basedn, scope=ldap3.SUBTREE, filter=None, attrs=None ):
            self.scope = scope
            self.basedn = basedn
            self.filter = filter
            self.attrs = attrs            

    def __init__(self, manager, name, config={}):
        logger.info('')
        super().__init__(manager, name, config)
        self.type = 'ldap'

        # default ldap auth protocol is SIMPLE
        self.auth_type  = config.get('auth_type', 'SIMPLE').upper() 
        # default ldap service account is None 
        serviceaccount = config.get('serviceaccount', { 'login':None, 'password':None } )
        if isinstance(serviceaccount,dict):
            self.userid = serviceaccount.get('login')
            self.password = serviceaccount.get('password')
        
        self.users_ou = config.get('users_ou', config.get('basedn') ) 
        self.servers = config.get('servers', []) 
        self.timeout = config.get('timeout', 20)
        self.connect_timeout = config.get('connect_timeout', 5)
        self.use_ssl = config.get('secure', False) is True
        self.port = config.get('port') # if port is None ldap3.Server use default port 389 and 636
        self.useridattr = config.get('useridattr', 'cn')
        self.usercnattr = config.get('usercnattr', 'cn') 
        self.useruidattr = config.get('useruidattr', 'uid')
        self.domain = config.get('domain')
        self.kerberos_realm = config.get('kerberos_realm') # must be str od a dict of realm domain/value
        self.kerberos_krb5_conf = config.get('krb5_conf')
        # self.kerberos_service_identifier = config.get('krb5_service_identifier', '')
        self.kerberos_ktutil = config.get('ktutil', '/usr/bin/ktutil') # change to /usr/sbin/ktutil on macOS
        self.kerberos_kinit  = config.get('kinit', '/usr/bin/kinit')   # change to /usr/sbin/kinit on macOS
        # auth_protocol is a dict of auth protocol, will be injected inside the container
        self.auth_protocol = config.get('auth_protocol', { 'ntlm': False, 'cntlm': False, 'kerberos': False, 'citrix': False} )
        # if ldif is not set (None) 
        # add ldif user information auth_protocol to inform that this object contains ldif data 
        if self.auth_protocol.get('ldif') is None:
            self.auth_protocol['ldif'] = True

        self.LDAP_PAGE_SIZE = 8 
        # citrix template file 
        self.citrix_all_regions = None
        if self.auth_protocol.get('citrix'):
            self.citrix_all_regions = oc.lib.load_local_file( config.get('citrix_all_regions.ini' ) )
            if isinstance( self.citrix_all_regions, str):
                logger.info( 'provider %s has enabled citrix, mustache file %s', name, config.get('citrix_all_regions.ini') )
            else:
                logger.error( 'provider %s has disabled citrix, invalid entry citrix_all_regions.ini', name)

        self.exec_timeout = config.get('exec_timeout', 10)
        self.tls_require_cert = config.get( 'tls_require_cert', False)
        self.join_key_ldapattribut = config.get( 'join_key_ldapattribut' )
        self.krb5cctype = config.get('krb5cctype', 'MEMORY').upper()
        self.ldap_ipmod = config.get('ldap_ip_mode', ldap3.IP_V4_PREFERRED )

        # query users
        self.user_query = self.Query(
            config.get('basedn'), 
            config.get('scope', ldap3.SUBTREE),
            config.get('filter', '(&(objectClass=inetOrgPerson)(cn=%s))'), 
            config.get('attrs', ODLdapAuthProvider.DEFAULT_ATTRS ))

        # query groups
        self.group_query = self.Query(
            config.get('group_basedn', self.user_query.basedn),
            config.get('group_scope', self.user_query.scope),
            config.get('group_filter', "(&(objectClass=Group)(cn=%s))"),
            config.get('group_attrs'))


    @staticmethod
    def issafeLdapAuthCommonName(cn):
        ''' return True id cn is safe for LDAP Query '''
        for c in cn:
            # filter permit char
            permitchar = c.isalnum() or c == '-' or c == ' '
            if not permitchar:
                return False
        return True

    def finalize( self, auth, **params):
        if isinstance( auth.conn , ldap3.core.connection.Connection ):
            try:
                auth.conn.unbind()
            except Exception as e:
                self.logger.error( e )
        auth.conn = None


    def validate(self, userid, password, **params):

        userdn = None   # set default value
        conn   = None   # set default value

        if self.auth_type not in ['KERBEROS', 'NTLM', 'SIMPLE']:
            raise AuthenticationError('auth_type must be \'KERBEROS\', \'NTLM\', or \'SIMPLE\' ')

        if self.auth_type == 'KERBEROS':
            # can raise exception 
            self.krb5_validate( userid, password )
            # can raise exception 
            self.krb5_authenticate( userid, password )
            if not self.auth_only :
                conn = self.getconnection(userid, password) 
        elif self.auth_type == 'SIMPLE':
            # can raise exception 
            self.simple_validate(userid, password)   
            conn = self.getconnection(userid, password) 
            userdn = self.getuserdn(conn, userid)
        elif self.auth_type == 'NTLM':
            # can raise exception 
            self.ntlm_validate(userid, password)
            conn = self.getconnection(userid, password)
            userdn = self.getuserdn(conn, userid)
        return (userdn, conn)

    def krb5_authenticate(self, userid, password ):
        try:
            userid = userid.upper()
            krb5ccname = self.get_krb5ccname( userid )
            self.run_kinit( krb5ccname, userid, password )
        except Exception as e:
            self.remove_krb5ccname( krb5ccname )
            raise AuthenticationError('kerberos credentitials validation failed ' + str(e))

    def authenticate(self, userid, password, **params):
        # validate can raise exception 
        # like invalid credentials
        (userdn, conn) = self.validate(userid, password)   

        data = {    'userid': userid, 
                    'dn': userdn,
                    'environment': self.createauthenv(userid, password) }
        
        return (    { 'userid': userid, 'password': password }, 
                    AuthInfo( self.name, self.type, userid, data=data, protocol=self.auth_protocol, conn=conn) )

    def krb5_validate(self, userid, password):
        conn = None

        if not isinstance(userid,str) or len(userid) < 1 :
            raise AuthenticationError('user can not be an empty string')

        if len(userid) > 256 :
            raise AuthenticationError('user length must be less than 256 characters')

        if not isinstance(password,str) or len(password) < 1 :
            raise AuthenticationError('password can not be an empty string')

        # kerberos password length Limit.
        # Maximum number of characters supported for plain-text krb5-password config is 256
        if len(password) > 256 :
            raise AuthenticationError('password length must be less than 256 characters')


    def ntlm_validate(self, userid, password):
        conn = None
        if not isinstance(userid,str) or len(userid) < 1 :
            raise AuthenticationError('user can not be an empty string')

        # Limit the size of strings that are accepted. As an absolute limit any
        # user login can be no longer than 104 characters. See [1].
        # password can be no longer than 128 characters. See [2].
        #
        # [1] - https://technet.microsoft.com/en-us/library/bb726984.aspx
        # [2] - https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/ntlm-user-authentication
        #

        if len(userid) >= 104 :
            raise AuthenticationError('user login can be no longer than 104 characters')

        if not isinstance(password,str) or len(password) < 1 :
            raise AuthenticationError('password can not be an empty string')

        # ntlm password length Limit.
        # Maximum number of characters supported for plain-text ntlm config is 128
        if len(password) > 128 :
            raise AuthenticationError('password can be no longer than 128 characters')

        if self.auth_only is True:
            raise AuthenticationError('auth_only is set to True, but ldap.bind need to complete auth')
        

    def simple_validate(self, userid, password):
        """[summary]
            Return LDAPObject instance by opening LDAP connection

        Args:
            userid ([str]): [user name use to bind to ldap server ]
            password ([str]): [user password to bind to ldap server]

        Raises:
            execptions: [description]
            AuthenticationError: [description]
            AuthenticationError: [description]
            AuthenticationError: [description]
            AuthenticationError: [description]

        Returns:
            [conn]: [ldap3.core.connection.Connection ]
        """

        ''' validate userid and password, using bind to ldap server '''
        ''' validate can raise execptions '''
        ''' for example if all ldap servers are down or ''' 
        ''' if credentials are invalid ''' 
        # uncomment this line may dump password in clear text 
        # logger.debug(locals())
        conn = None

        # LDAP by itself doesn't place any restriction on the username
        # especially as LDAP doesn't really specify which attribute qualifies as the username.
        # The DN is similarly unencumbered.
        # set max value to 256
        if not isinstance(userid, str)  or len(userid) < 1 :
            raise AuthenticationError('user can not be an empty string')
        if len(userid) > 256 :
            raise AuthenticationError('user length must be less than 256 characters')

        if not isinstance(password,str) or len(password) < 1 :
            raise AuthenticationError('password can not be an empty string')

        # LDAP BIND password length Limit.
        # Maximum number of characters supported for plain-text bind-password config is 63
        if len(password) > 64 :
            raise AuthenticationError('password length must be less than 64 characters')
        
        if self.auth_only:
            raise AuthenticationError('auth_only is set to True, but ldap.bind need to complete auth')

   
    def getuserinfo(self, authinfo, **params):        
        # logger.debug(locals()) # uncomment this line may dump password in clear text 
        # authinfo.conn is ldap3.core.connection.Connection 

        if self.auth_only is True:
            # fake a userinfo with useridattr key ( like 'cn' or 'SAMAccountName' )
            # fill data with userid 
            userinfo = { self.useridattr: params.get( 'userid'), 'name': params.get( 'userid') }
        else: 
            q = self.user_query
            userinfo = self.search_one( authinfo.conn, q.basedn, q.scope, ldap_filter.filter_format(q.filter, [authinfo.token]), q.attrs, **params)
            if isinstance(userinfo, dict):
                # Add always userid entry, make sure this entry exists
                if not isinstance( userinfo.get('userid'), str) :
                    userinfo['userid'] = userinfo.get(self.useruidattr)
                # Add always name entry
                if not isinstance( userinfo.get('name'), str) :
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
            group_ldap_filter = ldap_filter.filter_format('(&'+self.user_query.filter+'(memberOf=%s))', [token,groupdn])
            return self.search(conn, self.user_query.basedn, self.user_query.scope, group_ldap_filter, ['cn'], True) is not None
        finally:
            if ldap_bind_userid: 
                conn.unbind()

    def getroles(self, authinfo, **params):   
        if self.auth_only :
            return []

        token = authinfo.token            
        q = self.user_query
        result = self.search_one( authinfo.conn, q.basedn, q.scope, ldap_filter.filter_format(q.filter, [token]), ['memberOf'], **params)
        # return [dn.split(',',2)[0].split('=',2)[1] for dn in result['memberOf']] if result else []
        memberOf = result.get('memberOf', [])
        if isinstance(memberOf, str):
             memberOf = [ memberOf ]    # always a list
        return memberOf

    def getuserdnldapconnection(self, userid):
        # rewrite the userid with full dn
        # format cn=Hubert J. Farnsworth,ou=people,dc=planetexpress,dc=com
        escape_userid = ldap_filter.escape_filter_chars(userid)
        if len(escape_userid) != len( userid ):
            self.logger.debug( 'WARNING ldap_filter.escape_filter_chars escaped' )
            self.logger.debug( 'value=%s escaped by ldap_filter.escape_filter_chars as value=%s', userid, escape_userid )
        return self.usercnattr + '=' + escape_userid + ',' + self.users_ou

    def ___getconnection(self, userid, password ):
        conn = None
        server_pool = ldap3.ServerPool( servers=None, pool_strategy=ldap3.ROUND_ROBIN, active=True, exhaust=True, single_state=False )
        for server in self.servers:
            server_pool.add( server, connect_timeout=self.connect_timeout, mode=self.ldap_ipmod )

        try:    
            # do kerberos bind
            if self.auth_type == 'KERBEROS': 
                # krb5ccname must already exist 
                krb5ccname = self.get_krb5ccname( userid )
                # os.putenv( 'KRB5CCNAME', krb5ccname )
                self.logger.info( 'create Connection object ldap3.KERBEROS as %s KRB5CCNAME: %s', userid, krb5ccname )
                # logger.debug(locals()) # uncomment this line may dump password in clear text 
                cred_store = {'ccache':  krb5ccname }
                kerberos_principal_name = self.get_kerberos_principal( userid )
                # If you specify user=, it is expected to be a Kerberos principal (though it appears you can omit the domain). 
                # If there is a credential for that user in the collection, it will be used.
                self.logger.info( 'create Connection object ldap3.KERBEROS as %s KRB5CCNAME: %s', kerberos_principal_name, krb5ccname )
                conn = ldap3.Connection( server_pool, user=kerberos_principal_name, authentication=ldap3.SASL, sasl_mechanism=ldap3.KERBEROS, raise_exceptions=True, cred_store=cred_store )
                # bind to the ldap server
                self.logger.debug( 'bind to the ldap server')
                conn.bind()
                # os.unsetenv('KRB5CCNAME')

            # do ntlm bind
            if self.auth_type == 'NTLM':
                # userid MUST be DOMAIN\\SAMAccountName format 
                # call overwrited by bODAdAuthProvider:getconnection
                self.logger.info( 'create Connection object ldap3.NTLM as %s', userid )
                # logger.debug(locals()) # uncomment this line may dump password in clear text 
                conn = ldap3.Connection( server_pool, user=userid, password=password, authentication=ldap3.NTLM, raise_exceptions=True  )
                # bind to the ldap server
                self.logger.debug( 'binding to the ldap server')
                conn.bind()
                
            # do textplain simple_bind_s 
            if self.auth_type == 'SIMPLE':
                # get the dn to bind 
                userdn = self.getuserdnldapconnection(userid)
                # logger.debug(locals()) # uncomment this line may dump password in clear text 
                self.logger.info( 'create Connection object ldap3.SIMPLE as %s', userdn )
                conn = ldap3.Connection( server_pool, user=userdn, password=password, authentication=ldap3.SIMPLE, raise_exceptions=True )
                # bind to the ldap server
                self.logger.debug( 'binding to the ldap server')
                conn.bind()
            return conn

        except ldap3.core.exceptions.LDAPBindError as e:
            self.logger.error( 'ldap3.core.exceptions.LDAPBindError to the ldap server %s %s', server_pool, str(e) )
            # ldap3.core.exceptions.LDAPBindError: - invalidCredentials
            raise e

        except ldap3.core.exceptions.LDAPAuthMethodNotSupportedResult as e:
            self.logger.error( 'ldap3.core.exceptions.LDAPAuthMethodNotSupportedResult to the ldap server %s %s', server_pool, str(e) )

        except ldap3.core.exceptions.LDAPExceptionError as e:
            self.logger.error( 'ldap3.core.exceptions.LDAPExceptionError to the ldap server %s %s', server_pool, str(e) )

        raise AuthenticationError('Can not contact LDAP servers, all servers are unavailable')
    
    def verify_auth_is_supported_by_ldap_server( self, supported_sasl_mechanisms ):
        #
        # from https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a98c1f56-8246-4212-8c4e-d92da1a9563b
        #
        # The SASL mechanisms supported by a Microsoft DC are exposed as strings in the supportedSASLMechanisms attribute of the rootDSE.
        # Windows 2000 operating system support GSSAPI, GSS-SPNEGO
        # Windows Server 2003 operating system and later support GSSAPI, GSS-SPNEGO, EXTERNAL, DIGEST-MD5
        # Active Directory supports Kerberos (see [MS-KILE]) and NTLM (see [MS-NLMP]) when using GSS-SPNEGO.
        # Active Directory supports Kerberos when using GSSAPI;
        #
        # DIGEST-MD5 is implemented even if it is deprecated and moved to historic (RFC6331, July 2011) 
        # because it is “insecure and unsuitable for use in protocols” (as stated by the RFC).
        is_supported = False
        if not isinstance( supported_sasl_mechanisms, list ):
            return is_supported
        if self.auth_type == 'KERBEROS': 
            if 'GSS-SPNEGO' in supported_sasl_mechanisms:
                is_supported = True
            if 'GSS-GSSAPI' in supported_sasl_mechanisms:
                is_supported = True
        if self.auth_type == 'NTLM': 
            if 'GSS-SPNEGO' in supported_sasl_mechanisms:
                is_supported = True
            if 'NTLM' in supported_sasl_mechanisms:
                is_supported = True
        if self.auth_type == 'SIMPLE': 
            if 'PLAIN' in supported_sasl_mechanisms:
                is_supported = True
        return is_supported


    def getconnection(self, userid, password ):
        self.logger.info( 'ldap getconnection auth userid=%s', userid )
        conn = None
        for server_name in self.servers:
            try: 
                self.logger.info( 'ldap getconnection:server server=%s use_ssl=%s auth_type=%s', str(server_name), str(self.use_ssl), self.auth_type )
                server = ldap3.Server( server_name, connect_timeout=self.connect_timeout, mode=self.ldap_ipmod, use_ssl=self.use_ssl, port=self.port, get_info='ALL')
                
                # create a Connection to get supported_sasl_mechanisms from server
                c = ldap3.Connection(server, auto_bind=False)
                c.open()  # establish connection without performing any bind (equivalent to ANONYMOUS bind)
                # read https://ldap3.readthedocs.io/en/latest/bind.html
                # supported_sasl_mechanisms example [ 'GSS-SPNEGO', 'GSSAPI', 'NTLM', 'PLAIN' ]
                # read supported_sasl_mechanisms supported by the ldap server
                supported_sasl_mechanisms = server.info.supported_sasl_mechanisms if server.info else None
                self.logger.info( 'supported_sasl_mechanisms by %s return %s', server_name, str(supported_sasl_mechanisms)  )
                del c # remove the c Connection, only use to get supported_sasl_mechanisms 

                if not self.verify_auth_is_supported_by_ldap_server( supported_sasl_mechanisms ):
                    self.logger.warning( '%s is not defined by %s.info.supported_sasl_mechanisms supported_sasl_mechanisms=%s', self.auth_type, server_name, str(supported_sasl_mechanisms) )
                 

                # do kerberos bind
                if self.auth_type == 'KERBEROS': 
                     # krb5ccname must already exist 
                    krb5ccname = self.get_krb5ccname( userid )
                    cred_store = {'ccache':  krb5ccname }
                    kerberos_principal_name = self.get_kerberos_principal( userid )
                    # If you specify user=, it is expected to be a Kerberos principal (though it appears you can omit the domain). 
                    # If there is a credential for that user in the collection, it will be used.
                    self.logger.info( 'ldap getconnection:Connection server=%s as user=%s authentication=ldap3.SASL, sasl_mechanism=ldap3.KERBEROS KRB5CCNAME=%s', server_name, kerberos_principal_name, cred_store )
                    conn = ldap3.Connection( server, user=kerberos_principal_name, authentication=ldap3.SASL, sasl_mechanism=ldap3.KERBEROS, read_only=True, raise_exceptions=True, cred_store=cred_store )

                # do ntlm bind
                if self.auth_type == 'NTLM':
                    # userid MUST be DOMAIN\\SAMAccountName format, call overwrited by bODAdAuthProvider:getconnection
                    # logger.debug(locals()) # uncomment this line may dump password in clear text 
                    self.logger.info( 'ldap getconnection:Connection server=%s userid=%s authentication=ldap3.NTLM', str(server), userid )
                    conn = ldap3.Connection( server, user=userid, password=password, authentication=ldap3.NTLM, read_only=True, raise_exceptions=True )
                # do textplain simple_bind_s 
                if self.auth_type == 'SIMPLE':
                    # get the dn to bind 
                    userdn = self.getuserdnldapconnection(userid)
                    # logger.debug(locals()) # uncomment this line may dump password in clear text 
                    self.logger.info( 'ldap getconnection:Connection server=%s userid=%s  authentication=ldap3.SIMPLE', str(server), userdn )
                    conn = ldap3.Connection( server, user=userdn, password=password, authentication=ldap3.SIMPLE, read_only=True, raise_exceptions=True )

                # let's bind to the ldap server
                # conn.open()
                self.logger.info( 'binding to the ldap server %s', server_name)
                conn.bind()
                self.logger.info( 'bind to %s done', server_name)

                return conn

            except ldap3.core.exceptions.LDAPBindError as e:
                self.logger.error( 'ldap3.core.exceptions.LDAPBindError to the ldap server %s %s', server, str(e) )
                # ldap3.core.exceptions.LDAPBindError: - invalidCredentials
                raise e

            except ldap3.core.exceptions.LDAPAuthMethodNotSupportedResult  as e:
                self.logger.error( 'ldap3.core.exceptions.LDAPAuthMethodNotSupportedResult to the ldap server %s %s', server, str(e) )

            except ldap3.core.exceptions.LDAPExceptionError as e:
                self.logger.error( 'ldap3.core.exceptions.LDAPExceptionError to the ldap server %s %s', server, str(e) )

        raise AuthenticationError('Can not contact LDAP servers, all servers are unavailable')
    
    def search_all(self, conn, basedn, scope, filter=None, attrs=None, **params):
        """[summary]

        Args:
            conn ([ldap3.core.connection.Connection]): [ldap 3 Connection]
            basedn ([str]): [base dn of the search request]
            scope ([enum]): [search context BASE, LEVEL, SUBTREE]
            filter ([str], optional): [filter of the search request]. Defaults to None.
            attrs ([list], optional): [single attribute or a list of attributes to be returned by the search]. Defaults to None.
            params ([dict], optional): [credentials to bind ldap server id conn is None]. Defaults to None.
        Returns:
            [type]: [description]
        """
        if not isinstance( conn, ldap3.core.connection.Connection ):    
            ldap_bind_userid     = params.get( 'userid',   self.userid )
            ldap_bind_password   = params.get( 'password', self.password )  
            conn = self.getconnection(ldap_bind_userid, ldap_bind_password)
        return self.search(conn, basedn, scope, filter, attrs, one=False)

    def search_one(self, conn, basedn, scope, filter=None, attrs=None, **params):                 
        if not isinstance( conn, ldap3.core.connection.Connection ):    
            ldap_bind_userid     = params.get( 'userid', self.userid )
            ldap_bind_password   = params.get( 'password', self.password )  
            conn = self.getconnection(ldap_bind_userid, ldap_bind_password)
        return self.search(conn, basedn, scope, filter, attrs, True)

    def search(self, conn, basedn, scope, filter=None, attrs=None, one=False):
        logger.debug(locals())
        withdn = attrs is not None and 'dn' in (a.lower() for a in attrs)
        entries = []
        time_start = time.time()
        results = conn.search( search_base=basedn, search_filter=filter, search_scope=scope, attributes=attrs)
        if results:
            for entry in conn.entries: 
                data = {}
                for k,v in entry.entry_attributes_as_dict.items():
                    data[k] = self.decodeValue(k,v)
                data['dn'] = entry.entry_dn
                if one: 
                    return data
                entries.append(data)
        time_done = time.time()
        elapsed = time_done - time_start
        self.logger.info( 'ldap search_s %s %s take %d ', basedn, str(filter), int(elapsed) )
        return entries if not one else None 

    def getuserdn(self, conn, id):
        return self.getdn(conn, self.user_query, id)

    def getgroupdn(self, conn, id):
        return self.getdn(conn, self.group_query, id)

    def getdn(self, conn, query, id):
        result = self.search(conn, query.basedn, query.scope, ldap_filter.filter_format(query.filter, [id]), ['cn', 'distinguishedName'], True)
        return result['distinguishedName'] if result else None

    def decodeValue(self, name, value):
        if not isinstance(value, list): 
           return value

        items = [] 
        for item in value:
            # try to translate bytes to str using decode utf8
            if isinstance(item,bytes): 
                try:
                    item = item.decode('utf-8')
                except UnicodeDecodeError as e:
                    # raw binary data
                    # Could be an raw binary JPEG data
                    # logger.warning('Attribute %s not decoded as utf-8, use raw data type: %s exception:%s', name, type(item), e)
                    pass
                except Exception as e:
                    logger.error('Attribute %s error to decode as utf-8, use raw data type: %s exception:%s', name, type(item), e)
            items.append(item)

        return items[0] if len(items) == 1 else items


    def get_kerberos_realm( self ):
        return self.kerberos_realm


    def createauthenv(self, userid, password):
        default_authenv = {}

        if not isinstance( self.auth_protocol, dict):
            # nothing to do 
            return default_authenv

        if self.auth_protocol.get('kerberos') is True:
            try:
                dict_hash = self.generateKerberosKeytab( userid, password )
                if isinstance( dict_hash, dict ): 
                    default_authenv.update( { 'kerberos' : {    'PRINCIPAL'   : userid,
                                                                'REALM' : self.get_kerberos_realm(),
                                                                **dict_hash } } )
            except Exception as e:
                pass
        
        if self.auth_protocol.get('ntlm') is True :
            try:
                dict_hash = self.generateNTLMhash(password)
                if isinstance( dict_hash, dict ):
                    default_authenv.update( { 'ntlm' : {    'NTLM_USER'   : userid,
                                                            'NTLM_DOMAIN' : self.domain,
                                                            **dict_hash } } )
            except Exception as e:
                    pass

        if self.auth_protocol.get('cntlm') is True :
            try:
                dict_hash = self.generateCNTLMhash( userid, password, self.domain)
                if isinstance( dict_hash, dict ):
                    default_authenv.update( { 'cntlm' : {   'NTLM_USER'   : userid,
                                                            'NTLM_DOMAIN' : self.domain,
                                                            **dict_hash } } )
            except Exception as e:
                    pass

        if self.auth_protocol.get('citrix') is True :
            try:
                dict_hash = self.generateCitrixAllRegionsini( username=userid, password=password, domain=self.domain) 
                if isinstance( dict_hash, dict ):
                    default_authenv.update( { 'citrix' : dict_hash } )
            except Exception as e:
                    pass


        #if self.auth_protocol.get('localaccount') is True :
        try:
            dict_hash = self.generateLocalAccount( user=userid, password=password ) 
            if isinstance( dict_hash, dict ):
                default_authenv.update( { 'localaccount' : dict_hash } )
        except Exception as e:
            pass

        return default_authenv
    

    def paged_search( self, conn, basedn, filter, attrlist, scope=ldap3.SUBTREE, sizelimit=0):
        entry_list = conn.extend.standard.paged_search(search_base = basedn,
                                            search_filter = filter,
                                            search_scope = scope,
                                            attributes = attrlist,
                                            paged_size = self.LDAP_PAGE_SIZE,
                                            generator=True)
        return entry_list


   
    def get_krb5ccname( self, principal ):
        # krb5ccname = 'FILE:/tmp/' + oc.auth.namedlib.normalize_name( principal ) + '.krb5ccname'
        # MEMORY: caches are for storage of credentials that don’t need to be made available outside of the current process.
        # krb5ccname = 'MEMORY:' + oc.auth.namedlib.normalize_name( principal )
        if self.krb5cctype == 'FILE' :
            krb5ccname = 'FILE:/tmp/' + oc.auth.namedlib.normalize_name( principal )
        elif self.krb5cctype == 'KEYRING':
            krb5ccname = 'KEYRING:persistent:'+ oc.auth.namedlib.normalize_name( principal ) + ':'
        else:
            krb5ccname = 'MEMORY:' + oc.auth.namedlib.normalize_name( principal )
        return krb5ccname

    def remove_krb5ccname( self, krb5ccname ):
        if krb5ccname.startswith( 'FILE:'):
            try :
                os.unlink( krb5ccname )
            except Exception as e:
                self.logger.error('failed to delete tmp file: %s %s', krb5ccname, e)


    def get_kerberos_principal( self, userid ):
        # A kerberos principal is normally your username followed by your Kerberos realm
        return userid + '@' + self.kerberos_realm

    def run_kinit( self, krb5ccname, userid, password ):
        store_cred_result = None
        kerberos_principal = self.get_kerberos_principal( userid )
        user = gssapi.Name(base=kerberos_principal, name_type=gssapi.NameType.user)
        bpass = password.encode('utf-8')
        
        # KRB5CCNAME = b"MEMORY:%userid%"
        # KRB5CCNAME = b"FILE:/tmp/krb5cc_1000"

        # this section code can raise gssapi.exceptions.GSSError
        req_creds = gssapi.raw.acquire_cred_with_password(user, bpass, usage='initiate')
        
        if isinstance( req_creds, gssapi.raw.AcquireCredResult):
            krb5ccname = str.encode(krb5ccname) # convert krb5ccname from str to bytes
            # context = gssapi.SecurityContext(name=server_name, creds=creds, usage='initiate')
            store_cred_result = gssapi.raw.store_cred_into( store={b'ccache': krb5ccname},
                                                            creds=req_creds.creds,
                                                            usage="initiate", 
                                                            overwrite=True )
            logger.debug( 'store_cred_into %s %s', krb5ccname, store_cred_result.usage )
            # exported_cred = gssapi.raw.export_cred(req_creds.creds)

        return store_cred_result

        ''' old code version with kinit subprocess
            userPrincipalName = userid + '@' + self.kerberos_realm
            cmd = [ self.kerberos_kinit, '-c', krb5ccname, userPrincipalName ]
            my_env = os.environ.copy()
            if self.kerberos_krb5_conf :
               my_env['KRB5_CONFIG'] = self.kerberos_krb5_conf
            self.logger.info( 'run kinit command %s', cmd )
            process = subprocess.run(cmd, input=password.encode(),  env=my_env )
            success = process.returncode
            return result
        '''


    def generateKerberosKeytab(self, principal, password ):
        self.logger.info('')
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

        if not isinstance(self.kerberos_krb5_conf, str):
            self.logger.error('invalid krb5.conf file option')
            return None

        if not isinstance(self.kerberos_ktutil, str):
            self.logger.error('invalid ktutil file option')
            return None

        koutputfilename = '/tmp/' + oc.auth.namedlib.normalize_name( principal ) + '.keytab'

        userPrincipalName = principal + '@' + self.get_kerberos_realm()
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
            # clean tmp filename
            removekoutputfile( koutputfilename )
            return keytab

       
        self.logger.info(str(self.kerberos_ktutil) + ' return code: ' + str(returncode))
        if returncode == 0:
            try:
                koutputfile = open( koutputfilename, mode='rb' )
                keytabdata = koutputfile.read() 
                koutputfile.close()

                krb5conf_file =  open( self.kerberos_krb5_conf )
                krb5conf = krb5conf_file.read() 
                krb5conf_file.close()
                keytab = { 'keytab' : keytabdata, 'krb5_conf': krb5conf }
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
        if  not isinstance(password, str) :
            self.logger.error('Invalid password parameters')
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
                if len( line ) < 1: # skipping empty line
                    continue
                # parse string format
                # NTLM_KEY=v8+pDkRc41i8weIufYRhVBPSv=dqM
                logger.info( 'Parsing %s', line )
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

    def generateCitrixAllRegionsini(self, username, password, domain ):
        """[generateCitrixAllRegionsini]
            Fill a template data to generate the All_Regions.ini user file
        Args:
            username ([str]): [user name]
            password ([str]): [password in clear text format]
            domain   ([str]): [domain name]

        Returns:
            [dict]: [All_Regions.ini hash dict]
        """
        hashes = {}
        # citrix_all_regions contains mustache template file data
        if isinstance(self.citrix_all_regions, str) :
            # read https://www.citrix.com/content/dam/citrix/en_us/documents/downloads/citrix-receiver/linux-oem-guide-13-1.pdf
            # These settings handle passwords stored on the client machine.
            self.logger.debug('Generating file All_Regions.ini for citrix-receiver')
            # fill data with dict entries
            data = chevron.render( self.citrix_all_regions, {'username': username, 'password': password, 'domain': domain })
            # return the All_Regions.ini hash dict
            hashes = { 'All_Regions.ini' : data }
        return hashes


    def generateCNTLMhash(self, user, password, domain ):
        self.logger.debug('Generating CNTLM hashes')
        hashes = {}

        cntlm_command = '/usr/sbin/cntlm'

        if  not isinstance( user, str)      or \
            not isinstance( password, str)  or \
            not isinstance( domain, str ) :
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

            # Output of is cntlm_command is :
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
    DEFAULT_ATTRS = ['distinguishedName', 'displayName', 'sAMAccountName', 'name', 'cn', 'homeDrive', 'homeDirectory', 'profilePath', 'memberOf', 'proxyAddresses', 'userPrincipalName', 'primaryGroupID']

    def __init__(self, manager, name, config):
        super().__init__(manager, name, config)
        self.type = 'activedirectory'
        self.useridattr = config.get('useridattr', 'sAMAccountName')
        self.domain_fqdn = config.get('domain_fqdn')
        self.domain = config.get('domain', self.domain_fqdn.split('.',1)[0] if self.domain_fqdn else self.name)
        if not isinstance(self.domain, str) :
            raise ValueError("Property domain must be set as string for active directory")
        else:
            self.domain = self.domain.upper()
        self.query_dcs = config.get('query_dcs', False) is True
        self.dcs_list_maxage = config.get('dcs_list_maxage', 3600)
        self.dcs_list_lastupdated = 0
        self.refreshdcs_lock = None
        self.servers = config.get('servers') or []
        self.user_query.filter = config.get('filter', '(&(objectClass=user)(sAMAccountName=%s))')
        self.user_query.attrs = config.get('attrs', ODAdAuthProvider.DEFAULT_ATTRS)
        self.group_query.filter = config.get('group_filter', "(&(objectClass=group)(cn=%s))")
        self.recursive_search = config.get('recursive_search', False) is True
        self.trusted_domains = config.get('trusted_domains')


        if self.query_dcs:
            if not self.domain_fqdn: 
                raise ValueError("provider %s: property 'domain_fqdn' not set, cannot query domain controllers list" % name)
            self.refreshdcs_lock = Lock()
            self.refreshdcs()

        elif len(self.servers)==0:
            if not self.domain_fqdn: 
                raise ValueError("provider %s: properties 'domain_fqdn' and 'servers' not set , cannot define domain FQDN as fallback (VIP) address" % name)
            self.servers = [ self.domain_fqdn ]
        if len(self.servers)==0:
            raise RuntimeError('Empty list of domain controllers')

        # query sites
        self.printer_query = self.Query(
            basedn=config.get('printer_printerdn', 'OU=Applications,' + config.get('basedn') ),
            scope=config.get('printer_scope', ldap3.SUBTREE),
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
            scope=config.get('site_scope', ldap3.SUBTREE),
            filter=config.get('site_filter', '(objectClass=subnet)'),
            attrs=config.get('site_attrs',['cn', 'siteObject', 'location']) )

    def get_kerberos_realm( self ):
        """[return the kerberos realm]

        Returns:
            [str]: [kerberos realm]
        """
        kerberos_realm = '' # dummy default value 
        if isinstance( self.kerberos_realm, dict ):
            kerberos_realm = self.kerberos_realm.get( self.domain )

        if isinstance( self.kerberos_realm, str ):
            kerberos_realm = self.kerberos_realm

        return kerberos_realm

    def getadlogin( self, userid ):
        adlogin = None
        if self.domain:
            adlogin = self.domain + '\\' + userid
        else:
            adlogin = userid
        return adlogin

    @staticmethod
    def splitadlogin( login ):
        domain = None
        sAMAccountName = login
        arr = login.split('\\', 1)
        if len(arr) > 1: 
            (domain,sAMAccountName) = tuple(arr) 
        return (domain,sAMAccountName)


    def authenticate(self, userid, password, **params):
        if not self.issafeAdAuthusername(userid) or not self.issafeAdAuthpassword(password):
            raise InvalidCredentialsError('Unsafe credentials')
       
        # authenticate can raise exception 
        (userdn, conn) = super().validate(userid, password)
    
        data = {    'userid': userid, 
                    'domain': self.domain, 
                    'ad_domain': self.domain,
                    'dn': userdn,
                    'environment': self.createauthenv(userid, password)
        }

        return (
            { 'userid': userid, 'password': password, 'domain': self.domain },
            AuthInfo(self.name, self.type, userid, data=data, protocol=self.auth_protocol, conn=conn)
        )

    def getuserinfo(self, authinfo, **params):
  
        userinfo = super().getuserinfo(authinfo, **params)
    
        if userinfo:
            # Add always userid entry
            # overwrite value from standard LDAP server
            # useridattr should be 'sAMAccountName'
            userinfo['userid'] = userinfo.get(self.useridattr)

            # read homeDrive homeDirectory and profilePath attributs
            # homeDrive
            homedrive = userinfo.get('homeDrive') 
            if isinstance( homedrive, str ):  userinfo['homeDrive'] = homedrive

            # homeDirectory
            homeDirectory = userinfo.get('homeDirectory') 
            if isinstance( homeDirectory, str ):    userinfo['homeDirectory'] = homeDirectory.replace('\\','/')

            # profilePath
            profilePath = userinfo.get('profilePath')
            if isinstance( profilePath, str ):      userinfo['profilePath'] = profilePath.replace('\\','/')
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
            filter = ldap_filter.filter_format('(&'+self.user_query.filter+'(memberOf:1.2.840.113556.1.4.1941:=%s))', [token,groupdn])
            return self.search(conn, self.user_query.basedn, self.user_query.scope, filter, ['cn'], True) is not None
        finally:
            if self.userid: 
                conn.unbind()

    def getroles(self, authinfo, **params):
        token = authinfo.token 
        if not self.recursive_search:
            return super().getroles(authinfo, **params)

        # ldap_bind_userid   = None 
        # ldap_bind_password = None 
        #
        #if not isinstance( authinfo.conn, ldap3.core.connection.Connection  ):    
        #    ldap_bind_userid     = params.get( 'userid', self.userid )
        #    ldap_bind_password   = params.get( 'password', self.password )  
        #    conn = self.getconnection(ldap_bind_userid, ldap_bind_password)
        #else:
        #    conn = authinfo.conn

        
        userdn = self.getuserdn(authinfo.conn, token)
        if not userdn: 
            return []

        return [entry['cn'] for entry in self.search(authinfo.conn, self.group_query.basedn, ldap3.SUBTREE, '(member:1.2.840.113556.1.4.1941:=%s)' % userdn, ['cn'])]
    

    
    def issafeAdAuthusername(self, username):
        """[issafeAdAuthusername]
            return True if username can be a safe sAMAccountName
            protect against injection
        Args:
            username ([str]): [user name]

        Returns:
            [bool]: [True or False]
        """

        if not isinstance(username, str): 
            return False

        # username len must be more than 0 and less than 20 chars lens
        if len(username) < 1 or len(username) > 20:
            return False    

        # Check if cstr contains INVALID_CHARS 
        for c in username:
            if c in ODAdAuthProvider.INVALID_CHARS: 
                return False
            if ord(c) < 32: 
                return False

        return True

    def issafeAdAuthpassword(self, password):
        """[issafeAdAuthpassword]
            return True if password can be a safe password
            protect against injection
        Args:
            password ([str]): [user password]

        Returns:
            [bool]: [True or False]
        """

        if not isinstance(password, str): 
            return False

        # password len must be more than 0 and less than 255 chars lens
        if len(password) < 1 or len(password) > 255:
            return False
        
        # Check if str contains chars with ascii value under 32  
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


    def getconnection(self, userid, password ):
        if self.auth_type == 'NTLM':
            # add the domain name to format login as DOMAIN\USER
            userid = self.getadlogin(userid)
        if self.auth_type == 'KERBEROS':
            # create a Kerberos TGT 
            self.krb5_authenticate( userid, password )
        return super().getconnection(userid, password )


    def listprinter( self, filter, **params):
        logger.info('')
        printerlist = []

        userid     = params.get( 'userid', self.userid )
        password   = params.get( 'password',self.password )                
        
        if isinstance(filter, str):
           filter = '(&' + self.printer_query.filter + filter + ')'
        else:
           filter = self.printer_query.filter
        logger.debug('filter %s', filter)
        try:
            # logger.debug('getconnection')
            conn = self.getconnection( userid, password )
            result = self.paged_search(conn, self.printer_query.basedn, filter, self.printer_query.attrs)
            # logger.debug('result %s', result)
            len_printers = len(result)
            logger.info('query result count:%d %s %s ', len_printers, self.printer_query.basedn, filter )

            for dn in result:
                attrs = result.get(dn)
                # attrs must be a dict
                if not isinstance( attrs, dict): 
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
        
        if not isinstance(userid, str) or not isinstance(password, str) :
            logger.info( 'service account not set in config file, listsite return empty site')
            return dictsite

        try:
            logger.debug('getconnection to ldap')
            conn = self.getconnection( userid, password )

            logger.debug('_pagedAsyncSearch %s %s %s ', self.site_query.basedn, self.site_query.filter, self.site_query.attrs)            
            result = self.paged_search(conn, self.site_query.basedn, self.site_query.filter, self.site_query.attrs )            
            # logger.debug('_pagedAsyncSearch return len=%d', len( result ))
            for dn in result:
                attrs = result[dn]

                if attrs is None:
                    logger.info( 'ldap dn=%s has no attrs %s, skipping', str(dn), self.site_query.attrs  )
                    continue

                if not isinstance( attrs, dict): 
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




@oc.logging.with_logger()
class ODAdAuthMetaProvider(ODAdAuthProvider):
    def __init__(self, manager, name, config):
        super().__init__(manager, name, config)
        self.type = 'metaactivedirectory'
        self.join_attributkey = config.get('join_key_ldapattribut')
        if not isinstance( self.join_key_ldapattribut, str ):
            raise ValueError( 'set join_key_ldapattribut is to provider metadirectory service' )
        if not self.is_serviceaccount_defined(config):
            raise InvalidCredentialsError("you must define a service account for Auth provider %s" % self.name)

        # add the join_key_ldapattribut to ODAdAuthProvider.DEFAULT_ATTRS for self.user_query.attrs
        default_attrs=ODAdAuthProvider.DEFAULT_ATTRS
        default_attrs.append( self.join_key_ldapattribut )
        self.user_query.attrs = default_attrs
        # add the join_attributkey as filter query
        # user_filter_join_attributkey = '(' + self.join_attributkey + '=%s))' 
        # self.user_query_join_attributkey = self.user_query
        # self.user_query_join_attributkey.filter = self.user_query.filter.replace( '(sAMAccountName=%s)', user_filter_join_attributkey )


    def validate(self, userid, password, **params):
        """[validate]
            this is a meta directory do not perform a ldap bind using current credentials  

        Args:
            userid ([type]): [description]
            password ([type]): [description]

        Returns:
            [type]: [description]
        """
        return super().validate(userid, password, **params)

    def authenticate(self, userid, password, **params):
        if not self.issafeAdAuthusername(userid) or not self.issafeAdAuthpassword(password):
            raise InvalidCredentialsError('Unsafe credentials')
       
        # validate can raise exception 
        (userdn, conn) = self.validate(userid, password)
    
        data = {    'userid': userid, 
                    'domain': self.domain, 
                    'ad_domain': self.domain,
                    'dn': userdn,
                    'environment': {}
        }

        return (
            { 'userid': userid, 'password': password, 'domain': self.domain },
            AuthInfo(self.name, self.type, userid, data=data, protocol=self.auth_protocol, conn=conn)
        )
        
    def getuserinfo(self, authinfo, **arguments):       
        userid = arguments.get( 'userid' )
        filter = ldap_filter.filter_format( self.user_query.filter, [ userid ] )
        logger.info( 'ODAdAuthMetaProvider:ldap.filter %s', filter)
        usersinfo = self.search_all(    conn=authinfo.conn, 
                                        basedn=self.user_query.basedn, 
                                        scope=self.user_query.scope, 
                                        filter=filter, 
                                        attrs=self.user_query.attrs )

        if not isinstance( usersinfo, list ) or len( usersinfo ) == 0:
            # User does not exist in metadirectory 
            # use login
            logger.error( 'user does not exist in metadirectory, skipping meta query' )
            return None

        if len( usersinfo ) > 1:
            # too much user with the same SAMAccountName 
            # may be Forest SAMAccountName Meta 
            logger.error( 'too much user %s in metadirectory len %d, skipping meta query', userid, len( usersinfo ) )
            logger.error( 'dump metadirectory %s', usersinfo )
            return None

        return usersinfo[0]



@oc.logging.with_logger()
class ODImplicitTLSCLientAdAuthProvider(ODAdAuthProvider):

    def __init__(self, manager, name, config):
        super().__init__(manager, name, config)
        self.dialog_url = config.get( 'dialog_url' )
        if not self.is_serviceaccount_defined(config):
            raise InvalidCredentialsError("you must define a service account for Auth provider %s" % self.name)

    def getclientdata(self):
        data =  super().getclientdata()
        data['dialog_url'] = self.dialog_url
        return data


    def authenticate(self, userid, **params):
        # validate can raise exception 
        # like invalid credentials
        q = self.user_query
        userdn=None

        if not self.issafeAdAuthusername(userid) :
            raise InvalidCredentialsError('Unsafe credentials')

        # get connection using the service account
        conn = self.getconnection(self.userid ,self.password)
        # look for the user in directory service 
        userinfo = self.search_one( conn=conn, basedn=q.basedn, scope=q.scope, filter=ldap_filter.filter_format(q.filter, [userid]), attrs=q.attrs, **params)
        if isinstance(userinfo, dict):
            userdn = userinfo.get('dn')
            # Add always userid entry, make sure this entry exists
            if not isinstance( userinfo.get('userid'), str) :
                userinfo['userid'] = userinfo.get(self.useruidattr)
            # Add always name entry
            if not isinstance( userinfo.get('name'), str) :
                userinfo['name'] = userinfo.get(self.useridattr)
        else:
            raise AuthenticationError('Implicit login user %s does not exist in directory service' % userid)

        data = {    'userid': userid,
                    'dn':     userdn,
                    'environment': self.createauthenv( userid, password=None) }
        
        return (    { 'userid': userid, 'password': None }, 
                      AuthInfo( self.name, self.type, userid, data=data, protocol=self.auth_protocol, conn=conn) )