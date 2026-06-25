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
import datetime
from contextvars import ContextVar
from typing import Optional

from fastapi import HTTPException, Request
from netaddr import IPNetwork, IPAddress

from oc.cherrypy import (
    getclientipaddr,
    getclientreal_ip,
    getclientxforwardedfor_listip,
    getclienthttp_headers,
)
from oc.logging import get_current_request

import oc.logging
import oc.od.acl
import oc.od.services
import oc.auth.jwt
import jwt
import haversine
from oc.od.asnumber import ODASNumber

from oc.auth.authroles import AuthRoles
from oc.auth.authuser import AuthUser
from oc.auth.authinfo import AuthInfo
from oc.auth.authresponse import AuthResponse
from oc.auth.authcache import AuthCache
from oc.auth.authmanager import (
    ODAuthManagerBase,
    ODExternalAuthManager,
    ODExplicitAuthManager,
    ODExplicitMetaAuthManager,
    ODImplicitAuthManager,
)
from oc.auth.authprovider import (
    ODAuthProviderBase,
    ODExternalAuthProvider,
    ODImplicitAuthProvider,
    ODImplicitTLSCLientAuthProvider,
    ODLdapAuthProvider,
    ODAdAuthProvider,
    ODAdAuthMetaProvider,
    ODImplicitTLSCLientAdAuthProvider,
)
from oc.od.error import AuthenticationError, InvalidCredentialsError, AuthenticationFailureError, ExternalAuthError, AuthenticationDenied

# ---------------------------------------------------------------------------
# ContextVar pour le cache d'authentification de la requête courante
# (remplace cherrypy.request.odauthcache)
# ---------------------------------------------------------------------------
_auth_cache_ctx: ContextVar[Optional["AuthCache"]] = ContextVar("_auth_cache_ctx", default=None)


def get_auth_cache() -> Optional["AuthCache"]:
    return _auth_cache_ctx.get()


def set_auth_cache(cache: "AuthCache") -> object:
    return _auth_cache_ctx.set(cache)


def reset_auth_cache(token: object) -> None:
    _auth_cache_ctx.reset(token)


logger = logging.getLogger(__name__)


@oc.logging.with_logger()
class ODAuthTool:

    # define meta manager and provider name
    manager_metaexplicit_name   = 'metaexplicit'
    provider_metadirectory_name = 'metadirectory'
    # define the list of manager supported type
    manager_name_list = [ 'external', 'metaexplicit', 'explicit', 'implicit' ]

    def __init__(self, redirect_url, jwt_config, config):
        self.redirect_url = redirect_url
        self.managers = {}
        self.jwt = oc.auth.jwt.ODJWToken(jwt_config)
        for name,cfg in config.items():
            try:
                # skip the entry if not enabled
                if not cfg.get('enabled', True):
                    self.logger.debug( f"Auth manager {name} is disabled, skipping")
                    continue
                self.logger.debug( f"Adding new Auth manager {name}")
                self.managers[name] = self.createmanager(name,cfg)
            except Exception as e:
                self.logger.exception(e)

    def parse_auth_request(self, request: Request = None) -> "AuthCache":
        """Parse la requête HTTP pour extraire et décoder le token JWT.
        Lit l'en-tête 'ABCAuthorization' de la requête FastAPI.
        """
        authcache = AuthCache()
        req = request or get_current_request()
        if req is None:
            return authcache
        http_request_token = req.headers.get("ABCAuthorization", None)
        if isinstance(http_request_token, str) and http_request_token.startswith( 'Bearer '):
            # remove the 'Bearer ' : len( 'Bearer ') = 7
            request_token = http_request_token[7:]
            # if there is some data to decode
            if len(request_token) > 0 : 
                try:
                    # get the dict decoded token
                    # can raise jwt.exceptions.ExpiredSignatureError: Signature has expired
                    decoded_token = self.jwt.decode( request_token )
                    # read user, roles, auth
                    # Build a cache data to store value from decoded token into an AuthCache object
                    authcache = AuthCache( decoded_token, origin='jwt.decoded')
                    authcache.markAuthDoneFromDecodedToken()
                except jwt.exceptions.ExpiredSignatureError as e:
                    # nothing to do
                    # log the exception as a warning 
                    # and continue with empty authcache
                    authcache.origin = 'jwt.ExpiredSignatureError'
                    self.logger.warning( e )
                except jwt.exceptions.DecodeError as e:
                    # nothing to do log the exception and continue with empty authcache
                    # this is an error
                    authcache.origin = 'jwt.DecodeError'
                    self.logger.error( e )
                except jwt.exceptions.PyJWTError as e:
                    # nothing to do log the exception and continue with empty authcache
                    # this is an error
                    authcache.origin = 'jwt.Error'
                    self.logger.error( e )
                except Exception as e:
                    authcache.origin = 'exceptionError'
                    # nothing to do log the exception and continue with empty authcache
                    self.logger.error( e )
        return authcache

    @property
    def current(self) -> "AuthCache":
        """Retourne le AuthCache pour la requête courante (via ContextVar)."""
        cache = get_auth_cache()
        if cache is None:
            self.logger.debug( 'request is not cached' )
            cache = self.parse_auth_request()
            set_auth_cache(cache)
        else:
            pass
            # self.logger.debug( '->. request is cached .<-' )
        return cache

    @property
    def user(self):
        return self.current.user
 
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
        # self.logger.debug('')
        bReturn = self.current.isValidAuth()
        # self.logger.debug(f"isauthenticated return {bReturn}")
        return bReturn
    
    @property
    def isidentified(self):
        # self.logger.debug('')
        bReturn = False
        if  self.isauthenticated:
            is_valid_user = self.current.isValidUser()
            if  is_valid_user:
                bReturn = True
        # self.logger.debug(f"isidentified return {bReturn}")
        return bReturn
        
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
        self.logger.debug( f"createmanager name={name} {cls}" )
        return cls(name, config)
 
    def findmanager(self, providername, managername=None):
        if managername: 
            return self.getmanager(managername, True)

        if providername:
            provider = self.findprovider(providername)
            if provider: 
                return provider.manager

        raise AuthenticationFailureError(f"Authentication manager not found: manager={managername} provider={providername}, check your configuration file")

    def getmanager(self, name:str, raise_error=False):
        if not isinstance(name, str): 
            if raise_error: 
                raise AuthenticationFailureError('Invalid authentication manager name')
            return None

        manager = self.managers.get(name)
        if not isinstance(manager, ODAuthManagerBase): 
            if raise_error: 
                raise AuthenticationFailureError(f"Undefined authentication manager {name}")
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
            if isinstance( provider, ODAuthProviderBase ): 
                break

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
    

    def reduce_auth_data( self, auth:AuthInfo )->dict:
        """reduce_token
            reduce token data to return only 

        Args:
            auth (_type_): _description_
        """
        auth_data_reduce = {} # return an empty auth_data_reduce by default
        
        if isinstance( auth.data, dict ):
            # filter to this entries
            if isinstance( auth.data.get('domain'), str ):
                auth_data_reduce['domain'] = auth.data.get('domain')
            if isinstance( auth.data.get('labels'), dict ):
                auth_data_reduce['labels'] = {}
                for key, value in auth.data.get('labels').items():
                    if key.isalnum(): # and isinstance(value, str):
                        auth_data_reduce['labels'][key] = value
            
        return auth_data_reduce


    def update_token( self, auth:AuthInfo, user:AuthUser, roles:AuthRoles ):        
        """update_token

            remove unused data
            call reducetoToken() for auth, user, roles
            compute the jwt token

        Args:
            auth (_type_): _description_
            user (_type_): _description_
            roles (_type_): _description_

        Returns:
            _type_: _description_
        """
        # remove unused data
        # call reducetoToken() for auth, user, roles
        # compute the jwt token
       
        # create jwt_auth_reduce
        auth_data_reduce = self.reduce_auth_data( auth )
        jwt_auth_reduce = { 'provider': auth.provider, 'providertype': auth.providertype, 'data': auth_data_reduce }
        # create jwt_user_reduce
        jwt_user_reduce = { 'name': user.get('name'), 'userid': user.get('userid') }
        # create a jwt_role_reduce

        jwt_role_reduce = dict(roles) # copy all data
        # jwt_role_reduce = {}
        
        # encode new jwt 
        jwt_token = self.jwt.encode( auth=jwt_auth_reduce, user=jwt_user_reduce, roles=jwt_role_reduce )

        return jwt_token 

        
    def compiledcondition( self, condition:dict, user:dict, roles:list, provider=None, auth=None, request=None )->bool:

        def isPrimaryGroup(user:dict, primaryGroupID:str)->bool:
            # if user is not a dict return False
            if not isinstance(user, dict):
                return False
            # primary group id is uniqu for
            if user.get('primaryGroupID') == primaryGroupID:
                return True
            return False

        def isTimeAfter( timeafter ):
            return False

        def isTimeBefore( timebefore ):
            return False

        def __isASNumber( ipsource:str, asnumber:str )->bool:
            bReturn = False
            try:
                if isinstance( oc.od.services.services.asnumber, ODASNumber ):
                    bReturn = oc.od.services.services.asnumber.lookup( ipsource, asnumber )
            except Exception as e:
                logger.error( e )
                bReturn = False
            # self.logger.debug( f"ipsource={ipsource} is in network={network} return {bReturn}")
            return bReturn

        def _isASNumber( ipsource:str, asnumber:str )->bool:
            # self.logger.debug(locals())
            if isinstance( asnumber, list ):
                for n in asnumber:
                    if __isASNumber( ipsource, n ):
                        return True
            elif isinstance( asnumber, str ):
                return __isASNumber( ipsource, asnumber )
            return False

        def isASNumber(ipsource:str, asnumber:str )->bool:
            # self.logger.debug(locals())
            if isinstance( ipsource, list ):
                for ip in ipsource:
                    if _isASNumber( ip, asnumber ):
                        return True
            elif isinstance( ipsource, str):
                return _isASNumber( ipsource, asnumber )
            return False


        def isGeoLocation(user:dict, geolocation:dict)->bool:
            # user.get('geolocation'): {accuracy: 14.884, latitude: 48.8555131, longitude: 2.3752174}
            # haversine.haversine()
            user_geolocation = user.get('geolocation')
            if not isinstance( user_geolocation, dict ):
                logger.error( "bad user location type")
                return False

            if not isinstance (geolocation.get('accuracy'), int ):
                 return False

            # format (latitude, longitude)
            user_latitude = user_geolocation.get('latitude')
            user_longitude = user_geolocation.get('longitude')
            if not isinstance( user_longitude, float) or not isinstance( user_longitude, float):
                logger.error( "bad user latitude or longitude type")
                return False
            loc1=( user_latitude, user_longitude)
            loc2=( geolocation.get('latitude'), geolocation.get('longitude') )
            logger.debug( f"isGeoLocation define geolocation {loc1} {loc2}")
            distance = haversine.haversine(loc1,loc2, unit=haversine.Unit.METERS)
            logger.debug( f"isGeoLocation compare {distance} < {geolocation.get('accuracy')} ")
            if distance < geolocation.get('accuracy'):
                return True
            return False

        def isHttpHeader( requestheader:dict, rulesheader:dict )->bool:
            if not isinstance( rulesheader, dict):
                logger.error(f"invalid value type http header {type(rulesheader)}, dict is expected in rule" )
                return False

            for headername in rulesheader.keys():
                if requestheader.get(headername) != rulesheader.get(headername):
                    return False
            return True

        def existHttpHeader( requestheader:dict, rulesheader:list )->bool:
            if not isinstance( rulesheader, list):
                logger.error(f"invalid value type http header {type(rulesheader)}, list is expected in rule" )
                return False

            for headername in rulesheader:
                if requestheader.get(headername) is None:
                    return False
            return True

        def isBoolean( value ):
            if not isinstance(value, bool):
                logger.warning(f"invalid value type boolean {type(value)}, bool is expected in rule")
                return False
            return value

        def isMemberOf(roles:list, groups:list)->bool:
            # self.logger.debug(locals())
            if not isinstance(roles,list):
                roles = [roles]
            if not isinstance(groups,list):
                groups = [groups]
            for m in roles:
                if not isinstance( m, str):
                    continue
                for g in groups:
                    if not isinstance( g, str):
                        continue
                    # logger.debug(f"isMemberOf {m} {g}")
                    if m.lower().startswith(g.lower()):
                        return True
            return False

        def __isinNetwork( ipsource:str, network:str )->bool:
            bReturn = False
            try:
                if IPAddress(ipsource) in IPNetwork( network ):
                    bReturn = True
            except Exception as e:
                logger.error( e )
                bReturn = False
            return bReturn

        def _isinNetwork( ipsource:str, network:str|list )->bool:
            # self.logger.debug(locals())
            if isinstance( network, list ):
                for n in network:
                    if __isinNetwork( ipsource, n ):
                        return True
            elif isinstance( network, str ):
                return __isinNetwork( ipsource, network )
            return False

        def isinNetwork( ipsource:str, network:str|list )->bool:
            # self.logger.debug(locals())
            if isinstance( ipsource, list ):
                for ip in ipsource:
                    if _isinNetwork( ip, network ):
                        return True
            elif isinstance( ipsource, str):
                return _isinNetwork( ipsource, network )
            return False

        def isAttribut(user, attribut, start_with=None, equal=None ):
            # if user is not a dict return False
            if not isinstance(user, dict):
                return False

            if not isinstance( attribut, str ):
                return False

            if not isinstance( start_with, str ) or not isinstance( equal, str ):
                return False

            try:
                attribut_user_value = str( user.get( attribut ) )
                if start_with :
                    return attribut_user_value.startswith( start_with )
                if equal :
                    return attribut_user_value.__eq__( equal )
            except Exception as e:
                self.logger.error(e)
                return False
            return False

        # self.logger.debug(f"condition {condition}" )

        compiled_result = False  # default compiled_result is False

        if type(condition) is not dict :
            return False

        # just a type sanity check
        expected = condition.get('expected')
        if type(expected) is not bool:
            self.logger.warning(f"invalid value type {type(expected)} bool is expected in rule" )

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
            result     = isHttpHeader( getclienthttp_headers(request or get_current_request()), httpheader )
            if result == condition.get( 'expected'):
                compiled_result = True

        httpheader = condition.get('existhttpheader')
        if type(httpheader) is list:
            result     = existHttpHeader( getclienthttp_headers(request or get_current_request()), httpheader )
            if result == condition.get( 'expected'):
                compiled_result = True

        memberOf = condition.get('memberOf') or condition.get('memberof')
        if isinstance(memberOf,str):
            self.logger.debug(f"memberOf is checking for ODAdAuthMetaProvider")
            # read the member LDAP attribut with objectClass=group
            # check if the provider object is an ODAdAuthMetaProvider
            # and auth object is an AuthInfo
            # kwargs can contain 'provider' and 'auth' entries
            if isinstance( provider, ODAdAuthMetaProvider ) and isinstance( auth, AuthInfo):
                self.logger.debug(f"This is a ODAdAuthMetaProvider and auth is AuthInfo")
                self.logger.debug(f"auth.isForeignSecurityPrincipalsWithSid={auth.isForeignSecurityPrincipalsWithSid}")
                if auth.isForeignSecurityPrincipalsWithSid is True:
                    # read the role (memberOf LDAP attribut of objectClass=user)
                    # use string compare if memberOf match
                    # the role have been updated with the meta_provider values
                    # this test run faster than calling meta_provider.isMemberOf
                    result = isMemberOf( roles, memberOf )
                else:
                    # call the isMember method to run LDAP Qeury and
                    # read the member attribut in group
                    # This is not the user's memberOf
                    self.logger.debug( f"this call will take a while")
                    self.logger.debug( f"isMemberOf query to provider={provider.name}")
                    result = provider.isMemberOf( auth, user, memberOf )

            elif isinstance( provider, ODLdapAuthProvider ) and isinstance( auth, AuthInfo):
                self.logger.debug(f"This is a ODLdapAuthProvider and auth is AuthInfo")
                if len(roles) == 0:
                    # run a query on the group cn to list all members
                    #
                    # dn: cn=admin_staff,ou=people,dc=planetexpress,dc=com
                    # objectclass: Group
                    # objectclass: top
                    # groupType: 2147483650
                    # cn: admin_staff
                    # member: cn=Hubert J. Farnsworth,ou=people,dc=planetexpress,dc=com
                    # member: cn=Hermes Conrad,ou=people,dc=planetexpress,dc=com
                    #
                    userdistinguished_name = auth.data.get('dn') # this is the user distinguished name
                    result = provider.isMemberOf( authinfo=auth, user=user, userdistinguished_name=userdistinguished_name, groupdistinguished_name=memberOf )
                else: 
                    # read the role (memberOf LDAP attribut of objectClass=user)
                    # use string compare if memberOf match
                    result = isMemberOf( roles, memberOf )

            self.logger.debug( f"isMemberOf({memberOf}) returns {result}")
            self.logger.debug( f"result == condition.get('expected') -> {result} == {condition.get('expected')}")
            if result == condition.get('expected'):
                compiled_result = True

        geolocation = condition.get('geolocation')
        if type(geolocation) is dict:
            result = isGeoLocation( user, geolocation  )
            if result == condition.get( 'expected'):
                compiled_result = True

        asnumber = condition.get('asnumber')
        if isinstance(asnumber, (str, list) ) :
            ipsource = getclientipaddr(request or get_current_request())
            # self.logger.debug( f"asnumber rules ipsource={ipsource}" )
            result = isASNumber( ipsource, asnumber )
            if result == condition.get( 'expected' ):
                compiled_result = True

        network = condition.get('network')
        if isinstance(network, (str, list) ) :
            ipsource = getclientipaddr(request or get_current_request())
            # self.logger.debug( f"network rules ipsource={ipsource}" )
            result = isinNetwork( ipsource, network )
            if result == condition.get( 'expected' ):
                compiled_result = True

        network = condition.get('network-x-forwarded-for')
        if isinstance(network, (str, list) ) :
            # getclientxforwardedfor_listip return a list of all ip addr
            # self.logger.debug(f"condition network-x-forwarded-for start" )
            ipsources = getclientxforwardedfor_listip(request or get_current_request())
            # self.logger.debug(f"condition network-x-forwarded-for test isinNetwork ipsources={ipsources} network={network}" )
            result = isinNetwork( ipsources, network )
            if result == condition.get( 'expected'):
                compiled_result = True

        network = condition.get('network-x-real-ip')
        if isinstance(network, (str, list) ) :
            # getclientreal_ip return single ip addr
            ipsource = getclientreal_ip(request or get_current_request())
            result = isinNetwork( ipsource, network )
            if result == condition.get( 'expected'):
                compiled_result = True

        network = condition.get('network-client-ip')
        if isinstance(network, (str, list) ) :
            ipsource = getclientipaddr(request or get_current_request())
            result = isinNetwork( ipsource, network )
            if result == condition.get( 'expected'):
                compiled_result = True

        primaryGroup = condition.get('primarygroupid')
        if primaryGroup is not None:
            # always use 'int' type format
            # from https://docs.microsoft.com/en-us/windows/win32/adschema/a-primarygroupid
            # Ldap-Display-Name primaryGroupID
            # Size 4 bytes
            # convert str to int
            if isinstance(primaryGroup,str):
                try:
                    primaryGroup = int(primaryGroup)
                except Exception as e:
                    self.logger.error( f"invalid primarygroupid type convert value {primaryGroup} to int failed {e}")

            if isinstance(primaryGroup,int):
                result = isPrimaryGroup( user, primaryGroup )
                if result == condition.get( 'expected'):
                    compiled_result = True
            else:
                self.logger.error( f"invalid primarygroupid type int is expected, get {type(primaryGroup)}" )

        attribut_dict = condition.get('attribut')
        if type(attribut_dict) is dict:
            attribut   = attribut_dict.get( 'attribut')
            startwith  = attribut_dict.get( 'startwith')
            equal      = attribut_dict.get( 'equal')
            result = isAttribut( user, attribut, startwith, equal )
            if result == condition.get('expected'):
                compiled_result = True

        # self.logger.debug( f"compiledcondition -> {compiled_result}")
        return compiled_result

    def compiledrule( self, name:str, rule:dict, thread_compiled_result, user, roles, provider=None, auth=None, request=None ):

        if not isinstance(rule,dict) :
            return False
        
        conditions  = rule.get('conditions')
        expected    = rule.get('expected')

        if not isinstance(expected,bool):
            self.logger.warning(f"invalid value type {type(expected)}, bool is expected in rule" )
            return False
        
        results = []
        for condition in conditions :
            r = self.compiledcondition(condition, user, roles, provider, auth, request)
            results.append( r )

        # if results is empty return False
        if len(results) == 0:
            return False

        compiled_result = all( results )
        result = compiled_result == expected
        thread_compiled_result[name] = result
        logger.debug( f"{name} rules {conditions} (compiled_result={compiled_result})==(expected=={expected}) return result={result}" )
        return result


    def compiledrules( self, rules:dict, user:dict, roles, provider=None, auth=None, use_memcache=False, memcache=None, request=None ):
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
        self.logger.debug('')
        
        # default values
        buildcompiledrules = {}
        # add builtin additional tags
        # always add 
        # - ipsource tag
        # - asnumber tag if not none
        # - all user info values with prefix 'user.' to avoid conflict with other tags
        ipsource = getclientipaddr(request or get_current_request())
        buildcompiledrules[ 'ipsource' ] = ipsource
        asnumber = oc.od.services.services.asnumber.getasn( ipsource )
        if isinstance( asnumber, str ): 
            buildcompiledrules[ 'asnumber' ] = asnumber

        # add rules 
        if not isinstance( rules, dict ):
            return buildcompiledrules

        thread_compiled_result = {}
        for name in rules.keys():
            thread_compiled_result[name] = None

        for name in rules.keys():
            try: 
                resultcompiled = self.compiledrule( name, rules.get(name), thread_compiled_result, user, roles, provider, auth, request )
                if resultcompiled is True:
                        k = rules.get(name).get('label')
                        # if a label exists
                        if isinstance(k, str):
                            # set the label value
                            # 'true' by default or the load value defined in config file
                            buildcompiledrules[ k ] = rules.get(name).get('load', 'true')
            except Exception as e:
                self.logger.error(f"rules {name} compilation failed {e} skipping rule")


        """
        # same version with thread support 
        compilerule_timeout = 640 # seconds
        threads = {}

        for name in rules.keys():
            try: 
                threads[name] = threading.Thread(
                    target=self.compiledrule,
                    args=[ name, rules.get(name), thread_compiled_result, user, roles, provider, auth ]
                )

                threads[name].start()
                logger.debug( f"thread[{name}] is starting id {threads[name].ident}")
            except Exception as e:
                self.logger.error( 'rules %s compilation failed %s, skipping rule', name, e)

        for name in threads.keys():
            logger.debug( f"thread[{name}] {threads[name].ident} is joining")
            threads[name].join( timeout=compilerule_timeout )
            if  threads[name].isAlive():
                # timeout expired
                self.logger.error( 'rules %s compilation failed with timeout', name )
                pass

            # logger.debug( f"rule={name} compiled_result={compiled_result}")
            if thread_compiled_result.get(name) is True:
                try:
                    k = rules.get(name).get('label')
                    # if a label exists
                    if k is not None:
                        # set the label value
                        # true by default or the load value
                        buildcompiledrules[ k ] = rules.get(name).get('load', 'true')
                except Exception as e:
                    self.logger.error( 'rules %s compilation failed %s, skipping rule', name, e)
        """

        return buildcompiledrules


    def findproviderusingrules(self, manager:str ):
        provider = None # default value

        # get explicit manager dict
        managers = self.managers.get(manager)
        if not isinstance(managers, ODExplicitAuthManager):
            raise AuthenticationFailureError(f"no authentication manager found {manager}" )

        # get provider dict for explicit manager
        providers = managers.providers
        if not isinstance(providers, dict):
            raise AuthenticationFailureError('no authentication provider found')

        # if there is only one provider then return the only one
        if len( providers ) == 1:
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



    def metalogin(self, provider:str, manager=None, **arguments): 
        """ [metalogin]
            same as login but use meta directory to select user informations like DOMAIN \\ SAMAccountName 
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

        self.logger.debug('')

        # take time to mesure time of login call
        server_utctimestamp = self.mesuretimeserver_utctimestamp(arguments=arguments)

        ( mgr_meta, provider_meta ) = self.get_metalogin_manager_provider()
        if  not isinstance( mgr_meta, ODExplicitMetaAuthManager) or \
            not isinstance( provider_meta, ODAdAuthMetaProvider):
            # no metaexplicit manager has been defined or no metaexplicit provider has been defined 
            self.logger.debug( 'skipping metalogin, no metaexplicit manager or no metadirectory provider has been defined')
            return self.login(provider, manager, **arguments)

        # 
        # do authenticate using service account to the metadirectory provider
        #
        try:
            auth = provider_meta.authenticate( provider_meta.userid, provider_meta.password )  
        except Exception as e:
            # no authenticate 
            self.logger.error( f"skipping metalogin, authenticate failed {e}")
            return self.login(provider, manager, **arguments)

        #
        # find user in metadirectory entries if exists
        # if an error occurs rollback to default login
        #
        metauser = None
        try:
            metauser = provider_meta.getuserinfo( auth, **arguments ) 
        except Exception as e:
            # no user provider has been found
            self.logger.error( f"skipping metalogin, no metauser getuserinfo error {e}" )
            return self.login(provider, manager, **arguments)
        
        if not isinstance( metauser, dict):
            # no user provider has been found
            # an error occurs in meta directory query
            self.logger.error( 'skipping metalogin, no metauser found' )
            return self.login(provider, manager, **arguments)

        # 
        # postpone with user domain sid 
        roles = provider_meta.getroles( auth, metauser, **arguments)
        if not isinstance(roles, list):
           raise AuthenticationFailureError( f"mgr.getroles provider={provider} error" )
        self.logger.debug( f"mgr.getroles provider={provider} success") 

        # check if acl matches with tag
        if not oc.od.acl.ODAcl().isAllowed( auth, provider_meta.acls ):
             raise AuthenticationDenied( 'Access is denied by security policy')
        
        new_login = metauser.get( provider_meta.join_key_ldapattribut )

        if not isinstance( new_login, str ):
            self.logger.debug( f"invalid object type(new_login)={type(new_login)} {provider_meta.join_key_ldapattribut}"  )
            return self.login(provider, manager, **arguments)

        providers_list = self.listprovider( manager_name='explicit' )
        (new_domain,new_userid) = ODAdAuthProvider.splitadlogin( new_login )
        new_provider = self.findproviderbydomainprefix( providers=providers_list, domain=new_domain ) 

        if not isinstance(new_provider, ODAdAuthProvider ):
            self.logger.error( f"provider domain={new_domain} to authenticate user={new_userid} is not defined" )
            raise AuthenticationFailureError(f"Can't find a provider for domain={new_domain} to authenticate user={new_userid}, check your config file" )

        # now we have found a new provider 
        # dump this info in log file
        # and them run auth
        self.logger.info( f"metadirectory replay from provider {provider_meta.name} -> {new_provider.name} from user {arguments.get('userid')} -> {new_userid} from domain {provider_meta.domain} -> {new_domain}" )

        # update login with new data from meta directory
        arguments[ 'userid'   ] = new_userid
        arguments[ 'provider' ] = new_provider.name
        arguments[ 'manager'  ] = 'explicit'

        # let's authenticate user with this provider 
        userloginresponse = self.login(**arguments)

        # if auth is successful 
        if  hasattr( userloginresponse, 'success')  and  userloginresponse.success is True and  \
            hasattr( userloginresponse, 'result')   and  isinstance( userloginresponse.result, AuthCache ) : 

            # now it's time to query for foreign keys to the meta provider
            # if the metaprovider has rules defined
            # then compile data using rules
            # and runs the rules to get associated labels tag
            # in most cases it use the memberof
            # self.logger.debug('== Query meta provider ==')
            # self.logger.debug(f"userloginresponse.result={userloginresponse.result}")
            # self.logger.debug(f"userloginresponse.result.user={userloginresponse.result.user}")
            # self.logger.debug(f"userloginresponse.result.user.get('objectSid')={userloginresponse.result.user.get('objectSid')}")

            # 
            # do authenticate using the user's credential to the metadirectory provider
            #
            try:
                # close previous auth
                self.logger.debug('close previous auth')
                # in kerberos auth mode 
                # we could keep TGT in memory
                # but for ntlm there is no stored in memory object
                # so we need to call provider_meta.finalize
                # and replay another auth 
                provider_meta.finalize(auth)
                self.logger.debug(' provider_meta.finalize(auth) done')

                #
                # newmetaprovider is a metaprovider with user auth config
                # the newmetaprovider is ephemral
                # make a copy of this provider_meta
                # to update the object's attributs 
                newmetaprovider = provider_meta.deepcopy()
                # update authentification 
                # get the domain, realm, kerberos config from the user domain
                # and set it to the new meta provider 
                newmetaprovider.updateauthentificationconfigfromprovider( new_provider )

                # replay an new auth to the provider_meta with the new login and the password
                self.logger.debug('replay an new auth to the provider_meta with the new login and the password')
                metaAuthInfoForUser = newmetaprovider.authenticate( arguments[ 'userid' ], arguments['password'] )

				# if the new_provider ( in fact the user's provider ) can only do auth
                # and doesn't allow ldap query
                # then we can't get the sid. objectSid will be None
                objectSid=userloginresponse.result.user.get('objectSid')
                if isinstance(objectSid, str) and len(objectSid)>0:
                    #  getrole_ForeignSecurityPrincipals( self, authinfo:AuthInfo, objectSid:str )
                    metaAuthInfoForUserRoles = newmetaprovider.getrole_ForeignSecurityPrincipals( authinfo=metaAuthInfoForUser, objectSid=objectSid )
                    # self.logger.debug(f"roles={roles}")
                    if isinstance(metaAuthInfoForUserRoles, list):
                        roles = roles + metaAuthInfoForUserRoles
                    metaAuthInfoForUser.isForeignSecurityPrincipalsWithSid=True
                self.logger.debug(f"roles={roles}")
                self.logger.debug(f"metaAuthInfoForUser.isForeignSecurityPrincipalsWithSid={metaAuthInfoForUser.isForeignSecurityPrincipalsWithSid}")

                # compile rules with the new usermetaauthinfo
                self.logger.debug('compiledrules')
                metaAuthInfoForUserLabels = self.compiledrules( newmetaprovider.rules, metauser, roles, provider=newmetaprovider, auth=metaAuthInfoForUser )
                # dump metaAuthInfoForUserLabels
                self.logger.debug( f"compiled rules metaAuthInfoForUserLabels {metaAuthInfoForUserLabels}" )
                # update the  auth.data['labels'] with the new metaAuthInfoForUserLabels
                auth.data['labels'].update( metaAuthInfoForUserLabels )
                # dump updated auth.data['labels']
                self.logger.info( f"compiled rules get labels {auth.data['labels']}" )

                # overwrite the previous login auth_duration_in_milliseconds
                # with the metalogin auth_duration_in_milliseconds
                auth_duration_in_milliseconds = self.mesuretimeserver_auth_duration(server_utctimestamp)

                # userloginresponse.result is an AuthCache 
                # overwrite role to reduce data if need 
                reduced_roles = newmetaprovider.reduce_roles_for_jwt( roles )

                #
                # buid a AuthCache as response result
                metaauthcache = AuthCache( 
                    dict_token={ 'auth': vars(auth), 'user': metauser, 'roles': reduced_roles }, 
                    auth_duration_in_milliseconds=auth_duration_in_milliseconds 
                ) 

                # merge userloginresponse with metaauthdata
                userloginresponse.result.merge( metaauthcache )
            
                userloginresponse.reason=f"a.Authentication on {provider_meta.getdisplaydescription()} via {new_provider.getdisplaydescription()} successful in {auth_duration_in_milliseconds:.2f} s"  # float two digits after comma

            except Exception as e:
                # no authenticate 
                self.logger.error( f"skipping metalogin, authenticate failed {e}")

        return userloginresponse


        
    def findproviderbydomainprefix( self, providers:list, domain:str ):
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
            if p.domain is None:
                continue
            if p.domain.upper() == domain :
                self.logger.debug( f"provider.name {p.name} match for domain {domain}") 
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


    def logintrytofindaprovider( self, manager:str ):
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
                raise AuthenticationFailureError(message='No authentication default provider can be found')
        return provider


    def mesuretimeserver_utctimestamp( self, arguments ):
        # mesure time betwwen client and serveur at the first time 
        # before all auth processing
        # show profiler time diff
        user_utctimestamp = arguments.get('utctimestamp')
        server_utctimestamp = datetime.datetime.now().timestamp()*1000
        if isinstance(user_utctimestamp, int):
            # convert server_utctimestamp to milliseconds
            arguments['difftime'] = server_utctimestamp - user_utctimestamp
            self.logger.debug(f"Diff between server-client {arguments['difftime']} in milliseconds")
        return server_utctimestamp

    def mesuretimeserver_auth_duration( self,server_utctimestamp):
        server_endoflogin_utctimestamp = datetime.datetime.now().timestamp()*1000
        auth_duration_in_milliseconds = (server_endoflogin_utctimestamp - server_utctimestamp)/1000 # in float second
        return auth_duration_in_milliseconds

    def update_user_resqueted_executeclassname(self, auth:AuthInfo, user_requested_features:dict)->None:
        # update auth.data['labels'] with user_requested_features entries
        if not isinstance( user_requested_features ,dict ):
            return
        
        # filter to ['executeclassname']
        for feature_name in ['executeclassname'] :
            feature_value = user_requested_features.get(feature_name)
            if not isinstance( feature_value, str) :
                return
            
            self.logger.debug( 
                f"previous auth.data['labels']['{feature_name}']={auth.data['labels'].get(feature_name)} updating value to auth.data['labels']['{feature_name}']='{feature_value}'" 
            )
            
            auth.data['labels'][feature_name] = feature_value


    def login(self, provider:str, manager=None, **arguments):  
        self.logger.debug('')
        auth = None # must be define to prevent referenced before assignment exception
        pdr  = None # must be define to prevent referenced before assignment exception
        response = AuthResponse(self)
        try:
            # take time to mesure time of login call
            server_utctimestamp = self.mesuretimeserver_utctimestamp(arguments=arguments)

            # if provider is None, it must be an explicit manager 
            if not isinstance(provider, str):
                # provider is None
                # can raise exception
                # do everythings possible to find one provider
                self.logger.debug( f"provider is None, login is trying to find a provider using manager={manager}" )
                provider = self.logintrytofindaprovider( manager )
                
            # look for an auth manager
            mgr = self.findmanager(provider, manager)

            # get the provider object from the provider name
            pdr = mgr.getprovider(provider, raise_error=True)
                 
            # do authenticate with the auth manager
            self.logger.debug( f"pdr.authenticate provider={provider} start") 
            auth = pdr.authenticate( **arguments)
            self.logger.debug( f"pdr.authenticate provider={provider} done") 

            if not isinstance( auth, AuthInfo ):
                raise AuthenticationFailureError('No authentication provided')
            
            # uncomment this line only to dump password in clear text format
            # self.logger.debug( f"mgr.getuserinfo arguments={arguments}")   
            self.logger.debug( f"pdr.getuserinfo provider={provider} start")          
            userinfo = pdr.getuserinfo( auth, **arguments)
            self.logger.debug( f"pdr.getuserinfo provider={provider} done")  
            if not isinstance(userinfo, dict ):
                raise AuthenticationFailureError(f"getuserinfo return {type(userinfo)} provider={provider}")
 
            # 
            # create claims with auth and userinfo
            self.logger.debug( f"pdr.createclaims provider={provider} start") 
            pdr.createclaims( auth, userinfo, **arguments )
            self.logger.debug( f"pdr.createclaims provider={provider} done") 
            
            #
            # get roles 
            self.logger.debug( f"pdr.getroles provider={provider} start")             
            roles = pdr.getroles( auth, userinfo, **arguments)
            self.logger.debug( f"pdr.getroles provider={provider} done") 
            if not isinstance(roles, list):
                raise AuthenticationFailureError( f"pdr.getroles provider={provider} error" )

            # check if acl matches with tag
            if not oc.od.acl.ODAcl().isAllowed( auth, pdr.acls ):
                 raise AuthenticationDenied( 'Access is denied by security policy')

            # if the provider has rules defined then 
            # compile data using rules
            # runs the rules to get associated labels tag
            auth.data['labels'] = self.compiledrules( rules=pdr.rules, user=userinfo, roles=roles, provider=pdr, auth=auth )

            # update auth.data['labels']['executeclassname'] 
            # if user requests feature executeclassname
            self.update_user_resqueted_executeclassname( auth, arguments.get('features') )
            
            # dump labels for debug 
            self.logger.debug( f"labels {auth.data.get('labels')}")
            # end of auth, mesuretimeserver_auth_duration
            auth_duration_in_milliseconds = self.mesuretimeserver_auth_duration(server_utctimestamp)

             # overwrite role to reduce data if need to reduce roles for jwt
            reduced_roles = pdr.reduce_roles_for_jwt( roles )

            # build a AuthCache as response result 
            myauthcache = AuthCache( 
                { 'auth': vars(auth), 'user': userinfo, 'roles': reduced_roles }, 
                auth_duration_in_milliseconds=auth_duration_in_milliseconds 
            ) 

            reason = f"a.Authentication on { pdr.getdisplaydescription() } successful in {auth_duration_in_milliseconds:.2f} s" # float two digits after comma
            response.update( manager=mgr, result=myauthcache, success=True, reason=reason )
            
        finally:
            if isinstance( pdr, ODAuthProviderBase):
                pdr.finalize( auth, **arguments)

        return response


    def su(self, source_provider_name, arguments):

        # look for the current provider source_provider_name
        source_provider = self.findprovider(source_provider_name)
        if source_provider.explicitproviderapproval is None:
            raise AuthenticationFailureError( f"provider {source_provider.providername} has no explicitproviderapproval" )
        
        # read the explicitproviderapproval from the source_provider
        target_provider_name = source_provider.explicitproviderapproval
        target_provider = self.findprovider(target_provider_name)

        # check if provider is a valid object 
        if not isinstance( target_provider, ODAuthProviderBase ):
            raise AuthenticationFailureError( f"provider {target_provider_name} is not approvable" )
        
        # check if target manager is an explicit manager
        if not isinstance( target_provider.manager, ODExplicitAuthManager ):    
            raise AuthenticationFailureError( f"provider explicitproviderapproval {source_provider.explicitproviderapproval} must be an explicit Auth Manager" )

        # do authenticate 
        response = self.login( provider=target_provider.name, manager=None, **arguments)
        return response

    def authenticate(self, provider:str,  manager=None, **arguments):
        return self.findmanager(provider, manager).authenticate(provider, **arguments)

    def getuserinfo(self, provider:str, authinfo:AuthInfo, manager=None, **arguments):
        return self.findmanager(provider, manager).getuserinfo(provider, authinfo, **arguments)

    def createclaims(self, provider:str, authinfo:AuthInfo, userinfo, manager=None, **arguments):
        return self.findmanager(provider, manager).createclaims(provider, authinfo, userinfo, **arguments)

    def getroles(self, provider:str, authinfo:AuthInfo, userinfo, manager=None, **arguments):
        return self.findmanager(provider, manager).getroles(provider, authinfo, userinfo, **arguments)

    def finalize(self, provider:str, authinfo:AuthInfo, manager=None, **arguments):
        return self.findmanager(provider, manager).finalize(provider, authinfo, **arguments)

    def authorize(self, allow_anonymous: bool = False, allow_authentified: bool = True) -> None:
        if allow_anonymous is True:
            return
        if not self.provider or not self.providertype:
            raise HTTPException(status_code=401, detail='Invalid token')
        if not allow_authentified:
            raise HTTPException(status_code=401, detail='Unauthorized')    

    def logout(self, provider, authinfo, manager=None, **arguments):
        """[logout]
        """
        return self.findmanager(provider, manager).logout(provider, authinfo, **arguments)
