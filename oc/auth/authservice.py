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
import mergedeep
import copy
import requests
import json
import crypt
import datetime
import re
from urllib.parse import urlparse
from ldap import filter as ldap_filter
import ldap3

#
# from ldap3.utils.log import set_library_log_detail_level, get_detail_level_name, set_library_log_hide_sensitive_data, EXTENDED
# set_library_log_detail_level(EXTENDED)
# set_library_log_hide_sensitive_data(False)
# 

import gssapi       # kerberos import
import haversine    # haversine import for geolocalization
import chevron      # for citrix All_Regions.ini

# OAuth lib
from requests_oauthlib import OAuth2Session

from threading import Lock
from collections import OrderedDict
from oc.cherrypy import getclientipaddr, getclientreal_ip, getclientxforwardedfor_listip, getclienthttp_headers
from netaddr import IPNetwork, IPAddress


import oc.logging
import oc.pyutils as pyutils
import oc.od.resolvdns
import jwt
import oc.auth.jwt
import oc.od.acl
import oc.lib
from oc.od.error import AuthenticationError, InvalidCredentialsError, AuthenticationFailureError, ExternalAuthError, AuthenticationDenied

logger = logging.getLogger(__name__)


# define some const
# max len for linux username (uid)
UID_MAX_LENGTH = 32
# max len KERBEROS USERNAME
KRB5_UID_MAX_LENGTH = 256
# max len KERBEROS PASSWORD
KRB5_PASSWORD_MAX_LENGTH = 256
# max len LDAP BIND LOGIN
LDAP_UID_MAX_LENGTH = 256
# max len LDAP PASSWORD
LDAP_PASSWORD_MAX_LENGTH = 64


#
# define AuthRoles
class AuthRoles(dict):
    def __init__(self,entries):
        if isinstance(entries,dict):
            super().__init__(entries)

    def __getattr__(self, name):
        return self.get(name)

    def __getitem__(self, key):
        return getattr(self, key, None)

    def merge(self, newroles ):
        if not isinstance( newroles, AuthRoles):
              raise ValueError('merge error invalid roles AuthRoles object type %s', str( type(newroles) ) )
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
              raise ValueError(f"merge error invalid user AuthUser object type {type(newuser)}")
        mergedeep.merge(newuser, self, strategy=mergedeep.Strategy.ADDITIVE) 
        return newuser

    def isValid( self ):
        return not(not self.get('userid') )

    def getPosixAccount( self ):
        posixaccount = None
        posixdata = self.get('posix')
        if isinstance( posixdata, dict):
            posixaccount = AuthUser.getdefaultPosixAccount( 
                uid=posixdata.get('uid'),
                gid=posixdata.get('gid'),
                uidNumber=posixdata.get('uidNumber'),
                gidNumber=posixdata.get('gidNumber'),
                homeDirectory=posixdata.get('homeDirectory'),
                description=posixdata.get('description'),
                groups=posixdata.get('groups'),
                gecos=posixdata.get('gecos') )
        return posixaccount
        
    def isPosixAccount( self ):
        bPosix = isinstance( self.get('posix'), dict)
        return bPosix

    @staticmethod
    def getConfigdefaultPosixAccount():
        return AuthUser.getdefaultPosixAccount( 
            uid=oc.od.settings.getballoon_loginname(),
            gid=oc.od.settings.getballoon_groupname(),
            uidNumber=oc.od.settings.getballoon_uidNumber(),
            gidNumber=oc.od.settings.getballoon_gidNumber(),
            homeDirectory=oc.od.settings.getballoon_homedirectory(),
            loginShell=oc.od.settings.getballoon_loginShell(),
            description='abcdesktop default account'
        )

    @staticmethod
    def getPosixAccountfromlocalAccount( localaccount:dict )->dict:
        if not isinstance(localaccount, dict):
            localaccount = AuthUser.getConfigdefaultPosixAccount()
        return AuthUser.getdefaultPosixAccount( 
            uid=localaccount.get('uid',oc.od.settings.getballoon_loginname()),
            gid=localaccount.get('gid',oc.od.settings.getballoon_groupname()),
            uidNumber=localaccount.get('uidNumber', oc.od.settings.getballoon_uidNumber()),
            gidNumber=localaccount.get('gidNumber',oc.od.settings.getballoon_gidNumber()),
            homeDirectory=localaccount.get('homeDirectory',oc.od.settings.getballoon_homedirectory()),
            loginShell=localaccount.get('loginShell',oc.od.settings.getballoon_loginShell()),
            description=localaccount.get('description','abcdesktop default account')
        )

    @staticmethod
    def getdefaultPosixAccount( uid, gid, uidNumber, gidNumber, cn=None, homeDirectory=None, loginShell=None, description=None, groups=None, gecos=None ):
        # https://ldapwiki.com/wiki/PosixAccount
        # The ObjectClass Type is defined as:
        # OID: 1.3.6.1.1.1.2.0
        # NAME: PosixAccount
        # MUST: cn uid uidNumber gidNumber homeDirectory

        # fix missing value if need
        if not isinstance(cn, str): 
            cn = uid
        if not isinstance(gid, str): 
            gid = uid
        if not isinstance(homeDirectory, str): 
            homeDirectory='/home/' + str(uid)
        if not isinstance(loginShell, str): 
            loginShell=oc.od.settings.balloon_shell

        defaultposixAccount = { 
            'cn':cn, 
            'uid':uid, 
            'gid':gid, 
            'uidNumber':uidNumber, 
            'gidNumber':gidNumber, 
            'homeDirectory':homeDirectory, 
            'loginShell':loginShell, 
            'description':description,
            'groups': groups,
            'gecos': gecos
        }
        return defaultposixAccount

    @staticmethod
    def mkpasswd( moustachedata ):  
        passwd = chevron.render( oc.od.settings.DEFAULT_PASSWD_FILE, moustachedata )
        return passwd

    @staticmethod
    def mksupplementalGroups(moustachedata:dict)->list:
        supplementalGroups = None
        groups = moustachedata.get('groups')
        if isinstance( groups, list ):
            supplementalGroups = []
            for group in groups:
                supplementalGroups.append(group['gidNumber'])
        return supplementalGroups

    
    @staticmethod
    def mkgroup ( moustachedata ):  
        etcgroup = chevron.render( oc.od.settings.DEFAULT_GROUP_FILE,  moustachedata )
        groups = moustachedata.get('groups')
        logger.debug( f"add user groups {groups}" )
        if isinstance( groups, list ):
            for group in groups:
                newline = f"{group['cn']}:x:{group['gidNumber']}:"
                uids = group.get('memberUid')
                logger.debug( f"add user memberUid: {uids}" )
                if isinstance(uids, str):
                    newline += uids
                if isinstance(uids, list) and len(uids) > 0:
                    n=0
                    for uid in uids:
                        newline += uids[n]
                        n=n+1
                        break
                    for uid in uids[n::]:
                        newline += ',' + uid
                logger.debug( f"new line for /etc/group:\n{newline}\n" )
                etcgroup += '\n' + newline
            etcgroup += '\n'
        return etcgroup
                    
    @staticmethod
    def mkgshadow ( moustachedata ):  
        gshadow = chevron.render( oc.od.settings.DEFAULT_GSHADOW_FILE,  moustachedata )
        groups = moustachedata.get('groups')
        if isinstance( groups, list ):
            for group in groups:
                # lpadmin:!::root
                newline = f"{group['cn']}:!::"
                uids = group.get('memberUid')
                if isinstance( uids, str ):
                    newline += uids
                if isinstance( uids, list ):
                    if len(uids) > 0:
                        newline += uids[0]
                        for uid in uids[1::]:
                            newline += ',' + uid
                gshadow += '\n' + newline
            gshadow += '\n'
        return gshadow

    @staticmethod
    def mkshadow( moustachedata ):  
        return chevron.render( oc.od.settings.DEFAULT_SHADOW_FILE, moustachedata )


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
        # labels entry must exixts in data
        if not isinstance( data.get('labels'), dict ):
            data['labels'] = {}
        self.data = data
         # claims must be a dict
        if not isinstance( claims, dict ):
           claims = {}
        self.claims = claims
        self.conn = conn
        self.isAuthDoneFromDecodedToken = False

    def __getitem__(self, key):
        return getattr(self, key, None)

    def get(self, key):
        return self[key]

    def get_labels(self):
        return self.data['labels']

    def get_claims(self, key):
        return self.claims.get(key)

    def set_claims( self, claims):
        self.claims = claims

    def set_data( self, data):
        self.data = data

    def get_identity(self):
        if isinstance( self.claims, dict ):
            return self.claims.get('identity')
        return {}

    def get_localaccount(self):
        localaccount = self.get_identity().get('localaccount')
        return localaccount

    def isValid(self):
        bReturn = False
        try:
            bReturn = not not (self.provider and self.isAuthDoneFromDecodedToken)
        except Exception:
            pass
        return bReturn
    
    def markAuthDoneFromDecodedToken(self, isDecodedToken=True):
        self.isAuthDoneFromDecodedToken = isDecodedToken

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
       
    def update( self, manager, result, success, reason='' ):
        self.manager = manager
        self.result=result
        self.success=success
        self.reason=reason
        
class AuthCache(object):
    NotSet  = object()

    def __init__(self, dict_token=None, auth_duration_in_milliseconds=None, origin=None):
        self.reset()
        if isinstance(dict_token, dict):
            self.setuser( dict_token.get('user'))
            self.setauth( dict_token.get('auth'))            
            self.setroles( dict_token.get('roles'))
        self._origin = origin
        self.auth_duration_in_milliseconds = auth_duration_in_milliseconds

    def markAuthDoneFromDecodedToken(self):
        self._auth.markAuthDoneFromDecodedToken()

    @property
    def origin( self ):
        return self._origin

    @origin.setter
    def origin(self, value):
        self._origin = value

    def reset(self):
        """[reset]
            Clear all previous cached data
            set internal cached value to AuthCache.NotSet
        """
        self._user  = AuthCache.NotSet
        self._roles = AuthCache.NotSet        
        self._auth  = AuthInfo()
        self._origin = None
        self.auth_duration_in_milliseconds = None

    @property 
    def user(self):
        return self._user
    
    def setuser( self, valuedict ):
        self._user = AuthUser( valuedict )

    def isValidUser(self):
        # != AuthCache.NotSet and not(not self._user.userid)
        isvalid = isinstance(self._user, AuthUser) and self._user.isValid()
        return isvalid
            
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
        """merge
            merge data with authprovider source to self
            example two active directories with relationship 
                    but with different groups and rules
        Args:
            new_authcache (AuthInfo): AuthInfo
        """
        # read user and roles from another authinfo
        # merge data from new_authcache to self
        self._user  = self.user.merge(new_authcache._user)
        self._roles = self.roles.merge(new_authcache._roles)
        self._auth  = self.auth.merge(new_authcache._auth)




@oc.logging.with_logger()
class ODAuthTool(cherrypy.Tool):

    # define meta manager and provider name
    manager_metaexplicit_name   = 'metaexplicit'
    provider_metadirectory_name = 'metadirectory'
    # define the list of manager supported type
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
                self.logger.info( 'Adding Auth manager %s', name)
                self.managers[name] = self.createmanager(name,cfg)
            except Exception as e:
                self.logger.exception(e)

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
        authcache = AuthCache()
        
        # by default user token use Authorization HTTP Header
        http_request_token = cherrypy.request.headers.get('ABCAuthorization', None)
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
    def current(self):
        # check if we can use cached request data 
        # to prevent decode twice update the request object 
        # by adding the cherrypy.request.odauthcache attribut
        if not hasattr(cherrypy.request, 'odauthcache') :  
            # attr is not found
            # parse_auth_request() will decode the token 
            # self.logger.debug( "current http request has no odauthcache" ) 
            cherrypy.request.odauthcache = self.parse_auth_request()    
        else:
            # self.logger.debug( f"current http request has cached odauthcache" ) 
            pass           
        return cherrypy.request.odauthcache 

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
        self.logger.info( 'createmanager name=%s %s', name, cls )
        return cls(name, config)
 
    def findmanager(self, providername, managername=None):
        if managername: 
            return self.getmanager(managername, True)

        if providername:
            provider = self.findprovider(providername)
            if provider: 
                return provider.manager

        raise AuthenticationFailureError('Authentication manager not found: manager=%s provider=%s, check your configuration file' % (managername,providername))

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
    

    def reduce_auth_data( self, auth ):
        """reduce_token
            reduce token data to return only 

        Args:
            auth (_type_): _description_
        """
        auth_data_reduce = {} # return an empty auth_data_reduce by default

        if isinstance( auth.data, dict ):
            # filter to this entries
            for entry in [ 'domain', 'labels' ] :
                if auth.data.get(entry) :
                    auth_data_reduce[entry] = auth.data.get(entry)

        return auth_data_reduce


    def update_token( self, auth, user, roles=None ):        
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

        # create jwt_role_reduce (futur usage) 
        # roles=None as default parameter 
        jwt_role_reduce = {} 
        # encode new jwt 
        jwt_token = self.jwt.encode( auth=jwt_auth_reduce, user=jwt_user_reduce, roles=jwt_role_reduce )

        return jwt_token 

        
        
    def compiledcondition( self, condition, user, roles, **kwargs ):     

        def isPrimaryGroup(user, primaryGroupID):
            # if user is not a dict return False
            if not isinstance(user, dict):
                return False

            # primary group id is uniqu for
            if user.get('primaryGroupID') == primaryGroupID:  
                return True
            return False

        #def isTimeAfter( timeafter ) :
        #    return False
        #
        #def isTimeBefore( timebefore ) :
        #    return False


        def isGeoLocation(user, geolocation):
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

        def isHttpHeader( requestheader, rulesheader ):
            if not isinstance( rulesheader, dict):
                logger.error(f"invalid value type http header %s, dict is expected in rule {type(rulesheader)}" )
                return False  

            for headername in rulesheader.keys():
                if requestheader.get(headername) != rulesheader.get(headername):
                    return False
            return True

        def existHttpHeader( requestheader, rulesheader ):
            if not isinstance( rulesheader, list):
                logger.error(f"invalid value type http header %s, list is expected in rule {type(rulesheader)}" )
                return False  

            for headername in rulesheader:
                if requestheader.get(headername) is None:
                    return False
            return True

        def isBoolean( value ):
            if not isinstance(value, bool):
                logger.warning('invalid value type boolean %s, bool is expected in rule', type(value) )
                return False  

            return value

        def isMemberOf(roles, groups )->bool:
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
                    logger.debug(f"isMemberOf {m}  {g}")
                    if m.lower().startswith(g.lower()):
                        return True
            return False

        def __isinNetwork( ipsource, network )->bool:
            try:
                if IPAddress(ipsource) in IPNetwork( network ):
                    return True
            except Exception as e:
                logger.error( e )
                return False
            return False

        def _isinNetwork( ipsource, network )->bool:
            if isinstance( network, list ):
                for n in network:
                    if __isinNetwork( ipsource, n ):
                        return True
            elif isinstance( network, str ):
                return __isinNetwork( ipsource, network )
            return False

        def isinNetwork( ipsource, network )->bool: 
            if isinstance( ipsource, list ):
                for ip in ipsource:
                    if _isinNetwork( ip, network ):
                        return True
            elif isinstance( ipsource, str):
                return _isinNetwork( ipsource, network )
            return False

        def isAttribut(user, attribut, start_with=None, equal=None ):
            # if user is not a dict return False
            if not isinstance(user, dict): return False
            if not isinstance( attribut, str ): return False
            if not isinstance( start_with, str ) or not isinstance( equal, str ): return False
                
            try:
                attribut_user_value = str( user.get( attribut ) )
                if start_with :
                    return attribut_user_value.startswith( start_with )
                if equal :
                    return attribut_user_value.__eq__( equal )
            except Exception as e:
                self.logger.error( str(e) ) 
                return False
            return False

        self.logger.info( f"condition {condition}" )

        compiled_result = False  # default compiled_result is False

        # a condition is always a dict else return false
        if not isinstance(condition,dict) :
            return False

        # just a type sanity check
        expected = condition.get('expected')
        if not isinstance(expected,bool):
            self.logger.warning( f"invalid value type {type(expected)}, bool is expected in rule" )
   
        # DO not change with lambda 
        # this is not a dummy code
        # this is readable code for human
        #
        always = condition.get('boolean')
        if isinstance(always,bool):
            result     = isBoolean( always )
            if result == condition.get( 'expected'):
                compiled_result = True

        httpheader = condition.get('httpheader')
        if isinstance(httpheader,dict):
            result     = isHttpHeader( getclienthttp_headers(), httpheader )
            if result == condition.get( 'expected'):
                compiled_result = True

        httpheader = condition.get('existhttpheader')
        if isinstance(httpheader,list):
            result     = existHttpHeader( getclienthttp_headers(), httpheader )
            if result == condition.get( 'expected'):
                compiled_result = True

        memberOf = condition.get('memberOf') or condition.get('memberof')
        if isinstance(memberOf,str):
            self.logger.debug('memberOf checking for ODAdAuthMetaProvider')
            # read the member LDAP attribut with objectClass=group
            # check if the provider object is an ODAdAuthMetaProvider
            # and auth object is an AuthInfo
            # kwargs can contain 'provider' and 'auth' entries
            meta_provider = kwargs.get('provider')
            auth = kwargs.get('auth')
            if isinstance( meta_provider, ODAdAuthMetaProvider ) and isinstance( auth, AuthInfo):
                # call the isMember method to run LDAP Qeury and 
                # read the member attribut in group
                # This is not the user's memberOf 
                self.logger.debug('This is a ODAdAuthMetaProvider and auth is AuthInfo')
                self.logger.debug( f"isMemberOf query to provider={meta_provider.name}")
                result = meta_provider.isMemberOf( auth, memberOf )
                self.logger.debug( f"meta_provider.isMemberOf -> result={result}")
                self.logger.debug( f"result == condition.get('expected') -> {result} == {condition.get('expected')}")
                if result == condition.get('expected'):
                    compiled_result = True
            else:
                # read the memberOf LDAP attribut of objectClass=user
                # use string compare to test if is MemberOf
                self.logger.debug('not a ODAdAuthMetaProvider')
                result = isMemberOf( roles, memberOf )
                if result == condition.get('expected'):
                    compiled_result = True

        geolocation = condition.get('geolocation')
        if isinstance(geolocation,dict):
            result = isGeoLocation( user, geolocation  )
            if result == condition.get( 'expected'):
                compiled_result = True

        network = condition.get('network')
        if isinstance(network, str ) or isinstance(network, list ) :
            ipsource = getclientipaddr()
            result = isinNetwork( ipsource, network )
            if result == condition.get( 'expected'):
                compiled_result = True

        network = condition.get('network-x-forwarded-for')
        if isinstance(network, str ) or isinstance(network, list ) :
            # getclientxforwardedfor_listip return a list of all ip addr
            ipsources = getclientxforwardedfor_listip()
            result = isinNetwork( ipsources, network )
            if result == condition.get( 'expected'):
                compiled_result = True

        network = condition.get('network-x-real-ip')
        if isinstance(network, str ) or isinstance(network, list ) :
            # getclientreal_ip return single ip addr
            ipsource = getclientreal_ip()
            result = isinNetwork( ipsource, network )
            if result == condition.get( 'expected'):
                compiled_result = True

        network = condition.get('network-client-ip')
        if isinstance(network, str ) or isinstance(network, list ) :
            ipsource = getclientipaddr()
            result = isinNetwork( ipsource, network )
            if result == condition.get( 'expected'):
                compiled_result = True

        primaryGroup = condition.get('primarygroupid')
        if primaryGroup is not None:
            # always use 'int' type format
            # from https://docs.microsoft.com/en-us/windows/win32/adschema/a-primarygroupid
            # Ldap-Display-Name	primaryGroupID
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

        self.logger.debug( f"compiledcondition -> {compiled_result}")
        return compiled_result

    def compiledrule( self, name, rule, user, roles, **kwargs ):        

        if type(rule) is not dict :
            return False
       
        conditions  = rule.get('conditions')   
        expected    = rule.get('expected')
        if type(expected) is not bool:
            self.logger.warning(f"invalid value type {type(expected)}, bool is expected in rule" )

        results = []
        for condition in conditions :
            r = self.compiledcondition(condition, user, roles, **kwargs)
            self.logger.debug(f"condition={condition} compiled_result={r}")
            results.append( r )
        
        # if results is empty return False 
        if len(results) == 0:
            return False

        compiled_result = all( results )
        logger.debug( f"rules (compiled_result={compiled_result})==(expected=={expected})" )
        result = compiled_result == expected 
        logger.debug( f"rules return {result}" )
        return result


    def compiledrules( self, rules, user, roles, **kwargs ):
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

        buildcompiledrules = {}
        if not isinstance( rules, dict ):
            return buildcompiledrules

        for name in rules.keys():
            try:
                compiled_result = self.compiledrule( name, rules.get(name), user, roles, **kwargs )
                logger.debug( f"rule={name} compiled_result={compiled_result}")
                if compiled_result is True:
                    k = rules.get(name).get('label')
                    # if a label exists
                    if k is not None:
                        # set the label value
                        # true by default or the load value
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

        self.logger.debug('')

        # take time to mesure time of login call
        server_utctimestamp = self.mesuretimeserver_utctimestamp(arguments=arguments)

        ( mgr_meta, provider_meta ) = self.get_metalogin_manager_provider()
        if  not isinstance( mgr_meta, ODExplicitMetaAuthManager) or \
            not isinstance( provider_meta, ODAdAuthMetaProvider):
            # no metaexplicit manager has been defined or no metaexplicit provider has been defined 
            self.logger.info( 'skipping metalogin, no metaexplicit manager or no metadirectory provider has been defined')
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
            self.logger.debug( 'invalid object type %s', provider_meta.join_key_ldapattribut  )
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
        self.logger.info(  "metadirectory translating user auth")
        self.logger.info( f"metadirectory replay from provider {provider_meta.name} -> {new_provider.name}" )
        self.logger.info( f"metadirectory replay from user {arguments.get('userid')} -> {new_userid}" )
        self.logger.info( f"metadirectory replay from domain {provider_meta.domain} -> {new_domain}" )

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
            # on most case it use the memberof 


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
                # compile rules with the new usermetaauthinfo
                self.logger.debug('compiledrules')
                metaAuthInfoForUserLabels = self.compiledrules( newmetaprovider.rules, metauser, roles, provider=newmetaprovider, auth=metaAuthInfoForUser )
                # dump metaAuthInfoForUserLabels
                self.logger.info( f"compiled rules metaAuthInfoForUserLabels {metaAuthInfoForUserLabels}" )
                # update the  auth.data['labels'] with the new metaAuthInfoForUserLabels
                auth.data['labels'].update( metaAuthInfoForUserLabels )
                # dump updated auth.data['labels']
                self.logger.info( 'compiled rules get labels %s', auth.data['labels'] )
                # overwrite the previous login auth_duration_in_milliseconds
                # with the metalogin auth_duration_in_milliseconds
                auth_duration_in_milliseconds = self.mesuretimeserver_auth_duration(server_utctimestamp)
                #
                # buid a AuthCache as response result 
                metaauthcache = AuthCache( 
                    dict_token={ 'auth': vars(auth), 'user': metauser, 'roles': roles }, 
                    auth_duration_in_milliseconds=auth_duration_in_milliseconds 
                ) 
                # merge userloginresponse with metaauthdata
                userloginresponse.result.merge( metaauthcache )
                userloginresponse.reason=f"a.Authentication on {provider_meta.getdisplaydescription()} via {new_provider.getdisplaydescription()} successful in {auth_duration_in_milliseconds:.2f} s"  # float two digits after comma

            except Exception as e:
                # no authenticate 
                self.logger.error( f"skipping metalogin, authenticate failed {e}")

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
            if p.domain is None:
                continue
            if p.domain.upper() == domain :
                self.logger.debug( 'provider.name %s match for domain=%s', p.name, domain) 
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
            # server_utctimestamp = float(datetime.datetime.utcnow().timestamp()) * 1000
            arguments['difftime'] = server_utctimestamp - user_utctimestamp
            self.logger.info(f"Diff between server-client {arguments['difftime']} in milliseconds")
        return server_utctimestamp

    def mesuretimeserver_auth_duration( self,server_utctimestamp):
        server_endoflogin_utctimestamp = datetime.datetime.now().timestamp()*1000
        auth_duration_in_milliseconds = (server_endoflogin_utctimestamp - server_utctimestamp)/1000 # in float second
        return auth_duration_in_milliseconds


    def login(self, provider, manager=None, **arguments):  
        self.logger.debug('')
        auth = None
        response = AuthResponse(self)
        try:
            # take time to mesure time of login call
            server_utctimestamp = self.mesuretimeserver_utctimestamp(arguments=arguments)

            # if provider is None, it must be an explicit manager 
            if not isinstance(provider, str):
                # provider is None
                # can raise exception
                # do everythings possible to find one provider
                self.logger.info( f"provider is None, login try to find a provider using manager={manager}" )
                provider = self.logintrytofindaprovider( manager )
                
            # look for an auth manager
            mgr = self.findmanager(provider, manager)
                 
            # do authenticate with the auth manager
            self.logger.debug( f"mgr.authenticate provider={provider} start") 
            auth = mgr.authenticate(provider, **arguments)
            self.logger.debug( f"mgr.authenticate provider={provider} done") 

            if not isinstance( auth, AuthInfo ):
                raise AuthenticationFailureError('No authentication provided')
            
            # uncomment this line only to dump password in clear text format
            # self.logger.debug( f"mgr.getuserinfo arguments={arguments}")   
            self.logger.debug( f"mgr.getuserinfo provider={provider} start")          
            userinfo = mgr.getuserinfo(provider, auth, **arguments)
            self.logger.debug( f"mgr.getuserinfo provider={provider} done")  
            if not isinstance(userinfo, dict ):
                raise AuthenticationFailureError(f"getuserinfo return {type(userinfo)} provider={provider}")
 
            # 
            # create claims with auth and userinfo
            self.logger.debug( f"mgr.createclaims provider={provider} start") 
            mgr.createclaims(provider, auth, userinfo, **arguments )
            self.logger.debug( f"mgr.createclaims provider={provider} done") 
            
            #
            # get roles 
            self.logger.debug( f"mgr.getroles provider={provider} start")             
            roles = mgr.getroles(provider, auth, userinfo, **arguments)
            self.logger.debug( f"mgr.getroles provider={provider} done") 
            if not isinstance(roles, list):
                raise AuthenticationFailureError( f"mgr.getroles provider={provider} error" )

            # get the provider object from the provider name
            pdr = mgr.getprovider(provider)

            # check if acl matches with tag
            if not oc.od.acl.ODAcl().isAllowed( auth, pdr.acls ):
                 raise AuthenticationDenied( 'Access is denied by security policy')

            # if the provider has rules defined then 
            # compile data using rules
            # runs the rules to get associated labels tag
            if pdr.rules:
                self.logger.debug( f"provider {provider} has rules, compile rules start" )      
                auth.data['labels'] = self.compiledrules( pdr.rules, userinfo, roles )
                self.logger.debug( "compiledrules done")      
                self.logger.info( f"compiled rules get labels {auth.data.get('labels')}")

            auth_duration_in_milliseconds = self.mesuretimeserver_auth_duration(server_utctimestamp)
            # build a AuthCache as response result 
            myauthcache = AuthCache( { 
                'auth': vars(auth), 
                'user': userinfo, 
                'roles': roles }, 
                auth_duration_in_milliseconds=auth_duration_in_milliseconds 
            ) 

            reason = f"a.Authentication on { pdr.getdisplaydescription() } successful in {auth_duration_in_milliseconds:.2f} s" # float two digits after comma
            response.update(    manager=mgr, 
                                result=myauthcache, 
                                success=True, 
                                reason=reason )
            
        finally:
            # call finalize to clean conn if need
            if isinstance( auth, AuthInfo ) :
                mgr.finalize(provider, auth, **arguments)

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

    def createclaims(self, provider, authinfo, userinfo, manager=None, **arguments):
        return self.findmanager(provider, manager).createclaims(provider, authinfo, userinfo, **arguments)

    def getroles(self, provider, authinfo, userinfo, manager=None, **arguments):
        return self.findmanager(provider, manager).getroles(provider, authinfo, userinfo, **arguments)

    def finalize(self, provider, authinfo, manager=None, **arguments):
        return self.findmanager(provider, manager).finalize(provider, authinfo, **arguments)

    def authorize(self, allow_anonymous=False, allow_authentified=True):        
        if allow_anonymous is True: 
            return
        if not self.provider or not self.providertype:
            raise cherrypy.HTTPError(401, 'Invalid token')
        if not allow_authentified:
            raise cherrypy.HTTPError(401, 'Unauthorized')    

    def logout(self, provider, authinfo, manager=None, **arguments):
        """[logout]
        """
        return self.findmanager(provider, manager).logout(provider, authinfo, **arguments)
        
          
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
            self.logger.info( 'Adding provider name %s ', name )
            provider = self.createprovider(name, cfg)
            try:
                # add only instance ODAuthProviderBase or herited
                self.add_provider( name, provider )    
            except Exception as e:
                self.logger.exception(e) 

    def add_provider( self, name, provider ):
        """[add_provider]
            add a provider object ODAuthProviderBase in providers dict
        Args:
            name ([str]): [key of the providers dict]
            provider ([ODAuthProviderBase]): [ODAuthProviderBase]
        """
        assert isinstance(name, str), 'bad provider name parameter'
        assert isinstance(provider, ODAuthProviderBase), 'bad provider parameters'
        self.providers[name] = provider  
       
    def authenticate(self, provider, **arguments):
        return self.getprovider(provider, True).authenticate(**arguments)

    def createclaims(self, provider, auth, userinfo, **arguments):
        provider = self.getprovider(provider, raise_error=True)
        return provider.createclaims(auth, userinfo, **arguments)

    def getuserinfo(self, provider, token, **arguments):
        userinfo =  self.getprovider(provider, True).getuserinfo(token, **arguments)
        if isinstance( userinfo, dict):
            # complete data from arguments
            for addionnalinfo in [ 'geolocation', 'utctimestamp']:
                userinfo[addionnalinfo]=arguments.get(addionnalinfo)
        return userinfo

    def getroles(self, provider, authinfo, userinfo, **arguments):
        return self.getprovider(provider, True).getroles(authinfo, userinfo, **arguments)

    def finalize(self, provider, authinfo, **arguments):
        return self.getprovider(provider, True).finalize(authinfo, **arguments)
    
    def createprovider(self, name, config):
        return ODAuthProviderBase(self, name, config)
    
    def logout(self, provider, authinfo, **arguments):
        return self.getprovider(provider, True).logout(authinfo, **arguments)

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
        providersmaplist = list( filter( lambda p: p.showclientdata is True, self.providers.values() ) )
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
        self.logger.debug( locals() )
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
        self.logger.debug( locals() )
        return ODAdAuthMetaProvider(self, name, config)

@oc.logging.with_logger()
class ODImplicitAuthManager(ODAuthManagerBase):
    def __init__(self, name, config):
        super().__init__(name, config)

    def createprovider(self, name, config):
        self.logger.debug( locals() )
        provider = None
        if config.get('useExplicitIdentityProvider'):
            provider = ODImplicitTLSCLientAdAuthProvider(self, name, config)
        else:
            provider = ODImplicitAuthProvider(self, name, config)
        return provider


@oc.logging.with_logger()
class ODRoleProviderBase(object):
    def getroles(self, authinfo, userinfo, **params):
        return []

@oc.logging.with_logger()
class ODAuthProviderBase(ODRoleProviderBase):
    def __init__(self, manager, name, config):
        """_summary_

        Args:
            manager (ODAuthManagerBase): ODAuthManager for this provider
            name (str): name of the provider, must be uniqu for a manager
            config (dict): provider config dict
        """
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
        self.regexp_validatation_dict = { 
            'userid': { 
                'regexp' : r"(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?",
                'message': "userid consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character. regex used for validation is '(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?')"
            }
        }
        self.default_user_if_not_exist = config.get('defaultuid', oc.od.settings.getballoon_loginname())
        self.default_passwd_if_not_exist = config.get('defaultpassword', oc.od.settings.getballoon_password())
        self.default_uidNumber_if_not_exist = config.get('defaultuidNumber', oc.od.settings.getballoon_uidNumber())
        self.default_gidNumber_if_not_exist = config.get('defaultgidNumber', oc.od.settings.getballoon_gidNumber())
        self.auth_protocol = config.get('auth_protocol', {} )
        # default memberof attribut name
        # for expliicc this should be memberOf
        # for external provider 
        self.memberof_attribut_name = config.get('memberof_attribut_name', '' )

    def getdisplaydescription( self ):
        return self.displayname
    
    def authenticate(self, **params):
        raise NotImplementedError()

    def getuserinfo(self, authinfo, **params):
        raise NotImplementedError()
    
    def logout(self, authinfo, **arguments):
        # default provider pass logout
        pass

    def regexp_validadation( self, data, key  ):
        regexp = self.regexp_validatation_dict.get(key)
        pat = re.compile( regexp.get('regexp') )
        match = re.fullmatch(pat, data)
        if not match:
             raise AuthenticationError( message= regexp.get('message') )

    def getclientdata(self):
        """getclientdata
            Filter data to the web client
        Returns:
            dict : config dict for the javascript web client auth 
        """
        clientdata = {  'name': self.name, 
                        'caption': self.caption, 
                        'displayname': self.displayname
        }
        return clientdata

    def finalize(self, auth, **params):
        pass

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

    def getdefault_uid(self, userinfo:AuthInfo, user:str)->str:
        """getdefault_uid
            return a default uid if user if not a posix account to fill /etc/passwd value 
            create a uid from userid or from user param
        Args:
            userinfo (_type_): _description_
            user (_type_): _description_
        """
        uid = userinfo.get('uid') or userinfo.get('userid') or user
        uid = ODAuthProviderBase.safe_uid(uid)
        return uid

    @staticmethod
    def safe_uid(uid:str,permit_dollar:bool=False)->str:
        """safe_uid
            NAME_REGEX="^[a-z][-a-z0-9]*\$"
            The first letter needs to be a-z, but subsequent letters of the user names can be '-', a-z, or 0-9. 
            read the uid and remove unsupported chars
        Args:
            uid (str): uid value, can be a ldap cn

        Returns:
            str: safe uid 
        """
        assert isinstance( uid, str), f"bad uid str is expected type {type(uid)}"
        
        lenuid = len(uid)
        i=0
        new_uid = ''
        for i in range(0,lenuid):
            if uid[i].isalnum():
                new_uid = new_uid + uid[i].lower()
                break

        if len(new_uid) < 1:
            raise ValueError( "invalid uid value")

        for j in range(i+1,lenuid):
            if uid[j].isalnum() or uid[j] == '-':
               new_uid = new_uid + uid[j].lower()
 
        if permit_dollar is True:
            # last char may be a dollar
            if lenuid>1 and uid[lenuid-1] == "$":  
                new_uid.append( '$' )
        
        # never more than USER_NAME_MAX_LENGTH
        new_uid= new_uid[0:UID_MAX_LENGTH-1]
        if not new_uid:
            raise ValueError("invalid uid value")
        return new_uid

    def getdefault_gid(self, userinfo , user):
        """getdefault_gid
            return a default gid if user if not a posix account

        Args:
            userinfo (_type_): _description_
            user (_type_): _description_
        """
        gid = userinfo.get('gid') or userinfo.get('userid')
        if not isinstance( gid, str):
            gid = user.replace(' ','').tolower()
        return gid
        
    def generateLocalAccount(self, userinfo, user, password ):
        
        uid = None
        gid = None
        description = None
        loginShell = None
        groups = None
        gecos = None
        homeDirectory = None
        uidNumber = self.default_uidNumber_if_not_exist
        gidNumber = self.default_gidNumber_if_not_exist

        posixAccount = userinfo.get('posix')
        if isinstance( posixAccount, dict ):
            uid = posixAccount.get('uid')
            gid = posixAccount.get('gid', uid)
            uidNumber = posixAccount.get('uidNumber')
            gidNumber = posixAccount.get('gidNumber')
            loginShell = posixAccount.get('loginShell')
            description = posixAccount.get('description')
            groups = posixAccount.get('groups')
            # futur usage
            homeDirectory = posixAccount.get('homeDirectory')
            gecos = posixAccount.get('gecos')

        if not isinstance( loginShell, str ): 
            loginShell = oc.od.settings.getballoon_loginShell()
        if not isinstance( uid, str ): 
            uid = self.getdefault_uid( userinfo, user )
        if not isinstance( gid, str ): 
            gid = self.getdefault_gid( userinfo, user )
        if not isinstance( password, str ): 
            password = self.default_passwd_if_not_exist
        if not isinstance( homeDirectory, str ): 
            homeDirectory = oc.od.settings.getballoon_homedirectory()
        
        hashes = {  
            'uid'  : uid,
            'gid'  : gid,
            'gecos': gecos,
            'groups': groups,
            'uidNumber': uidNumber,
            'gidNumber': gidNumber,
            'loginShell': loginShell,
            'description': description,
            'homeDirectory': homeDirectory,
            'sha512': crypt.crypt( password, crypt.mksalt(crypt.METHOD_SHA512) )
        }
        return hashes
    
    def createauthenv(self, userinfo, userid, password):
        self.logger.debug('createauthenv')
        default_authenv = {}
        dict_hash = self.generateLocalAccount( userinfo, user=userid, password=password ) 
        default_authenv.update( { 'localaccount' : dict_hash } )
        return default_authenv

    def createclaims( self, authinfo, userinfo, **arguments):
        userid = self.default_user_if_not_exist
        password = self.default_passwd_if_not_exist
        claims = {  'identity': self.createauthenv(userinfo, userid, password) }
        authinfo.set_claims(claims)

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
        self.revoke_url = config.get('revoke_url')
        # relation ship to allow an external provider to resign as an explicitprovider
        # after login process and pod create
        self.explicitproviderapproval = config.get('explicitproviderapproval')
        # the defautl attribut name for memberof is groups
        self.memberof_attribut_name = config.get('memberof_attribut_name', 'groups')

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
        self.logger.debug( f"provider {self.name} type {self.type} return token {token}" )
        authinfo = AuthInfo( provider=self.name, providertype=self.type, token=oauthsession, protocol='oauth')
        return authinfo


    def getuserinfo(self, authinfo, **params):

        # retrieve the token object from the previous authinfo 
        oauthsession = authinfo.token 

        # Check if token type is OAuth2Session
        if not isinstance(oauthsession,OAuth2Session) :
            raise ExternalAuthError( message='authinfo is an invalid token oauthsession object')

        userinfo = None
        if self.userinfo_auth is True and oauthsession.authorized is True:
            response_userinfo = oauthsession.get(self.userinfo_url)
            if isinstance(response_userinfo, requests.models.Response) and response_userinfo.ok is True :
                jsondata = response_userinfo.content.decode(response_userinfo.encoding or self.encoding ) 
                data = json.loads(jsondata)
                self.logger.debug( f"dump userinfo data={data}" )
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

    def getroles(self, authinfo, userinfo, **params):
        self.logger.debug('') 
        roles = []

        # auth_only do not use ldap query
        if self.auth_only : 
            # return empty list
            self.logger.debug(f"provider {self.name} is a auth_only={self.auth_only}, no roles can be read return {roles}") 
            return roles

        if isinstance( userinfo.get('groups'), list ):
            roles = userinfo.get('groups')

        return roles

    def logout(self, authinfo, **arguments):
        # requests-oauthlib does not provide a way to use tokens revocations
        #
        pass
        

# ODImplicitAuthProvider is an Anonymous AuthProvider
class ODImplicitAuthProvider(ODAuthProviderBase):
    def __init__(self, manager, name, config):
        super().__init__(manager, name, config)
        self.uid = config.get('uid', self.name)
        self.username = config.get('username', self.name)
        self.explicitproviderapproval = config.get('explicitproviderapproval') 
        self.dialog_url = config.get( 'dialog_url' )
    

    def getclientdata(self):
        data =  super().getclientdata()
        if self.dialog_url:
            data['dialog_url'] = self.dialog_url
        return data
        
    def getuserinfo(self, authinfo, **params):
        userinfo = {}
        name = None
        userid = None
        uid=None
        # Check if token type is str
        if  isinstance(authinfo.token ,str) :
            # anonymous can have a username
            # user name is set has the auth token 
            name   = authinfo.token
            userid = authinfo.token # take care, it must be uniqu
            uid    = self.safe_uid(name)
        else:
            # set default values
            name   = self.username      # anomymous by default
            userid = str(uuid.uuid4())  # create a uniqu user id
            uid    = self.uid           # anomymous by default
        
        userinfo['name'] = name
        userinfo['userid'] = userid
        anonymousPosix = AuthUser.getdefaultPosixAccount(
            uid=uid, 
            gid=uid, 
            cn=name, 
            uidNumber=oc.od.settings.getballoon_uidNumber(),
            gidNumber=oc.od.settings.getballoon_gidNumber(),
            homeDirectory=oc.od.settings.getballoon_homedirectory(),
            loginShell=oc.od.settings.getballoon_loginShell(),
            description='abcdesktop anonymous account' )
        userinfo['posix'] = anonymousPosix
        return userinfo

    def authenticate(self, userid=None, password=None, **params):
        if isinstance(userid,str):
            self.regexp_validadation( userid, 'userid' )
        data = { 'userid': userid }
        authinfo = AuthInfo( provider=self.name, providertype=self.type, token=userid, data=data)
        return authinfo

class ODImplicitTLSCLientAuthProvider(ODImplicitAuthProvider):

    def __init__(self, manager, name, config):
        super().__init__(manager, name, config)

    #
    # def getuserinfo(self, authinfo, **params):
    #    userinfo = copy.deepcopy(self.userinfo)
    #    # anonymous can have a username
    #    # user name is set has the auth token
    #    userinfo['name']   = authinfo.token
    #    userinfo['userid'] = authinfo.token # take care, it must be uniqu
    #
    #    return userinfo


@oc.logging.with_logger()
class ODLdapAuthProvider(ODAuthProviderBase,ODRoleProviderBase):
    # common attributs 
    # from InetOrgPerson objectClass Types
    # objectClass: inetOrgPerson
    # objectClass: organizationalPerson
    # objectClass: person
    # objectClass: posixAccount
    # objectClass: top
    DEFAULT_ATTRS = [ 'objectClass', 'cn', 'sn', 'description', 'givenName', 'jpegPhoto', 'mail', 'ou', 'title', 'uid', 'distinguishedName', 'displayName' ]
    # https://ldapwiki.com/wiki/top
    # The top level class from which all classes are derived.
    DEFAULT_TOP_ATTRS  = { 'top':  [ 'objectClass' ] }
    # https://ldapwiki.com/wiki/Person
    # Person is an Entity which may be on or more of 'Legal' Person and 'Natural Person'
    DEFAULT_PERSON_ATTRS = { 'Person' :  [ 'cn', 'sn', 'description', 'givenName', 'uid' ] }
    # https://ldapwiki.com/wiki/InetOrgPerson
    # InetOrgPerson ObjectClass Types is defined in RFC 2798 and updated in RFC 3698, RFC 4519, RFC 4524.
    DEFAULT_INETORGPERSON_ATTRS = { 'InetOrgPerson':  [ 'jpegPhoto', 'mail', 'displayName', 'publicKey' ] }
    # https://ldapwiki.com/wiki/OrganizationalPerson
    # The ObjectClass Type is defined as: the basis of an entry that represents a person in relation to an organization.(Source: X.521 [X.521]) RFC 4519
    DEFAULT_ORGANIZATIONALPERSON_ATTRS = { 'OrganizationalPerson' :  [ 'title', 'ou' ] }
    # from https://ldapwiki.com/wiki/PosixAccount
    # PosixAccount ObjectClass Types 
    DEFAULT_POSIXACCOUNT_ATTRS = { 'posixAccount' : [ 'cn', 'uid', 'uidNumber', 'gidNumber', 'homeDirectory', 'loginShell', 'description', 'gecos' ] }
    # from https://ldapwiki.com/wiki/PosixGroup
    # PosixGroup ObjectClass Types 
    DEFAULT_POSIXGROUP_ATTRS   = { 'posixGroup' : [ 'cn', 'gidNumber', 'memberUid', 'description' ] }
    # DEFAULT_MEMBEROF_ATTRIBUT_NAME
    DEFAULT_MEMBEROF_ATTRIBUT_NAME = 'memberOf'
    # from https://ldap3.readthedocs.io/en/latest/connection.html
    # LDAP_AUTH_SUPPORTED_METHOD
    LDAP_AUTH_SUPPORTED_METHOD = ['KERBEROS', 'NTLM', 'SIMPLE', 'ANONYMOUS']



    class Query(object):
        def __init__(self, basedn, scope=ldap3.SUBTREE, filter=None, attrs=None ):
            self.scope = scope
            self.basedn = basedn
            self.filter = filter
            self.attrs = attrs            

    def __init__(self, manager, name, config={}):
        self.logger.info('')
        super().__init__(manager, name, config)
        self.type = 'ldap'

        # default ldap auth protocol is SIMPLE
        # always in UPPER case
        self.auth_type  = config.get('auth_type', 'SIMPLE').upper()

        # create a service account to bind on ldap
        # add self.userid set to None if not defined in config file
        # add self.password set to None if not defined in config file
        self.loadserviceaccount( config )
        
        # users ou query, like ou=users,dc=example,dc=com 
        # if not set use ldap_basedn
        self.users_ou  = config.get('users_ou', config.get('ldap_basedn') ) 
        # groups ou query, ou=groups,dc=example,dc=com
        # if not set use ldap_basedn
        self.groups_ou = config.get('goups_ou', config.get('ldap_basedn') ) 
        # list of servers
        self.servers = config.get('servers', []) 
        # default ldap timeout
        self.timeout = config.get('ldap_timeout') # timeout in seconds 
        # ldap connect timeout
        self.connect_timeout = config.get('ldap_connect_timeout') # timeout in seconds for the connect operation
        self.useridattr = config.get('useridattr', 'cn')
        self.usercnattr = config.get('usercnattr', 'cn') 
        self.useruidattr = config.get('useruidattr', 'uid')
        self.domain = config.get('domain')
        self.kerberos_realm = config.get('kerberos_realm') # must be str
        self.kerberos_krb5_conf = config.get('krb5_conf')
        self.kerberos_ktutil = config.get('ktutil', '/usr/bin/ktutil') # change to /usr/sbin/ktutil on macOS
        self.ntlm_command = config.get('ntlm_command', '/var/pyos/oc/auth/ntlm/ntlm_auth')
        # self.kerberos_servers = config.get('kerberos_servers', self.servers)

        # not used deprecated 
        # do not launch /usr/bin/kinit anyore 
        # use gssapi  
        # self.kerberos_service_identifier = config.get('krb5_service_identifier', '')
        # self.kerberos_kinit  = config.get('kinit', '/usr/bin/kinit')   # change to /usr/sbin/kinit on macOS
        #

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
                self.logger.info( 'provider %s has enabled citrix, mustache file %s', name, config.get('citrix_all_regions.ini') )
            else:
                self.logger.error( 'provider %s has disabled citrix, invalid entry citrix_all_regions.ini', name)

        self.exec_timeout = config.get('exec_timeout', 10)
        self.tls_require_cert = config.get( 'tls_require_cert', False)
        self.join_key_ldapattribut = config.get( 'join_key_ldapattribut' )
        self.krb5cctype = config.get('krb5cctype', 'MEMORY').upper()
        self.ldap_ipmod = config.get('ldap_ip_mode', ldap3.IP_V4_PREFERRED )
        self.ldapPublicKeyobjectClass = 'ldapPublicKey'
        self.posixAccountobjectClass = 'posixAccount'
        self.posixGroupobjectClass = 'posixGroup'
        self.InetOrgPersonobjectClass = 'InetOrgPerson'
        self.memberof_attribut_name = config.get('memberof_attribut_name', ODLdapAuthProvider.DEFAULT_MEMBEROF_ATTRIBUT_NAME )

        # query user Person
        self.user_query = self.Query(
            self.users_ou, 
            config.get('scope', ldap3.SUBTREE),
            config.get('user_filter', '(&(objectClass=Person)(cn=%s))'), 
            config.get('user_attrs', 
                ODLdapAuthProvider.DEFAULT_TOP_ATTRS.get('top') + ODLdapAuthProvider.DEFAULT_PERSON_ATTRS.get('Person')
            )
        )

        # query user InetOrgPerson 
        self.InetOrgPerson_query = self.Query(
            self.users_ou, 
            config.get('scope', ldap3.SUBTREE),
            config.get('filter', '(&(objectClass=InetOrgPerson)(cn=%s))'), 
            config.get('attrs', 
                ODLdapAuthProvider.DEFAULT_TOP_ATTRS.get('top') + ODLdapAuthProvider.DEFAULT_INETORGPERSON_ATTRS.get('InetOrgPerson')
            )
        )

        # query groups
        self.group_query = self.Query(
            self.groups_ou,
            config.get('group_scope', self.user_query.scope),
            config.get('group_filter', "(&(objectClass=Group)(cn=%s))"),
            config.get('group_attrs'))

        # query posixaccount
        #
        # account uid=name1
        # dn: uid=name1,ou=Users,dc=example,dc=com
        # cn: Full Name
        # gidnumber: 2000
        # objectclass: posixAccount
        # objectclass: shadowAccount
        # uid: name1
        # uidnumber: 1000
        #
        # query to read posix account
        self.posixaccount_query = self.Query(
            self.users_ou, 
            config.get('posixAccount_scope', ldap3.SUBTREE),
            config.get('posixAccount_filter', '(&(objectClass=posixAccount)(cn=%s))'), 
            config.get('posixAccount_attrs', 
                ODLdapAuthProvider.DEFAULT_TOP_ATTRS.get('top') + ODLdapAuthProvider.DEFAULT_POSIXACCOUNT_ATTRS.get('posixAccount')
            )
        )

        # query posixgroup
        #
        # dn: cn=name1_group,ou=Groups,dc=example,dc=com
        # cn: name1_group
        # description: name1group
        # gidnumber: 2000
        # objectclass: posixGroup
        #
        # query to read the default user gidNumber group
        self.posixaccountgroup_query = self.Query(
            self.groups_ou,
            config.get('posixGroup_scope', ldap3.SUBTREE),
            config.get('posixAccountGroup_filter', '(&(objectClass=posixGroup)(gidNumber=%s))'), 
            config.get('posixGroup_attrs', 
                ODLdapAuthProvider.DEFAULT_TOP_ATTRS.get('top') + ODLdapAuthProvider.DEFAULT_POSIXGROUP_ATTRS.get('posixGroup')
            )
        )

        # query posixgroup
        #
        # dn: cn=name1_group,ou=Groups,dc=example,dc=com
        # cn: name1_group
        # description: name1group
        # gidnumber: 2000
        # objectclass: posixGroup
        #
        # query to read all other gidNumber group
        self.posixgroups_query = self.Query(
            self.groups_ou,
            config.get('posixGroup_scope', ldap3.SUBTREE),
            config.get('posixGroup_filter', '(&(objectClass=posixGroup)(!(gidNumber=%s))(memberUid=%s))'), 
            config.get('posixGroup_attrs', 
                ODLdapAuthProvider.DEFAULT_TOP_ATTRS.get('top') + ODLdapAuthProvider.DEFAULT_POSIXGROUP_ATTRS.get('posixGroup')
            )
        )


    def getdisplaydescription( self ):
        displaydescription = super().getdisplaydescription()
        if self.auth_type == 'KERBEROS':
            displaydescription = self.kerberos_realm
        elif self.auth_type == 'NTLM':
            displaydescription = self.domain
        return displaydescription

    def deepcopy( self ):
        self.logger.debug('')
        newprovider = copy.deepcopy( self )
        return newprovider


    def updateauthentificationconfigfromprovider( self, provider:ODAuthProviderBase ) -> ODAuthProviderBase :
        """ updateauthentificationconfig
            copy authentification attribut config from provider
                - domain
                - kerberos_realm
                - kerberos_krb5_conf
                - kerberos_ktutil
            update self
            use to support authnetification on microsoft active direcory trust relationship 
        Args:
            newprovider (ODAuthProviderBase): new provider to be updated

        Returns:
            ODAuthProviderBase: updated provider
        """
        self.logger.debug('')
        assert isinstance( provider, ODLdapAuthProvider), f"bad provider type {type(provider)}"

        self.domain = provider.domain
        self.kerberos_realm = provider.kerberos_realm
        self.kerberos_krb5_conf =  provider.kerberos_krb5_conf
        self.kerberos_ktutil =  provider.kerberos_ktutil


    def loadserviceaccount( self, config ):
        def readvaluefromfile( data:str ) -> str:
            """readvaluefromfile
                if data starts with 'file://'
                    open the path and return the first line of the file
                else
                    return data
            Args:
                data (str): value to check 

            Returns:
                same as parameter: file content if start with 'file://' else data
            """
            if isinstance( data, str ):
                fileurlparse = urlparse( data ) 
                if fileurlparse.scheme == 'file':
                    f = open( fileurlparse.path, 'r' )
                    data = f.readline().rstrip()
                    f.close()
            return data

        serviceaccount = config.get('serviceaccount', { 'login':None, 'password':None } )
        # self.userid set to None if not defined in config file
        self.userid = readvaluefromfile( serviceaccount.get('login') )
        # self.password set to None if not defined in config file
        self.password = readvaluefromfile( serviceaccount.get('password') )


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
        self.logger.debug( f"validate={userid}" )
        userdn = None   # set default value
        conn   = None   # set default value

        if self.auth_type not in ODLdapAuthProvider.LDAP_AUTH_SUPPORTED_METHOD:
             raise AuthenticationError(f"auth_type must be in {ODLdapAuthProvider.LDAP_AUTH_SUPPORTED_METHOD}")

        self.logger.debug( f"validate uses auth_type={self.auth_type}")
        if self.auth_type == 'KERBEROS':
            # can raise exception 
            self.logger.debug( f"validate={userid}" )
            self.krb5_validate( userid, password )
            self.krb5_authenticate( userid, password )
            if not self.auth_only :
                # krb5_authenticate has been done 
                # already_authenticate is True
                conn = self.getconnection(userid, password ) 
                userdn = self.getuserdn(conn, userid)
        elif self.auth_type == 'SIMPLE':
            # can raise exception 
            self.simple_validate(userid, password)
            # build the user dn string to bind the ldap server 
            # take 'Hubert J. Farnsworth' and return from the config file
            # 'cn=Hubert J. Farnsworth,ou=people,dc=planetexpress,dc=com'
            userdn = self.getuserdnldapconnection(userid)
            conn = self.getconnection(userdn, password) 
            # query again overwrite userdn
            userdn = self.getuserdn(conn, userid) 
        elif self.auth_type == 'ANONYMOUS':
            # the auth is anonymous, then the conn should always bind 
            conn = self.getconnection(None, None)
            # but we must find the user's dn
            # how to check the password
            userdn = self.getuserdn(conn, userid)
            # but we must find the user's dn
            # how to check the password 
            self.logger.debug( f"validate gets userdn={userdn}")
            if not isinstance( userdn, str):
                raise AuthenticationError( f"user {userid} is not found")
            # check the user's credentials
            self.logger.debug( f"validate starts new getconnection userdn={userdn} auth='SIMPLE' ")
            conn = self.getconnection(userdn, password, 'SIMPLE')
        elif self.auth_type == 'NTLM':
            # can raise exception 
            self.ntlm_validate(userid, password)
            ntlm_userid = self.domain + '\\' + userid
            conn = self.getconnection(ntlm_userid, password)
            userdn = self.getuserdn(conn, userid)
        return (userdn, conn)

    def krb5_authenticate(self, userid, password ):
        self.logger.debug( f"krb5_authenticate user={userid}" )
        try:
            userid = userid.upper()
            krb5ccname = self.get_krb5ccname( userid )
            self.run_kinit( krb5ccname, userid, password )
        except Exception as e:
            self.remove_krb5ccname( krb5ccname )
            raise AuthenticationError( f"kerberos credentitials validation failed {e}")

    def authenticate(self, userid, password, **params):
        self.logger.debug( "authenticate user={userid}" )
        # validate can raise exception 
        # like invalid credentials
        (userdn, conn) = self.validate(userid, password)   
        data = { 'userid': userid, 'dn': userdn }
        return AuthInfo( provider=self.name, providertype=self.type, token=userid, data=data, protocol=self.auth_protocol, conn=conn)

    
    def createclaims( self, authinfo, userinfo, userid, password,  **arguments):
        claims = { 'userid': userid, 'password': password }
        claims['identity'] =  self.createauthenv(userinfo, userid, password)
        authinfo.set_claims(claims)

    def krb5_validate(self, userid, password):
        assert isinstance(userid,str), f"userid must be str, get {type(userid)}"
        assert isinstance(password,str), f"password must be str, get {type(password)}"
  
        if not userid :
            raise AuthenticationError('user can not be an empty string')

        if len(userid) > KRB5_UID_MAX_LENGTH :
            raise AuthenticationError('user length must be less than 256 characters')

        if len(password) < 1 :
            raise AuthenticationError('password can not be an empty string')

        # kerberos password length Limit.
        # Maximum number of characters supported for plain-text krb5-password config is 256
        if len(password) > KRB5_PASSWORD_MAX_LENGTH :
            raise AuthenticationError('password length must be less than 256 characters')


    def ntlm_validate(self, userid, password):
        assert isinstance(userid,str), f"userid must be str, get {type(userid)}"
        assert isinstance(password,str), f"password must be str, get {type(password)}"
        if not userid :
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

        if not password :
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

        assert isinstance(userid,str), f"userid must be str, get {type(userid)}"
        assert isinstance(password,str), f"password must be str, get {type(password)}"

        # LDAP by itself doesn't place any restriction on the username
        # especially as LDAP doesn't really specify which attribute qualifies as the username.
        # The DN is similarly unencumbered.
        # set max value to 256
        if len(userid) == 0 :
            raise AuthenticationError('user can not be an empty string')
        if len(userid) > LDAP_UID_MAX_LENGTH :
            raise AuthenticationError('user length must be less than 256 characters')
        # LDAP BIND password length Limit.
        if len(password) == 0:
            raise AuthenticationError('password can not be an empty string')
        # Maximum number of characters supported for plain-text bind-password config is 63
        if len(password) > LDAP_PASSWORD_MAX_LENGTH:
            raise AuthenticationError('password length must be less than 64 characters')
        
        if self.auth_only:
            raise AuthenticationError('auth_only is set to True, but ldap.bind need to complete auth')

    def getuserinfo(self, authinfo, **params):        
        # self.logger.debug(locals()) # uncomment this line may dump password in clear text 
        # authinfo.conn is ldap3.core.connection.Connection 

        if self.auth_only is True:
            # fake a userinfo with data read from userid 
            userinfo = { 'userid': params.get('userid'), 'name': params.get('userid') }
        else:
            # query Person
            q = self.user_query
            attrs = [ '*' ] # get all attributs
            userinfo = self.search_one( authinfo.conn, q.basedn, q.scope, ldap_filter.filter_format(q.filter, [authinfo.token]), attrs, **params)
                        
            if isinstance(userinfo, dict):
                # Add always userid entry, make sure this entry exists
                if not isinstance( userinfo.get('userid'), str) :
                    userinfo['userid'] = userinfo.get(self.useruidattr)
                # Add always name entry
                if not isinstance( userinfo.get('name'), str) :
                    userinfo['name'] = userinfo.get(self.useridattr)

                ### commented code section 
                #   do not run more than one ldap query to read others attributs on the same dn
                #   query InetOrgPerson
                #if self.InetOrgPersonobjectClass in userinfo.get('objectClass', [] ):
                #    self.logger.debug( f"account is a {self.InetOrgPerson_query} objectClass={userinfo.get('objectClass')}")
                #    q = self.InetOrgPerson_query
                #    self.logger.debug( f"query for {self.InetOrgPerson_query} attributs")
                #    inetorgpersonuserinfo = self.search_one( authinfo.conn, basedn=q.basedn, scope=q.scope, filter=ldap_filter.filter_format(q.filter, [authinfo.token]), attrs=[self.ldapPublicKeyobjectClass], **params)
                #    if isinstance(inetorgpersonuserinfo, dict):
                #        userinfo.update( inetorgpersonuserinfo )
                #
                # if self.ldapPublicKeyobjectClass in userinfo.get('objectClass', [] ):
                #    publickeyuserinfo = self.search_one( authinfo.conn, basedn=q.basedn, scope=q.scope, filter=ldap_filter.filter_format(q.filter, [authinfo.token]), attrs=[self.ldapPublicKeyobjectClass], **params)
                #    if isinstance(publickeyuserinfo, dict):
                #        userinfo[self.ldapPublicKeyobjectClass ] = publickeyuserinfo.get( self.ldapPublicKeyobjectClass )
                ##

                if self.posixAccountobjectClass in userinfo.get('objectClass', [] ):
                    #
                    # this account is a posixAccount
                    #
                    # requery to read attributs uid, uidNumber, gidNumber, homeDirectory
                    self.logger.debug( f"account is a {self.posixAccountobjectClass} objectClass={userinfo.get('objectClass')}")
                    self.logger.debug( "query for posixAccount attributs")
                    q = self.posixaccount_query
                    posixuserinfo = self.search_one( authinfo.conn, q.basedn, q.scope, ldap_filter.filter_format(q.filter, [authinfo.token]), q.attrs, **params)
                    if isinstance(posixuserinfo, dict):
                        userinfo['posix'] = posixuserinfo
                        #
                        # requery to read attributs group cn
                        self.logger.debug( "query for posixGroup attributs")
                        q = self.posixaccountgroup_query
                        groupfilter = ldap_filter.filter_format(q.filter, [ str(posixuserinfo.get('gidNumber')) ] )
                        self.logger.debug( f"query basedn={q.basedn} for posixGroup attributs {groupfilter} attrs={q.attrs}")
                        posixgroupinfo =  self.search_one( authinfo.conn, q.basedn, q.scope, groupfilter, q.attrs, **params)
                        if isinstance(posixgroupinfo, dict):
                            # set the group name use the group cn
                            userinfo['posix']['gid'] = posixgroupinfo.get('cn')

                        #
                        # requery to read attributs all groups
                        self.logger.debug( "query for posixGroup attributs")
                        q = self.posixgroups_query
                        groupfilter = ldap_filter.filter_format(q.filter, [ str(posixuserinfo.get('gidNumber')), str(posixuserinfo.get('uid')) ] )
                        self.logger.debug( f"query basedn={q.basedn} for posix all groups attribut {groupfilter} attrs={q.attrs}")
                        posixallgroupslist =  self.search_all( authinfo.conn, q.basedn, q.scope, groupfilter, q.attrs, **params)
                        if isinstance(posixallgroupslist, list):
                            userinfo['posix']['groups'] = posixallgroupslist
                            
        return userinfo

    
    def getroles(self, authinfo, userinfo, **params):  
        self.logger.debug('') 
        roles = []

        # auth_only do not use ldap query
        if self.auth_only : 
            # return empty list
            self.logger.debug(f"provider {self.name} is a auth_only={self.auth_only}, no roles can be read return {roles}") 
            return roles

        try:
            token = authinfo.token            
            q = self.user_query
            result = self.search_one( 
                conn=authinfo.conn,
                basedn=q.basedn,
                scope=q.scope,
                filter=ldap_filter.filter_format(q.filter, [token]),
                attrs=['memberOf'],
                **params )
            # return [dn.split(',',2)[0].split('=',2)[1] for dn in result['memberOf']] if result else []
            roles = result.get( self.memberof_attribut_name, [])
            if not isinstance(roles, list):
                roles = [ roles ] # always a list
        except Exception as e:
            self.logger.error( e )
            # return empty list if an exception occurs

        self.logger.debug(f"roles on provider {self.name}, read {roles}" ) 
        return roles

    def getuserdnldapconnection(self, userid):
        # rewrite the userid with full dn
        # format cn=Hubert J. Farnsworth,ou=people,dc=planetexpress,dc=com
        escape_userid = ldap_filter.escape_filter_chars(userid)
        if len(escape_userid) != len( userid ):
            self.logger.debug( 'WARNING ldap_filter.escape_filter_chars escaped' )
            self.logger.debug( 'value=%s escaped by ldap_filter.escape_filter_chars as value=%s', userid, escape_userid )
        return self.usercnattr + '=' + escape_userid + ',' + self.users_ou

  
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


    def getconnection(self, userid:str, password:str, auth_type:str=None ):
        conn = None
        lastException = None
        if auth_type is None :
            auth_type = self.auth_type
        self.logger.info( f"ldap getconnection auth userid={userid} auth={auth_type}" )

        for server_name in self.servers:
            try: 
                self.logger.debug( f"ldap getconnection:create ldap3.Server server={server_name} auth_type={auth_type}")
                server = ldap3.Server( server_name, connect_timeout=self.connect_timeout, mode=self.ldap_ipmod, get_info='ALL')
                
                # create a Connection to get supported_sasl_mechanisms from server
                c = ldap3.Connection(server, auto_bind=False)
                c.open()  # establish connection without performing any bind (equivalent to ANONYMOUS bind)
                # read https://ldap3.readthedocs.io/en/latest/bind.html
                # supported_sasl_mechanisms example [ 'GSS-SPNEGO', 'GSSAPI', 'NTLM', 'PLAIN' ]
                # read supported_sasl_mechanisms supported by the ldap server
                supported_sasl_mechanisms = server.info.supported_sasl_mechanisms if server.info else None
                self.logger.debug( f"supported_sasl_mechanisms by {server_name} return {supported_sasl_mechanisms}" )
                del c # remove the c Connection, only use to get supported_sasl_mechanisms 

                if not self.verify_auth_is_supported_by_ldap_server( supported_sasl_mechanisms ):
                    self.logger.warning( f"{auth_type} is not defined in {server_name}.info.supported_sasl_mechanisms supported_sasl_mechanisms={supported_sasl_mechanisms}" )
                
                # do kerberos bind
                if auth_type == 'KERBEROS': 
                     # krb5ccname must already exist 
                    krb5ccname = self.get_krb5ccname( userid )
                    cred_store = {'ccache':  krb5ccname }
                    kerberos_principal_name = self.get_kerberos_principal( userid )
                    # If you specify user=, it is expected to be a Kerberos principal (though it appears you can omit the domain). 
                    # If there is a credential for that user in the collection, it will be used.
                    self.logger.debug( f"ldap getconnection:Connection server={server_name} as user={kerberos_principal_name} authentication=ldap3.SASL, sasl_mechanism=ldap3.KERBEROS KRB5CCNAME={cred_store}")
                    conn = ldap3.Connection( server, user=kerberos_principal_name, authentication=ldap3.SASL, sasl_mechanism=ldap3.KERBEROS, read_only=True, raise_exceptions=True, cred_store=cred_store )

                # do ntlm bind
                if auth_type == 'NTLM':
                    # https://ldap3.readthedocs.io/en/latest/connection.html
                    # NTLM uses NTLMv2 authentication. 
                    # Username must be in the form domain\user.
                    # userid MUST be DOMAIN\\SAMAccountName format, call overwrited by bODAdAuthProvider:getconnection
                    # self.logger.debug(locals()) # uncomment this line may dump password in clear text 
                    self.logger.info( f"ldap getconnection:Connection server={server_name} userid={userid} authentication=ldap3.NTLM" )
                    conn = ldap3.Connection( server, user=userid, password=password, authentication=ldap3.NTLM, read_only=True, raise_exceptions=True )
                    
                # do textplain simple_bind_s 
                if auth_type == 'SIMPLE':
                    # userid is a dn
                    # need to get the dn to bind previously userdn = self.getuserdnldapconnection(userid)
                    # self.logger.debug(locals()) # uncomment this line may dump password in clear text 
                    self.logger.info( f"ldap getconnection:Connection server={server_name} userdn={userid} authentication=ldap3.SIMPLE" )
                    conn = ldap3.Connection( server, user=userid, password=password, authentication=ldap3.SIMPLE, read_only=True, raise_exceptions=True )

                if auth_type == 'ANONYMOUS':
                    # authentication method, can be one of ANONYMOUS, SIMPLE, SASL or NTLM. Defaults to ANONYMOUS if user and password are both None
                    self.logger.info( f"ldap getconnection:Connection server={server_name} ANONYMOUS authentication=ldap3.ANONYMOUS" )
                    conn = ldap3.Connection( server, authentication=ldap3.ANONYMOUS, read_only=True, raise_exceptions=True )

                #
                # let's bind to the ldap server conn.open()
                self.logger.debug( f"binding to the ldap server {server_name}")
                conn.bind()
                self.logger.debug( f"bind to {server_name} done")
                #
                # return ldap3.Connection 
                return conn

            # An except clause may name multiple exceptions as a parenthesized
            # exceptions page https://ldap3.readthedocs.io/en/latest/exceptions.html
            except (ldap3.core.exceptions.LDAPInvalidDNSyntaxResult, 
                    ldap3.core.exceptions.LDAPInvalidCredentialsResult,
                    ldap3.core.exceptions.LDAPInvalidAttributeSyntaxResult) as e:
                self.logger.error( f"exception {e} to the ldap server {server}" )
                #
                # This is fatal error, do not continue to query other ldap server
                # raise ldap3.core.exceptions.LDAPInvalidCredentialsResult
                #
                e.code = 401
                raise e

            except ldap3.core.exceptions.LDAPAuthMethodNotSupportedResult as e:
                self.logger.error( f"exception {e} to the ldap server {server}" )
                lastException = e

            except ldap3.core.exceptions.LDAPExceptionError as e:
                self.logger.error( f"exception {e} to the ldap server {server}" )
                lastException = e

        # end of iterate each ldap server
        if isinstance(lastException, Exception ) :
            lastException.code = 401
            raise lastException

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
        self.logger.debug(locals())
        withdn = attrs is not None and 'dn' in (a.lower() for a in attrs)
        entries = []
        time_start = time.time() # expressed in seconds since the epoch, in UTC
        results = conn.search( search_base=basedn, search_filter=filter, search_scope=scope, attributes=attrs)
        if results is True:
            elapsed = time.time() - time_start # in seconds
            self.logger.info( f"ldap search_s {basedn} {filter} take {elapsed} seconds" )
            for entry in conn.entries: 
                data = {}
                for k,v in entry.entry_attributes_as_dict.items():
                    data[k] = self.decodeValue(k,v)
                data['dn'] = entry.entry_dn
                # if only the first entry is need as param
                # return it 
                if one: 
                    return data
                # else append to a entries list
                entries.append(data)
            return entries
        return None 

    def getuserdn(self, conn, id):
        return self.getdn(conn, self.user_query, id)

    def getgroupdn(self, conn, id):
        return self.getdn(conn, self.group_query, id)

    def getdn(self, conn, query, id):
        distinguishedName = None
        result = self.search(conn, query.basedn, query.scope, ldap_filter.filter_format(query.filter, [id]), ['cn', 'distinguishedName'], True)
        if isinstance(result, dict):
            distinguishedName = result.get('distinguishedName') or result.get('dn') 
        return distinguishedName

    def isMemberOf( self, authinfo, userdistinguished_name:str, groupdistinguished_name:str):
        self.logger.debug(f"userdistinguished_name={userdistinguished_name} groupdistinguished_name={groupdistinguished_name}")
        memberof = False
        filter = '(objectClass=group)'
        groupinfo = self.search_one( conn=authinfo.conn, 
                                    basedn=groupdistinguished_name, 
                                    scope=ldap3.BASE, 
                                    filter=filter, 
                                    attrs=['member'] )
        self.logger.debug(f"groupinfo={groupinfo}")
        if not isinstance( groupinfo, dict ):
            self.logger.debug('groupinfo is not a dict')
            return memberof
        
        member = groupinfo.get('member')
        if not isinstance( member, list ):
            self.logger.debug('member is not a list')
            return memberof
        self.logger.debug(f"member={member}")
        if userdistinguished_name in member:
            memberof = True
        self.logger.debug(f"return memberof={memberof}")
        return memberof
        

    def decodeValue(self, name, value):
        if not isinstance(value, list): 
           return value

        items = [] 
        for item in value:
            # try to translate bytes to str using decode utf8
            if isinstance(item,bytes): 
                try:
                    item = item.decode('utf-8')
                except UnicodeDecodeError:
                    # raw binary data
                    # Could be an raw binary JPEG data
                    # self.logger.warning('Attribute %s not decoded as utf-8, use raw data type: %s exception:%s', name, type(item), e)
                    pass
                except Exception as e:
                    self.logger.error('Attribute %s error to decode as utf-8, use raw data type: %s exception:%s', name, type(item), e)
            items.append(item)

        return items[0] if len(items) == 1 else items


    def get_kerberos_realm( self ):
        return self.kerberos_realm

    def createauthenv(self, userinfo, userid, password):
        #
        # create a localaccount entry in default_authenv dict
        default_authenv = super().createauthenv(userinfo, userid, password)

        # if kerberos is enabled
        if self.auth_protocol.get('kerberos') is True:
            try:
                dict_hash = self.generateKerberosKeytab( userid, password )
                if isinstance( dict_hash, dict ): 
                    default_authenv.update( { 
                        'kerberos' : { 
                            'PRINCIPAL': userid,
                            'REALM': self.get_kerberos_realm(),
                            **dict_hash 
                        } 
                    })
            except Exception as e:
                self.logger.error( f"generateKerberosKeytab failed, authenv can not be completed {e}" )
        
        # if ntlm is enabled
        if self.auth_protocol.get('ntlm') is True :
            try:
                dict_hash = self.generateNTLMhash(password)
                if isinstance( dict_hash, dict ):
                    default_authenv.update( { 
                        'ntlm' : { 
                            'NTLM_USER'   : userid,
                            'NTLM_DOMAIN' : self.domain,
                            **dict_hash 
                        } 
                    } )
            except Exception as e:
                self.logger.error( f"generateNTLMhash failed, authenv can not be completed {e}" )

        # if cntlm is enabled
        if self.auth_protocol.get('cntlm') is True :
            try:
                dict_hash = self.generateCNTLMhash( userid, password, self.domain)
                if isinstance( dict_hash, dict ):
                    default_authenv.update( { 
                        'cntlm' : {   
                            'NTLM_USER'   : userid,
                            'NTLM_DOMAIN' : self.domain,
                            **dict_hash } 
                        } )
            except Exception as e:
                self.logger.error( f"generateCNTLMhash failed, authenv can not be completed {e}" )

        # if citrix is enabled
        if self.auth_protocol.get('citrix') is True :
            try:
                dict_hash = self.generateCitrixAllRegionsini( username=userid, password=password, domain=self.domain) 
                if isinstance( dict_hash, dict ):
                    default_authenv.update( { 
                        'citrix' : dict_hash 
                        } 
                    )
            except Exception as e:
                self.logger.error( f"generateCitrixAllRegionsini failed, authenv can not be completed {e}" )
        
        return default_authenv
    

    def paged_search( self, conn, basedn, filter, attrlist, scope=ldap3.SUBTREE):
        # sizelimit=0
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
        ccname = oc.auth.namedlib.normalize_name( principal )
        if self.krb5cctype == 'FILE' :
            krb5ccname = 'FILE:/tmp/' + ccname
        elif self.krb5cctype == 'KEYRING':
            krb5ccname = 'KEYRING:persistent:'+ ccname + ':'
        else:
            krb5ccname = 'MEMORY:' + ccname
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
        self.logger.debug(f"running kerberos auth for {kerberos_principal}")

        # this section code can raise gssapi.exceptions.GSSError
        req_creds = gssapi.raw.acquire_cred_with_password(user, bpass, usage='initiate')
        
        if isinstance( req_creds, gssapi.raw.AcquireCredResult):
            krb5ccname = str.encode(krb5ccname) # convert krb5ccname from str to bytes
            # context = gssapi.SecurityContext(name=server_name, creds=creds, usage='initiate')
            store_cred_result = gssapi.raw.store_cred_into( store={b'ccache': krb5ccname},
                                                            creds=req_creds.creds,
                                                            usage="initiate", 
                                                            overwrite=True )
            
            self.logger.debug( f"store_cred_into {krb5ccname} {store_cred_result.usage}" )
            # exported_cred = gssapi.raw.export_cred(req_creds.creds)

        #
        # old code version with kinit subprocess
        #    userPrincipalName = userid + '@' + self.kerberos_realm
        #   cmd = [ self.kerberos_kinit, '-c', krb5ccname, userPrincipalName ]
        #    my_env = os.environ.copy()
        #    if self.kerberos_krb5_conf :
        #       my_env['KRB5_CONFIG'] = self.kerberos_krb5_conf
        #    self.logger.info( 'run kinit command %s', cmd )
        #    process = subprocess.run(cmd, input=password.encode(),  env=my_env )
        #    success = process.returncode
        #    return result
        #

        return store_cred_result


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
                self.logger.error( f"failed to delete tmp file: {koutputfilename} {e}" )

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

       
        self.logger.info( f"{self.kerberos_ktutil} return code: {returncode}" )
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
        hashes = None
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

            ret,out = pyutils.execproc( command=self.ntlm_command, 
                                        environment= {'NTLM_PASSWORD': password}, 
                                        timeout=self.exec_timeout)
            if ret != 0:
                raise RuntimeError( f"Command ntlm_auth returned error code: {ret}" )
            self.logger.info( f"Running ntlm_command={self.ntlm_command}" )
            hashes = {}
            for line in out:
                if len( line ) < 1: # skipping empty line
                    continue
                # parse string format
                # NTLM_KEY=v8+pDkRc41i8weIufYRhVBPSv=dqM
                self.logger.debug( f"Parsing {line}")
                try:
                    nv = line.index('=') # read the first entry of 
                    hashes[ line[ 0 : nv ] ] = line[ nv+1 : ]
                except Exception as e:
                    # Index if found otherwise raises an exception if str is not found
                    # by pass line 
                    self.logger.error( f"Parsing ntlm_auth result failed: {e}")
            self.logger.debug( f"NTLM hashes: {hashes}" )
        except Exception as e:
            self.logger.error( f"Failed: {e}" )

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
        hashes = None
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
        hashes = None

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

            hashes = {}
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
    DEFAULT_ATTRS = [ 'objectClass', 'distinguishedName', 'displayName', 'sAMAccountName', 'name', 'cn', 'homeDrive', 'homeDirectory', 'profilePath', 'memberOf', 'proxyAddresses', 'userPrincipalName', 'primaryGroupID', 'objectSid' ]
    # DEFAULT_ATTRS = [ 'objectClass', 'distinguishedName', 'displayName', 'sAMAccountName', 'name', 'cn', 'homeDrive', 'homeDirectory', 'profilePath', 'memberOf', 'proxyAddresses', 'userPrincipalName', 'primaryGroupID', 'objectSid' ]
    DEFAULT_ATTRS = [  'displayName', 'sAMAccountName', 'name', 'cn', 'homeDrive', 'homeDirectory', 'profilePath', 'memberOf', 'proxyAddresses', 'userPrincipalName', 'primaryGroupID', 'objectSid' ]

    DEFAULT_USER_ATTRS = [ 'homeDirectory', 'homeDrive', 'localeID', 'primaryGroupID', 'userAccountControl', 'memberOf' ]

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
            basedn=config.get('printer_printerdn', 'OU=Applications,' + config.get('ldap_basedn') ),
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
            
            
        # query site
        self.site_query = self.Query(
            basedn=config.get('site_subnetdn', 'CN=Subnets,CN=Sites,CN=Configuration,' + config.get('ldap_basedn') ),
            scope=config.get('site_scope', ldap3.SUBTREE),
            filter=config.get('site_filter', '(objectClass=subnet)'),
            attrs=config.get('site_attrs',['cn', 'siteObject', 'location']) )

    def getdefault_uid(self, userinfo:dict, user:str)->str:
        """getdefault_uid
            return a default uid if user if not a posix account
        Args:
            userinfo (dict): userinfo
            user (str): _description_

        Returns:
            str: uid
        """
        uid = None
        if isinstance( userinfo, dict) :
            # the self.useridattr (sAMAccountName) may not exist if auth is kerberos only
            uid = userinfo.get(self.useridattr)
            if isinstance( uid, str ):
                # convert a sAMAccountName to a linux uid 
                uid = ODAuthProviderBase.safe_uid( uid )
        if not isinstance( uid, str ):
            uid = super().getdefault_uid(userinfo , user)
        return uid


    def get_kerberos_realm( self ):
        """[return the kerberos realm]

        Returns:
            [str]: [kerberos realm]
        """
        kerberos_realm = None
        # self.kerberos_realm can be a dict or a str
        # if it is a dict, read the realm from the domain key value
        if isinstance( self.kerberos_realm, dict ):
            kerberos_realm = self.kerberos_realm.get( self.domain )
        # if it is a str, read the default kerberos_realm value
        if isinstance( self.kerberos_realm, str ):
            kerberos_realm = self.kerberos_realm

        return kerberos_realm

    def getntlmlogin( self, userid:str ):
        adlogin = userid
        assert isinstance( userid, str), 'bad userid parameter'
        ar = userid.split('\\')
        if len(ar)>2:
            raise AuthenticationFailureError('invalid login format') 
        if len(ar)==1 and isinstance(self.domain, str):
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
        if not self.issafeAdAuthusername(userid):
            raise InvalidCredentialsError('Unsafe login credentials')
        if not self.issafeAdAuthpassword(password):
            raise InvalidCredentialsError('Unsafe password credentials')
       
        # authenticate can raise exception 
        (userdn, conn) = super().validate(userid, password)
    
        data = {    'userid': userid, 
                    'domain': self.domain, 
                    'dn': userdn
        }
        authinfo = AuthInfo( provider=self.name, providertype=self.type, token=userid, data=data, protocol=self.auth_protocol, conn=conn)
        return authinfo


    def createclaims( self, authinfo, userinfo, userid, password,  **arguments):
        claims = { 'identity': self.createauthenv(userinfo, userid, password) }
        claims.update( { 'userid': userid, 'password': password, 'domain': self.domain } )
        authinfo.set_claims(claims)

    def getuserinfo(self, authinfo, **params):
        self.logger.debug('')
        userinfo = super().getuserinfo(authinfo, **params)
    
        if isinstance(userinfo, dict):
            #
            # Add always userid entry as sAMAccountName overwrite value from standard LDAP server
            # in most case : useridattr should be 'sAMAccountName'
            #
            useridattr = userinfo.get(self.useridattr) 
            if isinstance( useridattr, str ) and useridattr: 
                userinfo['userid'] = userinfo.get(self.useridattr)

            # read homeDrive homeDirectory and profilePath attributs
            # homeDrive
            # homedrive = userinfo.get('homeDrive') 
            # if isinstance( homedrive, str ) and homedrive: 
            #    userinfo['homeDrive'] = homedrive

            # homeDirectory replace chars
            homeDirectory = userinfo.get('homeDirectory') 
            if isinstance( homeDirectory, str ): 
                userinfo['homeDirectory'] = homeDirectory.replace('\\','/')

            # profilePath  replace chars
            profilePath = userinfo.get('profilePath')
            if isinstance( profilePath, str ):   
                userinfo['profilePath'] = profilePath.replace('\\','/')

        return userinfo

    
   

    def getroles(self, authinfo, userinfo, **params):
        self.logger.debug('')
        token = authinfo.token 
        if not self.recursive_search:
            return super().getroles(authinfo, userinfo, **params)

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
        if not isinstance(userdn, str): 
            return []

        return [entry['cn'] for entry in self.search(authinfo.conn, self.group_query.basedn, ldap3.SUBTREE, '(member:1.2.840.113556.1.4.1941:=%s)' % userdn, ['cn'])]
    

    
    def issafeAdAuthusername(self, username:str):
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

    def issafeAdAuthpassword(self, password:str):
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
            self.logger.info( f"Refreshing domain controllers list - {ldap_tcp_domain}")
            self.servers = oc.od.resolvdns.ODResolvDNS.resolv( fqdn_name=ldap_tcp_domain, query_type='SRV' )
            self.dcs_list_lastupdated = time.time()
            self.logger.info( "Domain controllers list: {self.servers}" )            
        finally:
            self.refreshdcs_lock.release()

    def isdcslistexpired(self):
        bReturn  =  self.query_dcs and                      \
                    self.dcs_list_maxage and                \
                    not self.refreshdcs_lock.locked() and   \
                    (time.time() - self.dcs_list_lastupdated > self.dcs_list_maxage)
        if bReturn is True:
           self.logger.debug( 'dcslist has expired' )
        return bReturn

    def getconnection(self, userid:str, password:str ):
        self.logger.debug('')
        if self.auth_type == 'NTLM':
            # add the domain name to format login as DOMAIN\USER if need
            userid = self.getntlmlogin(userid)
        if self.auth_type == 'KERBEROS':
            # create a Kerberos TGT 
            userid = userid.upper()
            self.krb5_authenticate( userid, password )
        return super().getconnection(userid, password )

    def listsite(self, **params):       
        self.logger.debug('')

        dictsite = {}
        len_dictsite = 0
        userid     = params.get( 'userid', self.userid )
        password   = params.get( 'password',self.password )                
        
        if not isinstance(userid, str) or not isinstance(password, str) :
            self.logger.info( 'service account not set in config file, listsite return empty site')
            return dictsite

        try:
            self.logger.debug('getconnection to ldap')
            conn = self.getconnection( userid, password )

            self.logger.debug('_pagedAsyncSearch %s %s %s ', self.site_query.basedn, self.site_query.filter, self.site_query.attrs)            
            result = self.paged_search(conn, self.site_query.basedn, self.site_query.filter, self.site_query.attrs )            
            # self.logger.debug('_pagedAsyncSearch return len=%d', len( result ))
            for dn in result:
                attrs = result[dn]

                if attrs is None:
                    self.logger.info( 'ldap dn=%s has no attrs %s, skipping', str(dn), self.site_query.attrs  )
                    continue

                if not isinstance( attrs, dict): 
                    self.logger.error( 'dn=%s attrs must be a dict, return data from ldap attrs %s', str(dn), str( type( attrs )))
                    continue
                
                entry = {}                
                # translate the 'cn' as 'subnet'     
                entry['subnet'] = self.decodeValue( 'cn', attrs.get('cn') )
                entry['siteObject'] = self.decodeValue( 'siteObject', attrs.get('siteObject') )
                entry['location'] = self.decodeValue( 'location', attrs.get('location') )
                
                if all([ entry.get('subnet'), entry.get('siteObject'), entry.get('location') ]):                       
                    dictsite[ entry.get('subnet') ] = entry
                
            len_dictsite = len( dictsite )
            self.logger.info('query result count:%d %s %s ', len_dictsite, self.site_query.basedn, self.site_query.filter)

            conn.unbind()

        except Exception as e:
            self.logger.error( 'LDAP query siteObject error: %s', e )     
        
        if len_dictsite == 0:
            self.logger.warning('ActiveDirectory has no siteObject defined')
            
        return dictsite




@oc.logging.with_logger()
class ODAdAuthMetaProvider(ODAdAuthProvider):
    def __init__(self, manager, name, config):
        super().__init__(manager, name, config)
        self.type = 'metaactivedirectory'
        self.trustedrelationship = config.get('trustedrelationship', True)
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

        self.foreign_query = self.Query(
            config.get('foreign_basedn', 'CN=ForeignSecurityPrincipals,' + self.user_query.basedn),
            config.get('foreign_scope', self.user_query.scope),
            config.get('foreign_filter', "(&(objectClass=foreignSecurityPrincipal)(objectSid=%s))"),
            config.get('foreign_attrs',  ['cn', 'distinguishedName'] ) )

        self.foreingmemberof_query = self.Query(
            config.get('foreingmemberof_basedn', 'CN=ForeignSecurityPrincipals,' + self.user_query.basedn),
            config.get('foreingmemberof_scope', self.user_query.scope),
            config.get('foreingmemberof_filter', "(memberof:1.2.840.113556.1.4.1941:=%s)"),
            config.get('foreingmemberof_attrs',  ['cn', 'distinguishedName'] ) )

    def validate(self, userid, password, **params):
        """[validate]
            this is a meta directory do not perform a ldap bind using current credentials  

        Args:
            userid ([type]): [description]
            password ([type]): [description]

        Returns:
            [type]: [description]
        """
        self.logger.debug('')
        return super().validate(userid, password, **params)

    def authenticate(self, userid, password, **params):
        self.logger.debug('')
        if not self.issafeAdAuthusername(userid):
            raise InvalidCredentialsError('Unsafe login credentials')
        if not self.issafeAdAuthpassword(password):
            raise InvalidCredentialsError('Unsafe password credentials')
       
        # validate can raise exception 
        (userdn, conn) = self.validate(userid, password)
    
        data = {    'userid': userid, 
                    'domain': self.domain,
                    'dn': userdn
        }
        authinfo = AuthInfo(provider=self.name, providertype=self.type, token=userid, data=data, protocol=self.auth_protocol, conn=conn)
        return authinfo

    def createclaims( self, authinfo, userinfo, userid, password, **arguments):
        claims = { 'userid': userid, 'password': password, 'domain': self.domain }
        authinfo.set_claims(claims)
        
    def getuserinfo(self, authinfo, **arguments):  
        self.logger.debug('')     
        userid = arguments.get( 'userid' )
        filter = ldap_filter.filter_format( self.user_query.filter, [ userid ] )
        self.logger.info( 'ODAdAuthMetaProvider:ldap.filter %s', filter)
        usersinfo = self.search_all(    conn=authinfo.conn, 
                                        basedn=self.user_query.basedn, 
                                        scope=self.user_query.scope, 
                                        filter=filter, 
                                        attrs=self.user_query.attrs )

        if not isinstance( usersinfo, list ) or len( usersinfo ) == 0:
            # User does not exist in metadirectory 
            # use login
            self.logger.error( 'user does not exist in metadirectory, skipping meta query' )
            return None

        if len( usersinfo ) > 1:
            # too much user with the same SAMAccountName 
            # may be Forest SAMAccountName Meta 
            self.logger.error( 'too much user %s in metadirectory len %d, skipping meta query', userid, len( usersinfo ) )
            self.logger.error( 'dump metadirectory %s', usersinfo )
            return None

        return usersinfo[0]

    def getforeignkeys(self, authinfo:AuthInfo, user:AuthUser): 
        self.logger.debug('')
        foreingdistinguished_name = self.getForeignDistinguishedName( authinfo, user.get( 'objectSid' ) )
        return foreingdistinguished_name

    def getroles(self, authinfo, userinfo, **params): 
        self.logger.debug('') 
        roles = []
        
        # auth_only do not use ldap query
        if self.auth_only : 
            # return empty list
            return roles

        # memberOf must always exists in Active Directory
        userid = params.get( 'userid' )
        filter = ldap_filter.filter_format( self.user_query.filter, [ userid ] )
        self.logger.info( 'ODAdAuthMetaProvider:ldap.filter %s', filter)
        userinfo = self.search_one( conn=authinfo.conn, 
                                    basedn=self.user_query.basedn, 
                                    scope=self.user_query.scope, 
                                    filter=filter, 
                                    attrs=['memberOf']  )

        if isinstance( userinfo, dict ) :
            roles = userinfo.get('memberOf',[])
            if not isinstance( roles, list ):
                roles = [ roles ]

        return roles
    
    def getForeignDistinguishedName( self, authinfo:AuthInfo, objectSid:str ):
        self.logger.debug('')
        # read
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/5aa09c90-c5db-4e97-98d0-b7cdd6bc1bfe
        # https://social.technet.microsoft.com/wiki/contents/articles/51367.active-directory-foreign-security-principals-and-special-identities.aspx
        #
        foreingdistinguished_name = None

        # objectSid is the original objectSid from the user domain
        self.logger.debug( f"objectSid is {objectSid}")

        if not isinstance(objectSid, str):
            self.logger.debug( "objectSid is not a str, return None")
            return foreingdistinguished_name
        #
        # look for objectSid inside the metadirecotry LDAP
        # A Foreign Security Principal (FSP) is an object created by the system
        # to represent a security principal in a trusted external forest.
        # These objects are created in the Foreign Security Principals container of the domain.
        #
        filter = ldap_filter.filter_format( self.foreign_query.filter, [ objectSid ] )
        self.logger.debug( f"ldap.filter {filter}")
        self.logger.debug( f"ldap search_all basedn={self.foreign_query.basedn} filter={filter} attrs={self.foreign_query.attrs}" )

        query_foreingdistinguished_name = self.search_all(  conn=authinfo.conn, 
                                                            basedn=self.foreign_query.basedn, 
                                                            scope=self.foreign_query.scope, 
                                                            filter=filter, 
                                                            attrs=self.foreign_query.attrs )

        self.logger.debug( f"ldap search result {type(query_foreingdistinguished_name)} {query_foreingdistinguished_name}")

        if not isinstance( query_foreingdistinguished_name, list ) or len( query_foreingdistinguished_name ) == 0:
            # foreign sid not exist in metadirectory 
            self.logger.debug( f"objectSid={objectSid} is not found, return None")
            return None

        foreingdistinguished_list = []
        # read the foreingdn.get('distinguishedName') in each entries in the list of dict
        # do not use map reduce it's too long than this simplest lines
        for foreingdn_dict in query_foreingdistinguished_name:
            if isinstance(foreingdn_dict, dict):
                dn = foreingdn_dict.get('distinguishedName')
                if isinstance(dn, str):
                    foreingdistinguished_list.append( dn )

        self.logger.debug( f"return foreingdistinguished_list={foreingdistinguished_list}" )
        return foreingdistinguished_list

    def isMemberOf(self, authinfo, groupdistinguished_name: str):
        memberof = False
        q = self.foreingmemberof_query
        filter = ldap_filter.filter_format( q.filter, [ groupdistinguished_name ] )
        try:
            self.logger.debug ( "run ldapquery isMember FSP:ForeignSecurityPrincipals" )
            self.logger.debug ( f"search_base={q.basedn}, search_scope={q.scope}, search_filter={filter}" )
            self.logger.debug ( "starting query" )
            memberof = authinfo.conn.search( search_base=q.basedn, search_filter=filter, search_scope=q.scope )
            self.logger.debug ( f"end of query authinfo.conn.search return {memberof}" )
            if memberof:
                self.logger.debug ( "start dumping data query" )
                for entry in authinfo.conn.response:
                    self.logger.debug(entry)
                self.logger.debug ( "end of dumping data query" )
        except Exception as e:
            self.logger.error( e )

        self.logger.debug ( f"return memberof={memberof}" )
        return memberof
        

    def isMemberOfForeingSecuriyPrincipalsbyObjectSid( self, authinfo:AuthInfo, user:AuthUser, groupdistinguished_name:str ):
        self.logger.debug('ODAdAuthMetaProvider')
        memberof = False
        foreing_distinguished_name = user.get('foreing_distinguished_name')
        self.logger.debug( f"foreing_distinguished_name is {foreing_distinguished_name}")

        if not isinstance(foreing_distinguished_name, list):
            self.logger.debug( "foreing_distinguished_name is not a list, return False")
            return memberof

        for userdistinguished_name in foreing_distinguished_name:
            self.logger.debug( f"call super().isMemberOf {userdistinguished_name} {groupdistinguished_name}")
            if super().isMemberOf( authinfo, userdistinguished_name, groupdistinguished_name):
                memberof = True
                break
        self.logger.debug( f"isMemberOf return {memberof}")
        return memberof


@oc.logging.with_logger()
class ODImplicitTLSCLientAdAuthProvider(ODAdAuthProvider):

    def __init__(self, manager, name, config):
        super().__init__(manager, name, config)
        self.dialog_url = config.get( 'dialog_url' )
        if not self.is_serviceaccount_defined(config):
            raise InvalidCredentialsError(f"you must define a service account for the implicit auth provider {self.name}")

    def getclientdata(self):
        data =  super().getclientdata()
        data['dialog_url'] = self.dialog_url
        return data

    # there is no password in createclaims for Implicit provider
    def createclaims(self, authinfo, userinfo, userid, **arguments):
        # for ODImplicitTLSCLientAdAuthProvider auth use TLS, password is None
        claims = { 'identity': self.createauthenv(userinfo, userid, password=None) }
        authinfo.set_claims( claims )

    def authenticate(self, userid, **params):
        # validate can raise exception 
        # like invalid credentials
        q = self.user_query
        
        if not self.issafeAdAuthusername(userid) :
            raise InvalidCredentialsError('Unsafe login credentials')

         # get connection using the service account
        conn = self.getconnection(self.userid ,self.password)
        # look for the user in directory service 
        userinfo = self.search_one( conn=conn, basedn=q.basedn, scope=q.scope, filter=ldap_filter.filter_format(q.filter, [userid]), attrs=q.attrs, **params)
        # if userinfo is None, user does not exist
        if not isinstance(userinfo, dict):
            raise AuthenticationError(f"Implicit login user {userid} does not exist in directory service")

        data = { 'userid': userid, 'dn': userinfo.get('dn') }
        authinfo = AuthInfo( provider=self.name, providertype=self.type, token=userid, data=data, protocol=self.auth_protocol, conn=conn)
        return authinfo