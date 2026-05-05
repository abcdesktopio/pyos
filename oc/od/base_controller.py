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
import ipaddress
import cherrypy
import oc.logging
import re
import hmac

from netaddr import IPNetwork, IPAddress
from oc.cherrypy import getclientipaddr, getxforwardedfor, getproxy_ipaddr_from_xforwardedfor_header
from oc.od.services import services

logger = logging.getLogger(__name__)

@oc.logging.with_logger()
class BaseController(object):

     def __init__( self, config=None):
          # by default a controller is enabled event if config is not set
          self.enable = True 
          self.config = config

          # init with default value
          # ipnetworklistfilter is None by default
          self.ipnetworklistfilter = None    
          # requestsallowed is None by default
          self.requestsallowed = None
          # apikey  is None by default

          self.apikey = None
          self.database_acl = []
          # set value from config
          if isinstance( config, dict ):
               self.init_ipfilter()
               self.requestsallowed = config.get('requestsallowed')
               # by default a controller is enabled
               self.enable = config.get('enable', True )
               # apikey is a list of str
               self.apikey = config.get('apikey')
               self.database_acl = config.get('database_acl', [])
          class_filter=r'^(\w+)Controller$'
          self.controllerprefix = re.match(class_filter, self.__class__.__name__).group(1).lower()

     def getlambdaroute( self, routecontenttype:dict, defaultcontenttype:str ):
          """_summary_
               read cherrypy.request.headers.elements('Accept')
               return the lambda to render http response from routecontenttype argument
          Args:
               routecontenttype (dict): {   
                    'text/html':        self.handler_logmein_html, 
                    'application/json': self.handler_logmein_json,
                    'text/plain':       self.handler_logmein_text 
               }
               defaultcontenttype(str): 'text/html'
               default entry of routecontenttype if 'Accept' does not match
          Returns:
               lambda function value (routecontenttype match value)
          """

          # read 'Accept' header
          accepts = cherrypy.request.headers.elements('Accept') # sorted by qvalue
          routecontenttypekeys = routecontenttype.keys()
          for accept in accepts:
               accept_content_type = accept.value.lower()
               if accept_content_type in routecontenttypekeys:
                    return routecontenttype[accept_content_type]
          
          # return the default entry
          return routecontenttype.get( defaultcontenttype )


     def overwrite_requestpermission_ifnotset( self, method:str, permission:bool )->None:
          """overwrite_requestpermission
               if a requestpermission is not set, set it to permission

          Args:
              method (str): _description_
              permission (bool): _description_
          """

          if isinstance( self.requestsallowed, dict):
               if self.requestsallowed.get(method) is None:
                    self.requestsallowed[method] = permission
          else:
               self.requestsallowed = { method: permission }

     def init_ipfilter( self ):
          """init_ipfilter
               load config dict
               read 'permitip' network list
               set self.ipnetworklistfilter entries as IPNetwork object

          Args:
              config (dict): configuration
          """
          if not isinstance( self.config ,dict):
               return

          ipfilterlist = self.config.get('permitip')
          if not isinstance(ipfilterlist,list):
               return
          
          self.ipnetworklistfilter = []
          for ipfilter in ipfilterlist:
               try:
                    ipnetwork = IPNetwork( ipfilter )
               except Exception as e:
                    self.logger.error( f"invalid value={ipfilter} type={type(ipfilter)}, skipping error {e}" )
                    continue
               self.ipnetworklistfilter.append( ipnetwork )


     def required_controller_security_check( self, ipAddr:str=None )->None:
          """required_controller_security_check
               check if the request is allowed to be processed by the controller
               if the request is not allowed, raise cherrypy.HTTPError with status 403"""

          if not isinstance( ipAddr, str): 
               ipAddr = getclientipaddr()

          if self.isban_ip(ipAddr):
               raise cherrypy.HTTPError( status=401, message='ip address is banned' )
        
          if self.isspoofed_proxyxforwardedfor(): 
               self.fail_ip(ipAddr) # ban the ip address if X-Forwarded-For header is spoofed
               raise cherrypy.HTTPError( status=401, message='spoofed X-Forwarded-For header detected' )

     def validate_env(self):
          '''
               return (auth, user) if the user is identified and authenticated. 
               else raise cherrypy.HTTPError( status=401, 'user is not identified') 
               or   raise cherrypy.HTTPError( status=401, 'user is not authenticated')
               or   raise cherrypy.HTTPError( status=401, 'ip address is banned')
               or   raise cherrypy.HTTPError( status=401, 'login is banned')
          '''

          if self.isban_ip():
               raise cherrypy.HTTPError( status=401, message='ip address is banned' )

          if self.isspoofed_proxyxforwardedfor():
               self.fail_ip() # ban the ip address if X-Forwarded-For header is spoofed
               raise cherrypy.HTTPError( status=401, message='spoofed X-Forwarded-For header detected' )
          
          if not services.auth.isauthenticated:
               self.fail_ip() # ban the ip address if user is not authenticated
               raise cherrypy.HTTPError( status=401, message='user is not authenticated')
          
          if not services.auth.isidentified:
               self.fail_ip() # ban the ip address if user is not identified
               raise cherrypy.HTTPError( status=401, message='user is not identified')


          user = services.auth.user
          auth = services.auth.auth
          roles = services.auth.roles

          if self.isban_login(user.userid):
               raise cherrypy.HTTPError( status=401, message='user is banned')

          return (auth, user, roles)

     def fail_ip( self, ipAddr:str=None ):
          if not isinstance( ipAddr, str):
               ipAddr = getclientipaddr()
          services.fail2ban.fail_ip( ipAddr )

     def fail_login( self, login:str):
          self.logger.debug('')
          isban =  services.fail2ban.fail_login( login )
          return isban

     def isban_ip( self, ipAddr:str=None ):
          if not isinstance( ipAddr, str):
               ipAddr = getclientipaddr()
          isban = services.fail2ban.isban( ipAddr, collection_name=services.fail2ban.ip_collection_name )
          if isban is True:
               self.logger.info(f"isban {ipAddr} return {isban}")
          return isban

     def isban_login( self, login:str):
          # self.logger.debug('')
          isban =  services.fail2ban.isban( login, collection_name=services.fail2ban.login_collection_name )
          if isban is True:
               self.logger.info(f"isban {login} return {isban}")
          return isban


     def isspoofed_proxyxforwardedfor(self):
          '''
               return True if the X-Forwarded-For header is spoofed, else return False
               A header is considered spoofed if the source ip address is not in trusted_proxy_cidr and X-Forwarded-For header exist
          '''
          bReturn = True # paranoid by default
          try:
               if not getxforwardedfor():
                    # if no X-Forwarded-For header, return False
                    return False
               
                # read X-Forwarded-For header
               proxies = getproxy_ipaddr_from_xforwardedfor_header()
               
               if len( proxies ) == 0:
                    # if no proxy in the HTTP request, return False
                    return False

               if len( oc.od.settings.ip_network_trusted_proxy_cidr ) == 0:
                    # if no trusted proxy network is set, return False
                    return False

               for proxy in proxies:
                    for network in oc.od.settings.ip_network_trusted_proxy_cidr:
                         # if proxy is in trusted proxy cidr list, return False
                         if IPAddress(proxy) in network:
                              return False

               # if proxy is not in trusted proxy cidr list and proxy exists in X-Forwarded-For header, 
               # consider it as spoofed
               return True

          except Exception as e:
               self.logger.error( e )
          return bReturn

     def is_ipsource_private(self):
          '''
               return True if the source ip address is allocated for private networks. 
               See iana-ipv4-special-registry (for IPv4) or iana-ipv6-special-registry (for IPv6).
          '''
          bReturn = False
          try:               
               myipaddr = ipaddress.ip_address(cherrypy.request.remote.ip)
               bReturn = myipaddr.is_private
          except Exception as e:
               self.logger.error( e )
          return bReturn

     def is_apikey(self):
          self.logger.debug('')
          bReturn = False
          apikey = cherrypy.request.headers.get('X-API-Key') or cherrypy.request.headers.get('X-Api-Key')
          self.logger.debug( f"read http header apikey={apikey}" )
          for k in self.apikey:
               # self.logger.debug( f"compare apikey {k}={apikey}" )
               bReturn = hmac.compare_digest(k, apikey)
               if bReturn is True: 
                    break 
          return bReturn
     
     def raise_http_error_message( self, error_message:str, status=403 ):
          self.logger.error( error_message )
          raise cherrypy.HTTPError( status, error_message)

     def is_permit_request(self):
          
          if not self.enable :
               self.raise_http_error_message( '403.10 - Invalid configuration' )

          is_api_filter = self.apifilter() # Check if the controller has an apikey filter 
          is_ip_filter = self.ipfilter() # Check if the controller has an ip filter
          # if both filters are set, at least one must match
          # self.logger.debug( f"is_api_filter={is_api_filter}, is_ip_filter={is_ip_filter}" )
          if not is_api_filter or not is_ip_filter:
               if not is_ip_filter:
                    self.raise_http_error_message( '403.7 - IP address access denied' )
               if not is_api_filter: 
                    self.raise_http_error_message( '403.1 - Execute access forbidden' )
               
          if isinstance( self.requestsallowed, dict ):
               # read the request path
               path = cherrypy.request.path_info
               arg = path.split('/')
               if len( arg ) < 3 : 
                    # the min value is 3
                    self.raise_http_error_message( '403.12 - Mapper denied access. Invalid request' )

               # read example
               # 'getdesktopdescription' from str '/composer/getdesktopdescription'
               request_info = arg[2]

               # check if method is allowed in config file
               is_allowed = self.requestsallowed.get( request_info )

               # if is_allowed is None, do not raise Error
               if is_allowed is False :
                    self.raise_http_error_message( '403.8 - Site access denied' )

     def apifilter(self):
          """apifilter
               check if the request apikey is in the permitted apikey list
               if no apikey list is set, return True
          Returns:
               bool: True if the request apikey is in the permitted apikey list or no list is set
          """
          self.logger.debug('')
          if isinstance(self.apikey, list):
               return self.is_apikey()          
          return True
          
     def ipfilter( self ):
          """ipfilter
               check if the client ip address is in the permitted network list
               if no network list is set, return True

          Returns:
               bool: True if the client ip address is in the permitted network list or no list is set
          """
          self.logger.debug('')
          if not isinstance(self.ipnetworklistfilter, list) :
               return True
          ipclient = getclientipaddr()
          if isinstance(ipclient, str):
               for ipnetwork in self.ipnetworklistfilter:
                    if IPAddress(ipclient) in ipnetwork:
                         self.logger.debug( f"ipsource {ipclient} is permited in network {ipnetwork}")
                         return True
          self.logger.info( f"ipsource {ipclient} access is denied, not in network list {self.ipnetworklistfilter}")
          return False