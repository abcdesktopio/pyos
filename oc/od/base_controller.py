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

from netaddr import IPNetwork, IPAddress
from oc.cherrypy import WebAppError, getclientipaddr
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
          # set value from config
          if isinstance( config, dict ):
               self.init_ipfilter()
               self.requestsallowed = config.get('requestsallowed')
               # by default a controller is enabled
               self.enable = config.get('enable', True )
               # apikey is a list of str
               self.apikey = config.get('apikey')
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

     def validate_env(self):
          '''
               return (auth, user) if the user is identified and authenticated. 
               else raise WebAppError('user is not identified') 
               or   raise WebAppError('user is not authenticated')
               or   raise WebAppError('ip address is banned')
               or   raise WebAppError('login is banned')
          '''

          if self.isban_ip():
               raise WebAppError('ip address is banned')
          
          if not services.auth.isauthenticated:
               self.fail_ip()
               raise WebAppError('user is not authenticated')
          
          if not services.auth.isidentified:
               self.fail_ip()
               raise WebAppError('user is not identified')


          user = services.auth.user
          auth = services.auth.auth

          if self.isban_login(user.userid):
               raise WebAppError('user is banned')

          return (auth, user)

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
               self.logger.debug( f"compare apikey {k}={apikey}" )
               bReturn = k == apikey
               if bReturn is True:
                    break 
          return bReturn

     def is_permit_request(self):
          
          if not self.enable :
               raise cherrypy.HTTPError( 400, "The controller is disabled in configuration file")

          # Check if the controller has an apikey filter 
          # if set it must match to the apikey list entries
          if not self.apifilter():
               # 403 -  rejected.
               raise cherrypy.HTTPError(status=403, message='X-API-Key http header is denied')

          # Check if the controller has an ip filter 
          # if set it must match to the ip network entries
          if not self.ipfilter():
               # 403.6 - IP address rejected.
               raise cherrypy.HTTPError(status=403, message='ip address is denied')

          if isinstance( self.requestsallowed, dict ):
               # read the request path
               path = cherrypy.request.path_info
               arg = path.split('/')
               if len( arg ) < 3 : 
                    # the min value is 3
                    self.logger.error( 'request is denied' )
                    raise cherrypy.HTTPError(400, 'Request is denied by configuration file')

               # read example
               # 'getdesktopdescription' from str '/composer/getdesktopdescription'
               request_info = arg[2]
               # check if method is allowed in config file
               is_allowed = self.requestsallowed.get( request_info )

               # if is_allowed is None, do not raise Error
               if is_allowed is False :
                    self.logger.error( 'request is denied' )
                    raise cherrypy.HTTPError(400, 'Request is denied by configuration file')

     def apifilter(self):
          self.logger.debug('')
          if isinstance(self.apikey, list):
               return self.is_apikey()          
          return True
          
     def ipfilter( self ):
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