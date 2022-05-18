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
from netaddr import IPNetwork, IPAddress

from oc.cherrypy import WebAppError, getclientipaddr
from oc.od.services import services


logger = logging.getLogger(__name__)

@oc.logging.with_logger()
class BaseController(object):

     def __init__( self, config=None):
          self.config = config
          self.ipnetworklistfilter = None
          self.init_ipfilter( config )

     def init_ipfilter( self, config ):
          if not isinstance(config,dict):
               return

          ipfilterlist = self.config.get( 'permitip')
          if type( ipfilterlist ) is not list:
               return
          
          self.ipnetworklistfilter = []
          for ipfilter in ipfilterlist:
               try:
                    ipnetwork = IPNetwork( ipfilter )
               except Exception as e:
                    self.logger.error( 'invalid value %s, skipping warning: %s', ipfilter, str(e) )
                    continue
               self.ipnetworklistfilter.append( ipnetwork )

     def validate_env(self):
          '''
               return (auth, user) if the user is identified and authenticated. 
               else raise WebAppError('User is not identified') 
               or   raise WebAppError('User is not authenticated')
               or   raise WebAppError('Http request is banned')
          '''

          if self.isban_ip():
               raise WebAppError('http request is banned')
          
          if not services.auth.isauthenticated:
               self.fail_ip()
               raise WebAppError('User is not authenticated')
          
          if not services.auth.isidentified:
               self.fail_ip()
               raise WebAppError('User is not identified')


          user = services.auth.user
          auth = services.auth.auth

          return (auth, user)

     def fail_ip( self, ipAddr=None ):
          if not isinstance( ipAddr, str):
               ipAddr = getclientipaddr()
          services.fail2ban.fail_ip( ipAddr )

     def fail_login( self, login):
          self.logger.debug('')
          isban =  services.fail2ban.fail_login( login )

     def isban_ip( self, ipAddr=None ):
          if not isinstance( ipAddr, str):
               ipAddr = getclientipaddr()
          isban = services.fail2ban.isban_ip( ipAddr )
          self.logger.debug(f"isban {ipAddr} return {isban}")
          return isban

     def isban_login( self, login):
          self.logger.debug('')
          isban =  services.fail2ban.isban_login( login )
          self.logger.debug(f"isban {login} return {isban}")
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

     def is_permit_request(self):
          if not self.ipfilter():
               # 403.6 - IP address rejected.
               raise cherrypy.HTTPError(status=403)

     def ipfilter( self ):
          if type( self.ipnetworklistfilter ) is not list :
               return True

          ipclient = getclientipaddr()
          
          if ipclient is not None:
               for ipnetwork in self.ipnetworklistfilter:
                    if IPAddress(ipclient) in ipnetwork:
                         self.logger.debug( 'ipsource %s is permited in network %s', ipclient, ipnetwork)
                         return True
          self.logger.info( 'ipsource %s access denied', ipclient)
          return False