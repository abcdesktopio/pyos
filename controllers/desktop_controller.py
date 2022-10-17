﻿#!/usr/bin/env python3
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
import oc.logging
import cherrypy
import json
from oc.od.services import services
from oc.cherrypy import Results
from oc.od.base_controller import BaseController
from oc.od.composer import fakednsquery

logger = logging.getLogger(__name__)


@cherrypy.config(**{ 'tools.auth.on': False })
@oc.logging.with_logger()
class DesktopController(BaseController):

    def __init__(self, config_controller=None):
        super().__init__(config_controller)
        self.dns_http_auth_key = None
        self.http_header_dns_name_authkey = 'authdnskey'
        if isinstance( config_controller, dict ):
            self.dns_http_auth_key = config_controller.get(self.http_header_dns_name_authkey)
            # by default dns is denied if it is not explicit allowed
            self.overwrite_requestpermission_ifnotset( 'dns', False )


    def handler_dns_json(self, dns):
        cherrypy.response.headers[ 'Content-Type'] = 'application/json;charset=utf-8'
        data = { 'ipaddr': dns }
        # convert data as str
        result_str = json.dumps( data ) + '\n'
        # encode with charset=utf-8
        return result_str.encode('utf-8')

    def handler_dns_text(self, dns):
        cherrypy.response.headers[ 'Content-Type'] = 'text/text;charset=utf-8'
        cherrypy.response.headers[ 'Cache-Control'] = 'No-Store'
        result_str = dns + '\n'
        return result_str.encode('utf-8')



    @cherrypy.expose
    @cherrypy.tools.allow(methods=['GET'])
    def dns( self, *args ):
        logger.debug('')

        # check if request is allowed, raise an exception if deny
        self.is_permit_request()
       
        query_authname = cherrypy.request.headers.get(self.http_header_dns_name_authkey)
        if query_authname != self.dns_http_auth_key:
            raise cherrypy.HTTPError( 401, f"The request attribut {self.http_header_name_authkey} is not authentified" )

        #
        # application/json  mime type is defines in RFC 4627
        if cherrypy.request.method == 'GET':
            dnsvalue =  self.handle_networkinginterfaces_GET( args )
            routecontenttype = {
                'text/plain':  self.handler_dns_text,
                'application/json': self.handler_dns_json 
            }
            return self.getlambdaroute( routecontenttype, defaultcontenttype='application/json' )( dnsvalue )
        else:
            raise cherrypy.HTTPError( 400, f"The request methot {cherrypy.request.method} not implemented" ) 

    def handle_networkinginterfaces_GET( self, args ):
        self.logger.debug('')

        if not isinstance( args, tuple):
            raise cherrypy.HTTPError( 400, "Invalid request") 

        if len(args)!=1:
            raise cherrypy.HTTPError( 400, "Invalid request")

        userid=args[0]
        if not isinstance(userid, str):
            raise cherrypy.HTTPError( 400, "Invalid request") 

        # can raise exception
        fakednsvalue = oc.od.composer.fakednsquery( userid )
        if not isinstance(fakednsvalue, str):
             raise cherrypy.HTTPError( 404, "Not found") 

        return fakednsvalue
