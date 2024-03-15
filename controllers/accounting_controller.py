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
import json
import oc.od.services
from oc.od.base_controller import BaseController

logger = logging.getLogger(__name__)

@cherrypy.tools.allow(methods=['GET'])
@cherrypy.config(**{ 'tools.auth.on': False })
@oc.logging.with_logger()
class AccountingController(BaseController):

    def __init__(self, config_controller=None):
        super().__init__(config_controller)

    # metrics request is protected by is_permit_request()
    @cherrypy.expose    
    def metrics(self, format='ebnf'):
        ''' return http response to metrics default format is ebnf '''

        self.is_permit_request()

        # disable trace for accounting request
        cherrypy.response.notrace = True        
        if format == 'json' :
            return self.dump_tojson()
        else:
            return self.dump_toebnf()            

    def dump_toebnf(self):
        ''' convert accounting dict to ebnf format '''
        cherrypy.response.headers['Content-Type'] = 'text/plain;charset=utf-8'
        output = ""
        #
        # read the doc at https://en.wikipedia.org/wiki/Extended_Backus%E2%80%93Naur_form
        # https://github.com/prometheus/docs/blob/master/content/docs/instrumenting/exposition_formats.md         
        # Sample 
        # metric_name [ # "{" label_name "=" `"` label_value `"` { "," label_name "=" `"` label_value `"` } [ "," ] "}" ] value [ timestamp ]
        #
        message = oc.od.services.services.accounting.todict()
        if type( message ) is dict:
            for k, v in message.items():
                # t = int( datetime.datetime.now().timestamp() )
                # dump data                
                if isinstance(v, dict):
                    # # HELP http_requests_total The total number of HTTP requests.
                    # # TYPE http_requests_total counter
                    # http_requests_total{method="post",code="200"} 1027 1395066363000
                    # http_requests_total{method="post",code="400"}    3 1395066363000

                    for ka in v:
                        if k in ['container', 'image'] :
                            datatype = oc.auth.namedlib.normalize_containername(str(ka))                            
                        else:    
                            datatype=str(ka)

                        output += "pyos_{counter}_total{{{counter}=\"{type}\"}} {value}\n".format( counter=k, type=datatype, value=str(v[ka]))  
                else:                    
                    # now = datetime.datetime.now() # current date and time
                    # timestamp = datetime.timestamp(now)
                    output += "# {} pyos_counter\n".format( k )  
                    output += "pyos_{counter}_total {value}\n".format( counter=k, value=message[k] )  
        return output.encode('utf8')

    def dump_tojson(self):
        ''' convert accounting dict to json format '''
        cherrypy.response.headers['Content-Type'] = 'application/json;charset=utf-8'
        message = oc.od.services.services.accounting.todict()
        return json.dumps(message).encode('utf8')