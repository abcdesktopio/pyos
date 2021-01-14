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
import re
import cherrypy
import cherrypy.lib.sessions
import netaddr
from cherrypy._cpdispatch import Dispatcher

import oc.pyutils as pyutils

logger = logging.getLogger(__name__)


# WARNING : No logging is possible inside getclientipaddr, 
# it would generate cycling dependencies call in oc.logging functions
def getclientipaddr_dict():
    ''' return a dict of all client ip '''
    ''' WARNING : No logging is possible inside getclientipaddr, 
                  it would generate cycling dependencies call in oc.logging functions'''
    xforwardedfor = cherrypy.request.headers.get('X-Forwarded-For')
    clientip = None
    realip   = None
    if type(xforwardedfor) is str:
        clientiplistxforwardedfor = xforwardedfor.split(',') # ',' is the defalut separator for 'X-Forwarded-For' header
        clientip = clientiplistxforwardedfor[0] # the first entry is the real client ip address source
        try:
            # Check if clientip is an ipAddr 
            netaddr.IPAddress(clientip)
        # No logging is possible inside getclientipaddr
        except netaddr.core.AddrFormatError as e: 
            pass
        except Exception as e : 
            pass

        realip = cherrypy.request.headers.get('X-Real-IP')
        try:
            # Check if realip is an ipAddr 
            netaddr.IPAddress(realip)
        # No logging is possible inside getclientipaddr
        except netaddr.core.AddrFormatError as e: 
            pass
        except Exception as e: 
            pass

        # last entries are proxies join it using ','
        # proxy ip is not used but set as :
        # proxyip = ','.join(clientiplistxforwardedfor[1::])

            
    clientip_dict = { 'X-Forwarded-For' : clientip,
                      'X-Real-IP':  realip,
                      'remoteip': cherrypy.request.remote.ip }
    return clientip_dict


# WARNING : No logging is possible inside getclientipaddr, 
# it would generate cycling dependencies call in oc.logging functions
def getclientipaddr():
    ''' return string ipAddr of browser client, None if failed '''
    ''' Do the best to obtain the Client IP Address
        use X-Forwarded-For HTTP header from nginx
        or use X-Real-IP-For HTTP header from nginx
        or cherrypy.request.remote.ip        
    '''
    ipaddr = None   # the return value
    clientip_dict = getclientipaddr_dict()
    ipaddr = clientip_dict.get('X-Forwarded-For')
    if ipaddr is None:
        ipaddr = clientip_dict.get('X-Real-IP')
        if ipaddr is None:
            ipaddr = clientip_dict.get('remoteip')

    return ipaddr





class WebAppError(cherrypy.HTTPError):
    def __init__(self, message, status=400, code=400, source=None): 
        super().__init__(status, message)
        self.code = code or status
        self.source = source
        self.status = status
        self.message = message

    def to_dict(self): 
        return { 'status':self.status, 'error': { 'code': self.code, 'message': self.message, 'source': self.source  } }

# Allow (partial) case-insensivity in URLs 
class CaseInsensitiveDispatcher(Dispatcher):
    def __call__(self, path_info):
        return Dispatcher.__call__(self, path_info.lower()) 

class Tools(object):
    
    @staticmethod
    def create_controllers(parent, source_module, config_controllers, module_filter=r'^\w+_controller$',class_filter=r'^(\w+)Controller$'):
        for _class in pyutils.import_classes(source_module, module_filter, class_filter):
            logger.debug( 'instancing class %s', _class.__name__)
            controller = _class(config_controllers.get( _class.__name__))
            controller.root = parent
            controller.logger = logging.getLogger(_class.__module__ + '.' + _class.__name__)
            setattr(parent, re.match(class_filter, _class.__name__).group(1).lower(), controller) 

    '''
    @staticmethod
    @cherrypy.tools.register('before_finalize')
    def allow_origin(origin='*',headers=['Accept',  'Accept-CH',  'Accept-Charset',  'Accept-Datetime',  'Accept-Encoding',  'Accept-Ext',  'Accept-Features',  'Accept-Language',  'Accept-Params',  'Accept-Ranges',  'Access-Control-Allow-Credentials',  'Access-Control-Allow-Headers',  'Access-Control-Allow-Methods',  'Access-Control-Allow-Origin',  'Access-Control-Expose-Headers',  'Access-Control-Max-Age',  'Access-Control-Request-Headers',  'Access-Control-Request-Method',  'Age',  'Allow',  'Alternates',  'Authentication-Info',  'Authorization',  'C-Ext',  'C-Man',  'C-Opt',  'C-PEP',  'C-PEP-Info',  'CONNECT',  'Cache-Control',  'Compliance',  'Connection',  'Content-Base',  'Content-Disposition',  'Content-Encoding',  'Content-ID',  'Content-Language',  'Content-Length',  'Content-Location',  'Content-MD5',  'Content-Range',  'Content-Script-Type',  'Content-Security-Policy',  'Content-Style-Type',  'Content-Transfer-Encoding',  'Content-Type',  'Content-Version',  'Cookie',  'Cost',  'DAV',  'DELETE',  'DNT',  'DPR',  'Date',  'Default-Style',  'Delta-Base',  'Depth',  'Derived-From',  'Destination',  'Differential-ID',  'Digest',  'ETag',  'Expect',  'Expires',  'Ext',  'From',  'GET',  'GetProfile',  'HEAD',  'HTTP-date',  'Host',  'IM',  'If',  'If-Match',  'If-Modified-Since',  'If-None-Match',  'If-Range',  'If-Unmodified-Since',  'Keep-Alive',  'Label',  'Last-Event-ID',  'Last-Modified',  'Link',  'Location',  'Lock-Token',  'MIME-Version',  'Man',  'Max-Forwards',  'Media-Range',  'Message-ID',  'Meter',  'Negotiate',  'Non-Compliance',  'OPTION',  'OPTIONS',  'OWS',  'Opt',  'Optional',  'Ordering-Type',  'Origin',  'Overwrite',  'P3P',  'PEP',  'PICS-Label',  'POST',  'PUT',  'Pep-Info',  'Permanent',  'Position',  'Pragma',  'ProfileObject',  'Protocol',  'Protocol-Query',  'Protocol-Request',  'Proxy-Authenticate',  'Proxy-Authentication-Info',  'Proxy-Authorization',  'Proxy-Features',  'Proxy-Instruction',  'Public',  'RWS',  'Range',  'Referer',  'Refresh',  'Resolution-Hint',  'Resolver-Location',  'Retry-After',  'Safe',  'Sec-Websocket-Extensions',  'Sec-Websocket-Key',  'Sec-Websocket-Origin',  'Sec-Websocket-Protocol',  'Sec-Websocket-Version',  'Security-Scheme',  'Server',  'Set-Cookie',  'Set-Cookie2',  'SetProfile',  'SoapAction',  'Status',  'Status-URI',  'Strict-Transport-Security',  'SubOK',  'Subst',  'Surrogate-Capability',  'Surrogate-Control',  'TCN',  'TE',  'TRACE',  'Timeout',  'Title',  'Trailer',  'Transfer-Encoding',  'UA-Color',  'UA-Media',  'UA-Pixels',  'UA-Resolution',  'UA-Windowpixels',  'URI',  'Upgrade',  'User-Agent',  'Variant-Vary',  'Vary',  'Version',  'Via',  'Viewport-Width',  'WWW-Authenticate',  'Want-Digest',  'Warning',  'Width',  'X-Content-Duration',  'X-Content-Security-Policy',  'X-Content-Type-Options',  'X-CustomHeader',  'X-DNSPrefetch-Control',  'X-Forwarded-For',  'X-Forwarded-Port',  'X-Forwarded-Proto',  'X-Frame-Options',  'X-Modified',  'X-OTHER',  'X-PING',  'X-PINGOTHER',  'X-Powered-By',  'X-Requested-With']):
        cherrypy.response.headers['Access-Control-Allow-Origin'] = origin
        # cherrypy.response.headers['Access-Control-Allow-Headers'] = ", ".join(headers)
    '''

    @staticmethod
    @cherrypy.tools.register('before_handler', priority=1)
    def add_response_result():
        request = cherrypy.serving.request
        handler = request.handler
        if handler is None: 
            return

        def new_handler(*args, **kwargs):
            request.result = handler(*args, **kwargs)
            return request.result

        request.handler = new_handler


class Results(object):
    @staticmethod
    def result(message=None, status=200, result=None):
        response = {
            'status': status,
            'result': result
        }

        if status == 200:
            response['message'] = message
        else:
            response['error'] = message or 'Unkown error'

        return response

    @staticmethod
    def continue_(message='continue', result=None):
        return Results.result(message, 100, result)

    @staticmethod
    def success(message='ok', result=None):
        return Results.result(message, 200, result)

    @staticmethod
    def error(message='unknow error', status=500, context=None):
        return Results.result(message, status)

    @staticmethod
    def unauthorized(message='unauthorized'):
        return Results.result(message, 401)
