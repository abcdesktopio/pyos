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

#########
# WARNING : No logging is possible inside getclientipaddr, 
# it would generate cycling dependencies call in oc.logging functions
#########

def getclienthttp_header(header_name, default=None):
    return cherrypy.request.headers.get(header_name, default)

def getclienthttp_headers():
    return cherrypy.request.headers

def getclientremote_ip():
    return cherrypy.request.remote.ip

def getclientreal_ip():
    realip = None
    try:
        _realip = cherrypy.request.headers.get('X-Real-IP')
        if isinstance( _realip, str ):
            # Check if realip is an ipAddr 
            ipaddr = netaddr.IPAddress(_realip)
            # reconvert to string make sure to remove garbage data 
            # like space ipaddr = netaddr.IPAddress( '127.0.0.1 ' )
            # str( ipaddr ) returns '127.0.0.1'
            realip = str( ipaddr )
            # No logging is possible inside getclientipaddr
    except netaddr.core.AddrFormatError: 
        # netaddr.core.AddrFormatError: failed to detect a valid IP address from ipaddr
        pass
    except Exception: 
        pass
    return realip

def getclientxforwardedfor_listip():
    clientiplist = []
    xforwardedfor = cherrypy.request.headers.get('X-Forwarded-For')
    if isinstance(xforwardedfor, str):
        clientiplistxforwardedfor = xforwardedfor.split(',') # ',' is the defalut separator for 'X-Forwarded-For' header
        # Check if clientip is an ipAddr 
        # clientiplistxforwardedfor[0] is the first entry is the real client ip address source
        if isinstance( clientiplistxforwardedfor, list ):
            for ipforwarded in clientiplistxforwardedfor:
                try:
                    # remove space in ipforwarded
                    ipforwarded = ipforwarded.strip()
                    # Check if ipaddr is an ipAddr 
                    ipaddr = netaddr.IPAddress( ipforwarded )
                    # reconvert to string safer way
                    clientiplist.append( str(ipaddr) )
                # No logging is possible inside getclientipaddr
                except netaddr.core.AddrFormatError: 
                    # netaddr.core.AddrFormatError: failed to detect a valid IP address from ipaddr
                    pass
                except Exception: 
                    pass
    return clientiplist

def getclientxforwardedfor_ip():
    clientip = None
    xforwardedfor = cherrypy.request.headers.get('X-Forwarded-For')
    if isinstance(xforwardedfor, str):
        try:
            # Check if clientip is an ipAddr 
            clientiplistxforwardedfor = xforwardedfor.split(',') # ',' is the defalut separator for 'X-Forwarded-For' header
            # clientiplistxforwardedfor[0] is the first entry is the real client ip address source
            if isinstance( clientiplistxforwardedfor, list ):
                # Check if ipaddr is an ipAddress 
                ipaddr = netaddr.IPAddress( clientiplistxforwardedfor[0] )
                # reconvert to string make sure to remove garbage data 
                # this is not dummy
                # you nedd to check if the str is a true ipaddress  
                # like space ipaddr = netaddr.IPAddress( '127.0.0.1 ' )
                # str( ipaddr ) returns '127.0.0.1'
                clientip = str( ipaddr )

        # No logging is possible inside getclientipaddr
        except netaddr.core.AddrFormatError: 
            # netaddr.core.AddrFormatError: failed to detect a valid IP address from ipaddr
            pass
        except Exception: 
            pass
    return clientip

def getclientipaddr_dict():
    """getclientipaddr_dict
        return a dict of all client ip 'X-Forwarded-For', X-Real-IP', and 'remoteip'
        No logging is possible inside getclientipaddr, 
        it would generate cycling dependencies call in oc.logging functions

        take care 
            X-Forwarded-For header can result in spoofed values being used for security-related purposes
            Syntax X-Forwarded-For: <client>, <proxy1>, <proxy2>
            where <client> is the client IP address

    Returns:
        dict: dict of all client ip 
                { 'X-Forwarded-For' : clientip,
                  'X-Real-IP':  realip,
                  'remoteip': cherrypy.request.remote.ip }
    """
    remoteip = getclientremote_ip()
    clientip = getclientxforwardedfor_ip()
    realip   = getclientreal_ip()

    clientip_dict = { 
        'X-Forwarded-For': clientip,
        'X-Real-IP':  realip,
        'remoteip': remoteip 
    }

    return clientip_dict


# WARNING : No logging is possible inside getclientipaddr, 
# it would generate cycling dependencies call in oc.logging functions
def getclientipaddr():
    """getclientipaddr
        return string ipAddr of browser client, None if failed
        
        Do the best to obtain the Client IP Address
        [ 'X-Forwarded-For', 'X-Real-IP', 'remoteip' ]
           use X-Forwarded-For HTTP header from nginx
        or use X-Real-IP-For HTTP header from nginx
        or cherrypy.request.remote.ip  
    Returns:
        str: ip client address
    """
    ipaddr = None   # the return value None by default
    clientip_dict = getclientipaddr_dict() # getclientipaddr_dict returns always a dict
    # look for each HTTP Header 
    for myip in clientip_dict.values():
        if isinstance( myip, str) : # should never be empty string
            ipaddr = myip
            break
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
            logger.debug( f"instancing class {_class.__name__}")
            controller = _class(config_controllers.get( _class.__name__))
            controller.root = parent
            controller.logger = logging.getLogger(_class.__module__ + '.' + _class.__name__)
            setattr(parent, re.match(class_filter, _class.__name__).group(1).lower(), controller)
    
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
    '''


class Results(object):
    @staticmethod
    def result(message:str=None, status:int=200, result:dict=None)->dict:
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
    def error(message='unknow error', status=500, _context=None):
        return Results.result(message, status)

    @staticmethod
    def unauthorized(message='unauthorized'):
        return Results.result(message, 401)