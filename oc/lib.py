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

# -*- coding: utf-8 -*-
import random   # for randomStringwithDigitsAndSymbols
import string   # for randomStringwithDigitsAndSymbols
import unicodedata      # for remove accent
import logging
import cherrypy

import oc.od.settings   # settings lib

from urllib.parse import urlparse


logger = logging.getLogger(__name__)

def randomStringwithDigitsAndSymbols(stringLength=10):
    ''' Generate a random string of letters, digits and special characters '''
    # password_characters = string.ascii_letters + string.digits + string.punctuation
    password_characters = string.ascii_letters + string.digits 
    return ''.join(random.choice(password_characters) for i in range(stringLength))

def get_target_ip_route(target_ip):    
    """ target_ip : str
        return hosname how to route the websocket from HTTP web browser to docker container """    
    http_requested_host = cherrypy.url()
    http_origin = cherrypy.request.headers.get('Origin', None)
    http_host   = cherrypy.request.headers.get('Host', None)
    # logger.debug(locals())

    route = None

    # set default value as fallback
    # to pass exception
    url = urlparse(http_requested_host)
    route = url.hostname

    # Now do the route
    if oc.od.settings.websocketrouting == 'default_host_url':
        try:
            myhosturl = oc.od.settings.default_host_url
            if myhosturl is None:
                myhosturl = http_origin
            logger.debug('Use %s', myhosturl)
            url = urlparse(myhosturl)
            route = url.hostname
        except Exception as e:
            logger.error('failed: %s', e)

    elif oc.od.settings.websocketrouting == 'bridge':
        route = target_ip

    elif oc.od.settings.websocketrouting == 'http_origin':
        if http_origin is not None:
            try:
                # use the origin url to connect to
                url = urlparse(http_origin)
                route = url.hostname
            except Exception as e:
                logger.error('Errror: %s', e)

    elif oc.od.settings.websocketrouting == 'http_host':
        try:
            # use the origin url to connect to
            url = urlparse(http_host)
            route = url.hostname
        except Exception as e:
            logger.error('Errror: %s', e)

    logger.info('Route websocket to: %s', route)
    return route


def remove_accents(input_str):
    ''' remove accents in string '''
    s = input_str
    try:
        # nkfd_form = unicodedata.normalize('NFKD', unicode(input_str))
        nkfd_form = unicodedata.normalize('NFKD', input_str)
        s = "".join([c for c in nkfd_form if not unicodedata.combining(c)])
    except Exception:
        pass
      
    r = s.lower()
    return r

        
def getCookie(name):    
    ''' retrieve the cookie name value      '''
    ''' return the value, None if not set   '''
    c = cherrypy.request.cookie.get(name)
    if c:
        return c.value
    else:
        return None

def setCookie( name, value, path='/', expire_in=None):    
    ''' set the cookie  '''
    cherrypy.response.cookie[name] = value
    
    
    # A cookie with the HttpOnly attribute is inaccessible to the JavaScript Document.cookie API; it is sent only to the server
    cherrypy.response.cookie[name]['httponly'] = True
    # A cookie with the Secure attribute is sent to the server only with an encrypted request over the HTTPS protocol, 
    # never with unsecured HTTP, and therefore can't easily be accessed by a man-in-the-middle attacker. 
    # set secure cookie if default_host_url starts with https
    # dev do not need https 
    cherrypy.response.cookie[name]['secure']   = oc.od.settings.default_host_url_is_securised
    cherrypy.response.cookie[name]['path'] = path
    # cherrypy.response.cookie[name]['samesite']= None
    # cherrypy.response.cookie[name]['secure']=True
    # cherrypy.response.cookie[name]['SameSite']='
    if expire_in :
        cherrypy.response.cookie[name]['max-age'] = expire_in    # Number of seconds until the cookie expires 
    cherrypy.response.cookie[name]['version'] = 1

def removeCookie(name, path='/'):
    ''' remove the cookie name  '''
    # When you wish to “delete” (expire) a cookie, therefore, 
    # you must set cherrypy.response.cookie[key] = value first, 
    # and then set its expires attribute to 0.
    cherrypy.response.cookie[name] = ''
    cherrypy.response.cookie[name]['expires'] = 0
    cherrypy.response.cookie[name]['path'] = path

'''
def _bytesTostr( b ):
    str = b
    if type(b) is bytes: # try to translate bytes to str using decode
        try:
            str = b.decode('utf-8')
        except Exception : # pass
            pass # return as bytes
    return str 

def bytesTostr( b ):
    if type(b) is list:
        for index, data in enumerate(b):
            b[index] = _bytesTostr( data )
    else:
        b =  _bytesTostr( b )
    return b
'''