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

# logger instance
logger = logging.getLogger(__name__)

# lib shared tools

def randomStringwithDigitsAndSymbols(stringLength=10):
    """[randomStringwithDigitsAndSymbols]
        Generate a random string of letters, digits and special characters
        allow char is string.ascii_letters + string.digits 
    Args:
        stringLength (int, optional): [length of randomString]. Defaults to 10.

    Returns:
        [str]: [the random string with digits and symbols]
    """
    # password_characters = string.ascii_letters + string.digits + string.punctuation
    password_characters = string.ascii_letters + string.digits 
    return ''.join(random.choice(password_characters) for i in range(stringLength))


def randomStringwithHexa(stringLength=10):
    # password_characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(string.hexdigits) for i in range(stringLength))

def remove_accents(input_str):
    """[remove_accents]
        remove accents in string and set to lower case
    Args:
        input_str ([str]): [str to remove accent]

    Returns:
        [str]: [str without accent]
    """
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
    """[getCookie] get the cookie name value
        retrieve the cookie name value 
        return the value, None if not set
    Args:
        name ([str]): [name of the cookie]

    Returns:
        [str]: [value of the cookie]
        None if not
    """
    c = cherrypy.request.cookie.get(name)
    if c and hasattr(c, 'value') :
        return c.value
    else:
        return None


def setCookie( name, value, path='/', expire_in=None):    
    """[setCookie] set a cookie

    Args:
        name ([str]): [name of the cookie]
        value ([str]): [value of the cookie]
        path (str, optional): [path of the cookie]. Defaults to '/'.
        expire_in ([int], optional): [Number of seconds until the cookie expires]. Defaults to None.
    """
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
    """[removeCookie] delete a cookie

    Args:
        name ([str]): [name of the cookie]
        path (str, optional): [path of the cookie]. Defaults to '/'.
    """
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