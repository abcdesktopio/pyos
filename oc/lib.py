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
import random           # for randomStringwithDigitsAndSymbols
import string           # for randomStringwithDigitsAndSymbols
import unicodedata      # for remove accent
import uuid
import json             # for try_to_read_json_entry

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

def uuid_digits( ndigits:int=5)->str:
    digits = uuid.uuid4().hex
    local_uuid = digits[-ndigits:]
    return local_uuid

def load_local_file( filename ):
    """[load_local_file]
        load file utf-8 text data 
    Args:
        filename ([str]): [filename]

    Returns:
        [str]: [file content]
        if filename is None, return None
    """
    data = None    
    if isinstance(filename, str) :
        f = open(filename, encoding='utf-8' )
        data = f.read()
        f.close()
    return data

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


def try_to_read_json_entry( key:str, myjson:str ):
    """try_to_read_json_entry

    Args:
        entry (str): name of the dict entry
        str_json (str): json str format

    Returns:
        str: entry value if exists, str_json else
    """
    str_return = myjson
    try:
        if isinstance( myjson, str ):
            myjson = json.loads( myjson )
        if isinstance( myjson, dict ):
            str_return = myjson.get(key)
    except Exception as e:
        pass
    return str_return