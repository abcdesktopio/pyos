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
import secrets          # for randomStringwithDigitsAndSymbols
import string           # for randomStringwithDigitsAndSymbols
import unicodedata      # for remove accent
import uuid             # for uuid_digits 
import json             # for try_to_read_json_entry
import base64           # for base64

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
    # alphabet = string.ascii_letters + string.digits + string.punctuation
    alphabet = string.ascii_letters + string.digits 
    return ''.join(secrets.choice(alphabet) for i in range(stringLength))

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
        # 'NFKD' : Normalization Form KC (NFKC)	Characters are decomposed by compatibility, 
        # then re-composed by canonical equivalence
        nkfd_form = unicodedata.normalize('NFKD', input_str)
        s = "".join([c for c in nkfd_form if not unicodedata.combining(c)])
    except Exception:
        pass
      
    r = s.lower()
    return r

def uuid_digits( ndigits:int=5)->str:
    """uuid_digits
        return a uuid string with the number of digit requested
    Args:
        ndigits (int, optional): number of digit. Defaults to 5.

    Returns:
        str: uuid str formated with the number of digit requested
    """
    digits = uuid.uuid4().hex
    local_uuid = digits[-ndigits:]
    return local_uuid

def load_local_file( filename:str ):
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

def create_svg_base64_content( name:str, width:int=64, height:int=64 )->str:
    """create_svg_content
        create a simple svg file with the name of the application
    Args:
        name (str): string to write in the svg file
        width (int, optional): width of the svg file. Defaults to 64.
        height (int, optional): height of the svg file. Defaults to 64. 
    Returns:
        str: svg file content
    """
    # create a simple svg file with thename of the application
    x = 0
    y = height/2
    text_svg = f'\
        <svg version="1.1" viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">\
            <rect width="100%" height="100%" fill="white"/>\
            <text x="{x}" y="{y}" fill="black">{name}</text>\
        </svg>'
    # encode the svg file in base64
    b64_text_svg = base64.b64encode(text_svg.encode('utf-8'))
    # return the base64 encoded svg file use strip to remove the last '\n' character
    return b64_text_svg.decode().strip()

def safe_loadicon_base64_filename( iconfilename:str, name:str="default", width:int=32, height:int=32 ):
    """loadiconfilename
        load icon file name from config
    Args:
        iconfilename (str): icon file name
    """
    b64iconcontent = None
    if not isinstance(iconfilename, str):
        b64iconcontent = create_svg_base64_content( name=name, width=width, height=height )
    else:
        try:
            f = open(iconfilename, 'rb')
            # read the file content
            b64iconcontent = base64.b64encode(f.read()).decode('utf-8')
            f.close()
        except Exception as e:
            # print( f"Error loading icon file {iconfilename} : {e}" )
            # create a simple svg file with the name of the application
            b64iconcontent = create_svg_base64_content( name=name, width=width, height=height )    
    return b64iconcontent

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

def fortunewheel( mylist:list )->list:
    """fortunewheel
        turn the fortune wheel in to a list 
    Args:
        mylist (list): list of element

    Returns:
        list: the mixed list
    """
    if isinstance(mylist, list):
        myrange = range( len(mylist) )
        # turn the wheel
        for b in range( len( mylist )):
            a = secrets.choice( myrange )  
            # swap mylist[a] and mylist[b]
            # print( f"swap mylist[{a}]={mylist[a]} <->  mylist[{b}]={mylist[b]}" )
            c = mylist[a]
            mylist[a] = mylist[b]
            mylist[b] = c
    return mylist