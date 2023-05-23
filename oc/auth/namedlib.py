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

from shellescape import quote

def normalize_name(name:str, encoding:str='utf-8', tolower:bool=True)->str:
    newname = ''
    # permit only DNS name [a-z][A-Z][0-9]-
    #
    # and for kubernetes lables
    # a valid label must be an empty string or consist of alphanumeric characters, '-', '_' or '.', 
    # and must start and end with an alphanumeric character 
    # (e.g. 'MyValue',  or 'my_value',  or '12345', 
    # regex used for validation is '(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?')
    for c in name:
      # filter permit char
      if c.isalnum() or c == '-': 
        newname = newname + c
      else:
        newname = newname + '-'
    
    # remove the first char if it's a '-'
    if newname[ 0 ] == '-':                 
      newname = newname[1::]
    
    # remove the last char if it's a '-'
    if newname[ -1 ] == '-':  
      newname = newname[:-1:]

    if tolower is True:
      newname = newname.lower()
      
    return newname


def normalize_name_dnsname(name:str)->str:
    return normalize_name( name )[0:62]

def normalize_name_label(name:str)->str:
    return normalize_name(name)

def normalize_networkname(name:str)->str:
    return normalize_name(name)

def normalize_containername(name:str)->str:
    # get the last part of
    # registry.domain.tld:443/oc.user.14.04:latest
    # return oc.user.14.04
    newname = name
    try:
      a = name.split('/')
      b = a[-1].split(':')
      newname = b[0]
    except Exception:
      pass
    return newname

def normalize_imagename(name:str)->str:
    return str( name.rsplit('/',1)[-1].rsplit('.',1)[0].split(':',1)[0].replace('.', '-') )


def normalize_alnum( c ):
  return c if c.isalnum() else '_'

def normalize_char( c ):
  if c.isalnum() or c == '-' or c == '_':
    return c
  else:
    return '_'

# (([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?')
def normalize_label( name:str )->str:
    # permit only DNS name [a-z][A-Z][0-9]-
    newname = ''
    for c in name:
         newname = newname + normalize_char(c)
    return newname

# Take care 
def normalize_shell_variable(myvar:str)->str:

    newNormalizedVar = quote( myvar)
    # myvar.replace('\'', '\\\'')
    # newNormalizedVar = normalizedVar
    # newNormalizedVar = '\'' + normalizedVar + '\''
    return newNormalizedVar


def snakeCaseToCamelCase(s:str)->str:
    """snakeCaseToCamelCase
        return None if an error occurs

    Args:
        s (str): str in snake_case format

    Returns:
        str: str in camelCase format
    """
    result=None
    try:
      # split underscore using split
      temp = s.split('_')
      # joining result
      result = temp[0] + ''.join(ele.title() for ele in temp[1:])
    except Exception:
      pass
    return result

  
def dictSnakeCaseToCamelCase(d:dict)->dict:
    new_dict = {}
    for key in d.keys():
      entry = d.get(key)
      newkey = snakeCaseToCamelCase(key) or key
      if isinstance(entry, dict):
        new_dict[newkey]=dictSnakeCaseToCamelCase(entry)
      else:
        new_dict[newkey]=entry
    return new_dict