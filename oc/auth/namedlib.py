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

def normalize_name(name, encoding='utf-8', tolower=True):
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
    if newname[ 0 ] == '-':                 newname = newname[1::]
    
    # remove the last char if it's a '-'
    if newname[ len(newname) - 1 ] == '-':  newname = newname[:-1:]

    if tolower is True:
      newname = newname.lower()
      
    return newname

def normalize_name_tolabel( name ):
    return normalize_name(name)

def normalize_networkname(name):
    return normalize_name(name)

def normalize_containername(name):
    # get the last part of
    # registry.domain.tld:443/oc.user.14.04:latest
    # return oc.user.14.04
    newname = name
    try:
      a = name.split('/')
      p = len(a) - 1
      b = a[p].split(':')
      newname = b[0]
    except Exception:
      pass
    return newname

def normalize_imagename(name):
    return name.rsplit('/',1)[-1].rsplit('.',1)[0].split(':',1)[0].replace('.', '-')


def normalize_alnum( c ):
  if c.isalnum() :
    return c
  else:
    return '_'


def normalize_char( c ):
  if c.isalnum() or c == '-' or c == '_':
    return c
  else:
    return '_'

# (([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?')
def normalize_label( name ):
    # permit only DNS name [a-z][A-Z][0-9]-
    newname = ''
    for c in name:
         newname = newname + normalize_char(c)
    return newname

# Take care 
def normalize_shell_variable(myvar):

    newNormalizedVar = quote( myvar)
    # myvar.replace('\'', '\\\'')
    # newNormalizedVar = normalizedVar
    # newNormalizedVar = '\'' + normalizedVar + '\''
    return newNormalizedVar
