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

# -*- coding: utf-8 -*-
import logging
import oc.logging
import oc.lib

logger = logging.getLogger(__name__)

class ODAcl():

    def __init__(self):
        pass

    def isAllowed( self, authinfo, acl ):
        if acl is None :
            # no acl has been defined
            return True

        if type(acl) is not dict :
            logger.error( 'invalid acl type, dict is attended' )
            return True
        
        deny   = acl.get('deny', [])
        if type(deny) is not list :
            logger.error( 'invalid acl deny type, list is attended get %s', str(type(deny)) )
            return False

        permit = acl.get('permit', [])
        if type(permit) is not list :
            logger.error( 'invalid acl deny type, list is attended get %s', str(type(permit)) )
            return False    

        isdeny   = False
        ispermit = False

        if authinfo.data and type( authinfo.data.get('labels') ) is dict :   
            for userlabel in authinfo.data.get('labels') :
                if userlabel in deny:
                    isdeny = True
                if userlabel in permit:
                    ispermit = True

        # special case for "all" keyword
        if "all" in permit: ispermit = True
        if "all" in deny:   isdeny = True

        if isdeny is True:    
            # app is denied 
            return False
        
        if ispermit is True:    
            # app is allowed
            return True
        
        # no deny and no permit 
        return False