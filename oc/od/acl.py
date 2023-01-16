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

@oc.logging.with_logger()
class ODAcl():
    """ODAcl class
        authorization must be explicit
    """
    def __init__(self):
        pass

    def isAllowed( self, authinfo, acl ):
        """isAllowed
            authorization must be explicit
        Args:
            authinfo (AuthInfo): Authentification 
            acl (dict): acl dict 'deny' and 'permit' entries

        Returns:
            bool: True if acl is explicit permit, else False 
        """
        if acl is None :
            # no acl has been defined
            # this is not an error
            return False

        if not isinstance( acl, dict)  :
            self.logger.error( 'invalid acl type, dict is attended' )
            return False
        
        deny   = acl.get('deny', [])
        if not isinstance(deny, list):
            self.logger.error( f"invalid acl deny type, list is attended get {str(type(deny))}" )
            return False

        permit = acl.get('permit', [])
        if not isinstance(permit, list)  :
            self.logger.error( f"invalid acl permit type, list is attended get {str(type(permit))}" )
            return False    

        isdeny   = False
        ispermit = False
  
        for userlabel in authinfo.get_labels() :
            if userlabel in deny:
                isdeny = True
            if userlabel in permit:
                ispermit = True

        # special case for "all" keyword
        if "all" in permit: 
            ispermit = True
        if "all" in deny:   
            isdeny = True

        # this is an acl
        # always starts by denied 
        if isdeny is True:    
            # app is denied 
            return False
        
        if ispermit is True:    
            # app is allowed
            return True
        
        # no deny and no permit 
        # authorization must be explicit
        # return False 
        return False