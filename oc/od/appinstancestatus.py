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

class ODAppInstanceStatus():
    def __init__(self, message:str=None, id:str=None, webhook:str=None, type:str=None, wm_class:str=None, icon:str=None, icondata:str=None):
        self.message = message
        self.id = id
        self.webhook = webhook
        self.type=type
        self.wm_class = wm_class
        self.icon = icon
        self.icondata = icondata

    def to_dict( self ):
        return { 
            'id': self.id, 
            'state': self.message, 
            'type': self.type, 
            'wm_class': self.wm_class,
            'icon': self.icon,
            'icondata': self.icondata,
        }
    
    def __str__(self):
        return str( self.to_dict() )