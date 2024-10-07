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
    def __init__(self, message=None, id=None, webhook=None, type=None, wm_class=None):
        self.message = message
        self.id = id
        self.webhook = webhook
        self.type=type
        self.wm_class = wm_class

    def to_dict( self ):
        return { 'container_id': self.id, 'state': self.message, 'type': self.type, 'wm_class': self.wm_class }
    
    def __str__(self):
        return str( self.to_dict() )
