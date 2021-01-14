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

import logging

logger = logging.getLogger(__name__)

class ODLogInfo:

    loginfo = {}

    def __init__(self):
        pass

    @staticmethod
    def start(key):
        ODLogInfo.loginfo[key] = []

    @staticmethod
    def set(message, key):
        try:
            ODLogInfo.loginfo[key].append(message)
        except Exception as e:
            logger.error('set %s',e) 

    @staticmethod    
    def get( key ):
        message = None
        try :
          message = ODLogInfo.loginfo[key].pop(0)
        except Exception:
            pass
        return message

    @staticmethod
    def stop( key ):
        ODLogInfo.loginfo[ key ].append('stopinfo')
