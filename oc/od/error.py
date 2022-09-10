#!/usr/bin/env python
# -*- coding: utf-8 -*-

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

class ODError(Exception):
    def __init__(self,message):
        super().__init__(message)

class ODResourceNotFound(ODError):
    def __init__(self,message):
        super().__init__(message)

class ODAPIError(ODError):
    def __init__(self,message):
        super().__init__(message)
