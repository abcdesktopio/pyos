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


class AuthResponse(object):
    def __init__(self, manager=None, success=False, result=None, reason='', error=None, code=200, redirect_to='/', claims={}):
        self.manager = manager
        self.success = success
        self.result = result
        self.error = error
        self.reason = reason
        self.claims = claims
        self.mgr = None
        self.redirect_to = redirect_to

    def update(self, manager, result, success, reason=''):
        self.manager = manager
        self.result = result
        self.success = success
        self.reason = reason
