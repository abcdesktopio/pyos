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
    def __init__(self, status:int=500, message:str=None ):
        super().__init__(message)

class ODResourceNotFound(ODError):
    def __init__(self,message):
        super().__init__(status=404,message=message)

class ODAPIError(ODError):
    def __init__(self,message):
        super().__init__(status=500,message=message)

#
# defined some AuthenticationError
#
class AuthenticationError(Exception):
    def __init__(self,message='Something went bad',code=401):
        self.message = message
        self.code = code

class InvalidCredentialsError(AuthenticationError):
    def __init__(self,message='Invalid credentials',code=401):
        self.message = message
        self.code = code

class AuthenticationFailureError(AuthenticationError):
    def __init__(self,message='Authentication failed',code=401):
        self.message = message
        self.code = code

class ExternalAuthError(AuthenticationError):
    def __init__(self,message='Authentication failure',code=401):
        self.message = message
        self.code = code 

class AuthenticationDenied(AuthenticationError):
    def __init__(self,message='Authentication denied by security policy',code=401):
        self.message = message
        self.code = code

class ExternalAuthLoginError(ExternalAuthError):
    def __init__(self,message='Log-in failed',code=401):
        self.message = message
        self.code = code

class ExternalAuthUserError(ExternalAuthError):
    def __init__(self,message='Fetch user info failed',status=401):
        self.message = message
        self.code = status


#
# defined some BanError
#
class BanAuthUserError(AuthenticationError):
    def __init__(self,message='User is banned',code=401):
        self.message = message
        self.code = code 

class BanAuthIPError(AuthenticationError):
    def __init__(self,message='IP is banned',code=401):
        self.message = message
        self.code = code 
