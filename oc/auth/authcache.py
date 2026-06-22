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
from oc.auth.authinfo import AuthInfo
from oc.auth.authuser import AuthUser
from oc.auth.authroles import AuthRoles


class AuthCache(object):
    NotSet = object()

    def __init__(self, dict_token: dict = None, auth_duration_in_milliseconds: int = None, origin=None):
        self.reset()
        if isinstance(dict_token, dict):
            self.setuser(dict_token.get('user'))
            self.setauth(dict_token.get('auth'))
            self.setroles(dict_token.get('roles'))
        self._origin = origin
        self.auth_duration_in_milliseconds = auth_duration_in_milliseconds

    def markAuthDoneFromDecodedToken(self):
        self._auth.markAuthDoneFromDecodedToken()

    @property
    def origin(self):
        return self._origin

    @origin.setter
    def origin(self, value):
        self._origin = value

    def reset(self):
        """[reset]
            Clear all previous cached data
            set internal cached value to AuthCache.NotSet
        """
        self._user = AuthCache.NotSet
        self._roles = AuthCache.NotSet
        self._auth = AuthInfo()
        self._origin = None
        self.auth_duration_in_milliseconds = None

    @property
    def user(self):
        return self._user

    def setuser(self, valuedict):
        self._user = AuthUser(valuedict)

    def isValidUser(self):
        isvalid = isinstance(self._user, AuthUser) and self._user.isValid()
        return isvalid

    def isValidRoles(self):
        return self._roles != AuthCache.NotSet

    def isValidAuth(self):
        return self._auth.isValid()

    @property
    def roles(self):
        return self._roles

    def setroles(self, rolevalues: dict | list):
        myroles = rolevalues
        # we convert a list of role to a dict with role as key and None as value
        # to be able to use the same code for list or dict of roles
        if isinstance(rolevalues, list):
            myroles = {}
            for role in rolevalues:
                if isinstance(role, str):
                    myroles[role] = None
        self._roles = AuthRoles(myroles)

    @property
    def auth(self):
        return self._auth

    def setauth(self, valuedict):
        """[setauth]
            set auth data from a AuthInfo data
            read datas from an AuthInfo and set
            [ 'provider', 'providertype', 'token', 'type', 'expires_in', 'protocol', 'data', 'claims') ]
            it to _auth  AuthCache Object

        Args:
            valuedict ([AuthInfo]): [AuthInfo object]
        """
        self._auth = AuthInfo(
            provider=valuedict.get('provider'),
            providertype=valuedict.get('providertype'),
            token=valuedict.get('token'),
            type=valuedict.get('type'),
            expires_in=valuedict.get('expires_in'),
            protocol=valuedict.get('protocol'),
            data=valuedict.get('data'),
            claims=valuedict.get('claims')
        )

    def merge(self, new_authcache):
        """merge
            merge data with authprovider source to self
            example two active directories with relationship
                    but with different groups and rules
        Args:
            new_authcache (AuthInfo): AuthInfo
        """
        self._user = self.user.merge(new_authcache._user)
        self._roles = self.roles.merge(new_authcache._roles)
        self._auth = self.auth.merge(new_authcache._auth)
