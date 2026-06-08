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
import mergedeep


class AuthInfo(object):
    def __init__(self, provider=None, providertype=None, token=None, type='Bearer', expires_in=None, protocol=None, data={}, claims={}, conn=None):
        """[summary]

        Args:
            provider ([str], optional): [name of the provider]. Defaults to None.
            providertype ([str], optional): [description]. Defaults to None.
            token ([object], optional): [data to keep between auth]. Defaults to None.
            type (str, optional): [authinfo type]. Defaults to 'Bearer'.
            expires_in ([int], optional): [expire in seconds]. Defaults to None.
            protocol ([str], optional): [description]. Defaults to None.
            data (dict, optional): [description]. Defaults to {}.
            claims (dict, optional): [description]. Defaults to {}.
            conn ([object], optional): [connection object]. Defaults to None.
        """
        self.provider = provider
        self.providertype = providertype
        self.protocol = protocol
        self.token = token
        self.type = type
        self.expires_in = expires_in
        # labels entry must exist in data
        if not isinstance(data.get('labels'), dict):
            data['labels'] = {}
        self.data = data
        # claims must be a dict
        if not isinstance(claims, dict):
            claims = {}
        self.claims = claims
        self.conn = conn
        self.isAuthDoneFromDecodedToken = False
        self.isForeignSecurityPrincipalsWithSid = False

    def __getitem__(self, key):
        return getattr(self, key, None)

    def get(self, key):
        return self[key]

    def get_labels(self):
        return self.data['labels']

    def get_claims(self, key):
        return self.claims.get(key)

    def set_claims(self, claims):
        self.claims = claims

    def set_data(self, data):
        self.data = data

    def get_identity(self):
        if isinstance(self.claims, dict):
            return self.claims.get('identity', {})
        return {}

    def get_localaccount(self):
        localaccount = self.get_identity().get('localaccount')
        return localaccount

    def isValid(self):
        bReturn = False
        try:
            bReturn = not not (self.provider and self.isAuthDoneFromDecodedToken)
        except Exception:
            pass
        return bReturn

    def markAuthDoneFromDecodedToken(self, isDecodedToken=True):
        self.isAuthDoneFromDecodedToken = isDecodedToken

    def todict(self):
        """[todict]
            convert AuthInfo public data to dict
        Returns:
            [dict]: AuthInfo to dict
        """
        mydict = {
            'provider': self.provider,
            'providertype': self.providertype,
            'protocol': self.protocol,
            'type': self.type,
            'data': self.data
        }
        return mydict

    def merge(self, newauthinfo):
        # merge only data object
        if not isinstance(newauthinfo, AuthInfo):
            raise ValueError(f"merge error invalid AuthInfo object type {type(newauthinfo)}")
        mergedeep.merge(newauthinfo.data, self.data, strategy=mergedeep.Strategy.ADDITIVE)
        self.data = newauthinfo.data
        return self
