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
from collections import OrderedDict

import oc.logging
from oc.auth.authinfo import AuthInfo
from oc.auth.authuser import AuthUser
from oc.auth.authprovider import (
    ODAuthProviderBase,
    ODExternalAuthProvider,
    ODImplicitAuthProvider,
    ODImplicitTLSCLientAdAuthProvider,
    ODLdapAuthProvider,
    ODAdAuthProvider,
    ODAdAuthMetaProvider,
)
from oc.od.error import AuthenticationFailureError

logger = logging.getLogger(__name__)


@oc.logging.with_logger()
class ODAuthManagerBase(object):
    def __init__(self, name, config):
        self.name = name
        self.providers = OrderedDict()
        self.initproviders(config)
        self.rules = config.get('rules')

    def initproviders(self, config):
        for name, cfg in config.get('providers', {}).items():
            if not cfg.get('enabled', True):
                continue
            self.logger.debug(f"adding provider name {name}")
            provider = self.createprovider(name, cfg)
            try:
                self.add_provider(name, provider)
            except Exception as e:
                self.logger.exception(e)

    def add_provider(self, name, provider):
        """[add_provider]
            add a provider object ODAuthProviderBase in providers dict
        Args:
            name ([str]): [key of the providers dict]
            provider ([ODAuthProviderBase]): [ODAuthProviderBase]
        """
        assert isinstance(name, str), 'bad provider name parameter'
        assert isinstance(provider, ODAuthProviderBase), 'bad provider parameters'
        self.providers[name] = provider

    def authenticate(self, provider, **arguments):
        return self.getprovider(provider, True).authenticate(**arguments)

    def createclaims(self, provider, auth, userinfo, **arguments):
        provider = self.getprovider(provider, raise_error=True)
        return provider.createclaims(auth, userinfo, **arguments)

    def getuserinfo(self, provider: str, token, **arguments):
        userinfo = self.getprovider(provider, True).getuserinfo(token, **arguments)
        if isinstance(userinfo, dict):
            for addionnalinfo in ['geolocation', 'utctimestamp']:
                userinfo[addionnalinfo] = arguments.get(addionnalinfo)
        return userinfo

    def getroles(self, provider: str, authinfo: AuthInfo, userinfo: AuthUser, **arguments):
        return self.getprovider(provider, True).getroles(authinfo, userinfo, **arguments)

    def finalize(self, provider: str, authinfo: AuthInfo, **arguments):
        return self.getprovider(provider, True).finalize(authinfo, **arguments)

    def createprovider(self, name: str, config: dict):
        return ODAuthProviderBase(self, name, config)

    def logout(self, provider: str, authinfo: AuthInfo, **arguments):
        return self.getprovider(provider, True).logout(authinfo, **arguments)

    def getrules(self):
        return self.rules

    def getprovider(self, name: str, raise_error=False):
        """[getprovider]
            return a provider from name
        Args:
            name ([str]): [name of the provider]
            raise_error (bool, optional): [raise error an exception if not exist]. Defaults to False.

        Raises:
            AuthenticationFailureError: ['Invalid authentication provider name']
            AuthenticationFailureError: ['Undefined authentication provider']

        Returns:
            [type]: [description]
        """
        if not isinstance(name, str):
            if raise_error:
                raise AuthenticationFailureError('Invalid authentication provider name')
            return None

        pdr = self.providers.get(name)

        if not isinstance(pdr, ODAuthProviderBase):
            self.logger.debug(f"failed getprovider from parameter name={name}")
            if raise_error is True:
                raise AuthenticationFailureError(f"undefined authentication provider {name}")
        return pdr

    def getclientdata(self):
        providersmaplist = list(filter(lambda p: p.showclientdata is True, self.providers.values()))
        providers = list(map(lambda p: p.getclientdata(), providersmaplist))
        return {'name': self.name, 'providers': providers}


@oc.logging.with_logger()
class ODExternalAuthManager(ODAuthManagerBase):
    def __init__(self, name, config):
        super().__init__(name, config)

    def createprovider(self, name, config):
        return ODExternalAuthProvider(self, name, config)


@oc.logging.with_logger()
class ODExplicitAuthManager(ODAuthManagerBase):
    def __init__(self, name, config):
        super().__init__(name, config)
        self.show_domains = config.get('show_domains', False)
        m = list(filter(lambda p: p.is_default(), self.providers.values()))
        self.default_domain = m[0].name if len(m) > 0 else None

    def createprovider(self, name, config):
        """[createprovider]
            create an authentication provider

        Args:
            name ([str]): [name of the provider]
            config ([dict]): [provider configuration]

        Returns:
            [ODAdAuthProvider or ODLdapAuthProvider]: [if domain is set in config return ODAdAuthProvider else ODLdapAuthProvider]
        """
        self.logger.debug(locals())
        provider = None
        if self.isActiveDirectory(config):
            provider = ODAdAuthProvider(self, name, config)
        else:
            provider = ODLdapAuthProvider(self, name, config)
        return provider

    def isActiveDirectory(self, config) -> bool:
        """[isActiveDirectory]
            True if config is an ActiveDirectory config else False
        Args:
            config ([dict]): [provider configuration]

        Returns:
            bool: [True if config is an ActiveDirectory config else False]
        """
        if config.get('domain'):
            return True
        else:
            return False

    def add_provider(self, name, provider):
        super().add_provider(name, provider)
        if isinstance(provider, ODAdAuthProvider) and provider.is_default():
            self.default_domain = provider.domain

    def getclientdata(self):
        data = super().getclientdata()
        data['default_domain'] = self.default_domain
        data['show_domains'] = self.show_domains
        return data

    def authenticate(self, provider, userid=None, password=None, **params):
        return self.getprovider(name=provider, raise_error=True).authenticate(userid, password)


@oc.logging.with_logger()
class ODExplicitMetaAuthManager(ODAuthManagerBase):
    def __init__(self, name, config):
        super().__init__(name, config)

    def createprovider(self, name, config):
        """[createprovider]
            create an authentication provider for meta directory
            only active directory is supported

        Args:
            name ([str]): [name of the provider]
            config ([dict]): [configuration]

        Returns:
            [ODAdAuthMetaProvider]: [ODAdAuthMetaProvider instance]
        """
        self.logger.debug(locals())
        return ODAdAuthMetaProvider(self, name, config)


@oc.logging.with_logger()
class ODImplicitAuthManager(ODAuthManagerBase):
    def __init__(self, name, config):
        super().__init__(name, config)

    def createprovider(self, name, config):
        self.logger.debug(locals())
        provider = None
        if config.get('useExplicitIdentityProvider'):
            provider = ODImplicitTLSCLientAdAuthProvider(self, name, config)
        else:
            provider = ODImplicitAuthProvider(self, name, config)
        return provider
