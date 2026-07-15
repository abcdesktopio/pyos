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
import time
import os
import subprocess
import uuid
import copy
import requests
import json
import passlib.hash
import datetime
import re
from urllib.parse import urlparse
from ldap import filter as ldap_filter
import ldap3

import gssapi
import haversine
import chevron

from requests_oauthlib import OAuth2Session
from threading import Lock

import urllib

import oc.logging
import oc.od.settings
import oc.od.resolvdns
import oc.auth.namedlib
import oc.lib
import oc.pyutils as pyutils
from oc.auth.authinfo import AuthInfo
from oc.auth.authuser import AuthUser
from oc.od.error import AuthenticationError, InvalidCredentialsError, AuthenticationFailureError, ExternalAuthError

logger = logging.getLogger(__name__)

# define some const
UID_MAX_LENGTH = 32
KRB5_UID_MAX_LENGTH = 256
KRB5_PASSWORD_MAX_LENGTH = 256
LDAP_UID_MAX_LENGTH = 256
LDAP_PASSWORD_MAX_LENGTH = 64


@oc.logging.with_logger()
class ODAuthProviderBase(object):
    def __init__(self, manager, name, config):
        self.name = name
        self.manager = manager
        self.type = config.get('type', self.name)
        self.displayname = config.get('displayname', self.name)
        self.icon = config.get('icon')
        self.backgroundcolor = config.get('backgroundcolor')
        self.textcolor = config.get('textcolor')
        self.caption = config.get('caption', self.displayname)
        policies = config.get('policies', {})
        self.acls = policies.get('acl', {'permit': ['all']})
        self.rules = policies.get('rules')
        self.default = config.get('default', False)
        self.auth_only = config.get('auth_only', False)
        self.showclientdata = config.get('showclientdata', True)
        self.regexp_validatation_dict = {
            'userid': {
                'regexp': r"(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?",
                'message': "userid consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character. regex used for validation is '(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?')"
            }
        }
        self.default_user_if_not_exist = config.get('defaultuid', oc.od.settings.getballoon_loginname())
        self.default_passwd_if_not_exist = config.get('defaultpassword', oc.od.settings.getballoon_password())
        self.default_uidNumber_if_not_exist = config.get('defaultuidNumber', oc.od.settings.getballoon_uidNumber())
        self.default_gidNumber_if_not_exist = config.get('defaultgidNumber', oc.od.settings.getballoon_gidNumber())
        self.auth_protocol = config.get('auth_protocol', {})
        self.memberof_attribut_name = config.get('memberof_attribut_name', '')
        self.icondata = oc.lib.safe_loadicon_base64_filename(self.icon)
        self.filter_reduce_roles_for_jwt = config.get('reduce_roles_for_jwt', 'raw')
        if isinstance(self.filter_reduce_roles_for_jwt, str):
            self.filter_reduce_roles_for_jwt = self.filter_reduce_roles_for_jwt.lower()

    def getdisplaydescription(self):
        return self.displayname

    def authenticate(self, **params):
        raise NotImplementedError()

    def getuserinfo(self, authinfo: AuthInfo, **params):
        raise NotImplementedError()

    def logout(self, authinfo: AuthInfo, **arguments):
        pass

    def regexp_validadation(self, data, key):
        regexp = self.regexp_validatation_dict.get(key)
        pat = re.compile(regexp.get('regexp'))
        match = re.fullmatch(pat, data)
        if not match:
            raise AuthenticationError(message=regexp.get('message'))

    def getclientdata(self):
        clientdata = {
            'name': self.name,
            'caption': self.caption,
            'displayname': self.displayname,
            'icon': self.icon,
            'backgroundcolor': self.backgroundcolor,
            'textcolor': self.textcolor,
            'type': self.type,
            'icondata': self.icondata
        }
        return clientdata

    def finalize(self, auth, **params):
        pass

    def is_default(self):
        return self.default

    def is_serviceaccount_defined(self, config):
        bReturn = False
        serviceaccount = config.get('serviceaccount')
        if isinstance(serviceaccount, dict):
            serviceaccount_login = serviceaccount.get('login')
            serviceaccount_password = serviceaccount.get('password')
            if isinstance(serviceaccount_login, str) and isinstance(serviceaccount_password, str):
                bReturn = True
        return bReturn

    def getdefault_uid(self, userinfo: AuthInfo, user: str) -> str:
        uid = userinfo.get('uid') or userinfo.get('userid') or user
        uid = ODAuthProviderBase.safe_uid(uid)
        uid = uid.lower()
        return uid

    def getroles(self, authinfo: AuthInfo, userinfo: AuthUser, **params):
        return []

    def reduce_roles_for_jwt(self, roles: list) -> list:
        if self.filter_reduce_roles_for_jwt == 'raw':
            return roles
        else:
            return []

    @staticmethod
    def safe_uid(uid: str, permit_dollar: bool = False) -> str:
        assert isinstance(uid, str), f"bad uid str is expected type {type(uid)}"

        lenuid = len(uid)
        i = 0
        new_uid = ''
        for i in range(0, lenuid):
            if uid[i].isalnum():
                new_uid = new_uid + uid[i].lower()
                break

        if len(new_uid) < 1:
            raise ValueError("invalid uid value")

        for j in range(i + 1, lenuid):
            if uid[j].isalnum() or uid[j] == '-':
                new_uid = new_uid + uid[j].lower()

        if permit_dollar is True:
            if lenuid > 1 and uid[lenuid - 1] == "$":
                new_uid.append('$')

        new_uid = new_uid[0:UID_MAX_LENGTH - 1]
        if not new_uid:
            raise ValueError("invalid uid value")
        return new_uid.lower()

    def getdefault_gid(self, userinfo, user):
        gid = userinfo.get('gid') or userinfo.get('userid')
        if not isinstance(gid, str):
            gid = user.replace(' ', '')
        gid = gid.lower()
        return gid

    def generateLocalAccount(self, userinfo, user, password):
        uid = None
        gid = None
        description = None
        loginShell = None
        groups = None
        gecos = None
        homeDirectory = None
        uidNumber = self.default_uidNumber_if_not_exist
        gidNumber = self.default_gidNumber_if_not_exist

        posixAccount = userinfo.get('posix')
        if isinstance(posixAccount, dict):
            uid = posixAccount.get('uid')
            gid = posixAccount.get('gid', uid)
            uidNumber = posixAccount.get('uidNumber')
            gidNumber = posixAccount.get('gidNumber')
            loginShell = posixAccount.get('loginShell')
            description = posixAccount.get('description')
            groups = posixAccount.get('groups')
            homeDirectory = posixAccount.get('homeDirectory')
            gecos = posixAccount.get('gecos')

        if not isinstance(loginShell, str):
            loginShell = oc.od.settings.getballoon_loginShell()
        if not isinstance(uid, str):
            uid = self.getdefault_uid(userinfo, user)
        if not isinstance(gid, str):
            gid = self.getdefault_gid(userinfo, user)
        if not isinstance(password, str):
            password = self.default_passwd_if_not_exist
        if not isinstance(homeDirectory, str):
            homeDirectory = oc.od.settings.getballoon_homedirectory(uid)
        hashes = {
            'uid': uid,
            'gid': gid,
            'gecos': gecos,
            'groups': groups,
            'uidNumber': uidNumber,
            'gidNumber': gidNumber,
            'loginShell': loginShell,
            'description': description,
            'homeDirectory': homeDirectory,
            'sha512': passlib.hash.sha512_crypt.using(rounds=5000).hash(password)
        }
        return hashes

    def createauthenv(self, userinfo, userid, password):
        self.logger.debug('createauthenv')
        default_authenv = {}
        dict_hash = self.generateLocalAccount(userinfo, user=userid, password=password)
        default_authenv.update({'localaccount': dict_hash})
        return default_authenv

    def createclaims(self, authinfo, userinfo, **arguments):
        userid = self.default_user_if_not_exist
        password = self.default_passwd_if_not_exist
        claims = {'identity': self.createauthenv(userinfo, userid, password)}
        authinfo.set_claims(claims)


@oc.logging.with_logger()
class ODExternalAuthProvider(ODAuthProviderBase):
    def __init__(self, manager, name, config):
        super().__init__(manager, name, config)
        self.displayname = config.get('displayname')
        self.encoding = config.get('encoding', 'utf-8')
        self.client_id = config.get('client_id')
        self.client_secret = config.get('client_secret')
        self.scope = config.get('scope')
        self.basic_auth = config.get('basic_auth', False) is True
        self.userinfo_auth = config.get('userinfo_auth', False) is True
        self.type = config.get('type', 'oauth')
        self.userinfomap = config.get('userinfomap')
        self.state = config.get('state')
        self.include_client_id = config.get('include_client_id', False)
        self.authorization_base_url = config.get('authorization_base_url')
        self.token_url = config.get('token_url')
        self.redirect_uri_prefix = config.get('redirect_uri_prefix')
        self.redirect_uri_querystring = config.get('redirect_uri_querystring')
        self.redirect_uri = self.redirect_uri_prefix + '?' + self.redirect_uri_querystring
        self.userinfo_url = config.get('userinfo_url')
        self.revoke_url = config.get('revoke_url')
        self.explicitproviderapproval = config.get('explicitproviderapproval')
        self.memberof_attribut_name = config.get('memberof_attribut_name', 'groups')

    def getclientdata(self):
        data = super().getclientdata()
        oauthsession = OAuth2Session(self.client_id, scope=self.scope, redirect_uri=self.redirect_uri)
        authorization_url, state = oauthsession.authorization_url(self.authorization_base_url, state=self.state)
        data['dialog_url'] = authorization_url
        data['explicitproviderapproval'] = self.explicitproviderapproval
        data['state'] = state
        return data

    def authenticate(self, **params) -> AuthInfo:
        # we don't need to add manager and provider parameters
        # query_string = f"manager={self.manager.name}&provider={self.name}"
        # query_string = ""
        query_string = urllib.parse.urlencode(params)
        oauthsession = OAuth2Session(self.client_id, scope=self.scope, redirect_uri=self.redirect_uri)
        authorization_response = self.redirect_uri_prefix + '?' + query_string
        access_token = oauthsession.fetch_token(self.token_url, client_secret=self.client_secret, include_client_id=self.include_client_id, authorization_response=authorization_response)
        self.logger.debug(f"provider {self.name} type {self.type} has returned an access_token")
        authinfo = AuthInfo(provider=self.name, providertype=self.type, token=oauthsession, protocol='oauth', data={})
        return authinfo

    def getuserinfo(self, authinfo: AuthInfo, **params):
        oauthsession = authinfo.token

        if not isinstance(oauthsession, OAuth2Session):
            raise ExternalAuthError(message='authinfo is an invalid token oauthsession object')

        userinfo = None
        if oauthsession.authorized is True:
            if self.userinfo_auth is True:
                response_userinfo = oauthsession.get(url=self.userinfo_url)
                if isinstance(response_userinfo, requests.models.Response) and response_userinfo.ok is True:
                    jsondata = response_userinfo.content.decode(response_userinfo.encoding or self.encoding)
                    data = json.loads(jsondata)
                    self.logger.debug(f"dump userinfo data={data}")
                    userinfo = self.parseuserinfo(data)
                    self.logger.debug("expecting to read posix account response format")
                    posixuser = AuthUser.getPosixAccountfromlocalAccount(userinfo)
                    self.logger.debug(f"posix account posixuser={posixuser}")
                    userinfo['posix'] = posixuser
                else:
                    self.logger.debug(f"userinfo response is not ok status_code={response_userinfo.status_code} reason={response_userinfo.reason} content={response_userinfo.content}")
                    raise ExternalAuthError(message=f"userinfo returns failed status_code={response_userinfo.status_code} reason={response_userinfo.reason} content={response_userinfo.content}")
            else:
                self.logger.debug(f"getuserinfo is not allowed for provider {self.name}")
                userinfo = {}
                uid = 'anonymous'
                userinfo['name'] = uid
                userinfo['userid'] = str(uuid.uuid4())
                anonymousPosix = AuthUser.getdefaultPosixAccount(
                    uid=uid,
                    gid=uid,
                    cn=uid,
                    uidNumber=oc.od.settings.getballoon_uidNumber(),
                    gidNumber=oc.od.settings.getballoon_gidNumber(),
                    homeDirectory=oc.od.settings.getballoon_homedirectory(uid),
                    gecos='anonymous user',
                    loginShell=oc.od.settings.getballoon_loginShell(),
                    description='abcdesktop anonymous account')
                userinfo['posix'] = anonymousPosix
        else:
            raise ExternalAuthError(message=f"session is not authorized {oauthsession.authorized}")

        self.logger.debug(f"userinfo={userinfo}")
        return userinfo

    def parseuserinfo(self, jsondata: dict) -> dict:
        if isinstance(self.userinfomap, dict):
            user = {}
            all = self.userinfomap.get('*')
            if all == '*':
                user = jsondata
            elif all is not None:
                user[all] = jsondata

            for k, v in self.userinfomap.items():
                if k == '*':
                    continue
                user[k] = pyutils.get_setting(jsondata, v)
        else:
            user = jsondata

        userid = user.get('userid') or jsondata.get('id') or jsondata.get('sub', '')
        userid = str(userid)
        name = user.get('name') or user.get('lastname') or userid
        user['userid'] = oc.auth.namedlib.normalize_name(userid)
        user['name'] = name
        return user

    def finalize(self, auth, **params):
        if not isinstance(auth, AuthInfo):
            return
        oauthsession = auth.token
        if isinstance(oauthsession, OAuth2Session):
            auth.token = oauthsession.token
            oauthsession.close()

    def getroles(self, authinfo: AuthInfo, userinfo: AuthUser, **params):
        self.logger.debug('')
        roles = []

        if self.auth_only:
            self.logger.debug(f"provider {self.name} is a auth_only={self.auth_only}, no roles can be read return {roles}")
            return roles

        if isinstance(userinfo.get('groups'), list):
            for role in userinfo.get('groups'):
                if isinstance(role, str):
                    roles.append(role)
        return roles

    def logout(self, authinfo, **arguments):
        pass


class ODImplicitAuthProvider(ODAuthProviderBase):
    def __init__(self, manager, name, config):
        super().__init__(manager, name, config)
        self.uid = config.get('uid', self.name)
        self.username = config.get('username', self.name)
        self.explicitproviderapproval = config.get('explicitproviderapproval')
        self.dialog_url = config.get('dialog_url')

    def getclientdata(self):
        data = super().getclientdata()
        if self.dialog_url:
            data['dialog_url'] = self.dialog_url
        return data

    def getuserinfo(self, authinfo, **params):
        userinfo = {}
        name = None
        userid = None
        uid = None
        if isinstance(authinfo.token, str):
            name = authinfo.token
            userid = authinfo.token
            uid = self.safe_uid(name)
        else:
            name = self.username
            userid = str(uuid.uuid4())
            uid = self.uid

        userinfo['name'] = name
        userinfo['userid'] = userid
        anonymousPosix = AuthUser.getdefaultPosixAccount(
            uid=uid,
            gid=uid,
            cn=name,
            uidNumber=oc.od.settings.getballoon_uidNumber(),
            gidNumber=oc.od.settings.getballoon_gidNumber(),
            homeDirectory=oc.od.settings.getballoon_homedirectory(uid),
            loginShell=oc.od.settings.getballoon_loginShell(),
            gecos='anonymous user',
            description='abcdesktop anonymous account')
        userinfo['posix'] = anonymousPosix
        return userinfo

    def authenticate(self, userid=None, password=None, **params):
        if isinstance(userid, str):
            self.regexp_validadation(userid, 'userid')
        data = {'userid': userid}
        authinfo = AuthInfo(provider=self.name, providertype=self.type, token=userid, data=data)
        return authinfo


class ODImplicitTLSCLientAuthProvider(ODImplicitAuthProvider):
    def __init__(self, manager, name, config):
        super().__init__(manager, name, config)


@oc.logging.with_logger()
class ODLdapAuthProvider(ODAuthProviderBase):
    DEFAULT_ATTRS = ['objectClass', 'cn', 'sn', 'description', 'givenName', 'jpegPhoto', 'mail', 'ou', 'title', 'uid', 'distinguishedName', 'displayName']
    DEFAULT_TOP_ATTRS = {'top': ['objectClass']}
    DEFAULT_PERSON_ATTRS = {'Person': ['cn', 'sn', 'description', 'givenName', 'uid']}
    DEFAULT_INETORGPERSON_ATTRS = {'InetOrgPerson': ['jpegPhoto', 'mail', 'displayName', 'publicKey']}
    DEFAULT_ORGANIZATIONALPERSON_ATTRS = {'OrganizationalPerson': ['title', 'ou']}
    DEFAULT_POSIXACCOUNT_ATTRS = {'posixAccount': ['cn', 'uid', 'uidNumber', 'gidNumber', 'homeDirectory', 'loginShell', 'description', 'gecos']}
    DEFAULT_POSIXGROUP_ATTRS = {'posixGroup': ['cn', 'gidNumber', 'memberUid', 'description']}
    DEFAULT_MEMBEROF_ATTRIBUT_NAME = 'memberOf'
    LDAP_AUTH_SUPPORTED_METHOD = ['KERBEROS', 'NTLM', 'SIMPLE', 'ANONYMOUS']

    class Query(object):
        def __init__(self, basedn, scope=ldap3.SUBTREE, filter=None, attrs=None):
            self.scope = scope
            self.basedn = basedn
            self.filter = filter
            self.attrs = attrs

    def __init__(self, manager, name, config={}):
        self.logger.debug('')
        super().__init__(manager, name, config)
        self.type = 'ldap'
        self.auth_type = config.get('auth_type', 'SIMPLE').upper()
        self.loadserviceaccount(config)
        self.users_ou = config.get('users_ou', config.get('ldap_basedn'))
        self.groups_ou = config.get('goups_ou', config.get('ldap_basedn'))
        self.servers = config.get('servers', [])
        self.timeout = config.get('ldap_timeout')
        self.connect_timeout = config.get('ldap_connect_timeout')
        self.useridattr = config.get('useridattr', 'cn')
        self.usercnattr = config.get('usercnattr', 'cn')
        self.useruidattr = config.get('useruidattr', 'uid')
        self.domain = config.get('domain')
        self.kerberos_realm = config.get('kerberos_realm')
        self.kerberos_krb5_conf = config.get('krb5_conf')
        self.kerberos_ktutil = config.get('ktutil', '/usr/bin/ktutil')
        self.ntlm_command = config.get('ntlm_command', '/var/pyos/oc/auth/ntlm/ntlm_auth')
        self.auth_protocol = config.get('auth_protocol', {'ntlm': False, 'cntlm': False, 'kerberos': False, 'citrix': False})
        if self.auth_protocol.get('ldif') is None:
            self.auth_protocol['ldif'] = True
        self.LDAP_PAGE_SIZE = 8
        self.citrix_all_regions = None
        if self.auth_protocol.get('citrix'):
            self.citrix_all_regions = oc.lib.load_local_file(config.get('citrix_all_regions.ini'))
            if isinstance(self.citrix_all_regions, str):
                self.logger.debug(f"provider {name} has enabled citrix, mustache file {config.get('citrix_all_regions.ini')}")
            else:
                self.logger.error(f"provider {name} has disabled citrix, invalid entry citrix_all_regions.ini")
        self.exec_timeout = config.get('exec_timeout', 10)
        self.join_key_ldapattribut = config.get('join_key_ldapattribut')
        self.krb5cctype = config.get('krb5cctype', 'MEMORY').upper()
        self.ldap_ipmod = config.get('ldap_ip_mode', ldap3.IP_V4_PREFERRED)
        self.ldapPublicKeyobjectClass = 'ldapPublicKey'
        self.posixAccountobjectClass = 'posixAccount'
        self.posixGroupobjectClass = 'posixGroup'
        self.InetOrgPersonobjectClass = 'InetOrgPerson'
        self.memberof_attribut_name = config.get('memberof_attribut_name', ODLdapAuthProvider.DEFAULT_MEMBEROF_ATTRIBUT_NAME)

        self.user_query = self.Query(
            self.users_ou,
            config.get('scope', ldap3.SUBTREE),
            config.get('user_filter', '(&(objectClass=Person)(cn=%s))'),
            config.get('user_attrs',
                ODLdapAuthProvider.DEFAULT_TOP_ATTRS.get('top') + ODLdapAuthProvider.DEFAULT_PERSON_ATTRS.get('Person')
            )
        )

        self.InetOrgPerson_query = self.Query(
            self.users_ou,
            config.get('scope', ldap3.SUBTREE),
            config.get('filter', '(&(objectClass=InetOrgPerson)(cn=%s))'),
            config.get('attrs',
                ODLdapAuthProvider.DEFAULT_TOP_ATTRS.get('top') + ODLdapAuthProvider.DEFAULT_INETORGPERSON_ATTRS.get('InetOrgPerson')
            )
        )

        self.group_query = self.Query(
            self.groups_ou,
            config.get('group_scope', self.user_query.scope),
            config.get('group_filter', "(&(objectClass=Group)(cn=%s))"),
            config.get('group_attrs'))

        self.posixaccount_query = self.Query(
            self.users_ou,
            config.get('posixAccount_scope', ldap3.SUBTREE),
            config.get('posixAccount_filter', '(&(objectClass=posixAccount)(cn=%s))'),
            config.get('posixAccount_attrs',
                ODLdapAuthProvider.DEFAULT_TOP_ATTRS.get('top') + ODLdapAuthProvider.DEFAULT_POSIXACCOUNT_ATTRS.get('posixAccount')
            )
        )

        self.posixaccountgroup_query = self.Query(
            self.groups_ou,
            config.get('posixGroup_scope', ldap3.SUBTREE),
            config.get('posixAccountGroup_filter', '(&(objectClass=posixGroup)(gidNumber=%s))'),
            config.get('posixGroup_attrs',
                ODLdapAuthProvider.DEFAULT_TOP_ATTRS.get('top') + ODLdapAuthProvider.DEFAULT_POSIXGROUP_ATTRS.get('posixGroup')
            )
        )

        self.posixgroups_query = self.Query(
            self.groups_ou,
            config.get('posixGroup_scope', ldap3.SUBTREE),
            config.get('posixGroup_filter', '(&(objectClass=posixGroup)(!(gidNumber=%s))(memberUid=%s))'),
            config.get('posixGroup_attrs',
                ODLdapAuthProvider.DEFAULT_TOP_ATTRS.get('top') + ODLdapAuthProvider.DEFAULT_POSIXGROUP_ATTRS.get('posixGroup')
            )
        )

        self.filter_reduce_roles_for_jwt = config.get('reduce_roles_for_jwt', 'cn')
        if isinstance(self.filter_reduce_roles_for_jwt, str):
            self.filter_reduce_roles_for_jwt = self.filter_reduce_roles_for_jwt.lower()

    def getdisplaydescription(self):
        displaydescription = super().getdisplaydescription()
        if self.auth_type == 'KERBEROS':
            displaydescription = self.kerberos_realm
        elif self.auth_type == 'NTLM':
            displaydescription = self.domain
        return displaydescription

    def deepcopy(self):
        self.logger.debug('')
        newprovider = copy.deepcopy(self)
        return newprovider

    def updateauthentificationconfigfromprovider(self, provider: ODAuthProviderBase) -> ODAuthProviderBase:
        self.logger.debug('')
        assert isinstance(provider, ODLdapAuthProvider), f"bad provider type {type(provider)}"
        self.domain = provider.domain
        self.kerberos_realm = provider.kerberos_realm
        self.kerberos_krb5_conf = provider.kerberos_krb5_conf
        self.kerberos_ktutil = provider.kerberos_ktutil

    def loadserviceaccount(self, config):
        def readvaluefromfile(data: str) -> str:
            if isinstance(data, str):
                fileurlparse = urlparse(data)
                if fileurlparse.scheme == 'file':
                    f = open(fileurlparse.path, 'r')
                    data = f.readline().rstrip()
                    f.close()
            return data

        serviceaccount = config.get('serviceaccount', {'login': None, 'password': None})
        self.userid = readvaluefromfile(serviceaccount.get('login'))
        self.password = readvaluefromfile(serviceaccount.get('password'))

    @staticmethod
    def issafeLdapAuthCommonName(cn):
        for c in cn:
            permitchar = c.isalnum() or c == '-' or c == ' '
            if not permitchar:
                return False
        return True

    def finalize(self, auth, **params):
        if not isinstance(auth, AuthInfo):
            return
        if isinstance(auth.conn, ldap3.core.connection.Connection):
            try:
                auth.conn.unbind()
            except Exception as e:
                self.logger.error(e)
        auth.conn = None

    def validate(self, userid, password, **params):
        self.logger.debug(f"validate={userid}")
        userdn = None
        conn = None

        if self.auth_type not in ODLdapAuthProvider.LDAP_AUTH_SUPPORTED_METHOD:
            raise AuthenticationError(f"auth_type must be in {ODLdapAuthProvider.LDAP_AUTH_SUPPORTED_METHOD} entry is {self.auth_type}")

        self.logger.debug(f"validate uses auth_type={self.auth_type}")
        if self.auth_type == 'KERBEROS':
            self.logger.debug(f"validate={userid}")
            self.krb5_validate(userid, password)
            self.krb5_authenticate(userid, password)
            if not self.auth_only:
                conn = self.getconnection(userid, password)
                userdn = self.getuserdn(conn, userid)
        elif self.auth_type == 'SIMPLE':
            self.simple_validate(userid, password)
            userdn = self.getuserdnldapconnection(userid)
            conn = self.getconnection(userdn, password)
            userdn = self.getuserdn(conn, userid)
        elif self.auth_type == 'ANONYMOUS':
            conn = self.getconnection(None, None)
            userdn = self.getuserdn(conn, userid)
            self.logger.debug(f"validate gets userdn={userdn}")
            if not isinstance(userdn, str):
                raise AuthenticationError(f"user {userid} is not found")
            self.logger.debug(f"validate starts new getconnection userdn={userdn} auth='SIMPLE' ")
            conn = self.getconnection(userdn, password, 'SIMPLE')
        elif self.auth_type == 'NTLM':
            self.ntlm_validate(userid, password)
            ntlm_userid = self.domain + '\\' + userid
            conn = self.getconnection(ntlm_userid, password)
            userdn = self.getuserdn(conn, userid)
        return (userdn, conn)

    def krb5_authenticate(self, userid, password):
        self.logger.debug(f"krb5_authenticate user={userid}")
        try:
            userid = userid.upper()
            krb5ccname = self.get_krb5ccname(userid)
            self.run_kinit(krb5ccname, userid, password)
        except Exception as e:
            self.remove_krb5ccname(krb5ccname)
            raise AuthenticationError(f"kerberos credentitials validation failed {e}")

    def authenticate(self, userid, password, **params):
        self.logger.debug("authenticate user={userid}")
        (userdn, conn) = self.validate(userid, password)
        data = {'userid': userid, 'dn': userdn}
        return AuthInfo(provider=self.name, providertype=self.type, token=userid, data=data, protocol=self.auth_protocol, conn=conn)

    def createclaims(self, authinfo, userinfo, userid, password, **arguments):
        claims = {'userid': userid, 'password': password}
        claims['identity'] = self.createauthenv(userinfo, userid, password)
        authinfo.set_claims(claims)

    def krb5_validate(self, userid, password):
        assert isinstance(userid, str), f"userid must be str, get {type(userid)}"
        assert isinstance(password, str), f"password must be str, get {type(password)}"

        if not userid:
            raise AuthenticationError('user can not be an empty string')
        if len(userid) > KRB5_UID_MAX_LENGTH:
            raise AuthenticationError('user length must be less than 256 characters')
        if len(password) < 1:
            raise AuthenticationError('password can not be an empty string')
        if len(password) > KRB5_PASSWORD_MAX_LENGTH:
            raise AuthenticationError('password length must be less than 256 characters')

    def ntlm_validate(self, userid, password):
        assert isinstance(userid, str), f"userid must be str, get {type(userid)}"
        assert isinstance(password, str), f"password must be str, get {type(password)}"
        if not userid:
            raise AuthenticationError('user can not be an empty string')
        if len(userid) >= 104:
            raise AuthenticationError('user login can be no longer than 104 characters')
        if not password:
            raise AuthenticationError('password can not be an empty string')
        if len(password) > 128:
            raise AuthenticationError('password can be no longer than 128 characters')
        if self.auth_only is True:
            raise AuthenticationError('auth_only is set to True, but ldap.bind need to complete auth')

    def simple_validate(self, userid, password):
        assert isinstance(userid, str), f"userid must be str, get {type(userid)}"
        assert isinstance(password, str), f"password must be str, get {type(password)}"

        if len(userid) == 0:
            raise AuthenticationError('user can not be an empty string')
        if len(userid) > LDAP_UID_MAX_LENGTH:
            raise AuthenticationError('user length must be less than 256 characters')
        if len(password) == 0:
            raise AuthenticationError('password can not be an empty string')
        if len(password) > LDAP_PASSWORD_MAX_LENGTH:
            raise AuthenticationError(f"password length must be less than {LDAP_PASSWORD_MAX_LENGTH} characters")
        if self.auth_only:
            raise AuthenticationError('auth_only is set to True, but ldap.bind need to complete auth')

    def getuserinfo(self, authinfo, **params):
        if self.auth_only is True:
            userinfo = {'userid': params.get('userid'), 'name': params.get('userid')}
        else:
            q = self.user_query
            attrs = ['*']
            userinfo = self.search_one(authinfo.conn, q.basedn, q.scope, ldap_filter.filter_format(q.filter, [authinfo.token]), attrs, **params)

            if isinstance(userinfo, dict):
                if not isinstance(userinfo.get('userid'), str):
                    userinfo['userid'] = userinfo.get(self.useruidattr)
                if not isinstance(userinfo.get('name'), str):
                    userinfo['name'] = userinfo.get(self.useridattr)

                if self.posixAccountobjectClass in userinfo.get('objectClass', []):
                    self.logger.debug(f"account is a {self.posixAccountobjectClass} objectClass={userinfo.get('objectClass')}")
                    self.logger.debug("query for posixAccount attributs")
                    q = self.posixaccount_query
                    posixuserinfo = self.search_one(authinfo.conn, q.basedn, q.scope, ldap_filter.filter_format(q.filter, [authinfo.token]), q.attrs, **params)
                    if isinstance(posixuserinfo, dict):
                        userinfo['posix'] = posixuserinfo
                        self.logger.debug("query for posixGroup attributs")
                        q = self.posixaccountgroup_query
                        groupfilter = ldap_filter.filter_format(q.filter, [str(posixuserinfo.get('gidNumber'))])
                        self.logger.debug(f"query basedn={q.basedn} for posixGroup attributs {groupfilter} attrs={q.attrs}")
                        posixgroupinfo = self.search_one(authinfo.conn, q.basedn, q.scope, groupfilter, q.attrs, **params)
                        if isinstance(posixgroupinfo, dict):
                            userinfo['posix']['gid'] = posixgroupinfo.get('cn')

                        self.logger.debug("query for posixGroup attributs")
                        q = self.posixgroups_query
                        groupfilter = ldap_filter.filter_format(q.filter, [str(posixuserinfo.get('gidNumber')), str(posixuserinfo.get('uid'))])
                        self.logger.debug(f"query basedn={q.basedn} for posix all groups attribut {groupfilter} attrs={q.attrs}")
                        posixallgroupslist = self.search_all(authinfo.conn, q.basedn, q.scope, groupfilter, q.attrs, **params)
                        if isinstance(posixallgroupslist, list):
                            userinfo['posix']['groups'] = posixallgroupslist

        return userinfo

    def reduce_roles_for_jwt(self, roles: list) -> list:
        filtered_roles = []
        if not isinstance(roles, list):
            self.logger.error(f"Expected a list of roles gets {type(roles)} instead {roles}")
            return filtered_roles

        if self.filter_reduce_roles_for_jwt is None:
            return filtered_roles

        if not isinstance(self.filter_reduce_roles_for_jwt, str):
            return filtered_roles

        if self.filter_reduce_roles_for_jwt == 'none':
            return filtered_roles

        if self.filter_reduce_roles_for_jwt == 'raw':
            return roles

        if self.filter_reduce_roles_for_jwt == 'cn':
            try:
                for role in roles:
                    splitted_role = role.split(',', 1)[0]
                    if len(splitted_role) > 2:
                        splitted_cnvalue = splitted_role.split('=', 1)
                        if len(splitted_cnvalue) == 2:
                            filtered_roles.append(splitted_cnvalue[1])
            except Exception as e:
                self.logger.error(e)
        return filtered_roles

    def getroles(self, authinfo: AuthInfo, userinfo: AuthUser, **params):
        self.logger.debug('')
        roles = []

        if self.auth_only:
            self.logger.debug(f"provider {self.name} is a auth_only={self.auth_only}, no roles can be read return {roles}")
            return roles

        try:
            token = authinfo.token
            q = self.user_query
            result = self.search_one(
                conn=authinfo.conn,
                basedn=q.basedn,
                scope=q.scope,
                filter=ldap_filter.filter_format(q.filter, [token]),
                attrs=['memberOf'],
                **params)
            roles = result.get(self.memberof_attribut_name, [])
            if not isinstance(roles, list):
                roles = [roles]
        except Exception as e:
            self.logger.error(e)

        self.logger.debug(f"roles on provider {self.name}, read {roles}")
        return roles

    def getuserdnldapconnection(self, userid):
        escape_userid = ldap_filter.escape_filter_chars(userid)
        if len(escape_userid) != len(userid):
            self.logger.debug('WARNING ldap_filter.escape_filter_chars escaped')
            self.logger.debug(f"value='{userid}' -> '{escape_userid}' escaped by ldap_filter.escape_filter_chars")
        return self.usercnattr + '=' + escape_userid + ',' + self.users_ou

    def verify_auth_is_supported_by_ldap_server(self, supported_sasl_mechanisms):
        is_supported = False
        if not isinstance(supported_sasl_mechanisms, list):
            return is_supported
        if self.auth_type == 'KERBEROS':
            if 'GSS-SPNEGO' in supported_sasl_mechanisms:
                is_supported = True
            if 'GSS-GSSAPI' in supported_sasl_mechanisms:
                is_supported = True
        if self.auth_type == 'NTLM':
            if 'GSS-SPNEGO' in supported_sasl_mechanisms:
                is_supported = True
            if 'NTLM' in supported_sasl_mechanisms:
                is_supported = True
        if self.auth_type == 'SIMPLE':
            if 'PLAIN' in supported_sasl_mechanisms:
                is_supported = True
        return is_supported

    def getconnection(self, userid: str, password: str, auth_type: str = None):
        conn = None
        lastException = None
        if auth_type is None:
            auth_type = self.auth_type
        self.logger.debug(f"ldap getconnection auth userid={userid} auth={auth_type}")
        servers = self.servers.copy()
        oc.lib.fortunewheel(servers)
        self.logger.debug(f"servers list order servers={servers}")
        for server_name in servers:
            try:
                self.logger.debug(f"ldap getconnection:create ldap3.Server server={server_name} auth_type={auth_type}")
                server = ldap3.Server(server_name, connect_timeout=self.connect_timeout, mode=self.ldap_ipmod, get_info='ALL')

                c = ldap3.Connection(server, client_strategy=ldap3.SAFE_SYNC, auto_bind=False)
                c.open()
                supported_sasl_mechanisms = server.info.supported_sasl_mechanisms if server.info else None
                del c

                if not self.verify_auth_is_supported_by_ldap_server(supported_sasl_mechanisms):
                    self.logger.debug(f"{auth_type} is not defined in {server_name}.info.supported_sasl_mechanisms supported_sasl_mechanisms={supported_sasl_mechanisms}")

                time_before_connection = datetime.datetime.now().timestamp()

                if auth_type == 'KERBEROS':
                    krb5ccname = self.get_krb5ccname(userid)
                    cred_store = {'ccache': krb5ccname}
                    kerberos_principal_name = self.get_kerberos_principal(userid)
                    self.logger.debug(f"ldap getconnection:Connection server={server_name} as user={kerberos_principal_name} authentication=ldap3.SASL, sasl_mechanism=ldap3.KERBEROS KRB5CCNAME={cred_store}")
                    conn = ldap3.Connection(server, user=kerberos_principal_name, authentication=ldap3.SASL, client_strategy=ldap3.SAFE_SYNC, sasl_mechanism=ldap3.KERBEROS, read_only=True, raise_exceptions=True, cred_store=cred_store)

                if auth_type == 'NTLM':
                    self.logger.info(f"ldap getconnection:Connection server={server_name} userid={userid} authentication=ldap3.NTLM")
                    conn = ldap3.Connection(server, user=userid, password=password, authentication=ldap3.NTLM, client_strategy=ldap3.SAFE_SYNC, read_only=True, raise_exceptions=True)

                if auth_type == 'SIMPLE':
                    self.logger.info(f"ldap getconnection:Connection server={server_name} userdn={userid} authentication=ldap3.SIMPLE")
                    conn = ldap3.Connection(server, user=userid, password=password, authentication=ldap3.SIMPLE, client_strategy=ldap3.SAFE_SYNC, read_only=True, raise_exceptions=True)

                if auth_type == 'ANONYMOUS':
                    self.logger.info(f"ldap getconnection:Connection server={server_name} ANONYMOUS authentication=ldap3.ANONYMOUS")
                    conn = ldap3.Connection(server, authentication=ldap3.ANONYMOUS, client_strategy=ldap3.SAFE_SYNC, read_only=True, raise_exceptions=True)

                conn.bind()
                time_after_connection = datetime.datetime.now().timestamp()
                diff_time_connection = (time_after_connection - time_before_connection) * 1000
                self.logger.debug(f"bind to {server_name} done in {diff_time_connection} ms")
                return conn

            except (ldap3.core.exceptions.LDAPInvalidDNSyntaxResult,
                    ldap3.core.exceptions.LDAPInvalidCredentialsResult,
                    ldap3.core.exceptions.LDAPInvalidAttributeSyntaxResult) as e:
                self.logger.error(f"exception {e} to the ldap server {server}")
                e.code = 401
                raise e

            except ldap3.core.exceptions.LDAPAuthMethodNotSupportedResult as e:
                self.logger.error(f"exception {e} to the ldap server {server}")
                lastException = e

            except ldap3.core.exceptions.LDAPExceptionError as e:
                self.logger.error(f"exception {e} to the ldap server {server}")
                lastException = e

        if isinstance(lastException, Exception):
            lastException.code = 401
            raise lastException

        raise AuthenticationError('Can not contact LDAP servers, all servers are unavailable')

    def search_all(self, conn, basedn, scope, filter=None, attrs=None, **params):
        if not isinstance(conn, ldap3.core.connection.Connection):
            ldap_bind_userid = params.get('userid', self.userid)
            ldap_bind_password = params.get('password', self.password)
            conn = self.getconnection(ldap_bind_userid, ldap_bind_password)
        return self.search(conn, basedn, scope, filter, attrs, one=False)

    def search_one(self, conn, basedn, scope, filter=None, attrs=None, **params):
        if not isinstance(conn, ldap3.core.connection.Connection):
            ldap_bind_userid = params.get('userid', self.userid)
            ldap_bind_password = params.get('password', self.password)
            conn = self.getconnection(ldap_bind_userid, ldap_bind_password)
        return self.search(conn, basedn, scope, filter, attrs, True)

    def search(self, conn, basedn, scope, filter=None, attrs=None, one=False):
        self.logger.debug('')
        entries = []
        ldap3_status, ldap3_results, ldap3_response, ldap3_request = \
            conn.search(search_base=basedn, search_filter=filter, search_scope=scope, attributes=attrs)
        if ldap3_status is True:
            if isinstance(ldap3_response, list):
                for entry in ldap3_response:
                    type_of_entry = entry.get('type')
                    if isinstance(type_of_entry, str) and type_of_entry != 'searchResEntry':
                        continue

                    data = {}
                    dn = entry.get('dn')
                    if isinstance(dn, str):
                        data['dn'] = dn

                    attributes = entry.get('attributes')
                    if isinstance(attributes, ldap3.utils.ciDict.CaseInsensitiveDict):
                        for k, v in attributes.items():
                            data[k] = self.decodeValue(name=k, value=v)

                    if one is True:
                        return data

                    if len(data) > 0:
                        entries.append(data)
            return entries
        return None

    def getuserdn(self, conn, id):
        return self.getdn(conn, self.user_query, id)

    def getgroupdn(self, conn, id):
        return self.getdn(conn, self.group_query, id)

    def getdn(self, conn, query, id):
        distinguishedName = None
        result = self.search(conn, query.basedn, query.scope, ldap_filter.filter_format(query.filter, [id]), ['cn', 'distinguishedName'], True)
        if isinstance(result, dict):
            distinguishedName = result.get('distinguishedName') or result.get('dn')
        return distinguishedName

    def isMemberOf(self, authinfo: AuthInfo, user: dict, userdistinguished_name: str, groupdistinguished_name: str):
        self.logger.debug(f"userdistinguished_name={userdistinguished_name} groupdistinguished_name={groupdistinguished_name}")
        memberof = False
        group_name = groupdistinguished_name.split(',', 1)[0].split('=', 1)[1]
        filter = f"(cn={group_name})"
        group_basedn = groupdistinguished_name.split(',', 1)[1]
        self.logger.debug(f"group_name={group_name}, filter={filter}, group_basedn={group_basedn}")
        groupinfo = self.search_one(conn=authinfo.conn,
                                    basedn=group_basedn,
                                    scope=ldap3.SUBTREE,
                                    filter=filter,
                                    attrs=['objectClass', 'member', 'memberUid'])

        self.logger.debug(f"groupinfo={groupinfo}")
        if not isinstance(groupinfo, dict):
            self.logger.debug('groupinfo is not a dict')
            return memberof

        member = groupinfo.get('member')
        if isinstance(member, list):
            self.logger.debug(f"member={member}")
            if userdistinguished_name in member:
                memberof = True

        if isinstance(user, dict):
            memberUid = groupinfo.get('memberUid')
            if isinstance(memberUid, list):
                self.logger.debug(f"memberUid={memberUid}")
                uid = user.get('posix', {}).get('uid') or user.get('uid')
                if uid in memberUid:
                    memberof = True

        self.logger.debug(f"return memberof={memberof}")
        return memberof

    def decodeValue(self, name, value):
        if not isinstance(value, list):
            return value

        items = []
        for item in value:
            if isinstance(item, bytes):
                try:
                    item = item.decode('utf-8')
                except UnicodeDecodeError:
                    pass
                except Exception as e:
                    self.logger.error(f"Attribute {name} error to decode as utf-8, use raw data type:{type(item)} exception:{e}")
            items.append(item)

        return items[0] if len(items) == 1 else items

    def get_kerberos_realm(self):
        return self.kerberos_realm

    def createauthenv(self, userinfo, userid, password):
        default_authenv = super().createauthenv(userinfo, userid, password)

        if self.auth_protocol.get('kerberos') is True:
            try:
                dict_hash = self.generateKerberosKeytab(userid, password)
                if isinstance(dict_hash, dict):
                    default_authenv.update({
                        'kerberos': {
                            'PRINCIPAL': userid,
                            'REALM': self.get_kerberos_realm(),
                            **dict_hash
                        }
                    })
            except Exception as e:
                self.logger.error(f"generateKerberosKeytab failed, authenv can not be completed {e}")

        if self.auth_protocol.get('ntlm') is True:
            try:
                dict_hash = self.generateNTLMhash(password)
                if isinstance(dict_hash, dict):
                    default_authenv.update({
                        'ntlm': {
                            'NTLM_USER': userid,
                            'NTLM_DOMAIN': self.domain,
                            **dict_hash
                        }
                    })
            except Exception as e:
                self.logger.error(f"generateNTLMhash failed, authenv can not be completed {e}")

        if self.auth_protocol.get('cntlm') is True:
            try:
                dict_hash = self.generateCNTLMhash(userid, password, self.domain)
                if isinstance(dict_hash, dict):
                    default_authenv.update({
                        'cntlm': {
                            'NTLM_USER': userid,
                            'NTLM_DOMAIN': self.domain,
                            **dict_hash
                        }
                    })
            except Exception as e:
                self.logger.error(f"generateCNTLMhash failed, authenv can not be completed {e}")

        if self.auth_protocol.get('citrix') is True:
            try:
                dict_hash = self.generateCitrixAllRegionsini(username=userid, password=password, domain=self.domain)
                if isinstance(dict_hash, dict):
                    default_authenv.update({'citrix': dict_hash})
            except Exception as e:
                self.logger.error(f"generateCitrixAllRegionsini failed, authenv can not be completed {e}")

        return default_authenv

    def paged_search(self, conn, basedn, filter, attrlist, scope=ldap3.SUBTREE):
        entry_list = conn.extend.standard.paged_search(
            search_base=basedn,
            search_filter=filter,
            search_scope=scope,
            attributes=attrlist,
            paged_size=self.LDAP_PAGE_SIZE,
            generator=True)
        return entry_list

    def get_krb5ccname(self, principal):
        ccname = oc.auth.namedlib.normalize_name(principal)
        if self.krb5cctype == 'FILE':
            krb5ccname = 'FILE:/tmp/' + ccname
        elif self.krb5cctype == 'KEYRING':
            krb5ccname = 'KEYRING:persistent:' + ccname + ':'
        else:
            krb5ccname = 'MEMORY:' + ccname
        return krb5ccname

    def remove_krb5ccname(self, krb5ccname):
        if krb5ccname.startswith('FILE:'):
            try:
                os.unlink(krb5ccname)
            except Exception as e:
                self.logger.error(f"failed to delete tmp file: {krb5ccname} {e}")

    def get_kerberos_principal(self, userid):
        return userid + '@' + self.kerberos_realm

    def run_kinit(self, krb5ccname, userid, password):
        store_cred_result = None
        kerberos_principal = self.get_kerberos_principal(userid)
        user = gssapi.Name(base=kerberos_principal, name_type=gssapi.NameType.user)
        bpass = password.encode('utf-8')

        self.logger.debug(f"running kerberos auth for {kerberos_principal}")
        req_creds = gssapi.raw.acquire_cred_with_password(user, bpass, usage='initiate')

        if isinstance(req_creds, gssapi.raw.AcquireCredResult):
            krb5ccname = str.encode(krb5ccname)
            store_cred_result = gssapi.raw.store_cred_into(
                store={b'ccache': krb5ccname},
                creds=req_creds.creds,
                usage="initiate",
                overwrite=True)
            self.logger.debug(f"store_cred_into {krb5ccname} {store_cred_result.usage}")

        return store_cred_result

    def generateKerberosKeytab(self, principal, password):
        self.logger.debug('')
        keytab = {}

        def removekoutputfile(koutputfilename):
            try:
                os.unlink(koutputfilename)
            except Exception as e:
                self.logger.error(f"failed to delete tmp file: {koutputfilename} {e}")

        if not all([principal, password]):
            self.logger.error('makekeytab invalid parameters ')
            return None

        if not isinstance(self.kerberos_krb5_conf, str):
            self.logger.debug('krb5.conf file is unconfigured')
            return None

        if not isinstance(self.kerberos_ktutil, str):
            self.logger.debug('ktutil file is unconfigured')
            return None

        koutputfilename = f"/tmp/{oc.auth.namedlib.normalize_name(principal)}.keytab"
        userPrincipalName = f"{principal}@{self.get_kerberos_realm()}"
        inputs = [
            f"addent -password -p {userPrincipalName} -k 1 -f",
            password,
            f"wkt {koutputfilename}",
            "q"
        ]

        returncode = None
        try:
            self.logger.debug(f"makekeytab Popen {self.kerberos_ktutil}")
            my_env = os.environ.copy()
            my_env['KRB5_CONFIG'] = self.kerberos_krb5_conf
            proc = subprocess.Popen(
                args=self.kerberos_ktutil,
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=my_env)

            for p in inputs:
                proc.stdin.write(p.encode() + b'\n')
            proc.stdin.close()
            returncode = proc.wait(self.exec_timeout)

        except Exception as e:
            self.logger.error(f"command {self.kerberos_ktutil} {e}")
            removekoutputfile(koutputfilename)
            return keytab

        self.logger.debug(f"{self.kerberos_ktutil} return code: {returncode}")
        if returncode == 0:
            try:
                koutputfile = open(koutputfilename, mode='rb')
                keytabdata = koutputfile.read()
                koutputfile.close()

                krb5conf_file = open(self.kerberos_krb5_conf)
                krb5conf = krb5conf_file.read()
                krb5conf_file.close()
                keytab = {'keytab': keytabdata, 'krb5_conf': krb5conf}
            except Exception as e:
                self.logger.error(f"read keytab file {koutputfilename} error: {e}")
        else:
            self.logger.debug(f"failed to run {self.kerberos_ktutil} return code {returncode}")

        removekoutputfile(koutputfilename)
        return keytab

    def generateNTLMhash(self, password):
        self.logger.debug('Generatin NTLM hashes')
        hashes = None
        if not isinstance(password, str):
            self.logger.error('Invalid password parameters')
            return hashes
        try:
            ret, out = pyutils.execproc(
                command=self.ntlm_command,
                environment={'NTLM_PASSWORD': password},
                timeout=self.exec_timeout)
            if ret != 0:
                raise RuntimeError(f"Command ntlm_auth returned error code: {ret}")
            hashes = {}
            for line in out:
                if len(line) < 1:
                    continue
                try:
                    nv = line.index('=')
                    hashes[line[0:nv]] = line[nv + 1:]
                except Exception as e:
                    self.logger.error(f"Parsing ntlm_auth result failed: {e}")
        except Exception as e:
            self.logger.error(f"Failed: {e}")

        return hashes

    def generateCitrixAllRegionsini(self, username, password, domain):
        hashes = None
        if isinstance(self.citrix_all_regions, str):
            self.logger.debug('Generating file All_Regions.ini for citrix-receiver')
            data = chevron.render(self.citrix_all_regions, {'username': username, 'password': password, 'domain': domain})
            hashes = {'All_Regions.ini': data}
        return hashes

    def generateCNTLMhash(self, user, password, domain):
        self.logger.debug('Generating CNTLM hashes')
        hashes = None
        cntlm_command = '/usr/sbin/cntlm'

        if not isinstance(user, str) or not isinstance(password, str) or not isinstance(domain, str):
            self.logger.error('CNTLM missing parameters, CNTLM hashes has been disabled')
            return hashes

        if not os.path.isfile(cntlm_command):
            self.logger.error(f"command {cntlm_command} not found CNTLM hashes has been disabled")
            return hashes

        try:
            password = password + '\n'
            command = [cntlm_command, '-H', '-u', user, '-d', domain]
            ret, out = pyutils.execproc(command=command, input=password, timeout=self.exec_timeout)
            if ret != 0:
                raise RuntimeError(f"Command cntml returns error code {ret}")

            hashes = {}
            for line in out:
                nv = line.split(' ')
                datalist = [x for x in nv if x]
                if len(datalist) < 2:
                    continue
                key = datalist[0]
                value = datalist[1]
                if len(key) > 0 and len(value) > 0:
                    key = 'CNTLM_' + key.upper()
                    hashes[key] = value
            self.logger.debug(f"CNTLM hashes: {hashes}")
        except Exception as e:
            self.logger.error(e)

        return hashes


@oc.logging.with_logger()
class ODAdAuthProvider(ODLdapAuthProvider):
    INVALID_CHARS = ['"', '/', '[', ']', ':', ';', '|', '=', ',', '+', '*', '?', '<', '>']
    DEFAULT_ATTRS = ['displayName', 'sAMAccountName', 'name', 'cn', 'homeDrive', 'homeDirectory', 'profilePath', 'memberOf', 'proxyAddresses', 'userPrincipalName', 'primaryGroupID', 'objectSid']
    DEFAULT_USER_ATTRS = ['homeDirectory', 'homeDrive', 'localeID', 'primaryGroupID', 'userAccountControl', 'memberOf']

    def __init__(self, manager, name, config):
        super().__init__(manager, name, config)
        self.type = 'activedirectory'
        self.useridattr = config.get('useridattr', 'sAMAccountName')
        self.domain_fqdn = config.get('domain_fqdn')
        self.domain = config.get('domain', self.domain_fqdn.split('.', 1)[0] if self.domain_fqdn else self.name)
        if not isinstance(self.domain, str):
            raise ValueError("Property domain must be set as string for active directory")
        else:
            self.domain = self.domain.upper()
        self.query_dcs = config.get('query_dcs', False) is True
        self.dcs_list_maxage = config.get('dcs_list_maxage', 3600)
        self.dcs_list_lastupdated = 0
        self.refreshdcs_lock = None
        self.user_query.filter = config.get('filter', '(&(objectClass=user)(sAMAccountName=%s))')
        self.user_query.attrs = config.get('attrs', ODAdAuthProvider.DEFAULT_ATTRS)
        self.group_query.filter = config.get('group_filter', "(&(objectClass=group)(cn=%s))")
        self.recursive_search = config.get('recursive_search', False) is True
        self.trusted_domains = config.get('trusted_domains')

        if self.query_dcs:
            if not self.domain_fqdn:
                raise ValueError(f"provider {name} property 'domain_fqdn' not set, cannot query domain controllers list")
            self.refreshdcs_lock = Lock()
            self.refreshdcs()
        elif len(self.servers) == 0:
            if not self.domain_fqdn:
                raise ValueError(f"provider {name} properties 'domain_fqdn' and 'servers' not set , cannot define domain FQDN as fallback (VIP) address")
            self.servers = [self.domain_fqdn]
        if len(self.servers) == 0:
            raise RuntimeError('Empty list of domain controllers')

        self.printer_query = self.Query(
            basedn=config.get('printer_printerdn', 'OU=Applications,' + config.get('ldap_basedn')),
            scope=config.get('printer_scope', ldap3.SUBTREE),
            filter=config.get('printer_filter', '(objectClass=printQueue)'),
            attrs=config.get('printer_attrs',
                ['cn', 'uNCName', 'location', 'driverName', 'driverVersion', 'name',
                 'portName', 'printColor', 'printerName', 'printLanguage', 'printSharename',
                 'serverName', 'shortServerName', 'url', 'printMediaReady',
                 'printBinNames', 'printMediaSupported', 'printOrientationsSupported'
                 ]))

        self.site_query = self.Query(
            basedn=config.get('site_subnetdn', 'CN=Subnets,CN=Sites,CN=Configuration,' + config.get('ldap_basedn')),
            scope=config.get('site_scope', ldap3.SUBTREE),
            filter=config.get('site_filter', '(objectClass=subnet)'),
            attrs=config.get('site_attrs', ['cn', 'siteObject', 'location']))

    def getdefault_uid(self, userinfo: dict, user: str) -> str:
        uid = None
        if isinstance(userinfo, dict):
            uid = userinfo.get(self.useridattr)
            if isinstance(uid, str):
                uid = ODAuthProviderBase.safe_uid(uid)
                uid = uid.lower()
        if not isinstance(uid, str):
            uid = super().getdefault_uid(userinfo, user)
        uid = uid.lower()
        return uid

    def get_kerberos_realm(self):
        kerberos_realm = None
        if isinstance(self.kerberos_realm, dict):
            kerberos_realm = self.kerberos_realm.get(self.domain)
        if isinstance(self.kerberos_realm, str):
            kerberos_realm = self.kerberos_realm
        return kerberos_realm

    def getntlmlogin(self, userid: str):
        adlogin = userid
        assert isinstance(userid, str), 'bad userid parameter'
        ar = userid.split('\\')
        if len(ar) > 2:
            raise AuthenticationFailureError('invalid login format')
        if len(ar) == 1 and isinstance(self.domain, str):
            adlogin = self.domain + '\\' + userid
        else:
            adlogin = userid
        return adlogin

    @staticmethod
    def splitadlogin(login):
        domain = None
        sAMAccountName = login
        arr = login.split('\\', 1)
        if len(arr) > 1:
            (domain, sAMAccountName) = tuple(arr)
        return (domain, sAMAccountName)

    def authenticate(self, userid, password, **params):
        if not self.issafeAdAuthusername(userid):
            raise InvalidCredentialsError('Unsafe login credentials')
        if not self.issafeAdAuthpassword(password):
            raise InvalidCredentialsError('Unsafe password credentials')

        (userdn, conn) = super().validate(userid, password)
        data = {'userid': userid, 'domain': self.domain, 'dn': userdn}
        authinfo = AuthInfo(provider=self.name, providertype=self.type, token=userid, data=data, protocol=self.auth_protocol, conn=conn)
        return authinfo

    def createclaims(self, authinfo, userinfo, userid, password, **arguments):
        claims = {'identity': self.createauthenv(userinfo, userid, password)}
        claims.update({'userid': userid, 'password': password, 'domain': self.domain})
        authinfo.set_claims(claims)

    def getuserinfo(self, authinfo, **params):
        self.logger.debug('')
        userinfo = super().getuserinfo(authinfo, **params)

        if isinstance(userinfo, dict):
            useridattr = userinfo.get(self.useridattr)
            if isinstance(useridattr, str) and useridattr:
                userinfo['userid'] = userinfo.get(self.useridattr)

            homeDirectory = userinfo.get('homeDirectory')
            if isinstance(homeDirectory, str):
                userinfo['homeDirectory'] = homeDirectory.replace('\\', '/')

            profilePath = userinfo.get('profilePath')
            if isinstance(profilePath, str):
                userinfo['profilePath'] = profilePath.replace('\\', '/')

        return userinfo

    def getroles(self, authinfo: AuthInfo, userinfo: AuthUser, **params):
        self.logger.debug('')
        roles = []
        token = authinfo.token
        if not self.recursive_search:
            return super().getroles(authinfo, userinfo, **params)

        userdn = self.getuserdn(authinfo.conn, token)
        if not isinstance(userdn, str):
            return []

        for entry in self.search(
                authinfo.conn,
                self.group_query.basedn,
                ldap3.SUBTREE,
                f"(member:1.2.840.113556.1.4.1941:={userdn})",
                ['cn']):
            roles.append(entry.get('cn'))

        return roles

    def issafeAdAuthusername(self, username: str):
        if not isinstance(username, str):
            return False
        if len(username) < 1 or len(username) > 20:
            return False
        for c in username:
            if c in ODAdAuthProvider.INVALID_CHARS:
                return False
            if ord(c) < 32:
                return False
        return True

    def issafeAdAuthpassword(self, password: str):
        if not isinstance(password, str):
            return False
        if len(password) < 1 or len(password) > 255:
            return False
        for c in password:
            if ord(c) < 32:
                return False
        return True

    def refreshdcs(self):
        if not self.refreshdcs_lock.acquire(False):
            return
        try:
            ldap_tcp_domain = '_ldap._tcp.' + self.domain_fqdn
            self.logger.debug(f"Refreshing domain controllers list - {ldap_tcp_domain}")
            self.servers = oc.od.resolvdns.ODResolvDNS.resolv(fqdn_name=ldap_tcp_domain, query_type='SRV')
            self.dcs_list_lastupdated = time.time()
            self.logger.debug("Domain controllers list: {self.servers}")
        finally:
            self.refreshdcs_lock.release()

    def isdcslistexpired(self):
        bReturn = self.query_dcs and \
                  self.dcs_list_maxage and \
                  not self.refreshdcs_lock.locked() and \
                  (time.time() - self.dcs_list_lastupdated > self.dcs_list_maxage)
        if bReturn is True:
            self.logger.debug('dcslist has expired')
        return bReturn

    def getconnection(self, userid: str, password: str):
        self.logger.debug('')
        if self.auth_type == 'NTLM':
            userid = self.getntlmlogin(userid)
        if self.auth_type == 'KERBEROS':
            userid = userid.upper()
            self.krb5_authenticate(userid, password)
        return super().getconnection(userid, password)

    def listsite(self, **params):
        self.logger.debug('')
        dictsite = {}
        len_dictsite = 0
        userid = params.get('userid', self.userid)
        password = params.get('password', self.password)

        if not isinstance(userid, str) or not isinstance(password, str):
            self.logger.debug('service account not set in config file, listsite return empty site')
            return dictsite

        try:
            self.logger.debug('getconnection to ldap')
            conn = self.getconnection(userid, password)
            self.logger.debug(f"_pagedAsyncSearch {self.site_query.basedn} {self.site_query.filter} {self.site_query.attrs}")
            result = self.paged_search(conn, self.site_query.basedn, self.site_query.filter, self.site_query.attrs)
            for dn in result:
                attrs = result[dn]
                if attrs is None:
                    self.logger.debug(f"ldap dn={dn} has no attrs {self.site_query.attr} skipping")
                    continue
                if not isinstance(attrs, dict):
                    self.logger.error(f"dn={dn} attrs must be a dict, return data from ldap attrs {type(attrs)}")
                    continue
                entry = {}
                entry['subnet'] = self.decodeValue('cn', attrs.get('cn'))
                entry['siteObject'] = self.decodeValue('siteObject', attrs.get('siteObject'))
                entry['location'] = self.decodeValue('location', attrs.get('location'))
                if all([entry.get('subnet'), entry.get('siteObject'), entry.get('location')]):
                    dictsite[entry.get('subnet')] = entry

            len_dictsite = len(dictsite)
            self.logger.debug(f"query result count:{len_dictsite} {self.site_query.basedn} {self.site_query.filter}")
            conn.unbind()

        except Exception as e:
            self.logger.warning(f"LDAP query siteObject {e}")

        if len_dictsite == 0:
            self.logger.warning('ActiveDirectory has no siteObject defined')

        return dictsite


@oc.logging.with_logger()
class ODAdAuthMetaProvider(ODAdAuthProvider):
    def __init__(self, manager, name, config):
        super().__init__(manager, name, config)
        self.type = 'metaactivedirectory'
        self.trustedrelationship = config.get('trustedrelationship', True)
        self.join_attributkey = config.get('join_key_ldapattribut')
        if not isinstance(self.join_key_ldapattribut, str):
            raise ValueError('set join_key_ldapattribut is to provider metadirectory service')
        if not self.is_serviceaccount_defined(config):
            raise InvalidCredentialsError(f"you must define a service account for meta auth provider {self.name}")

        default_attrs = ODAdAuthProvider.DEFAULT_ATTRS
        default_attrs.append(self.join_key_ldapattribut)
        self.user_query.attrs = default_attrs

        self.foreign_query = self.Query(
            config.get('foreign_basedn', 'CN=ForeignSecurityPrincipals,' + self.user_query.basedn),
            config.get('foreign_scope', self.user_query.scope),
            config.get('foreign_filter', "(&(objectClass=foreignSecurityPrincipal)(objectSid=%s))"),
            config.get('foreign_attrs', ['cn', 'distinguishedName', 'memberOf']))

        self.foreingmemberof_query = self.Query(
            config.get('foreingmemberof_basedn', 'CN=ForeignSecurityPrincipals,' + self.user_query.basedn),
            config.get('foreingmemberof_scope', self.user_query.scope),
            config.get('foreingmemberof_filter', "(memberof:1.2.840.113556.1.4.1941:=%s)"),
            config.get('foreingmemberof_attrs', ['cn', 'distinguishedName']))

    def validate(self, userid, password, **params):
        return super().validate(userid, password, **params)

    def authenticate(self, userid: str, password: str, **params):
        self.logger.debug('')
        if not self.issafeAdAuthusername(userid):
            raise InvalidCredentialsError('Unsafe login credentials')
        if not self.issafeAdAuthpassword(password):
            raise InvalidCredentialsError('Unsafe password credentials')

        (userdn, conn) = self.validate(userid, password)
        data = {'userid': userid, 'domain': self.domain, 'dn': userdn}
        authinfo = AuthInfo(provider=self.name, providertype=self.type, token=userid, data=data, protocol=self.auth_protocol, conn=conn)
        return authinfo

    def createclaims(self, authinfo: AuthInfo, userinfo: AuthUser, userid: str, password: str, **arguments):
        claims = {'userid': userid, 'password': password, 'domain': self.domain}
        authinfo.set_claims(claims)

    def getuserinfo(self, authinfo: AuthInfo, **arguments):
        self.logger.debug('')
        userid = arguments.get('userid')
        filter = ldap_filter.filter_format(self.user_query.filter, [userid])
        self.logger.debug(f"ODAdAuthMetaProvider:ldap.filter {filter}")
        usersinfo = self.search_all(
            conn=authinfo.conn,
            basedn=self.user_query.basedn,
            scope=self.user_query.scope,
            filter=filter,
            attrs=self.user_query.attrs)

        if not isinstance(usersinfo, list) or len(usersinfo) == 0:
            self.logger.error('user does not exist in metadirectory, skipping meta query')
            return None

        if len(usersinfo) > 1:
            self.logger.error(f"too much user {userid} in metadirectory len {len(usersinfo)}, only one is expected, skipping meta query")
            self.logger.error(f"dump metadirectory {usersinfo}")
            return None

        return usersinfo[0]

    def getforeignkeys(self, authinfo: AuthInfo, user: AuthUser):
        self.logger.debug('')
        foreingdistinguished_name = self.getForeignDistinguishedName(authinfo, user.get('objectSid'))
        return foreingdistinguished_name

    def getroles(self, authinfo: AuthInfo, userinfo: AuthUser, **params):
        self.logger.debug('')
        roles = []

        if self.auth_only:
            return roles

        userid = params.get('userid')
        filter = ldap_filter.filter_format(self.user_query.filter, [userid])
        self.logger.debug(f"ODAdAuthMetaProvider:ldap.filter {filter}")
        userinfo = self.search_one(
            conn=authinfo.conn,
            basedn=self.user_query.basedn,
            scope=self.user_query.scope,
            filter=filter,
            attrs=['memberOf'])

        if isinstance(userinfo, dict):
            roles = userinfo.get('memberOf', [])
            if not isinstance(roles, list):
                roles = [roles]

        return roles

    def getForeignDistinguishedName(self, authinfo: AuthInfo, objectSid: str):
        self.logger.debug('')
        foreingdistinguished_name = None
        self.logger.debug(f"objectSid is {objectSid}")

        if not isinstance(objectSid, str):
            self.logger.debug("objectSid is not a str, return None")
            return foreingdistinguished_name

        filter = ldap_filter.filter_format(self.foreign_query.filter, [objectSid])
        self.logger.debug(f"ldap.filter {filter}")
        self.logger.debug(f"ldap search_all basedn={self.foreign_query.basedn} filter={filter} attrs={self.foreign_query.attrs}")

        query_foreingdistinguished_name = self.search_all(
            conn=authinfo.conn,
            basedn=self.foreign_query.basedn,
            scope=self.foreign_query.scope,
            filter=filter,
            attrs=self.foreign_query.attrs)

        self.logger.debug(f"ldap search result {type(query_foreingdistinguished_name)} {query_foreingdistinguished_name}")

        if not isinstance(query_foreingdistinguished_name, list) or len(query_foreingdistinguished_name) == 0:
            self.logger.debug(f"objectSid={objectSid} is not found, return None")
            return None

        foreingdistinguished_list = []
        for foreingdn_dict in query_foreingdistinguished_name:
            if isinstance(foreingdn_dict, dict):
                dn = foreingdn_dict.get('distinguishedName')
                if isinstance(dn, str):
                    foreingdistinguished_list.append(dn)

        self.logger.debug(f"return foreingdistinguished_list={foreingdistinguished_list}")
        return foreingdistinguished_list

    def isMemberOf(self, authinfo: AuthInfo, groupdistinguished_name: str):
        memberof = False
        q = self.foreingmemberof_query
        filter = ldap_filter.filter_format(q.filter, [groupdistinguished_name])
        time_start = time.time()
        try:
            self.logger.debug(f"run ldapquery isMember FSP:ForeignSecurityPrincipals")
            self.logger.debug(f"starting query search_base={q.basedn}, search_scope={q.scope}, search_filter={filter}")
            ldap3_status, ldap3_results, ldap3_response, ldap3_request = authinfo.conn.search(
                search_base=q.basedn, search_filter=filter, search_scope=q.scope)
            elapsed = time.time() - time_start
            self.logger.debug(f"ldap search {q.basedn} {filter} take {elapsed} seconds")
            self.logger.debug(f"ldap3_status={ldap3_status}, ldap3_results={ldap3_results}, ldap3_response={ldap3_response}, ldap3_request={ldap3_request}")
            if ldap3_status is True:
                if isinstance(ldap3_response, list) and len(ldap3_response) > 0:
                    if isinstance(ldap3_response[0], dict):
                        dn = ldap3_response[0].get('dn')
                        if isinstance(dn, str) and len(dn) > 0:
                            memberof = True
        except Exception as e:
            self.logger.error(e)

        self.logger.debug(f"return memberof={memberof}")
        return memberof

    def isMemberOfForeingSecuriyPrincipalsbyObjectSid(self, authinfo: AuthInfo, user: dict, groupdistinguished_name: str):
        self.logger.debug('ODAdAuthMetaProvider')
        memberof = False
        foreing_distinguished_name = user.get('foreing_distinguished_name')
        self.logger.debug(f"foreing_distinguished_name is {foreing_distinguished_name}")

        if not isinstance(foreing_distinguished_name, list):
            self.logger.debug("foreing_distinguished_name is not a list, return False")
            return memberof

        for userdistinguished_name in foreing_distinguished_name:
            self.logger.debug(f"call super().isMemberOf {userdistinguished_name} {groupdistinguished_name}")
            if super().isMemberOf(authinfo, user, userdistinguished_name, groupdistinguished_name):
                memberof = True
                break
        self.logger.debug(f"isMemberOf return {memberof}")
        return memberof

    def getrole_ForeignSecurityPrincipals(self, authinfo: AuthInfo, objectSid: str):
        self.logger.debug(f"objectSid={objectSid}")
        roles = []

        if not isinstance(objectSid, str):
            self.logger.debug(f"objectSid is not a str, return None")
            return None

        filter = ldap_filter.filter_format(self.foreign_query.filter, [objectSid])
        self.logger.debug(f"ldap search_all basedn={self.foreign_query.basedn} filter={filter} attrs={self.foreign_query.attrs}")

        query_foreingdistinguished = self.search_one(
            conn=authinfo.conn,
            basedn=self.foreign_query.basedn,
            scope=self.foreign_query.scope,
            filter=filter,
            attrs=self.foreign_query.attrs)

        if not isinstance(query_foreingdistinguished, dict):
            self.logger.debug(f"objectSid={objectSid} is not found, return {roles}")
            return None

        roles = query_foreingdistinguished.get('memberOf')
        if isinstance(roles, str):
            roles = [roles]
        self.logger.debug(f"return {type(roles)} {roles}")
        return roles


@oc.logging.with_logger()
class ODImplicitTLSCLientAdAuthProvider(ODAdAuthProvider):

    def __init__(self, manager, name, config):
        super().__init__(manager, name, config)
        self.dialog_url = config.get('dialog_url')
        if not self.is_serviceaccount_defined(config):
            raise InvalidCredentialsError(f"you must define a service account for the implicit auth provider {self.name}")

    def getclientdata(self):
        data = super().getclientdata()
        data['dialog_url'] = self.dialog_url
        return data

    def createclaims(self, authinfo, userinfo, userid, **arguments):
        claims = {'identity': self.createauthenv(userinfo, userid, password=None)}
        authinfo.set_claims(claims)

    def authenticate(self, userid, **params):
        q = self.user_query

        if not self.issafeAdAuthusername(userid):
            raise InvalidCredentialsError('Unsafe login credentials')

        conn = self.getconnection(self.userid, self.password)
        userinfo = self.search_one(conn=conn, basedn=q.basedn, scope=q.scope, filter=ldap_filter.filter_format(q.filter, [userid]), attrs=q.attrs, **params)
        if not isinstance(userinfo, dict):
            raise AuthenticationError(f"Implicit login user {userid} does not exist in directory service")

        data = {'userid': userid, 'dn': userinfo.get('dn')}
        authinfo = AuthInfo(provider=self.name, providertype=self.type, token=userid, data=data, protocol=self.auth_protocol, conn=conn)
        return authinfo
