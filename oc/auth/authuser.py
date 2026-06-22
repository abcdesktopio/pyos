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
import mergedeep
import chevron

import oc.od.settings

logger = logging.getLogger(__name__)


class AuthUser(dict):
    def __init__(self, entries):
        if type(entries) is dict:
            super().__init__(entries)

    def __getattr__(self, name):
        return self.get(name)

    def __getitem__(self, key):
        return getattr(self, key, None)

    def merge(self, newuser):
        if not isinstance(newuser, AuthUser):
            raise ValueError(f"merge error invalid user AuthUser object type {type(newuser)}")
        mergedeep.merge(newuser, self, strategy=mergedeep.Strategy.ADDITIVE)
        return newuser

    def isValid(self):
        return not(not self.get('userid'))

    def getPosixAccount(self):
        posixaccount = None
        posixdata = self.get('posix')
        if isinstance(posixdata, dict):
            posixaccount = AuthUser.getdefaultPosixAccount(
                uid=posixdata.get('uid'),
                gid=posixdata.get('gid'),
                uidNumber=posixdata.get('uidNumber'),
                gidNumber=posixdata.get('gidNumber'),
                homeDirectory=posixdata.get('homeDirectory'),
                description=posixdata.get('description'),
                groups=posixdata.get('groups'),
                gecos=posixdata.get('gecos'))
        return posixaccount

    def isPosixAccount(self):
        bPosix = isinstance(self.get('posix'), dict)
        return bPosix

    @staticmethod
    def getConfigdefaultPosixAccount():
        uid = oc.od.settings.getballoon_loginname()
        gid = oc.od.settings.getballoon_groupname()
        uidNumber = oc.od.settings.getballoon_uidNumber()
        gidNumber = oc.od.settings.getballoon_gidNumber()
        homeDirectory = oc.od.settings.getballoon_homedirectory(uid)
        loginShell = oc.od.settings.getballoon_loginShell()
        description = 'abcdesktop default account'
        return AuthUser.getdefaultPosixAccount(
            uid=uid,
            gid=gid,
            uidNumber=uidNumber,
            gidNumber=gidNumber,
            homeDirectory=homeDirectory,
            loginShell=loginShell,
            description=description
        )

    @staticmethod
    def getPosixAccountfromlocalAccount(localaccount: dict) -> dict:
        if not isinstance(localaccount, dict):
            return AuthUser.getConfigdefaultPosixAccount()

        uid = localaccount.get('uid', oc.od.settings.getballoon_loginname())
        gid = localaccount.get('gid', oc.od.settings.getballoon_groupname())
        uidNumber = localaccount.get('uidNumber', oc.od.settings.getballoon_uidNumber())
        gidNumber = localaccount.get('gidNumber', oc.od.settings.getballoon_gidNumber())
        homeDirectory = localaccount.get('homeDirectory', oc.od.settings.getballoon_homedirectory(uid))
        loginShell = localaccount.get('loginShell', oc.od.settings.getballoon_loginShell())
        description = localaccount.get('description', "abcdesktop generated account")
        return AuthUser.getdefaultPosixAccount(
            uid=uid,
            gid=gid,
            uidNumber=uidNumber,
            gidNumber=gidNumber,
            homeDirectory=homeDirectory,
            loginShell=loginShell,
            description=description
        )

    @staticmethod
    def getdefaultPosixAccount(uid, gid, uidNumber, gidNumber, cn=None, homeDirectory=None, loginShell=None, description=None, groups=None, gecos=None):
        uid = uid.lower()

        if not isinstance(cn, str):
            cn = uid
        if not isinstance(gid, str):
            gid = uid
        if not isinstance(homeDirectory, str):
            homeDirectory = '/home/' + str(uid)
        if not isinstance(loginShell, str):
            loginShell = oc.od.settings.balloon_shell

        defaultposixAccount = {
            'cn': cn,
            'uid': uid,
            'gid': gid.lower(),
            'uidNumber': uidNumber,
            'gidNumber': gidNumber,
            'homeDirectory': homeDirectory,
            'loginShell': loginShell,
            'description': description,
            'groups': groups,
            'gecos': gecos
        }
        return defaultposixAccount

    @staticmethod
    def mkpasswd(moustachedata: dict) -> str:
        assert (isinstance(moustachedata, dict))
        passwd = chevron.render(oc.od.settings.DEFAULT_PASSWD_FILE, moustachedata)
        passwd += '\n'
        return passwd

    @staticmethod
    def mkpasswd_newline(moustachedata: dict) -> str:
        assert (isinstance(moustachedata, dict))
        uid = moustachedata.get('uid')
        uidNumber = moustachedata.get('uidNumber')
        gidNumber = moustachedata.get('gidNumber')
        gecos = moustachedata.get('gecos')
        homeDirectory = moustachedata.get('homeDirectory')
        loginShell = moustachedata.get('loginShell')
        passwd = f"{ uid }:x:{ uidNumber }:{ gidNumber }:{ gecos }:{ homeDirectory }:{ loginShell }\n"
        return passwd

    @staticmethod
    def mksupplementalGroups(moustachedata: dict) -> list:
        assert (isinstance(moustachedata, dict))
        supplementalGroups = None
        groups = moustachedata.get('groups')
        if isinstance(groups, list):
            supplementalGroups = []
            for group in groups:
                supplementalGroups.append(group['gidNumber'])
        return supplementalGroups

    @staticmethod
    def mkgroup(moustachedata: dict) -> str:
        assert (isinstance(moustachedata, dict))
        etcgroup = chevron.render(oc.od.settings.DEFAULT_GROUP_FILE, moustachedata)
        new_etc_group_lines = AuthUser.mkgroup_newline(moustachedata)
        if len(new_etc_group_lines) > 0:
            etcgroup += new_etc_group_lines
        return etcgroup

    @staticmethod
    def mkgroup_newline(moustachedata: dict) -> str:
        """
        mkgroup_newline
            generate the group file from the moustachedata
            and the template file DEFAULT_GROUP_FILE
            Args: moustachedata (dict): moustachedata
            Returns: group (str): group file content
        """
        assert (isinstance(moustachedata, dict))
        new_etc_group_lines = ''

        gid = moustachedata.get('gid')
        gidNumber = moustachedata.get('gidNumber')
        uid = moustachedata.get('uid')
        if isinstance(gid, str) and isinstance(gidNumber, int):
            new_etc_group_lines = f"{ gid }:x:{ gidNumber }:\n"

        groups = moustachedata.get('groups')
        logger.debug(f"add user groups {groups}")
        if isinstance(groups, list):
            for group in groups:
                newline = f"{group['cn']}:x:{group['gidNumber']}:"
                uids = group.get('memberUid')
                if isinstance(uids, str):
                    newline += uids
                if isinstance(uids, list) and len(uids) > 0:
                    n = 0
                    for uid in uids:
                        newline += uids[n]
                        n = n + 1
                        break
                    for uid in uids[n::]:
                        newline += ',' + uid
                new_etc_group_lines += newline + '\n'
        return new_etc_group_lines

    @staticmethod
    def mkgshadow(moustachedata: dict) -> str:
        """mkgshadow
            generate the gshadow file from the moustachedata
            and the template file DEFAULT_GSHADOW_FILE

        Args: moustachedata (dict): moustachedata
        Returns: gshadow (str): gshadow file content
        """
        assert (isinstance(moustachedata, dict))
        gshadow = chevron.render(oc.od.settings.DEFAULT_GSHADOW_FILE, moustachedata)
        mkshadow_newline = AuthUser.mkgshadow_newline(moustachedata)
        if len(mkshadow_newline) > 0:
            gshadow += mkshadow_newline
            gshadow += '\n'
        return gshadow

    @staticmethod
    def mkgshadow_newline(moustachedata: dict) -> str:
        assert (isinstance(moustachedata, dict))
        new_etc_shadow_lines = ''
        groups = moustachedata.get('groups')
        if isinstance(groups, list):
            for group in groups:
                newline = f"{group['cn']}:!::"
                uids = group.get('memberUid')
                if isinstance(uids, str):
                    newline += uids
                if isinstance(uids, list):
                    if len(uids) > 0:
                        newline += uids[0]
                        for uid in uids[1::]:
                            newline += ',' + uid
                new_etc_shadow_lines += newline + '\n'
        return new_etc_shadow_lines + '\n'

    @staticmethod
    def mkshadow(moustachedata: dict) -> str:
        line_mkshadow = chevron.render(oc.od.settings.DEFAULT_SHADOW_FILE, moustachedata)
        line_mkshadow += '\n'
        return line_mkshadow

    @staticmethod
    def mkshadow_newline(moustachedata: dict) -> str:
        shadow_template_newline = "{{ uid }}:{{ sha512 }}:19080:0:99999:7:::"
        shadow_newline = chevron.render(shadow_template_newline, moustachedata)
        shadow_newline += '\n'
        return shadow_newline

    @staticmethod
    def to_static_dict(local_dict):
        """to_static_dict

        Returns:
            dict: dict with only static value
            no 'geolocation', 'utctimestamp'
        """
        static_dict = {}
        no_static_key = ['geolocation', 'utctimestamp']
        for key in local_dict.keys():
            if key in no_static_key:
                continue
            else:
                static_dict[key] = local_dict.get(key)
        return static_dict
