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
import oc.logging
import json
logger = logging.getLogger(__name__)


@oc.logging.with_logger()
class ODDesktop(object):

    def __init__(self, nodehostname=None, hostname=None, name=None, desktop_id=None, ipAddr=None, status=None, container_id=None, container_name=None, vncPassword=None, fqdn=None, desktop_interfaces=None, websocketroute=None, websocketrouting=None, xauthkey=None, pulseaudio_cookie=None  ):
        self._id = desktop_id
        self._ipAddr = ipAddr
        self._status = status
        # remove the 'docker://' prefix if exist
        if container_id and container_id.startswith('docker://'):
            container_id = container_id[9:] # 9 is the length of the string 'docker://'
        self._container_id = container_id
        self._nodehostname = nodehostname
        self._vncPassword = vncPassword
        self._hostname = hostname
        self._container_name = container_name
        self._name = name
        self._fqdn = fqdn
        self._desktop_interfaces    = desktop_interfaces
        self._websocketroute        = websocketroute
        self._websocketrouting      = websocketrouting
        self._xauthkey              = xauthkey
        self._pulseaudio_cookie     = pulseaudio_cookie



    # id is the container id in docker mode
    # id is the pod id in kubernetes node
    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, val ):
        self._id = val

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, val ):
        self._name = val

    @property
    def nodehostname(self):
        return self._nodehostname

    @property
    def hostname(self):
        return self._hostname

    @property
    def fqdn(self):
        return self._fqdn

    @property
    def xauthkey(self):
        return self._xauthkey

    @property
    def pulseaudio_cookie(self):
        return self._pulseaudio_cookie


    @property
    def internaluri(self):
        ''' describe how to reach the desktop from external access '''
        ''' could be a ip address if oc.od.settings.desktopuseinternalfqdn is False '''
        ''' in kubernetes mode should be formated as '''
        ''' c37c3213-0b85-4b40-88b6-63767930878b.desktop.abcdesktop.svc.cluster.local. '''
        ''' This value is used inside the token as hash parameter '''
        ''' and then read by nginx to forward the request to the pod '''
        ''' internaluri MUST always return a valid value '''
        uri = self._fqdn
        if not uri :
            uri = self._ipAddr
        return uri

    @property
    def container_id(self):
        return self._container_id

    @container_id.setter
    def container_id(self, val ):
        self._container_id = val

    @property
    def container_name(self):
        return self._container_name

    @container_name.setter
    def container_name(self, val ):
        self._container_name = val

    @property
    def status(self):
        return self._status

    @status.setter
    def status(self, val ):
        self._status = val
    
    @property
    def ipAddr(self):
        return self._ipAddr

    @ipAddr.setter
    def ipAddr(self, val ):
        self._ipAddr = val
 
    @property
    def vncPassword(self):
        return self._vncPassword

    @vncPassword.setter
    def vncPassword(self, val ):
        self._vncPassword = val

    @property 
    def websocketrouting(self):
        return self._websocketrouting

    @websocketrouting.setter
    def websocketrouting(self, val):
        self._websocketrouting = val


    def isRunning(self):
        status = str(self._status)
        if status.lower() == 'running':
           return True
        return False

    def isTerminating(self):
        status = str(self._status)
        if status.lower() == 'terminating':
           return True
        return False

    @property 
    def desktop_interfaces(self):
        return self._desktop_interfaces

    @property 
    def websocketroute(self):
        return self._websocketroute

    def to_dict(self):
        return {
            'id':       self._id,
            'ipAddr':   self._ipAddr,
            'status':   self._status,
            'container_id' : self._container_id,
            'nodehostname' : self._nodehostname,
            'vncPassword' : self._vncPassword,
            'hostname' : self._hostname,
            'container_name' : self._container_name,
            'name' : self._name,
            'fqdn' : self._fqdn,
            'desktop_interfaces' : self._desktop_interfaces,
            'websocketroute' : self._websocketroute,
            'websocketrouting' : self._websocketrouting
        }

    def to_json(self):
        my_dict = self.to_dict()
        return json.dumps(my_dict, sort_keys=True, indent=4)

    