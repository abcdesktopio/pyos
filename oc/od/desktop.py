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

    def __init__(self, nodehostname=None, hostname=None, name=None, desktop_id=None, ipAddr=None, status=None, container_id=None, container_name=None, vncPassword=None, fqdn=None, desktop_interfaces=None, websocketroute=None, websocketrouting=None, xauthkey=None, pulseaudio_cookie=None, broadcast_cookie=None, storage_container_id=None, labels=None, websockettcpport=None, uid=None  ):
        self._id = desktop_id
        self._ipAddr = ipAddr
        self._status = status

        # remove the 'docker://' prefix if exist
        if container_id and container_id.startswith('docker://'):
            container_id = container_id[9:] # 9 is the length of the string 'docker://'
        if storage_container_id and storage_container_id.startswith('docker://'):
            storage_container_id = storage_container_id[9:] # 9 is the length of the string 'docker://'    
            
        self._container_id  = container_id
        self._nodehostname  = nodehostname
        self._vncPassword   = vncPassword
        self._hostname      = hostname
        self._name          = name
        self._fqdn          = fqdn
        self._container_name        = container_name
        self._desktop_interfaces    = desktop_interfaces
        self._websocketroute        = websocketroute
        self._websocketrouting      = websocketrouting
        self._websockettcpport      = websockettcpport
        self._xauthkey              = xauthkey
        self._pulseaudio_cookie     = pulseaudio_cookie
        self._broadcast_cookie      = broadcast_cookie
        self._storage_container_id  = storage_container_id
        self._labels                = labels
        self._uid                   = uid

    # id is the container id in docker mode
    # id is the pod id in kubernetes node
    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, val ):
        self._id = val

    @property
    def uid(self):
        return self._uid

    @uid.setter
    def uid(self, val ):
        self._uid = val

    @property
    def labels(self):
        return self._labels
        
    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, val ):
        self._name = val

    @property
    def storage_container_id(self):
        return self._storage_container_id

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
    def broadcast_cookie(self):
        return self._broadcast_cookie


    @property
    def internaluri(self):
        # describe how to reach the desktop from external access
        # could be a ip address
        # or in kubernetes mode should be formated as '''
        # c37c3213-0b85-4b40-88b6-63767930878b.desktop.abcdesktop.svc.cluster.local. '''
        # This value is used inside the token as hash parameter '''
        # and then read by nginx to forward the request to the pod '''
        # internaluri MUST always return a valid value '''
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
    def websockettcpport(self):
        return self._websockettcpport
    
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
        return str(self._status).lower() == 'running'

    def isTerminating(self):
        return str(self._status).lower() == 'terminating'

    def get_default_ipaddr(self,interface_name=None):
        mydefault_ipaddr = None
        if isinstance( interface_name, str) and isinstance( self._desktop_interfaces, dict ):
            if isinstance( self._desktop_interfaces.get(interface_name), dict ):
                mydefault_ipaddr = self._desktop_interfaces.get(interface_name).get('ips')
        if mydefault_ipaddr is None:
            mydefault_ipaddr = self._ipAddr
        return mydefault_ipaddr

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

def isdesktopreachabled( desktop:ODDesktop )->bool:
    if not isinstance( desktop, ODDesktop):
        return False
    reachaable = isinstance(desktop.internaluri,str) and isinstance(desktop.vncPassword,str)
    return reachaable

def getunreachablemessage( desktop:ODDesktop )->str:
    error_msg = ''
    if not isinstance( desktop, ODDesktop):
        return 'invalid desktop instance'
    if not isinstance(desktop.internaluri,str): 
        error_msg += 'internaluri is unreachable'
    if not isinstance(desktop.vncPassword, str):
        if len(error_msg)>0: 
            error_msg += ' ' 
        error_msg += 'vncpasswod is not defined'
    return error_msg