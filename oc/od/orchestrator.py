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
from platform import node
from typing_extensions import assert_type
import oc.logging
from oc.od.apps import ODApps
import oc.od.settings
import oc.lib
import oc.auth.namedlib
import os
import time
import datetime
import binascii
import aiohttp

import yaml
import json
import chevron
import requests
import copy
import asyncio
import threading



# kubernetes-asyncio: bibliothèque kubernetes asynchrone
from kubernetes_asyncio import client, config, watch
from kubernetes_asyncio.client.rest import ApiException
from kubernetes_asyncio.client.api.core_v1_api import CoreV1Api

from kubernetes_asyncio.client.models.v1_pod import V1Pod
from kubernetes_asyncio.client.models.v1_pod_spec import V1PodSpec
from kubernetes_asyncio.client.models.v1_pod_status import V1PodStatus
# from kubernetes_asyncio.client.models.v1_container import V1Container
from kubernetes_asyncio.client.models.v1_ephemeral_container import V1EphemeralContainer
from kubernetes_asyncio.client.models.v1_status import V1Status
from kubernetes_asyncio.client.models.v1_container import V1Container

# kubernetes_asyncio.client.models.v1_container
from kubernetes_asyncio.client.models.v1_container_status import V1ContainerStatus
from kubernetes_asyncio.client.models.v1_container_state import V1ContainerState
from kubernetes_asyncio.client.models.v1_container_state_terminated import V1ContainerStateTerminated
from kubernetes_asyncio.client.models.v1_container_state_running import V1ContainerStateRunning
from kubernetes_asyncio.client.models.v1_container_state_waiting import V1ContainerStateWaiting

# Volume
from kubernetes_asyncio.client.models.v1_persistent_volume_claim import V1PersistentVolumeClaim
#from kubernetes_asyncio.client.models.v1_volume import V1Volume
#from kubernetes_asyncio.client.models.v1_volume_mount import V1VolumeMount
#from kubernetes_asyncio.client.models.v1_local_volume_source import V1LocalVolumeSource
#from kubernetes_asyncio.client.models.v1_flex_volume_source import V1FlexVolumeSource
#from kubernetes_asyncio.client.models.v1_host_path_volume_source import V1HostPathVolumeSource
#from kubernetes_asyncio.client.models.v1_secret_volume_source import V1SecretVolumeSource

# Secret
from kubernetes_asyncio.client.models.v1_secret import V1Secret
#from kubernetes_asyncio.client.models.v1_secret_list import V1SecretList
from kubernetes_asyncio.client.models.v1_event_source import V1EventSource
from kubernetes_asyncio.client.models.v1_object_field_selector import V1ObjectFieldSelector
from kubernetes_asyncio.client.models.v1_object_reference import V1ObjectReference

from kubernetes_asyncio.client.models.core_v1_event import CoreV1Event
from kubernetes_asyncio.client.models.v1_node_list import V1NodeList
from kubernetes_asyncio.client.models.v1_node import V1Node
from kubernetes_asyncio.client.models.v1_env_var import V1EnvVar
from kubernetes_asyncio.client.models.v1_pod_list import V1PodList
from kubernetes_asyncio.client.models.v1_config_map import V1ConfigMap
from kubernetes_asyncio.client.models.v1_deployment import V1Deployment

#from kubernetes_asyncio.client.models.v1_endpoint import V1Endpoint
from kubernetes_asyncio.client.models.v1_endpoints import V1Endpoints
#from kubernetes_asyncio.client.models.v1_endpoints_list import V1EndpointsList
from kubernetes_asyncio.client.models.v1_endpoint_subset import V1EndpointSubset
from kubernetes_asyncio.client.models.core_v1_endpoint_port import CoreV1EndpointPort
from kubernetes_asyncio.client.models.v1_endpoint_address import V1EndpointAddress
from kubernetes_asyncio.client.models.v1_object_meta import V1ObjectMeta
from kubernetes_asyncio.client.models.v1_resource_requirements import V1ResourceRequirements
from kubernetes_asyncio.client.models.v1_delete_options import V1DeleteOptions

# kubernetes (sync) - uniquement pour l'exec streaming via WebSocket
import kubernetes as _k8s_sync
from kubernetes.stream import stream as _k8s_sync_stream
from kubernetes.stream.ws_client import ERROR_CHANNEL


import oc.lib
import oc.od.acl
import oc.od.volume
import oc.od.persistentvolumeclaim
import oc.od.secret         # manage secret for kubernetes
import oc.od.registry
from oc.od.appinstancestatus import ODAppInstanceStatus
from oc.od.error import ODAPIError, ODError   # import all error classes
from oc.od.desktop import ODDesktop
from oc.od.vnc_password import ODVncPassword
from oc.auth.authuser import AuthUser
from oc.auth.authinfo import AuthInfo
from oc.auth.authroles import AuthRoles

logger = logging.getLogger(__name__)


DEFAULT_PULSE_TCP_PORT = 4713
DEFAULT_CUPS_TCP_PORT  = 631


def selectOrchestrator():
    """select Orchestrator
    return a kubernetes ODOrchestratorKubernetes

    Returns:
        [ODOrchestrator]: [description]
    """
    myOrchestrator = oc.od.orchestrator.ODOrchestratorKubernetes()
    return myOrchestrator

@oc.logging.with_logger()
class ODOrchestratorBase(object):

    def on_desktoplaunchprogress(self, key, *args):
        if callable(self.desktoplaunchprogress): 
            self.desktoplaunchprogress(self, key, *args)

    def __init__(self):

        # container name is x-UUID
        self.graphicalcontainernameprefix   = 'x'   # graphical container letter prefix x for x11
         # container name is a-UUID
        self.spawnercontainernameprefix     = 'a'   # graphical container letter prefix a for spwaner
        # printer name is c-UUID
        self.printercontainernameprefix     = 'c'   # printer container letter prefix c for cups
        # sound name is s-UUID
        self.soundcontainernameprefix       = 's'   # sound container letter prefix p for pulseaudio
        # sound name is p-UUID
        self.filercontainernameprefix       = 'f'   # file container letter prefix f for file service
        # init name is i-UUID
        self.initcontainernameprefix        = 'i'   # init container letter prefix i for init
        # ssh name is h-UUID
        self.sshcontainernameprefix         = 'h'   # ssh container letter prefix h for ssh
        # webshell name is w-UUID
        self.webshellcontainernameprefix    = 'w'   # webshell container letter prefix w
        # name separtor only for human read 
        self.snapshotcontainernameprefix    = 't'   # snapshot container letter prefix t
        # name separtor only for human read 
        self.containernameseparator         = '-'   # separator

        self.nameprefixdict = { 
            'graphical' : self.graphicalcontainernameprefix,
            'spawner'   : self.spawnercontainernameprefix,
            'webshell'  : self.webshellcontainernameprefix,
            'printer'   : self.printercontainernameprefix,
            'sound'     : self.soundcontainernameprefix,  
            'filer'     : self.filercontainernameprefix,
            'init'      : self.initcontainernameprefix,
            'ssh'       : self.sshcontainernameprefix,
            'snapshot'  : self.snapshotcontainernameprefix
        }
        self.name                   = 'base'
        self.endpoint_domain        = 'desktop'
        self.desktoplaunchprogress  = oc.pyutils.Event()        
        self.x11servertype          = 'x11server'        
        self.pod_application        = 'pod_application'
        self.pod_application_pull   = 'pod_application_pull'
        self.ephemeral_container    = 'ephemeral_container'
        self.abcdesktop_role_desktop = 'desktop'

    def get_containername( self, authinfo, userinfo, currentcontainertype, myuuid ):
        prefix = self.nameprefixdict[currentcontainertype]
        return prefix + self.containernameseparator + currentcontainertype
    
        # prefix = self.nameprefixdict[currentcontainertype]
        # name = prefix + self.containernameseparator + authinfo.provider + self.containernameseparator + userinfo.userid
        # name = oc.auth.namedlib.normalize_name_dnsname( name )
        # return self.get_basecontainername( prefix, userid, myuuid )
        # return name

    # def get_basecontainername( self, containernameprefix, userid, container_name ):
    #    user_container_name = self.containernameseparator
    #    if isinstance( userid, str ):
    #        user_container_name = userid + self.containernameseparator
    #    name = containernameprefix + self.containernameseparator + user_container_name + container_name
    #    name = oc.auth.namedlib.normalize_name_dnsname( name )
    #    return name

    def get_normalized_username(self, name:str ):
        """[get_normalized_username]
            return a username without accent to be use in label and container name
        Args:
            name ([str]): [username string]

        Returns:
            [str]: [username correct value]
        """
        return oc.lib.remove_accents( name ) 
   
    def resumedesktop(self, authinfo:AuthInfo, userinfo:AuthUser, **kwargs):
        raise NotImplementedError(f"{type(self)}.resumedesktop")

    def createdesktop(self, authinfo:AuthInfo, userinfo:AuthUser, rolesinfo:AuthRoles, **kwargs):
        raise NotImplementedError(f"{type(self)}.createdesktop")

    async def build_volumes( self, authinfo:AuthInfo, userinfo:AuthUser, volume_type, secrets_requirement, rules, **kwargs):
        raise NotImplementedError(f"{type(self)}.build_volumes")

    def findDesktopByUser( self, authinfo:AuthInfo, userinfo:AuthUser ):
        raise NotImplementedError(f"{type(self)}.findDesktopByUser")

    async def removedesktop(self, authinfo:AuthInfo, userinfo:AuthUser, args={}):
        raise NotImplementedError(f"{type(self)}.removedesktop")

    def getsecretuserinfo(self, authinfo:AuthInfo, userinfo:AuthUser):
        raise NotImplementedError(f"{type(self)}.getsecretuserinfo")

    def execwaitincontainer( self, desktop, command, timeout):
        raise NotImplementedError(f"{type(self)}.execwaitincontainer")

    def is_configured( self):
        raise NotImplementedError(f"{type(self)}.is_configured")

    def countdesktop(self):
        raise NotImplementedError(f"{type(self)}.countdesktop")

    def listContainerApps( self, authinfo, userinfo, apps ):
        raise NotImplementedError(f"{type(self)}.listContainerApps")

    def countRunningContainerforUser( self, authinfo, userinfo):  
        raise NotImplementedError(f"{type(self)}.countRunningContainerforUser")

    def envContainerApp( self, authinfo:AuthInfo, userinfo:AuthUser, pod_name:str, containerid:str):
        raise NotImplementedError(f"{type(self)}.envContainerApp")
    
    def removeContainerApp( self, authinfo, userinfo, containerid):
        raise NotImplementedError(f"{type(self)}.removeContainerApp")

    def logContainerApp( self, authinfo, userinfo, podname, containerid):
        raise NotImplementedError(f"{type(self)}.logContainerApp")

    def stopContainerApp( self, authinfo, userinfo, myDesktop, podname, containerid, timeout=5 )->bool:
        raise NotImplementedError(f"{type(self)}.stopContainerApp")

    def get_volumename(self, prefix, userinfo):
        if not isinstance(prefix,str):
             raise ValueError(f"invalid prefix value {type(self)}")

        if not isinstance(userinfo, oc.auth.authservice.AuthUser):
             raise ValueError(f"invalid userinfo value {type(self)}")

        lower_userid = userinfo.get('userid').lower()
        name = f"{prefix}-{lower_userid}"
        normalize_name = oc.auth.namedlib.normalize_name_volunename(name)
        return normalize_name

    async def user_connect_count(self, desktop:ODDesktop, timeout=10):
        """user_connect_count
            call bash script /composer/connectcount.sh inside a desktop
        Args:
            desktop (ODDesktop): ODDesktop
            timeout (int, optional): in seconds. Defaults to 10.

        Raises:
            ValueError: ValueError('invalid desktop object type') if desktop id not an ODDesktop

        Returns:
            int: number of user connected on a desktop
                -1 if error
                else number of connection to the x11 websocket 
        """
        self.logger.debug('')
        nReturn = -1 # default value is a error
        if not isinstance(desktop,ODDesktop):
            raise ValueError('invalid desktop object type')

        # call bash script in oc.user 
        # bash script 
        # !/bin/bash
        # COUNT=$(netstat -t | grep 'ESTABLISHED' | grep 6081 | wc -l)
        # echo $COUNT
        command = [ '/composer/connectcount.sh' ]      
        result = await self.execwaitincontainer( desktop, command, timeout)
        if not isinstance(result,dict):
            # do not raise exception 
            return nReturn

        self.logger.debug( f"command={command} returns exitcode={result.get('ExitCode')} output={result.get('stdout')}" )
        if result.get('ExitCode') == 0 and result.get('stdout'):
            try:
                nReturn = int(result.get('stdout'))
            except ApiException as e:
                self.logger.error(e)
        return nReturn

    def list_dict_secret_data( self, authinfo, userinfo, access_type=None, hidden_empty=False ):
        """get a dict of secret (key value) for the access_type
           if access_type is None will list all user secrets
        Args:
            authinfo (AuthInfo): authentification data
            userinfo (AuthUser): user data 
            access_type (str): type of secret like 'auth' 

        Returns:
            dict: return dict of secret key value 
        """
        return {}

    async def waitForDesktopProcessReady(self, desktop:ODDesktop, queue:asyncio.Queue):
        self.logger.debug('')
        bReturn = False

        nCountMax = 42
        # check if supervisor has stated all processs
        # processes = [ 'startplasma-x11', 'plasma_session', 'kded5', 'ksmserver', 'kglobalaccel5', 'xembedsniproxy', 'kaccess', 'plasmashell', 'gmenudbusmenuproxy' ]
        nCount = 1
        servicesListening = oc.od.settings.desktop_pod['graphical'].get('waitfor_listeningservices', [ 'graphical', 'spawner' ] )
        services = oc.od.settings.desktop_pod['graphical'].get('waitfor_services', [ 'xserver', 'novnc', 'spawner-service', 'plasmashell' ] )
        processes = oc.od.settings.desktop_pod['graphical'].get('waitfor_processes', [ 'plasmashell', 'xfwm4', 'kded5', 'kglobalaccel5' ] )
        bServiceStatus = {} 
        bProcessStatus = {}
        bServicesListening = {}

        for service in services: bServiceStatus[service] = False
        for service in servicesListening: bServicesListening[service] = False
        for process in processes: bProcessStatus[process] = False

        start_now = datetime.datetime.now()

        #
        # wait for service status ready
        nServiceCount = 1
        while nCount < nCountMax:
            for service in services: 
                if not bServiceStatus[service] :
                    queue.put_nowait( (100, f"c.Waiting desktop service {service}") )
                    bServiceStatus[service] = await self.waitForServiceReady( desktop, service_name=service )
                    if bServiceStatus[service] is True:
                        nServiceCount += 1
            nCount += 1
            if all( bServiceStatus.values() ):
                self.logger.debug( f"desktop services {services} are ready" )  
                queue.put_nowait( (100, f"c.Desktop services {services} are started") )                
                break
        
        #
        # wait for proces status ready
        nProcessCount = 1
        nCount = 0
        while nCount < nCountMax:
            for process in processes: 
                if not bProcessStatus[process] :
                    queue.put_nowait( (100, f"c.Waiting for desktop process {process}") )
                    bProcessStatus[process] = await self.waitForProcessReady( desktop, process_name=process )
                    if bProcessStatus[process] is True:
                        nProcessCount += 1
                    else:
                        sleepfor = 1/nProcessCount
                        await asyncio.sleep( sleepfor )
            nCount += 1

            if all( bProcessStatus.values() ):
                self.logger.debug( f"desktop processes are ready" )  
                queue.put_nowait( (100, f"c.Desktop processes are started") )                
                break
   

        #
        # wait for service listening
        nCount = 1
        while nCount < nCountMax:
            for service in ['graphical', 'spawner']: 
                messageinfo = f"c.Waiting for a response from desktop {service}"
                queue.put_nowait( (100, messageinfo) )
                # check if WebSockifyListening id listening on tcp port 6081
                if bServicesListening[service] is False:
                    bServicesListening[service] = await self.waitForServiceListening( desktop, service=service, timeout=0)
                    if bServicesListening[service] is False:
                        messageinfo = f"c.Desktop {service} service is not listening."
                        queue.put_nowait( (100, messageinfo) )
                        await asyncio.sleep(nCount/nCountMax)
            nCount += 1
            
            if  all( bServicesListening.values() ):
                self.logger.debug( "desktop services are ready" )        
                end_now = datetime.datetime.now()   
                diff_time = end_now - start_now
                diff_time_seconds = diff_time.total_seconds()                
                queue.put_nowait( (100, f"c.Desktop services are running after {diff_time_seconds}") )
                bReturn = True
                break 
        
        # Can not chack process status     
        self.logger.warning( f"waitForDesktopProcessReady not ready services status:{bServicesListening}" )
        return bReturn


    async def waitForServiceHealtz(self, desktop, service, timeout=5):
        """waitForServiceHealtz

        Args:
            desktop (ODDesktop): desktop object to waitForServiceHealtz
            service (str): namwe of the service 
            timeout (int, optional): timeout in seconds. Defaults to 1.

        Raises:
            ValueError: invalid desktop object type, desktop is not a ODDesktop
            ODAPIError: error in configuration file 'healtzbin' must be a string
            ODAPIError: error in configuration file 'tcpport' must be a int

        Returns:
            bool: True the the service healtz is up, else False
        """
        self.logger.debug('')
        # Note the same timeout value is used twice
        # for the wait_port command and for the exec command         
        
        assert_type( desktop, ODDesktop)

        # healtz binary command is optional 
        # return True if not define
        if not isinstance( oc.od.settings.desktop_pod[service].get('healtzbin'), str):
            # no healtz binary command has been set
            # no need to run command
            return True
        
        port = port=oc.od.settings.desktop_pod[service].get('tcpport')
        binding = f"http://{desktop.ipAddr}:{port}/{service}/healtz"

        # curl --max-time [SECONDS] [URL]
        healtzbintimeout = oc.od.settings.desktop_pod[service].get('healtzbintimeout', timeout*1000 )
        command = [ oc.od.settings.desktop_pod[service].get('healtzbin'), '--max-time', str(healtzbintimeout), binding ]       
        result = await self.execwaitincontainer( desktop, command, timeout)
        self.logger.debug( f"command {command} returns {result.get('exit_code')} output {result.get('stdout')}" )

        if isinstance(result, dict):
            return result.get('ExitCode') == 0
        else:
            return False

    async def waitForServiceReady(self, desktop:ODDesktop, service_name:str)-> bool:
        """waitForServicePlasmaShell

        Args:
            desktop (ODDesktop): desktop object to waitForServiceListening
        
        Raises:
            ValueError: invalid desktop object type, desktop is not a ODDesktop
            ODAPIError: error in configuration file 'waitportbin' must be a string
            ODAPIError: error in configuration file 'tcpport' must be a int

        Returns:
            bool: True the the service is up
        """

        self.logger.debug('')       
        assert_type( desktop, ODDesktop)

        # Note the same timeout value is used twice
        # for the wait_port command and for the exec command  
        command = [ "/usr/bin/supervisorctl", "status", service_name ] 
        result = await self.execwaitincontainer( desktop, command )
        if isinstance(result, dict):
            # self.logger.debug( f"command={command} exit_code={result.get('ExitCode')} stdout={result.get('stdout')}" )
            isserviceready = result.get('ExitCode') == 0
            # self.logger.debug( f"isservice {service_name} ready={isserviceready}")
            return isserviceready
        return False

    async def waitForProcessReady(self, desktop:ODDesktop, process_name:str)-> bool:
        """waitForServicePlasmaShell

        Args:
            desktop (ODDesktop): desktop object to waitForServiceListening
        
        Raises:
            ValueError: invalid desktop object type, desktop is not a ODDesktop
            ODAPIError: error in configuration file 'waitportbin' must be a string
            ODAPIError: error in configuration file 'tcpport' must be a int

        Returns:
            bool: True the the service is up
        """

        self.logger.debug('')       
        assert_type( desktop, ODDesktop)

        # Note the same timeout value is used twice
        # for the wait_port command and for the exec command  
        command = [ "/usr/bin/pidof", process_name ] 
        result = await self.execwaitincontainer( desktop, command )
        if isinstance(result, dict):
            # self.logger.debug( f"command={command} exit_code={result.get('ExitCode')} stdout={result.get('stdout')}" )
            isprocessready = result.get('ExitCode') == 0
            # self.logger.debug( f"isservice {service_name} ready={isserviceready}")
            return isprocessready
        return False

      
    async def waitForServiceListening(self, desktop:ODDesktop, service:str, timeout:int=2)-> bool:
        """waitForServiceListening

        Args:
            desktop (ODDesktop): desktop object to waitForServiceListening
            service (str): name of the service to check, should be 'graphical' or 'spawner'
            timeout (int, optional): timeout in seconds. Defaults to 2.

        Raises:
            ValueError: invalid desktop object type, desktop is not a ODDesktop
            ODAPIError: error in configuration file 'waitportbin' must be a string
            ODAPIError: error in configuration file 'tcpport' must be a int

        Returns:
            bool: True the the service is up
        """

        self.logger.debug('')       
        assert_type( desktop, ODDesktop)

        # Note the same timeout value is used twice
        # for the wait_port command and for the exec command  

        waitportbincommand = oc.od.settings.desktop_pod[service].get('waitportbin')
        # check if waitportbincommand is a string
        if not isinstance( waitportbincommand, str):
            # no waitportbin command has been set
            self.logger.error(f"error in configuration file 'waitportbin' must be a string. Type read in config {type(waitportbincommand)}" )
            raise ODAPIError( f"error in configuration file 'waitportbin' must be a string defined as healtz command line. type defined {type(waitportbincommand)}" )
        
        port = oc.od.settings.desktop_pod[service].get('tcpport')
        if not isinstance( port, int):
            # no tcpport has been set
            self.logger.error(f"error in configuration file 'tcpport' must be a int. Type read in config {type(port)}" )
            raise ODAPIError( f"error in configuration file 'tcpport' must be a int. Type read in config {type(port)}" )
        
        binding = f"{desktop.ipAddr}:{port}"
        # 
        # waitportbin use a timeout (in milliseconds).
        # execwaitincontainer use a timeout (in seconds).
        # 
        waitportbintimeout = oc.od.settings.desktop_pod[service].get('waitportbintimeout', timeout*1000 )
        command = [ oc.od.settings.desktop_pod[service].get('waitportbin'), '-t', str(waitportbintimeout), binding ]       
        result = await self.execwaitincontainer( desktop, command, timeout)
     
        if isinstance(result, dict):
            self.logger.debug( f"command={command} exit_code={result.get('ExitCode')} stdout={result.get('stdout')}" )
            isportready = result.get('ExitCode') == 0
            self.logger.debug( f"isportready={isportready}")
            if isportready is True:
                self.logger.debug( f"binding {binding} is up")
                return await self.waitForServiceHealtz(desktop, service, timeout)

        self.logger.debug( f"binding {binding} is down")
        return False

    @staticmethod
    def generate_cookie( cookie_len:int):
        assert_type( cookie_len, int )
        key = binascii.b2a_hex(os.urandom(cookie_len))
        return key.decode( 'utf-8' )

    @staticmethod
    def generate_xauthkey():
        """generate_xauthkey
            create a xauth cookie
        Returns:
            str: xauth cookie
        """
        # generate key, xauth requires 128 bit hex encoding
        # xauth add ${HOST}:0 . $(xxd -l 16 -p /dev/urandom)
        return ODOrchestratorBase.generate_cookie(cookie_len=15)

    @staticmethod
    def generate_pulseaudiocookie():
        """generate_pulseaudiocookie
            create a pulse audio cookie of 32 Bytes
        Returns:
            str: pulseaudiocookie
        """
        # generate key, PULSEAUDIO requires PA_NATIVE_COOKIE_LENGTH 256 Bytes
        # but kubernetes labels must be no more than 63 characters
        # len( binascii.b2a_hex(os.urandom(16)).decode( 'utf-8' )) = 32 < 64
        # use this fix in entrypoint
        # for i in {1..8} 
        # do 
        #   echo "$PULSEAUDIO_COOKIE" >> cookie 
        # done
        return ODOrchestratorBase.generate_cookie(cookie_len=16)

    @staticmethod
    def generate_broadcastcookie():
        """generate_broadcastcookie
             create a pulse broadcast cookie

        Returns:
            str: broadcastcookie value
        """
        # generate key, SPAWNER and BROADCAT service
        # use os.urandom(24) as key 
        return ODOrchestratorBase.generate_cookie(cookie_len=24)

@oc.logging.with_logger()
class ODOrchestrator(ODOrchestratorBase):
    
    def __init__(self ):
        super().__init__()
        self.name = 'docker'
        
    def prepareressources(self, authinfo:AuthInfo, userinfo:AuthUser):
        self.logger.debug('externals ressources are not supported in docker mode')  

    def getsecretuserinfo(self, authinfo:AuthInfo, userinfo:AuthUser):  
        ''' cached userinfo are not supported in docker mode '''    
        ''' return an empty dict '''
        self.logger.debug('get cached userinfo are not supported in docker mode')
        return {} 

    async def build_volumes( self, authinfo:AuthInfo, userinfo:AuthUser, volume_type, secrets_requirement, rules, **kwargs):
        raise NotImplementedError(f"{type(self)}.build_volumes")
  
    def countdesktop(self):
        raise NotImplementedError(f"{type(self)}.countdesktop")

    def removedesktop(self, authinfo, userinfo, args={}):
        raise NotImplementedError(f"{type(self)}.removedesktop")

    def execwaitincontainer( self, desktop, command, timeout=1000):
        raise NotImplementedError(f"{type(self)}.removedesktop")

    @staticmethod
    def applyappinstancerules_homedir( authinfo, rules ):
        homedir_enabled = False # by default application do not share the user homedir
        # Check if there is a specify rules to start this application
        if isinstance(rules,dict):
            # Check if there is a homedir rule
            rule_homedir =  rules.get('homedir')
            if isinstance(rule_homedir,dict):
                # read the default rule first and them apply specific rules
                homedir_enabled = rule_homedir.get('default', False )
                # list user context tag 
                # check if user auth tag context exist
                for kn in rule_homedir.keys():
                    ka = None
                    for ka in authinfo.get_labels() :
                        if kn == ka :
                            if type(rule_homedir.get(kn)) is bool:
                                homedir_enabled = rule_homedir.get(kn)
                            break
                    if kn == ka :   # double break 
                        break

        return homedir_enabled

    @staticmethod
    def applyappinstancerules_network( authinfo, rules ):
        """[applyappinstancerules_network]
            return a dict network_config

        Args:
            authinfo ([type]): [description]
            rules ([type]): [description]

        Returns:
            [dict ]: [network config]
            network_config = {  'network_disabled' : network_disabled, 
                                'name': name, 
                                'dns': dns
                                'webhook' : webhook}
        """
        # set default context value 
        network_config = {  'network_disabled' :    False, 
                            'annotations':          None,
                            'name':                 None, 
                            'external_dns':         None,
                            'internal_dns':         None,
                            'webhook' :             None,
                            'websocketrouting' :    oc.od.settings.websocketrouting,
                            'websocketrouting_interface' :  None }
      

        # Check if there is a specify rules to start this application
        if type(rules) is dict  :
            # Check if there is a network rule
            rule_network =  rules.get('network')
            if type(rule_network) is dict:
                # read the default context first 
                rule_network_default = rule_network.get('default', True)
                if rule_network_default is False:
                    network_config[ 'network_disabled' ] = True
              
                if type(rule_network_default) is dict:
                    network_config.update( rule_network_default )
                
                # list user context tag 
                # check if user auth tag context exist
                for kn in rule_network.keys():
                    ka = None
                    for ka in authinfo.get_labels():
                        if kn == ka :
                            network_config.update ( rule_network.get(kn) )
                            break
                    if kn == ka :
                        break

        return network_config
    

    def createappinstance(self, myDesktop, app, authinfo, userinfo={}, userargs=None, **kwargs ):                    
        raise NotImplementedError(f"{type(self)}.createappinstance")

    def buildwebhookinstance( self, authinfo, userinfo, app, network_config, network_name=None, appinstance_id=None ):

        webhook = None

        # if context_network_webhook call request to webhook and replace all datas
        context_network_webhook = network_config.get('webhook')
        if isinstance( context_network_webhook, dict) : 
            webhook = {}
            # if create exist 
            webhookstartcmd = context_network_webhook.get('create')
            if isinstance( webhookstartcmd, str) :
                # build the webhook url 
                # fillwebhook return None if nothing to do
                webhookcmd = self.fillwebhook(  mustachecmd=webhookstartcmd, 
                                                app=app, 
                                                authinfo=authinfo, 
                                                userinfo=userinfo, 
                                                network_name=network_name, 
                                                containerid=appinstance_id )
                webhook['create'] = webhookcmd

            # if destroy exist 
            webhookstopcmd = context_network_webhook.get('destroy')
            if isinstance( webhookstopcmd, str) :
                # fillwebhook return None if nothing to do
                webhookcmd = self.fillwebhook(  mustachecmd=webhookstopcmd, 
                                                app=app, 
                                                authinfo=authinfo, 
                                                userinfo=userinfo, 
                                                network_name=network_name, 
                                                containerid=appinstance_id )
                webhook['destroy'] = webhookcmd
        return webhook

    def fillwebhook(self, mustachecmd, app, authinfo, userinfo, network_name, containerid ):
        if not isinstance(mustachecmd, str) :
            return None
        sourcedict = {}
        # merge all dict data from app, authinfo, userinfo, and containerip
        # if add is a ODDekstop use to_dict to convert ODDesktop to dict 
        # else app is a dict 
        # self.logger.debug( f"type of app is {type(app)}" )
        if isinstance( app, dict ) :
            sourcedict.update( app )
        elif isinstance(app, ODDesktop ):
            sourcedict.update( app.to_dict().copy() )
            # desktop_interface is a dict 
            # { 
            #   'eth0': {'mac': '56:c7:eb:dc:c0:b8', 'ips': '10.244.0.239'      }, 
            #   'net1': {'mac': '2a:94:43:e0:f4:46', 'ips': '192.168.9.137'     }, 
            #   'net2': {'mac': '1e:50:5f:b7:85:f6', 'ips': '161.105.208.143'   }
            # }
            # self.logger.debug( f"type(desktop_interfaces)={type(app.desktop_interfaces)}" )
            if isinstance(app.desktop_interfaces, dict ):
                self.logger.debug( f"desktop_interfaces is {app.desktop_interfaces}" )
                for interface in app.desktop_interfaces.keys():
                    self.logger.debug( f"{interface} is {app.desktop_interfaces.get(interface)}" )
                    ipAddr = app.desktop_interfaces.get(interface).get('ips')
                    self.logger.debug( f"{interface} has ip addr {ipAddr}" )
                    sourcedict.update( { interface: ipAddr } )

        # Complete with user data
        sourcedict.update( authinfo.todict() )
        sourcedict.update( userinfo )

        # merge all dict data from desktopwebhookdict, app, authinfo, userinfo, and containerip
        moustachedata = {}
        for k in sourcedict.keys():
            if isinstance(sourcedict[k], str):
                if oc.od.settings.desktop['webhookencodeparams'] is True:
                    moustachedata[k] = requests.utils.quote(sourcedict[k])
                else: 
                    moustachedata[k] = sourcedict[k]

        moustachedata.update( oc.od.settings.desktop['webhookdict'] )
        self.logger.debug( f"moustachedata={moustachedata}" )
        webhookcmd = chevron.render( mustachecmd, moustachedata )
        return webhookcmd

    def logs( self, authinfo, userinfo ):
        raise NotImplementedError(f"{type(self)}.logs")

    def isgarbagable( self, container, expirein, force=False ):
        raise NotImplementedError(f"{type(self)}.isgarbagable")

@oc.logging.with_logger()
class ODOrchestratorKubernetes(ODOrchestrator):

    _shared_kubeapi = None
    _shared_kubeapi_sync = None

    def __init__(self):
        super().__init__()

        # define two king of application:
        # - ephemeral container
        # - pod
        self.appinstance_classes = {    
            'ephemeral_container': ODAppInstanceKubernetesEphemeralContainer,
            'pod_application': ODAppInstanceKubernetesPod 
        }
        self.all_phases_status = [ 'Running', 'Terminated', 'Waiting', 'Completed', 'Succeeded']
        self.all_running_phases_status = [ 'Running', 'Waiting' ]
        self.all_waiting_phases_status = [ 'Waiting' ]

        # self.appinstance_classes = appinstance_classes_dict.
        # Configs can be set in Configuration class directly or using helper
        # utility. If no argument provided, the config will be loaded from
        # default location.
    
        #check if we are inside a cluster or not
        # https://kubernetes.io/docs/concepts/services-networking/connect-applications-service/#environment-variables
        # Example
        #   KUBERNETES_SERVICE_HOST=10.0.0.1
        #   KUBERNETES_SERVICE_PORT=443
        #   KUBERNETES_SERVICE_PORT_HTTPS=443
        #
        # if os.getenv('KUBERNETES_SERVICE_HOST') and os.getenv('KUBERNETES_SERVICE_PORT') :
        #     # self.logger.debug( 'env has detected $KUBERNETES_SERVICE_HOST and $KUBERNETES_SERVICE_PORT' )
        #    # self.logger.debug( 'config.load_incluster_config start')
        #    config.load_incluster_config() # set up the client from within a k8s pod
        #    # self.logger.debug( 'config.load_incluster_config kubernetes mode done')
        #else:
        #    # self.logger.debug( 'config.load_kube_config not in cluster mode')
        #    config.load_kube_config()
        #    # self.logger.debug( 'config.load_kube_config done')
        
        # Load kubernetes-asyncio config
        # load_incluster_config is sync, load_kube_config is async
        try:
            config.load_incluster_config()  # sync call
            self.logger.debug("kubernetes_asyncio load_incluster_config done")
        except Exception as e_in:
            # Fallback: load_kube_config is async - run it in a fresh thread (no running loop there)
            _exc = []
            def _load_kube():
                try:
                    asyncio.run(config.load_kube_config())
                except Exception as e:
                    _exc.append(e)
            _t = threading.Thread(target=_load_kube)
            _t.start()
            _t.join()
            if not _exc:
                _k8s_asyncio_configured = True
                self.logger.debug("kubernetes_asyncio load_kube_config done")
            else:
                self.logger.error(f"kubernetes_asyncio load_incluster_config failed: {e_in}")
                self.logger.error(f"kubernetes_asyncio load_kube_config failed: {_exc[0]}")

        # Chargement de la configuration kubernetes (sync) uniquement pour l'exec streaming
        try:
            _k8s_sync.config.load_incluster_config()
        except Exception:
            try:
                _k8s_sync.config.load_kube_config()
            except Exception:
                pass

        self.name = 'kubernetes'
        # self._kubeapi = None  # lazy init : créé au premier appel dans un contexte async
        # self._shared_kubeapi_sync = None  # lazy init : créé au premier appel dans un contexte sync
        self.namespace = oc.od.settings.namespace
        self.bConfigure = True

    @property
    def kubeapi(self):
        """Lazy init : CoreV1Api est créé au premier accès, toujours dans un contexte async (event loop uvicorn actif)."""
        if ODOrchestratorKubernetes._shared_kubeapi is None:
            ODOrchestratorKubernetes._shared_kubeapi = client.CoreV1Api()
        return ODOrchestratorKubernetes._shared_kubeapi

    @property
    def kubeapi_sync(self):
        if ODOrchestratorKubernetes._shared_kubeapi_sync is None:
            ODOrchestratorKubernetes._shared_kubeapi_sync = _k8s_sync.client.CoreV1Api()
        return ODOrchestratorKubernetes._shared_kubeapi_sync

    async def _async_load_k8s_config(self):
        """Charge la configuration kubernetes-asyncio de manière asynchrone."""
        try:
            await config.load_incluster_config()
            self.logger.debug("load_incluster_config done")
        except Exception as e_in:
            try:
                await config.load_kube_config()
                self.logger.debug("load_kube_config done")
            except Exception as e_out:
                self.logger.error("This is a fatal error")
                self.logger.error(f"load_incluster_config failed {e_in}")
                self.logger.error(f"load_kube_config failed {e_out}")

    def __del__(self):
        # self.close())
        self.logger.debug( 'deleting ODOrchestratorKubernetes')

    async def close(self):
        self.logger.debug( 'call kubeapi close')
        # if isinstance( self._kubeapi, CoreV1Api):
        #    await self._kubeapi.api_client.close()
        # self._kubeapi = None
        # if isinstance( self.kubeapi_sync, CoreV1Api):
        # self.kubeapi_sync.api_client.close()
        # self.kubeapi_sync = None
        

    def is_configured(self)->bool: 
        """[is_configured]
            return True if kubernetes is configured 
            call list_node() API  
        Returns:
            [bool]: [True if kubernetes is configured, else False]
        """
        return self.bConfigure
        
    async def is_list_node_enabled(self)->bool: 
        """[is_list_node_enabled]
            return True if kubernetes is configured and can call list_node() API  
        Returns:
            [bool]: [True if kubernetes is configured, else False]
        """
        bReturn = False
        try:
            if self.bConfigure :
                # run a dummy node list to check if kube is working
                node_list = await self.kubeapi.list_node()
                if isinstance( node_list, V1NodeList) and len(node_list.items) > 0:
                    bReturn = True
        except Exception as e:
            self.logger.warning( e )
        return bReturn


    async def listEndpointAddresses( self, endpoint_name:str )->tuple:
        """listEndpointAddresses

        Args:
            endpoint_name (str): name of the endpoint

        Returns:
            tuple: (int, [ str ]) (port, list of address)
            port: can be None or int
            list of address: can be None or list of str 
        """
        list_endpoint_addresses = None
        list_endpoint_port = None
        endpoint = await self.kubeapi.read_namespaced_endpoints( name=endpoint_name, namespace=self.namespace )
        if isinstance( endpoint, V1Endpoints ):
            if not isinstance( endpoint.subsets, list) or len(endpoint.subsets) == 0:
                return (list_endpoint_port, list_endpoint_addresses) # (None, None)

            endpoint_subset = endpoint.subsets[0]
            if isinstance( endpoint_subset, V1EndpointSubset ) :
                list_endpoint_addresses = []
                # read the uniqu port number
                # pyos listen on only one tcp port
                endpoint_port = endpoint_subset.ports[0]
                if isinstance( endpoint_port, CoreV1EndpointPort ):
                    list_endpoint_port = endpoint_port.port

                # read add addreses
                if not isinstance( endpoint_subset.addresses , list ):
                    self.logger.error('read_namespaced_endpoints no entry addresses found')
                else:
                    for address in endpoint_subset.addresses :
                        if isinstance( address, V1EndpointAddress):
                            list_endpoint_addresses.append( address.ip )

        return (list_endpoint_port, list_endpoint_addresses)

    async def get_podname( self, authinfo:AuthInfo, userinfo:AuthUser, pod_sufix:str )->str:
        """[get_podname]
            return a pod name from authinfo, userinfo and uuid 
        Args:
            authinfo (AuthInfo): authentification data
            userinfo (AuthUser): user data 
            pod_sufix ([str]): [uniqu sufix]

        Returns:
            [str]: [name of the user pod]
        """
        posixuser = await self.alwaysgetPosixAccountUser( authinfo, userinfo )
        podname = posixuser.get('uid') + self.containernameseparator + pod_sufix
        return oc.auth.namedlib.normalize_name_dnsname( podname )[0:252]
 
    def get_labelvalue( self, label_value:str)->str:
        """[get_labelvalue]

        Args:
            label_value ([str]): [label_value name]

        Returns:
            [str]: [return normalized label name]
        """
        if label_value is None:
            return label_value
        if not isinstance(label_value, str):
            label_value = json.stringify(label_value)
            # self.logger.error( f"get_labelvalue invalid type {type(label_value)} for label value {label_value}" )
            # return None
        no_accent_normalize_data = oc.lib.remove_accents( label_value )
        normalize_data = oc.auth.namedlib.normalize_label( no_accent_normalize_data )
        return normalize_data


    async def commit_config( self, configmap_name:str, config:dict)->dict:
        """commit_config

        Args:
            config (dict): config dict to commit

        Returns:
            dict: config dict commited
        """
        self.logger.debug('')
        assert isinstance(configmap_name, str),  f"configmap_name has invalid type {type(configmap_name)}"
        assert isinstance(config, dict),  f"config has invalid type {type(config)}"
        # write config to kubernetes configmap
        # use the same name as the namespace
        try:
            # read the configmap if exist
            myconfigmap = await self.kubeapi.read_namespaced_config_map( name=configmap_name, namespace=self.namespace )
            if isinstance(myconfigmap, V1ConfigMap):
                # update the configmap with new data
                myconfigmap.data = config
                myconfigmap.metadata.resource_version = myconfigmap.metadata.resource_version
                updated_configmap = await self.kubeapi.replace_namespaced_config_map( name=configmap_name, namespace=self.namespace, body=myconfigmap )
                return updated_configmap.data
        except ApiException as e:
            if e.status == 404:
                # create a new configmap if not exist
                new_configmap = V1ConfigMap(
                    metadata=V1ObjectMeta(name=configmap_name),
                    data=config
                )
                created_configmap = await self.kubeapi.create_namespaced_config_map( namespace=self.namespace, body=new_configmap )
                return created_configmap.data
            else:
                self.logger.error(e)
                raise e


    async def rollout_deployment( self, deployment_name:str, timeout:int=60)->dict|bool:
        """rollout_deployment

        Args:
            deployment_name (str): name of the deployment
            timeout (int, optional): timeout in seconds. Defaults to 30.

        Returns:
            bool: True if rollout is successful, False otherwise
        """
        self.logger.debug('')
        assert isinstance(deployment_name, str),  f"deployment_name has invalid type {type(deployment_name)}"
        assert isinstance(timeout, int),  f"timeout has invalid type {type(timeout)}"

        try:
            appsV1Api = client.AppsV1Api()

            # Get the current deployment
            deployment = await appsV1Api.read_namespaced_deployment(name=deployment_name, namespace=self.namespace)
            if not isinstance(deployment, V1Deployment):
                self.logger.error(f"Deployment {deployment_name} not found in namespace {self.namespace}")
                return False

            now = datetime.datetime.utcnow()
            now = str(now.isoformat("T") + "Z")
            body = {
                'spec': {
                    'template':{
                        'metadata': {
                            'annotations': {
                                'kubectl.kubernetes.io/restartedAt': now
                            }
                        }
                    }
                }
            }

            # Rollout the deployment
            patched = await appsV1Api.patch_namespaced_deployment(name=deployment_name, namespace=self.namespace, body=body)
            return patched.status.to_dict()
           
        except Exception as a:
            self.logger.error(f"Error during rollout of deployment {deployment_name}: {a}")
            return False

    async def logs( self, authinfo:AuthInfo, userinfo:AuthUser )->str:
        """logs

        Args:
            authinfo (AuthInfo): AuthInfo
            userinfo (AuthUser): AuthUser

        Returns:
            str: str log content
            return '' empty str by default ( if not found of error ) 
        """
        self.logger.debug('')
        assert isinstance(authinfo, AuthInfo),  f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo, AuthUser),  f"userinfo has invalid type {type(userinfo)}"

        strlogs = ''
        myPod = self.findPodByUser(authinfo, userinfo)
        if isinstance(myPod, V1Pod):
            try:
                myDesktop = self.pod2desktop_reduced( pod=myPod )
                pod_name = myPod.metadata.name  
                container_name = myDesktop.container_name
                strlogs = await self.kubeapi.read_namespaced_pod_log( name=pod_name, namespace=self.namespace, container=container_name, pretty='true' )
            except ApiException as e:
                self.logger.error(e)
        else:
            self.logger.debug( f"No pod found for user {userinfo.userid}" )
        return strlogs

    async def build_volumes_secrets( self, authinfo:AuthInfo, userinfo:AuthUser, volume_type:str, secrets_requirement:list, rules={}, **kwargs:dict)->dict:
        self.logger.debug('')
        assert isinstance(authinfo, AuthInfo),  f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo, AuthUser),  f"userinfo has invalid type {type(userinfo)}"

        volumes = {}        # set empty dict of V1Volume dict by default
        volumes_mount = {}  # set empty dict of V1VolumeMount by default
        #
        # mount secret in /var/secrets/abcdesktop
        # abcdesktop is the default namespace
        # mount secret in /var/secrets/$NAMESPACE
        #
        if not isinstance( secrets_requirement, list ):
            self.logger.debug( f"skipping secrets_requirement={secrets_requirement} type={type(secrets_requirement)}, no secret to mount" ) 
        else:
            self.logger.debug( f"secrets_requirement is {secrets_requirement}" ) 
            # for access_type in ['auth', 'ldif']:
            for access_type in ['auth']:
                self.logger.debug( f"listing list_dict_secret_data access_type='{access_type}'" )
                mysecretdict = await self.list_dict_secret_data( authinfo, userinfo, access_type=access_type )
            
                if isinstance( mysecretdict, dict):
                    # read all entries in dict
                    # like for access_type=auth
                    # {'auth-ntlm-fry': {'type': 'abcdesktop/ntlm', 'data': {...}}}
                    # like for access_type=ldif
                    # {'auth-ldif-alex': {'type': 'abcdesktop/ldif', 'data': {...}}}
                    #
                    self.logger.debug(f"list of secret is {mysecretdict.keys()}")
                    for secret_name in mysecretdict.keys():
                        # https://kubernetes.io/docs/concepts/configuration/secret
                        # create an entry eq: 
                        #
                        # /var/secrets/abcdesktop/ntlm
                        # /var/secrets/abcdesktop/kerberos
                        #  
                        self.logger.debug(f"checking {secret_name} access_type='{access_type}'")

                        if not isinstance(mysecretdict[secret_name], dict):
                            self.logger.error(f"skipping secret {secret_name} is not a dict")
                            continue

                        # only mount secrets_requirement
                        if 'all' not in secrets_requirement:
                            if mysecretdict[secret_name]['type'] not in secrets_requirement:
                                self.logger.debug(f"skipping {mysecretdict[secret_name]['type']} not in {secrets_requirement}")
                                continue

                        self.logger.debug( f"adding secret type {mysecretdict[secret_name]['type']} to volume pod" )
                        secretmountPath = oc.od.settings.desktop['secretsrootdirectory'] + mysecretdict[secret_name]['type'] 

                        normalizevolume_name = oc.auth.namedlib.normalize_name_volunename( secret_name )
                        # mode is 644 -> rw-r--r--
                        # Owing to JSON limitations, you must specify the mode in decimal notation.
                        # 644 in decimal equal to 420
                        volumes[normalizevolume_name] = {
                            'name':normalizevolume_name,
                            'secret': {
                                'secretName': secret_name,
                                'defaultMode': 420
                            }
                        }
                        volumes_mount[normalizevolume_name] = {
                            'name':normalizevolume_name,
                            'mountPath':secretmountPath
                        }

        return (volumes, volumes_mount)

    async def build_volumes_additional_for_flexvolume( self, authinfo:AuthInfo, userinfo:AuthUser, volume_type, secrets_requirement, mountvol, **kwargs):

        self.logger.debug('')
        assert isinstance(authinfo, AuthInfo),  f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo, AuthUser),  f"userinfo has invalid type {type(userinfo)}"

        volumes = {}        # set empty volume dict by default
        volumes_mount = {}  # set empty volume_mount dict by default
        
        fstype = mountvol.fstype
        volume_name = self.get_volumename( mountvol.name, userinfo )

        secret = oc.od.secret.selectSecret( self.namespace, self.kubeapi, prefix=mountvol.name, secret_type=fstype )
        if isinstance( secret, oc.od.secret.ODSecret):
            driver_type =  self.namespace + '/' + fstype
        
            # read the container mount point from the secret
            # for example /home/balloon/U             
            # Read data from secret    
            secret_name         = secret.get_name( authinfo, userinfo )
            secret_dict_data    = await secret.read_alldata( authinfo, userinfo )
            if not isinstance( secret_dict_data, dict ):
                # skipping bad values
                self.logger.error( f"Invalid value read from secret={secret_name} type={type(secret_dict_data)}" )
                return ( None, None )
            
            volmountsecretedata = secret_dict_data.get('data')
            if not isinstance( volmountsecretedata, dict ):
                # skipping bad values
                self.logger.error( f"Invalid value read from secret={secret_name}['data'] expecting type=dict gets type={type(volmountsecretedata)}" )
                return ( None, None )
            
            mountPath           = volmountsecretedata.get( 'mountPath')
            networkPath         = volmountsecretedata.get( 'networkPath' )
            
            # Check if the secret contains valid datas 
            if not isinstance( mountPath, str) :
                # skipping bad values
                self.logger.error( f"Invalid value for mountPath read from secret={secret_name} type={type(mountPath)}" )
                return ( None, None )

            if not isinstance( networkPath, str) :
                # skipping bad values
                self.logger.error( f"Invalid value for networkPath read from secret={secret_name}  type={type(networkPath)}" )
                return ( None, None )

            volumes_mount[mountvol.name] = {'name': volume_name, 'mountPath': mountPath }     
            posixaccount = await self.alwaysgetPosixAccountUser( authinfo, userinfo )
            # Default mount options
            mountOptions = f"uid={posixaccount.get('uidNumber')},gid={posixaccount.get('gidNumber')}"
            # concat mountOptions for the volume if exists 
            if mountvol.has_options():
                mountOptions += f",{mountvol.mountOptions}"

            # dump for debug
            self.logger.debug( f"flexvolume: {mountvol.name} set option {mountOptions}" )
            self.logger.debug( f"flexvolume: read secret {secret_name} to mount {networkPath}")
            # add dict volumes entry mountvol.name
            volumes[mountvol.name] = {  
                'name': volume_name,
                'flexVolume' : {
                    'driver': driver_type,
                    'fsType': fstype,
                    'secretRef' : { 'name': secret_name },
                    'options'   : { 'networkPath':  networkPath, 'mountOptions': mountOptions }
                }
            }
            # dump for debug
            self.logger.debug( f"volumes {mountvol.name} use volume {volumes[mountvol.name]} and volume mount {volumes_mount[mountvol.name]}")
        
        return (volumes, volumes_mount)
    
    async def build_volumes_additional_by_rules( self, authinfo:AuthInfo, userinfo:AuthUser, queue: asyncio.Queue=None, volume_type=None, secrets_requirement=None, rules={}, **kwargs):
        self.logger.debug('')
        assert isinstance(authinfo, AuthInfo),  f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo, AuthUser),  f"userinfo has invalid type {type(userinfo)}"

        volumes = {}        # set empty volume dict by default
        volumes_mount = {}  # set empty volume_mount dict by default
        if isinstance( rules, dict ):
            self.logger.debug( f"selected volume by rules {rules}" )
            mountvols = oc.od.volume.selectODVolumebyRules( authinfo, userinfo, rules=rules.get('volumes') )
            for mountvol in mountvols:
                fstype = mountvol.fstype
                volume_name = self.get_volumename( mountvol.name, userinfo )
                self.logger.debug( f"selected volume fstype:{fstype} volumes name:{volume_name}")

                if fstype=='nfs':
                    volumes_mount[mountvol.name] = {
                        'name': volume_name, 
                        'mountPath': mountvol.mountPath
                    }
                    volumes[mountvol.name] = {  
                        'name': volume_name,
                        'nfs' : {
                            'server': mountvol.server,
                            'path': mountvol.path,
                            'readOnly': mountvol.readOnly
                        }
                    }
                    continue

                if fstype=='hostpath':
                    volumes_mount[mountvol.name] = {
                        'name': volume_name, 
                        'mountPath': mountvol.mountPath,
                        'mountPropagation': mountvol.mountPropagation
                    }
                    volumes[mountvol.name] = {  
                        'name': volume_name,
                        'hostPath' : {
                            'path': mountvol.path,
                            'readOnly': mountvol.readOnly,
                            'type': mountvol.hostPathType
                        }
                    }
                    continue

                if fstype=='pvc':
                    claimName = mountvol.claimName
                    if isinstance(claimName, str):
                        volumes_mount[mountvol.name] = {
                            'name': volume_name, 
                            'mountPath': mountvol.mountPath,
                            'mountPropagation': mountvol.mountPropagation
                        }
                        volumes[mountvol.name] = { 
                            'name': volume_name, 
                            'persistentVolumeClaim': { 'claimName': mountvol.claimName } 
                        }
                    continue     
                   
                if fstype=='cifs': # this is a flexvolume
                    (flex_volumes, flex_volumes_mount) = await self.build_volumes_additional_for_flexvolume( 
                        authinfo=authinfo, 
                        userinfo=userinfo,
                        volume_type=volume_type, 
                        secrets_requirement=secrets_requirement, 
                        mountvol=mountvol, 
                        kwargs=kwargs)
                    if isinstance(flex_volumes, dict) and isinstance(flex_volumes_mount, dict):
                        volumes.update( flex_volumes )
                        volumes_mount.update( flex_volumes_mount )

                if fstype=='csi': # this is a csi 
                    pass

        return (volumes, volumes_mount)

    async def get_user_homedirectory(self, authinfo:AuthInfo, userinfo:AuthUser )->str:
        self.logger.debug('')
        assert_type(authinfo, AuthInfo)
        assert_type(userinfo, AuthUser)
        localaccount = oc.od.secret.ODSecretLocalAccount( namespace=self.namespace, kubeapi=self.kubeapi )
        localaccount_secret = await localaccount.read( authinfo,userinfo )
        homeDirectory = oc.od.secret.ODSecretLocalAccount.read_data( localaccount_secret, 'homeDirectory' )
        if not isinstance( homeDirectory, str ):
            homeDirectory = oc.od.settings.getballoon_homedirectory( userinfo.userid )
        return homeDirectory

    async def get_mixedataforchevron(self, authinfo:AuthInfo, userinfo:AuthUser )->dict:
        assert_type(authinfo, AuthInfo)
        assert_type(userinfo, AuthUser)
        mixedata = await self.alwaysgetPosixAccountUser( authinfo, userinfo )
        mixedata.update( authinfo.todict() )
        mixedata.update( authinfo.get_labels())
        mixedata.update( userinfo )
        mixedata['provider']=authinfo.provider.lower()
        mixedata['uuid']=oc.lib.uuid_digits()
        return mixedata

    async def build_volumes_home( self, authinfo:AuthInfo, userinfo:AuthUser, queue: asyncio.Queue, volume_type:str, secrets_requirement, rules={}, **kwargs):
        self.logger.debug('')
        assert isinstance(authinfo, AuthInfo),  f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo, AuthUser),  f"userinfo has invalid type {type(userinfo)}"
        volumes = {}        # set empty volume dict by default
        volumes_mount = {}  # set empty volume_mount dict by default
        volume_home_name = 'home'
        # homedirectorytype is by default None 
        homedirectorytype = oc.od.settings.desktop['homedirectorytype']
        self.logger.debug(f"homedirectorytype is {homedirectorytype} and volume_type is {volume_type}")
        subpath_name = oc.auth.namedlib.normalize_name( userinfo.userid )
        self.logger.debug(f"subpath_name is {subpath_name}")
        user_homedirectory = os.path.join(  await self.get_user_homedirectory(authinfo, userinfo), 
                                            oc.od.settings.desktop.get('appendpathtomounthomevolume','') )
        user_homedirectory = os.path.normpath( user_homedirectory )
        self.logger.debug( f"user_homedirectory mounts home volume to {user_homedirectory}" )
            
        # set default value 
        # home is emptyDir
        # cache is emptyDir Memory
        volumes['home']         = { 'name': volume_home_name, 'emptyDir': {} }
        volumes_mount['home']   = { 'name': volume_home_name, 'mountPath': user_homedirectory }

        for directorytomemoryemptydir in oc.od.settings.desktop['directorytomemoryemptydir']:
            directorytomemoryemptydir_user_homedirectory = os.path.join( await self.get_user_homedirectory(authinfo, userinfo), directorytomemoryemptydir )
            self.logger.debug( f"map {directorytomemoryemptydir_user_homedirectory} to emptyDir medium Memory" )
            volume_name = oc.auth.namedlib.normalize_name( directorytomemoryemptydir )
            volumes[volume_name]       = { 'name': volume_name,  **oc.od.settings.desktop['directorytomemory']  }
            volumes_mount[volume_name] = { 'name': volume_name,  'mountPath': directorytomemoryemptydir_user_homedirectory }
            if volume_type in ['pod_application']:
                self.logger.debug( f"warning {volume_type} maps {directorytomemoryemptydir_user_homedirectory} to emptyDir medium Memory" )
                self.logger.debug( f"warning {directorytomemoryemptydir} does not share data" )

        # now ovewrite home values
        if homedirectorytype == 'persistentVolumeClaim':
            self.logger.debug( f"use homedirectorytype persistentVolumeClaim" ) 
            claimName = None # None is the default value, nothing to do
            # self.logger.debug( f"type of oc.od.settings.desktop['persistentvolumeclaim'] is {type(oc.od.settings.desktop['persistentvolumeclaim'])}" )
            if isinstance( oc.od.settings.desktop['persistentvolumeclaim'], str):
                # oc.od.settings.desktop['persistentvolumeclaim'] is the name of the PVC
                # in this case, there is only one shared PVC for all users
                # and it must already exists 
                if volume_type in [ 'pod_desktop', 'pod_application' ] :
                    claimName = oc.od.settings.desktop['persistentvolumeclaim']

            elif isinstance( oc.od.settings.desktop['persistentvolumeclaim'], dict):
                # oc.od.settings.desktop['persistentvolumeclaim'] must be created by pyos
                self.logger.debug( f"build home volume with volume_type={volume_type} and persistentvolumeclaim is a dict" )
                if volume_type in [ 'pod_desktop', 'pod_application' ] :
                    # create a pvc to store desktop volume
                    persistentvolume = copy.deepcopy( oc.od.settings.desktop['persistentvolume'] )
                    persistentvolumeclaim = copy.deepcopy( oc.od.settings.desktop['persistentvolumeclaim'] )
                    # use chevron mustache to replace template value in persistentvolume and persistentvolumeclaim
                    mixeddata = await self.get_mixedataforchevron( authinfo, userinfo )
                    self.updateChevronDictWithmixedData( persistentvolume, mixeddata=mixeddata)
                    self.updateChevronDictWithmixedData( persistentvolumeclaim, mixeddata=mixeddata)
                    self.logger.debug( f"persistentvolume={persistentvolume} persistentvolumeclaim={persistentvolumeclaim}" )
                    
                    # create the user's persistentVolumeClaim if not exist
                    odvol = oc.od.persistentvolumeclaim.ODPersistentVolumeClaim( self.namespace, self.kubeapi )
                    pvc = await odvol.create( 
                                    authinfo=authinfo,
                                    userinfo=userinfo, 
                                    persistentvolume_request=persistentvolume,
                                    persistentvolumeclaim_request=persistentvolumeclaim )
                    # wait for user's persistentVolumeClaim to bound 
                    if isinstance( pvc, V1PersistentVolumeClaim ):
                        claimName = pvc.metadata.name
                        (status,msg) = await odvol.waitforBoundPVC( name=claimName, queue=queue )
                        self.logger.debug( f"bound PersistentVolumeClaim {claimName} return {status} {msg}" )
                        if status is False:
                            self.logger.error( f"PersistentVolumeClaim {claimName} can NOT Bound, {msg}")
                            # we continue but this can be a fatal error
                    else:
                        self.logger.error( "can not create PersistentVolumeClaim" )
                        
                if volume_type in [ 'ephemeral_container']:
                    persistentvolumeclaim = copy.deepcopy( oc.od.settings.desktop['persistentvolumeclaim'] )
                    # use chevron mustache to replace template value in persistentvolumeclaim
                    mixeddata = await self.get_mixedataforchevron( authinfo, userinfo )
                    self.updateChevronDictWithmixedData( persistentvolumeclaim, mixeddata=mixeddata)
                    self.logger.debug( f"persistentvolumeclaim={persistentvolumeclaim}" )
                    odpvc = oc.od.persistentvolumeclaim.ODPersistentVolumeClaim(self.namespace, self.kubeapi)
                    pvc = await odpvc.find_pvc(authinfo, userinfo, persistentvolumeclaim )
                    assert isinstance(pvc, V1PersistentVolumeClaim ),  f"persistentvolumeclaim for {volume_type} is not found"
                    claimName = pvc.metadata.name
               
            # Map the home directory
            # volume_type is in [ 'ephemeral_container', 'pod_desktop', 'pod_application' ] :
            self.logger.debug( f"persistentVolumeClaim claimName={claimName}" )
            if isinstance(claimName, str):
                volumes['home'] = { 'name': volume_home_name, 'persistentVolumeClaim': { 'claimName': claimName } }
                volumes_mount['home'] = { 'name': volume_home_name, 'mountPath': user_homedirectory }
                if oc.od.settings.desktop['persistentvolumeclaimforcesubpath'] is True:
                    volumes_mount['home']['subPath'] = subpath_name
           
        elif homedirectorytype == 'hostPath' :
            # Map the home directory
            # mount_volume = '/mnt/abcdesktop/$USERNAME' on host
            # volume type is 'DirectoryOrCreate'
            # same as 'subPath' but use hostpath
            # 'subPath' is not supported for ephemeral container
            #
            # An empty directory will be created there as needed with permission set to 0755, 
            # having the same group and ownership with Kubelet.
            #
            mount_volume = oc.od.settings.desktop['hostPathRoot'] + '/' + subpath_name
            volumes['home'] = {
                'name':volume_home_name, 
                'hostPath': {
                    'path':mount_volume, 
                    'type':'DirectoryOrCreate'
                }  
            }
            volumes_mount['home'] = {
                'name':volume_home_name, 
                'mountPath':user_homedirectory
            }

        elif homedirectorytype == 'nfs' :
            nfs = copy.deepcopy( oc.od.settings.desktop['nfs'] )
            # use chevron mustache to replace template value in persistentvolumeclaim
            mixeddata = await self.get_mixedataforchevron( authinfo, userinfo )
            self.updateChevronDictWithmixedData( nfs, mixeddata=mixeddata)
            self.logger.debug( f"nfs={nfs}" )
            volumes['home'] = {
                'name':volume_home_name, 
                'nfs': nfs
            }
            volumes_mount['home'] = {
                'name':volume_home_name, 
                'mountPath':user_homedirectory
            }

        self.logger.debug( f"volumes_mount['home']: {volumes_mount.get('home')}" )
        self.logger.debug( f"volumes['home']: {volumes.get('home')}")
        self.logger.debug( f"volumes_mount['cache']: {volumes_mount.get('cache')}" )
        self.logger.debug( f"volumes['cache']: {volumes.get('cache')}")
        return (volumes, volumes_mount)


    async def build_volumes_vnc( self, authinfo:AuthInfo, userinfo:AuthUser, volume_type, secrets_requirement, rules={}, **kwargs):
        self.logger.debug('')
        assert isinstance(authinfo, AuthInfo),  f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo, AuthUser),  f"userinfo has invalid type {type(userinfo)}"
        volumes = {}        # set empty volume dict by default
        volumes_mount = {}  # set empty volume_mount dict by default
         # Add VNC password
        mysecretdict = await self.list_dict_secret_data( authinfo, userinfo, access_type='vnc' )
        # mysecretdict must be a dict
        assert isinstance(mysecretdict, dict),  f"mysecretdict has invalid type {type(mysecretdict)}"
        assert len(mysecretdict)>0,             f"mysecretdict has invalid len {len(mysecretdict)}"
        # the should only be one secret type vnc
        secret_auth_name = next(iter(mysecretdict)) # first entry of the dict
        # create an entry /var/secrets/abcdesktop/vnc
        secretmountPath = oc.od.settings.desktop['secretsrootdirectory'] + mysecretdict[secret_auth_name]['type']
        # mode is 644 -> rw-r--r--
        # Owing to JSON limitations, you must specify the mode in decimal notation.
        # 644 in decimal equal to 420
        secret_auth_normalizevolume_name = oc.auth.namedlib.normalize_name_volunename( secret_auth_name )
        volumes[secret_auth_normalizevolume_name] = {
            'name': secret_auth_normalizevolume_name,
            'secret': { 
                'secretName': secret_auth_name, 
                'defaultMode':420 }
        }
        volumes_mount[secret_auth_normalizevolume_name] = {
            'name':secret_auth_normalizevolume_name, 
            'mountPath': secretmountPath
        } 
        return (volumes, volumes_mount)


    async def get_volumes_localaccount_name( self, authinfo:AuthInfo, userinfo:AuthUser )->str:
        """get_volumes_localaccount_name

        Args:
            authinfo (AuthInfo): AuthInfo
            userinfo (AuthUser): AuthUser

        Returns:
            str: return the name of the localaccount volume same as secret 
            None if not found
        """
        self.logger.debug('')
        assert isinstance(authinfo, AuthInfo),  f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo, AuthUser),  f"userinfo has invalid type {type(userinfo)}"
        
        localaccount_name = None
        mysecretdict = await self.list_dict_secret_data( authinfo, userinfo, access_type='localaccount' )
        if isinstance(mysecretdict, dict ) and len(mysecretdict)>0:
            localaccount_name = list( mysecretdict.keys() )[0] # should be only one, get the first one
        return localaccount_name


    async def build_volumes_localaccount( self, authinfo:AuthInfo, userinfo:AuthUser ):
        self.logger.debug('')
        assert isinstance(authinfo, AuthInfo),  f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo, AuthUser),  f"userinfo has invalid type {type(userinfo)}"
        volumes = {}        # set empty volume dict by default
        volumes_mount = {}  # set empty volume_mount dict by default

        #
        # mount secret in directory desktop['secretslocalaccount'] eq: /etc/localaccount
        mysecretdict = await self.list_dict_secret_data( authinfo, userinfo, access_type='localaccount' )
        assert isinstance(mysecretdict, dict), f"no secret type access_type='localaccount' found for userid={userinfo.userid}"

        # there should be only one items
        localaccountsecretitems = mysecretdict.items()
        if len(localaccountsecretitems) != 1:
            self.logger.error( f"{userinfo.userid} localaccountsecretitems is invalid len, len=1 is expected gets, len={len(localaccountsecretitems)} {localaccountsecretitems}" )
            self.logger.debug( f"{userinfo.userid} abcdesktop secret has expired, found {len(localaccountsecretitems)} expecting 1" )
            raise Exception( f"Your secret has been deleted, found {len(localaccountsecretitems)}, please reload" )

        secret_auth_name = list(mysecretdict.keys())[0]
        assert isinstance(secret_auth_name,str), f"secret_auth_name is not a str {secret_auth_name}"
        self.logger.debug( f"adding secret type {mysecretdict[secret_auth_name]['type']}" )

        # mode is 644 -> rw-r--r--
        # Owing to JSON limitations, you must specify the mode in decimal notation.
        # 420 in decimal equal to 644 -> rw-r--r-- value for passwd and group
        # 640 in decimal equal to 416 -> rw-r----- value for shadow and gshadow   
        secretmountPath = oc.od.settings.desktop['secretslocalaccount']
        # secret_auth_localaccount_volume_name = oc.auth.namedlib.normalize_name_volunename( secret_auth_name )
        secret_auth_localaccount_volume_name = 'extrausers'
        volumes[secret_auth_localaccount_volume_name] = { 
            'name': secret_auth_localaccount_volume_name, 
            'secret': { 
                'secretName': secret_auth_name, 
                'items': [
                    { 'key': 'passwd', 'path': 'passwd',  'mode': 420 },
                    { 'key': 'group',  'path': 'group',   'mode': 420 },
                    { 'key': 'shadow', 'path': 'shadow',  'mode': 416 },
                    { 'key': 'gshadow','path': 'gshadow', 'mode': 416 }
                ]
            } 
        }
        volumes_mount[secret_auth_localaccount_volume_name] = { 
            'name': secret_auth_localaccount_volume_name, 
            'mountPath': secretmountPath 
        }

        return (volumes, volumes_mount)
    
        '''
        This section code does the same but with one volume per file in [ 'passwd', 'group', 'shadow', 'gshadow' ]
        It build for example with a sample pod 

            #
            # this yaml file overwrite passwd file into the container 
            #
            apiVersion: v1
            kind: Pod
            metadata:
            namespace: abcdesktop
            name: sample
            spec:
            containers:
            - name: sample
                image: busybox
                command: [ '/bin/sleep', '3600s' ]
                volumeMounts:
                - mountPath: "/etc/passwd"
                    subPath: passwd
                    name: localaccount
            volumes:
                - name: localaccount
                secret:
                    secretName: auth-localaccount-alex
                    items:
                    - key: passwd
                      path: passwd

        This section code doesn't work when we try to start an ephemeralContainer 
        because ephemeralContainers don't support subpath
        source https://github.com/kubernetes-client/python/blob/master/kubernetes/docs/V1EphemeralContainer.md
        The error code when you try to start an ephemeralContainer is 
        error "message":"Pod is invalid: spec.ephemeralContainers[0].volumeMounts[11].subPath
        "Forbidden: cannot be set for an Ephemeral Container"
 
        for filesecret in [ 'passwd', 'group', 'shadow', 'gshadow' ] :
            mountPath = f"/etc/{filesecret}"
            volumename = f"localaccount{filesecret}"
            volumes[ volumename ] = { 
                'name': volumename, 
                'secret': { 
                    'secretName': secret_auth_name,  
                    'items': [ {'key': filesecret, 'path': filesecret} ]
                }
            }
            volumes_mount[volumename] = { 
                'name': volumename, 
                'mountPath':  mountPath, 
                'subPath': filesecret
            }     

        We use a workaround by creating a symbolic links
        - /etc/passwd -> /etc/localaccount/passwd    
        - /etc/group -> /etc/localaccount/group
        - /etc/shadow -> /etc/localaccount.shadow/shadow
        - /etc/gshadow -> /etc/localaccount.shadow/gshadow
        '''

    def build_volumes_snapshot( self ):
        """[build_volumes_snapshot]
        """
        self.logger.debug('')
        
        volumes = {}        # set empty volume dict by default
        volumes_mount = {}  # set empty volume_mount dict by default
        snapshot_volume_name = 'snapshot'
        volumes[snapshot_volume_name] = { 
            'name': snapshot_volume_name,
            'hostPath': {
                'path': oc.od.settings.snapshot_mountpath,
                'type': oc.od.settings.snapshot_mounttype
            }
        }
        volumes_mount[snapshot_volume_name] = {
            'name': snapshot_volume_name, 
            'mountPath': oc.od.settings.snapshot_mountpath 
        }
        return (volumes, volumes_mount)



    async def build_volumes( self, authinfo:AuthInfo, userinfo:AuthUser, queue: asyncio.Queue=None, volume_type=None, secrets_requirement=None, rules={}, **kwargs):
        """[build_volumes]

        Args:
            authinfo ([type]): [description]
            userinfo (AuthUser): user data
            volume_type ([str]): 'pod_desktop', 'pod_application', 'ephemeral_container'
            rules (dict, optional): [description]. Defaults to {}.

        Returns:
            [type]: [description]
        """
        volumes = {}        # set empty volume dict by default
        volumes_mount = {}  # set empty volume_mount dict by default

        #
        # mount init localaccount volume
        #
        (init_localaccount_volumes, init_localaccount_volumes_mount) = await self.build_volumes_localaccount(authinfo, userinfo )
        volumes.update(init_localaccount_volumes)
        volumes_mount.update(init_localaccount_volumes_mount)

        #
        # mount home volume
        #
        (home_volumes, home_volumes_mount) = await self.build_volumes_home(authinfo, userinfo, queue, volume_type, secrets_requirement, rules, **kwargs)
        volumes.update(home_volumes)
        volumes_mount.update(home_volumes_mount)

        #
        # Set localtime to server time
        #
        if oc.od.settings.desktop['uselocaltime'] is True:
            volumes['localtime'] = { 'name': 'localtime', 'hostPath': { 'path': '/etc/localtime' } }
            volumes_mount['localtime'] = { 'name': 'localtime', 'mountPath' : '/etc/localtime' }

        #
        # volume shared between all container inside the desktop pod
        #
        if volume_type in [ 'pod_desktop', 'pod_application', 'ephemeral_container' ] :
            for vol_name in oc.od.settings.desktop_pod.get('graphical', {}).get('volumes', []):
                if isinstance( oc.od.settings.desktop_pod.get('default_volumes').get(vol_name), dict) and \
                   isinstance( oc.od.settings.desktop_pod.get('default_volumes_mount').get(vol_name), dict ):        
                    volumes[vol_name] = oc.od.settings.desktop_pod.get('default_volumes').get(vol_name)
                    volumes_mount[vol_name] = oc.od.settings.desktop_pod.get('default_volumes_mount').get(vol_name)

        #
        # mount vnc secret in /var/secrets/abcdesktop
        # always add vnc secret for the grapical container only type pod_desktop
        # add vnc only for desktop_pod because application_pod and ephemeral_container don't need vnc access
        if volume_type == 'pod_desktop' :
            (vnc_volumes, vnc_volumes_mount) = \
                await self.build_volumes_vnc(authinfo, userinfo, volume_type, secrets_requirement, rules, **kwargs)
            volumes.update(vnc_volumes)
            volumes_mount.update(vnc_volumes_mount)

        #
        # mount other secrets in /var/secrets/abcdesktop
        #
        (secret_volumes, secret_volumes_mount) = \
            await self.build_volumes_secrets(authinfo, userinfo, volume_type, secrets_requirement, rules, **kwargs)
        volumes.update(secret_volumes)
        volumes_mount.update(secret_volumes_mount)

        #
        # mount voulumes from rules
        #
        (rules_volumes, rules_volumes_mount) = \
            await self.build_volumes_additional_by_rules(authinfo, userinfo, volume_type, secrets_requirement, rules, **kwargs)
        volumes.update(rules_volumes)
        volumes_mount.update(rules_volumes_mount)
        self.logger.debug('volumes end')        
        return (volumes, volumes_mount)


    def _execwaitincontainer( self, pod_name:str, container_name:str, command:list, call_result:dict=None, key:str=None, timeout:int=5):
        """execwaitincontainer
            execwaitincontainer execute command in desktop
        Args:
            desktop (ODDesktop): desktop
            command (list): list of string commands
            timeout (int, optional): timeout. Defaults to 5.

        Returns:
            dict: { 'ExitCode': int, 'stdout': None } 
            default { 'ExitCode': -1, 'stdout': None } 
        """
        result = { 'ExitCode': -1, 'stdout': None } # default value 
        #
        # calling exec and wait for response.
        # read https://github.com/kubernetes-client/python/blob/master/examples/pod_exec.py
        # for more example
        #   
        try:            
            # self.logger.debug( f"_execwaitincontainer pod_name={pod_name} container_name={container_name} command={command} timeout={timeout}" )
            resp = _k8s_sync_stream(  self.kubeapi_sync.connect_get_namespaced_pod_exec, 
                            name=pod_name, 
                            namespace=self.namespace, 
                            command=command,                                                                
                            container=container_name,
                            stderr=True, stdin=False,
                            stdout=True, tty=False,
                            _preload_content=False, #  need a client object websocket           
            )
            resp.run_forever(timeout) # timeout in seconds
            err = resp.read_channel(ERROR_CHANNEL, timeout=timeout)
            respdict = yaml.safe_load(err)        
            result['stdout'] = resp.read_stdout()
            # should be like:
            # {"metadata":{},"status":"Success"}
            if isinstance(respdict, dict):
                # status = Success or ExitCode = ExitCode
                exit_code = respdict.get('ExitCode')
                if isinstance( exit_code, int):
                    result['ExitCode'] = exit_code
                else:
                    if respdict.get('status') == 'Success':
                        result['ExitCode'] = 0

        except Exception as e:
            self.logger.error( f"command exec failed {e}") 

        if isinstance(key, str) and isinstance(call_result, dict):
            call_result[key] = result
            self.logger.debug( f"call_result[{key}]={call_result[key]}" ) 

        return result
        
    async def execwaitincontainer( self, desktop:ODDesktop, command:list, timeout:int=5)->dict:
        assert isinstance(desktop, ODDesktop), f"desktop is not a ODDesktop {type(desktop)}"
        result = await asyncio.to_thread(
            self._execwaitincontainer,
            pod_name=desktop.name,
            container_name=desktop.container_name,
            command=command,
            timeout=timeout
        )
        return result

    async def get_container_resources_usage( self, authinfo:AuthInfo, userinfo:AuthUser, container_name:str ) -> dict:
        ephemeralcontainerappinstance = ODAppInstanceKubernetesEphemeralContainer( self )
        return await ephemeralcontainerappinstance.get_resources_usage( authinfo, userinfo, container_name )
       
    
    async def get_pod_resources_usage( self, authinfo:AuthInfo, userinfo:AuthUser, pod_name:str ) -> dict:
        podappinstance = ODAppInstanceKubernetesPod( self )
        return await podappinstance.get_resources_usage( authinfo, userinfo, pod_name )

    async def getdesktop_resources_usage( self, authinfo:AuthInfo, userinfo:AuthUser ) -> dict:
        """
        getdesktop_resources_usage
            get the resources usage of the desktop pod
        Args:
            authinfo (AuthInfo): authinfo
            userinfo (AuthUser): userinfo
        
        """
        resources_usage = { 'timestamp': time.time() }
        myPod = await self.findPodByUser(authinfo, userinfo )
        if isinstance(myPod, V1Pod ):
            # read the graphical container name
            container = self.getcontainerfromPod( self.graphicalcontainernameprefix, myPod ) 
            if isinstance( container, V1ContainerStatus):
                # create an app instance 
                appinstance = ODAppInstanceBase( self )
                # read resources of the container name 
                resources_usage = await appinstance.get_resources_usage( myPod, container.name )

        return resources_usage

    async def removePod( self, myPod:V1Pod, propagation_policy:str='Foreground', grace_period_seconds:int=None) -> V1Pod:
        """_summary_
            Remove a pod
            like command 'kubectl delete pods'
        Args:
            myPod (V1Pod): V1Pod
            propagation_policy (str, optional): propagation_policy. Defaults to 'Foreground'.
            # https://kubernetes.io/docs/concepts/architecture/garbage-collection/
            # propagation_policy = 'Background'
            # propagation_policy = 'Foreground'
            # Foreground: Children are deleted before the parent (post-order)
            # Background: Parent is deleted before the children (pre-order)
            # Orphan: Owner references are ignored
            # delete_options = client.V1DeleteOptions( propagation_policy = propagation_policy, grace_period_seconds = grace_period_seconds )

        Returns:
            v1status: v1status
        """
        self.logger.debug('')
        assert isinstance(myPod, V1Pod), f"myPod invalid type {type(myPod)}"
        deletedPod = None
        try:  
            deletedPod = await self.kubeapi.delete_namespaced_pod(  
                name=myPod.metadata.name, 
                namespace=self.namespace, 
                grace_period_seconds=grace_period_seconds, 
                propagation_policy=propagation_policy 
            )

        except ApiException as e:
            # self.logger.error( f"{e}" )
            pass

        return deletedPod

    async def removesecrets( self, authinfo:AuthInfo, userinfo:AuthUser )->bool:
        """removesecrets
            remove all kubernetes secrets for a give user
            list_dict_secret_data( authinfo, userinfo, access_type=None)
            then delete the secret 
            
        Args:
            authinfo (AuthInfo): authinfo
            userinfo (AuthUser): authuser

        Returns:
            bool: True if all users's secrets are deleted else False
        """
        self.logger.debug('')
        assert isinstance(authinfo, AuthInfo),  f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo, AuthUser),  f"userinfo has invalid type {type(userinfo)}"
        ''' remove all kubernetes secrets for a give user '''
        ''' access_type is None will list all secret type '''
        bReturn = True
        # access_type is None will list all secret type
        dict_secret = await self.list_dict_secret_data( authinfo, userinfo, access_type=None)
        for secret_name in dict_secret.keys():
            try:
                self.logger.debug( f"deleting secret name {secret_name}")
                v1status = await self.kubeapi.delete_namespaced_secret( name=secret_name, namespace=self.namespace )
                if not isinstance(v1status,V1Status) :
                    self.logger.error( 'invalid V1Status type return by delete_namespaced_secret')
                    continue
                self.logger.debug(f"deleted secret={secret_name} status={v1status.status}") 
                if v1status.status != 'Success':
                    self.logger.error(f"secret {secret_name} can not be deleted {v1status}" ) 
                    bReturn = bReturn and False
            except ApiException as e:
                self.logger.error(f"secret {secret_name} can not be deleted {e}") 
                bReturn = bReturn and False
        self.logger.debug(f"removesecrets for {userinfo.userid} return {bReturn}" ) 
        return bReturn 
   


    async def removeconfigmap( self, authinfo:AuthInfo, userinfo:AuthUser )->bool:
        """removeconfigmap
            remove all kubernetes configmap for a give user

        Args:
            authinfo (AuthInfo): authinfo
            userinfo (AuthUser): authuser

        Returns:
            bool: True if all users's configmaps are deleted else False
        """
        self.logger.debug('')
        assert isinstance(authinfo, AuthInfo),  f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo, AuthUser),  f"userinfo has invalid type {type(userinfo)}"
        bReturn = True
        dict_configmap = await self.list_dict_configmap_data( authinfo, userinfo, access_type=None)
        for configmap_name in dict_configmap.keys():
            try:            
                v1status = await self.kubeapi.delete_namespaced_config_map( name=configmap_name, namespace=self.namespace )
                if not isinstance(v1status,V1Status) :
                    self.logger.error( 'Invalid V1Status type return by delete_namespaced_config_map')
                    continue
                self.logger.debug(f"configmap {configmap_name} status {v1status.status}") 
                if v1status.status != 'Success':
                    self.logger.error(f"configmap name {configmap_name} can not be deleted {str(v1status)}") 
                    bReturn = bReturn and False
                    
            except ApiException as e:
                self.logger.error(f"configmap name {configmap_name} can not be deleted: error {e}") 
                bReturn = bReturn and False
        return bReturn 

    async def removepodindesktop(self, authinfo:AuthInfo, userinfo:AuthUser, myPod:V1Pod=None )->bool:
        self.logger.debug('')
        assert isinstance(authinfo, AuthInfo),  f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo, AuthUser),  f"userinfo has invalid type {type(userinfo)}"
        # get the user's pod
        if not isinstance(myPod, V1Pod ):
            myPod = await self.findPodByUser(authinfo, userinfo )

        if isinstance(myPod, V1Pod ):
            # delete this pod immediatly
            deletedpod = await self.removePod( myPod=myPod, propagation_policy='Foreground', grace_period_seconds=0 )
            if isinstance(deletedpod,V1Pod):
                return True
        return False
    
    """removePodSync
    def removePodSync(self, authinfo:AuthInfo, userinfo:AuthUser , myPod:V1Pod=None )->bool:
        self.logger.debug('')
        assert isinstance(authinfo, AuthInfo),  f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo, AuthUser),  f"userinfo has invalid type {type(userinfo)}"
        # get the user's pod
        if not isinstance(myPod, V1Pod ):
            myPod = self.findPodByUser(authinfo, userinfo )
        nTry = 0
        nMaxTry = 42
        if isinstance(myPod, V1Pod ):
            deletedPod = self.removePod( myPod, propagation_policy='Foreground', grace_period_seconds=30 )
            if isinstance(deletedPod, V1Pod ):
                while nTry<nMaxTry:
                    try:
                        myPod = self.kubeapi.read_namespaced_pod(namespace=self.namespace,name=deletedPod.metadata.name)
                        if isinstance(myPod, V1Pod ):
                            message = f"b.deleting {myPod.metadata.name} {myPod.status.phase} {nTry}/{nMaxTry}"
                            self.logger.debug( message )
                            self.on_desktoplaunchprogress( message )
                    except ApiException as e:
                        if e.status == 404:
                            return True
                        else:
                            self.on_desktoplaunchprogress( e )
                            return False
                    # wait one second
                    time.sleep(1) 
                    nTry = nTry + 1
        return False
    """

    async def removedesktop(self, authinfo:AuthInfo, userinfo:AuthUser, myPod:V1Pod=None, snapshot:bool=False  )->ODDesktop:
        """removedesktop
            remove kubernetes pod for a give user
            then remove kubernetes user's secrets and configmap
        Args:
            authinfo (AuthInfo): _description_
            userinfo (AuthUser): _description_
            myPod (V1Pod, optional): _description_. Defaults to None.

        Returns:
            myDesktop: ODDesktop
        """
        # self.logger.debug('')
        assert isinstance(authinfo, AuthInfo),  f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo, AuthUser),  f"userinfo has invalid type {type(userinfo)}"

        # get the user's pod
        if not isinstance(myPod, V1Pod ):
            myPod = await self.findPodByUser(authinfo, userinfo )

        myDesktop = None
        if isinstance(myPod, V1Pod ):
            # log lovel to info for accounting
            self.logger.info( f"removedesktop {myPod.metadata.name} for {authinfo.provider} {userinfo.userid}" ) 
            
            # convert pod to ODDesktop as return value
            myDesktop = self.pod2desktop_reduced( myPod, authinfo, userinfo)

            # Suppression parallèle avec asyncio.gather (remplace threading)
            myappinstance = ODAppInstanceKubernetesPod( self )
            self.logger.debug( 'starting remove tasks')
            await asyncio.gather(
                self.removePod(myPod),
                myappinstance.removeAppInstanceKubernetesPod(authinfo, userinfo),
                self.removesecrets(authinfo, userinfo),
                self.removeconfigmap(authinfo, userinfo),
                self.removepvc(authinfo, userinfo),
                return_exceptions=True
            )
            self.logger.debug( 'remove tasks done')
        else:
            self.logger.error( f"removedesktop can not find desktop {authinfo} {userinfo}" )
        return myDesktop

    async def removepvc(self, authinfo:AuthInfo, userinfo:AuthUser)->V1PersistentVolumeClaim:
        self.logger.debug('')
        
        bReturn = False
        if isinstance( oc.od.settings.desktop['persistentvolumeclaim'], str):
            # there is only one PVC for all users
            # by pass this call
            return bReturn 
        
        if oc.od.settings.desktop['removepersistentvolumeclaim'] is False:
            # removepersistentvolumeclaim is False, do not delete 
            # by pass this call
            return bReturn 

        assert isinstance(authinfo, AuthInfo),  f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo, AuthUser),  f"userinfo has invalid type {type(userinfo)}"
        odvol = oc.od.persistentvolumeclaim.ODPersistentVolumeClaim( self.namespace, self.kubeapi )
        # list all pvc for the user and delete pvc
        deleted_pvc = await odvol.delete_pvc( authinfo=authinfo, userinfo=userinfo )
        return deleted_pvc


    def preparelocalaccount( self, localaccount:dict )->dict:
        assert isinstance(localaccount, dict),f"invalid localaccount type {type(localaccount)}"    
        mydict_config = { 
            # 'passwd' : AuthUser.mkpasswd(localaccount), 
            # 'shadow' : AuthUser.mkshadow(localaccount), 
            # 'group'  : AuthUser.mkgroup(localaccount),
            # 'gshadow': AuthUser.mkgshadow(localaccount), 
            # '\n' fix the \ No newline at end of file issue
            # passwd file need a final newline 
            'passwd' : AuthUser.mkpasswd_newline(localaccount), 
            'shadow' : AuthUser.mkshadow_newline(localaccount), 
            'group'  : AuthUser.mkgroup_newline(localaccount),
            'gshadow': AuthUser.mkgshadow_newline(localaccount), 
        }
        return mydict_config
            
    async def prepareressources(self, authinfo:AuthInfo, userinfo:AuthUser):
        """[prepareressources]

        Args:
            authinfo (AuthInfo): authentification data
            userinfo (AuthUser): user data

        """
        self.logger.debug('')
        assert isinstance(authinfo, AuthInfo),  f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo, AuthUser),  f"userinfo has invalid type {type(userinfo)}"
        # create a kerberos kubernets secret 
        #  
        # translate the userid as sAMAccountName in the authinfo.claims dict
        # Flex volume use kubernetes secret                    
        # arguments = authinfo.claims
        # arguments['user'] = authinfo.claims['userid']
        # arguments['data'] = { 'realm': authinfo.claims['realm'], 'ticket': authinfo.claims['ticket'] }

        # Build the kubernetes secret 
        # auth_type = 'kerberos'
        # secret_type = 'abcdesktop/' + auth_type
        # secret = ODSecret( self.namespace, self.kubeapi, secret_type )
        # auth_secret = await secret.create( arguments )
          # compile a env list with the auth list  
        # translate auth environment to env 

        #
        # Create ODSecretLDIF, build userinfo object secret ldif cache
        # This section is necessary to get user photo in user_controller.py
        # dump the ldif in kubernetes secret 
        # whoami entry point use the ldiff secret 
        # create a ldif secret
        self.logger.debug('oc.od.secret.ODSecretLDIF creating')
        secret = oc.od.secret.ODSecretLDIF( namespace=self.namespace, kubeapi=self.kubeapi )
        createdsecret = await secret.create( authinfo, userinfo, data=userinfo )
        if not isinstance( createdsecret, V1Secret):
            self.logger.error(f"can not create secret {secret.get_name(authinfo, userinfo)}")
        else:
            self.logger.debug(f"LDIF secret.create {secret.get_name(authinfo, userinfo)} created")
        self.logger.debug('create oc.od.secret.ODSecretLDIF created')

        # create files as secret 
        # - passwd 
        # - shadow 
        # - group 
        # - gshadow
        # files will be store in /var/lib/extrausers in the desktop container
        localaccount_data = authinfo.get_localaccount()
        # localaccount_data is a dict like
        # { 'uid': 'fry', 'gid': 'fry', 'gecos': [], 'groups': None, 'uidNumber': 2042, 'gidNumber': 12042, 'loginShell': '/bin/bash', 'description': 'Human', 'homeDirectory': '/home/fry', 'sha512': '$6$wliVSqROUCodfRsM$...oiyyvAmJl1'}
        localaccount_files = self.preparelocalaccount( localaccount_data )
        # create dict from localaccount_data entry for 'passwd', 'shadow', 'group', 'gshadow' files
        # { 'passwd': 'root:x:0:0:root:/roo.../bin/bash\n', 
        #   'shadow': 'root:*:19020:0:99999...999:7:::\n\n', 
        #   'group': 'root:x:0:\ndaemon:x:1...y:x:12042:', 
        #   'gshadow': 'root:*::\ndaemon:*::\n...::\nfry:!::'
        # }
        self.logger.debug('localaccount secret.create creating')
        # create ODSecretLocalAccount object
        secret = oc.od.secret.ODSecretLocalAccount( namespace=self.namespace, kubeapi=self.kubeapi )
        # put localaccount_files into ODSecretLocalAccount secret
        createdsecret = await secret.create( authinfo, userinfo, data=localaccount_files )
        # check if createdsecret is a V1Secret
        if not isinstance( createdsecret, V1Secret):
            self.logger.error(f"can not create secret {secret.get_name(authinfo, userinfo)}")
        else:
            self.logger.debug(f"localaccount secret.create {secret.get_name(authinfo, userinfo)} created")

        if userinfo.isPosixAccount():
            self.logger.debug('posixaccount secret.create creating')
            secret = oc.od.secret.ODSecretPosixAccount( namespace=self.namespace, kubeapi=self.kubeapi )
            createdsecret = await secret.create( authinfo, userinfo, data=userinfo.getPosixAccount())
            if not isinstance( createdsecret, V1Secret):
                self.logger.error(f"can not create posixaccount secret {secret.get_name(authinfo, userinfo)}")
            else:
                self.logger.debug(f"posixaccount secret.create {secret.get_name(authinfo, userinfo)} created")

        # for each identity in auth enabled
        identities = authinfo.get_identity()
        if isinstance( identities, dict ) :
            for identity_key in identities.keys():
                self.logger.debug(f"secret.create {identity_key} creating")
                secret = oc.od.secret.selectSecret( self.namespace, self.kubeapi, prefix=None, secret_type=identity_key )
                # build a kubernetes secret with the identity auth values 
                # values can be empty to be updated later
                if isinstance( secret, oc.od.secret.ODSecret):
                    identity_data=identities.get(identity_key)
                    createdsecret = await secret.create( authinfo, userinfo, data=identity_data )
                    if not isinstance( createdsecret, V1Secret):
                        self.logger.error(f"can not create secret {secret.get_name(authinfo, userinfo)}")
                    else:
                        self.logger.debug(f"secret.create {secret.get_name(authinfo, userinfo)} created")
    
        # Create volume from policies 
        self.logger.debug('create volumes from policies')
        rules = oc.od.settings.desktop['policies'].get('rules')
        if isinstance(rules, dict):
            mountvols = oc.od.volume.selectODVolumebyRules( authinfo, userinfo,  rules.get('volumes') )
            for mountvol in mountvols:
                # use as a volume defined and the volume is mountable
                fstype = mountvol.fstype # Get the fstype: for example 'cifs' or 'cifskerberos' or 'webdav' or 'nfs'
                # find a secret class, can return None if fstype does not need a auth like crentials
                # for example 'hostPath' doesn't need credentials but 'cifs' need credentials 
                secret = oc.od.secret.selectSecret( self.namespace, self.kubeapi, prefix=mountvol.name, secret_type=fstype)
                if isinstance( secret, oc.od.secret.ODSecret):
                    # Flex volume use kubernetes secret, add mouting path
                    arguments = { 'mountPath': mountvol.containertarget, 'networkPath': mountvol.networkPath, 'mountOptions': mountvol.mountOptions }
                    # Build the kubernetes secret
                    auth_secret = await secret.create( authinfo, userinfo, arguments )
                    if not isinstance( auth_secret, V1Secret):
                        self.logger.error( f"Failed to build auth secret {secret.get_name(authinfo, userinfo)} fstype={fstype}" )
                    else:
                        self.logger.debug(f"secret.create {secret.get_name(authinfo, userinfo)} created")

    def get_annotations_lastlogin_datetime(self):
        """get_annotations_lastlogin_datetime
            return a dict { 'lastlogin_datetime': datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S") }

        Returns:
            dict: { 'lastlogin_datetime': datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        """
        annotations = { 'lastlogin_datetime': datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S") } 
        return annotations


    def read_pod_annotations_lastlogin_datetime(self, pod:V1Pod )->datetime.datetime:
        """read_pod_annotations_lastlogin_datetime
            read pod annotations data lastlogin_datetime value

        Args:
            pod (V1Pod): kubernetes pod

        Returns:
            datetime: a datetime from pod.metadata.annotations.get('lastlogin_datetime') None if not set
        """
        resumed_datetime = None
        try:
            str_lastlogin_datetime = pod.metadata.annotations.get('lastlogin_datetime')
            if isinstance(str_lastlogin_datetime,str):
                resumed_datetime = datetime.datetime.strptime(str_lastlogin_datetime, "%Y-%m-%dT%H:%M:%S")
        except Exception as e:
            self.logger.error( e ) 
        return resumed_datetime

    def read_pod_creation_timestamp(self, pod:V1Pod )->str:
        """read_pod_annotations_lastlogin_datetime
            read pod annotations data lastlogin_datetime value

        Args:
            pod (V1Pod): kubernetes pod

        Returns:
            str: string datetime iso formated else None if error
        """
        isoformat_creation_timestamp = None
        try:
            isoformat_creation_timestamp = datetime.datetime.isoformat(pod.metadata.creation_timestamp)
        except Exception as e:
            self.logger.error( e ) 
        return isoformat_creation_timestamp


    async def resumedesktop(self, authinfo:AuthInfo, userinfo:AuthUser)->ODDesktop:
        """resume desktop update the lastconnectdatetime annotations data
           findPodByuser and update the lastconnectdatetime using patch_namespaced_pod
        Args:
            authinfo (AuthInfo): authentification data
            userinfo (AuthUser): user data 

        Returns:
            [ODesktop]: Desktop Object updated annotations data
        """
        self.logger.debug('')
        assert isinstance(authinfo, AuthInfo),  f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo, AuthUser),  f"userinfo has invalid type {type(userinfo)}"
        myDesktop = None
        myPod = await self.findPodByUser(authinfo, userinfo)
        if isinstance(myPod, V1Pod ):
            # check the pod status
            if isinstance(myPod.status, V1PodStatus):
                if myPod.status.phase != 'Running':
                    # someting goes wrong
                    return f"Your pod is in phase {myPod.status.phase}, resume pod failed" 
            else:
                return 'Your pod has no status entry, fatal error' 
            # update the metadata.annotations ['lastlogin_datetime'] in pod
            annotations = myPod.metadata.annotations
            new_lastlogin_datetime = self.get_annotations_lastlogin_datetime()
            annotations['lastlogin_datetime'] = new_lastlogin_datetime['lastlogin_datetime']
            newmetadata=V1ObjectMeta(annotations=annotations)
            body = V1Pod(metadata=newmetadata)
            v1newPod = await self.kubeapi.patch_namespaced_pod(   
                name=myPod.metadata.name, 
                namespace=self.namespace, 
                body=body )
            # do not use pod2desktop_reduced, we need to read the vnc password  
            if isinstance(v1newPod, V1Pod ):
                myDesktop = await self.pod2desktop( pod=v1newPod, authinfo=authinfo, userinfo=userinfo )
            else:
                self.logger.error( 'Patch annontation lastlogin_datetime failed' )
                # reread the non updated desktop if patch failed
                myDesktop = await self.pod2desktop( pod=myPod, authinfo=authinfo, userinfo=userinfo )
        return myDesktop

    async def getsecretuserinfo(self, authinfo:AuthInfo, userinfo:AuthUser)->dict:
        """read cached user info dict from a ldif secret

        Args:
            authinfo (AuthInfo): authentification data
            userinfo (AuthUser): user data 

        Returns:
            [dict]: cached user info dict from ldif secret
                    empty dict if None
        """
        self.logger.debug('')
        assert isinstance(authinfo, AuthInfo),  f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo, AuthUser),  f"userinfo has invalid type {type(userinfo)}"
        dict_secret = await self.list_dict_secret_data( authinfo, userinfo )
        raw_secrets = {}
        for key in dict_secret.keys():
            secret = dict_secret[key]
            if isinstance(secret, dict) and secret.get('type') == 'abcdesktop/ldif':
                raw_secrets.update( secret )
                break
        return raw_secrets

    async def getldifsecretuserinfo(self, authinfo:AuthInfo, userinfo:AuthUser)->dict:
        """getldifsecretuserinfo 
                read cached user info dict from a ldif secret

        Args:
            authinfo (AuthInfo): authentification data
            userinfo (AuthUser): user data 

        Returns:
            [dict]: cached user info dict from ldif secret
                    empty dict if None
        """
        self.logger.debug('')
        assert isinstance(authinfo, AuthInfo),  f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo, AuthUser),  f"userinfo has invalid type {type(userinfo)}"
        secret = oc.od.secret.ODSecretLDIF( namespace=self.namespace, kubeapi=self.kubeapi )
        data = await secret.read_alldata(authinfo,userinfo)
        return data


    async def list_dict_configmap_data( self, authinfo:AuthInfo, userinfo:AuthUser, access_type=None, hidden_empty=False )->dict:
        """get a dict of secret (key value) for the access_type
           if access_type is None will list all user secrets
        Args:
            authinfo (AuthInfo): authentification data
            userinfo (AuthUser): user data 
            access_type (str): type of secret like 'auth' 

        Returns:
            dict: return dict of secret key value 
        """
        access_userid = userinfo.userid
        access_provider = authinfo.provider
        configmap_dict = {}
        try: 
            label_selector = f"access_userid={access_userid}"
            if oc.od.settings.desktop['authproviderneverchange'] is True:
                label_selector += f",access_provider={access_provider}"
            if isinstance(access_type,str) :
                label_selector += f",access_type={access_type}"
           
            kconfigmap_list = await self.kubeapi.list_namespaced_config_map(self.namespace, label_selector=label_selector)
          
            for myconfigmap in kconfigmap_list.items:
                if hidden_empty :
                    # check if mysecret.data is None or an emtpy dict 
                    if myconfigmap.data is None :
                        continue
                    if isinstance( myconfigmap.data, dict) and len( myconfigmap.data ) == 0: 
                        continue
                configmap_dict[myconfigmap.metadata.name] = { 'data': myconfigmap.data }
      
        except ApiException as e:
            self.logger.error( f"ApiException {e}" )
    
        return configmap_dict

    async def list_dict_secret_data( self, authinfo:AuthInfo, userinfo:AuthUser, access_type=None, hidden_empty=False )->dict:
        """get a dict of secret (key value) for the access_type
           if access_type is None will list all user secrets
        Args:
            authinfo (AuthInfo): authentification data
            userinfo (AuthUser): user data 
            access_type (str): type of secret like 'auth' 

        Returns:
            dict: return dict of secret key value 
        """
        self.logger.debug('')
        assert isinstance(authinfo, AuthInfo),  f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo, AuthUser),  f"userinfo has invalid type {type(userinfo)}"
        access_userid = userinfo.userid
        access_provider = authinfo.provider
        secret_dict = {}
        try: 
            label_selector = f"access_userid={access_userid}"

            if oc.od.settings.desktop['authproviderneverchange'] is True:
                label_selector += f",access_provider={access_provider}"
            if isinstance(access_type,str) :
                label_selector += f",access_type={access_type}"
           
            ksecret_list = await self.kubeapi.list_namespaced_secret(self.namespace, label_selector=label_selector)
          
            for mysecret in ksecret_list.items:
                if hidden_empty :
                    # check if mysecret.data is None or an emtpy dict 
                    if mysecret.data is None :
                        continue
                    if isinstance( mysecret.data, dict) and len( mysecret.data ) == 0: 
                        continue

                secret_dict[mysecret.metadata.name] = { 'type': mysecret.type, 'data': mysecret.data }
                if isinstance( mysecret.data, dict):
                    for mysecretkey in mysecret.data:
                        data = oc.od.secret.ODSecret.read_data( mysecret, mysecretkey )
                        secret_dict[mysecret.metadata.name]['data'][mysecretkey] = data 

        except ApiException as e:
            self.logger.error( f"ApiException: {e}" )
    
        return secret_dict


    def filldictcontextvalue( self, authinfo:AuthInfo, userinfo:AuthUser, desktop:ODDesktop, network_config:str, network_name=None, appinstance_id=None ):
        assert isinstance(authinfo, AuthInfo),  f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo, AuthUser),  f"userinfo has invalid type {type(userinfo)}"
        fillvalue = network_config
        # self.logger.debug( f"type(network_config) is {type(network_config)}" )
        # check if network_config is str, dict or list
        if isinstance( network_config, str) :
            fillvalue = self.fillwebhook(   mustachecmd=network_config, 
                                            app=desktop, 
                                            authinfo=authinfo, 
                                            userinfo=userinfo, 
                                            network_name=network_name, 
                                            containerid=appinstance_id )

        elif isinstance( network_config, dict) :
            fillvalue = {}
            for k in network_config.keys():
                fillvalue[ k ] = self.filldictcontextvalue( authinfo, userinfo, desktop, network_config[ k ], network_name, appinstance_id )

        elif isinstance( network_config, list) :
            fillvalue = [None] * len(network_config)
            for i, item in enumerate(network_config):
                fillvalue[ i ] = self.filldictcontextvalue( authinfo, userinfo, desktop, item, network_name, appinstance_id )
    
        # self.logger.debug(f"filldictcontextvalue return fillvalue={fillvalue}")
        return fillvalue

    async def countRunningAppforUser( self, authinfo:AuthInfo, userinfo:AuthUser, myDesktop:ODDesktop)->int:
        """countRunningAppforUser

        Args:
            authinfo (AuthInfo): AuthInfo
            userinfo (AuthUser): AuthUser
            myDesktop (ODDesktop): ODDesktop

        Returns:
            int: counter of running applications for a user
        """
        assert isinstance(authinfo, AuthInfo),  f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo, AuthUser),  f"userinfo has invalid type {type(userinfo)}"
        assert isinstance(myDesktop, ODDesktop),  f"myDesktop has invalid type {type(myDesktop)}"
        self.logger.debug('')
        count = 0
        for appinstance in self.appinstance_classes.values() :
            myappinstance = appinstance( self )
            count += len( await myappinstance.list(authinfo, userinfo, myDesktop ) )
        return count


    async def list_application_by_type_of_application( self, authinfo:AuthInfo, userinfo:AuthUser, myDesktop:ODDesktop, list_of_application_type:list, apps:ODApps=None, phase_filter:list=None )->list:
        assert isinstance(authinfo, AuthInfo),   f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo, AuthUser),   f"userinfo has invalid type {type(userinfo)}"
        assert isinstance(myDesktop, ODDesktop), f"myDesktop has invalid type {type(myDesktop)}"
        self.logger.debug('')
        list_apps = []
        if not isinstance(phase_filter, list):
            phase_filter = self.all_phases_status
        if self.pod_application in list_of_application_type :
            myappinstance = ODAppInstanceKubernetesPod( self )
            list_apps += await myappinstance.list(authinfo, userinfo, myDesktop, phase_filter=phase_filter, apps=apps)
        if self.ephemeral_container in list_of_application_type:
            myappinstance = ODAppInstanceKubernetesEphemeralContainer( self )
            list_apps += await myappinstance.list(authinfo, userinfo, myDesktop, phase_filter=phase_filter, apps=apps)
        return list_apps

    async def listContainerApps( self, authinfo:AuthInfo, userinfo:AuthUser, myDesktop:ODDesktop, apps:ODApps=None ):
        """listContainerApps

        Args:
            authinfo (AuthInfo): AuthInfo
            userinfo (AuthUser): AuthUser
            myDesktop (ODDesktop): ODDesktop
            apps (ODApps): ODApps

        Returns:
            list: list of applications
        """
        assert isinstance(authinfo, AuthInfo),   f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo, AuthUser),   f"userinfo has invalid type {type(userinfo)}"
        assert isinstance(myDesktop, ODDesktop), f"myDesktop has invalid type {type(myDesktop)}"
        self.logger.debug('')
        list_apps = []
        for appinstance in self.appinstance_classes.values() :
            myappinstance = appinstance( self )
            list_apps += await myappinstance.list(authinfo, userinfo, myDesktop, phase_filter=self.all_phases_status, apps=apps)
        return list_apps


    async def getAppInstanceKubernetes( self, authinfo:AuthInfo, userinfo:AuthUser, pod_name:str, containerid:str):
        """getAppInstanceKubernetes
            return the AppInstanceKubernetes of an appliction
            find if contianerid is a ephemeralcontainer or a pod application
        Args:
            authinfo (AuthInfo): AuthInfo
            userinfo (AuthUser): AuthUser
            pod_name (str): str
            containerid (str): str

        Returns:
            ODAppInstanceBase can be :
                - ODAppInstanceKubernetesEphemeralContainer(ODAppInstanceBase): ephemeral container application
                - ODAppInstanceKubernetesPod(ODAppInstanceBase): pod application
        """
        assert isinstance(pod_name, str), f"podname has invalid type {type(pod_name)}"
        assert isinstance(containerid, str), f"containerid has invalid type {type(containerid)}"
        myappinstance = None
        myPod = await self.kubeapi.read_namespaced_pod(namespace=self.namespace,name=pod_name)
        if isinstance( myPod, V1Pod ):
            # if type is x11server app is an ephemeral container
            pod_type = myPod.metadata.labels.get( 'type' )
            if pod_type == self.x11servertype:
                if isinstance( myPod.status, V1PodStatus ):
                    if isinstance( myPod.status.ephemeral_container_statuses, list ):
                        for container in myPod.status.ephemeral_container_statuses:
                            if container.name == containerid:
                                myappinstance = ODAppInstanceKubernetesEphemeralContainer( self )
                                break

            # if myappinstrance is not found
            # try to find it as a pod application
            if myappinstance is None:
                try:
                    myappPod = await self.kubeapi.read_namespaced_pod(namespace=self.namespace,name=containerid)
                    if isinstance( myappPod, V1Pod ):
                        pod_type = myappPod.metadata.labels.get( 'type' )
                        if pod_type == self.pod_application:
                            myappinstance = ODAppInstanceKubernetesPod( self )
                except ApiException as e:
                    # not found
                    pass

        return myappinstance

    async def logContainerApp( self, authinfo:AuthInfo, userinfo:AuthUser, pod_name:str, app_name:str):
        assert isinstance(pod_name, str), f"podname has invalid type {type(pod_name)}"
        log_app = None
        myappinstance = await self.getAppInstanceKubernetes(authinfo, userinfo, pod_name, app_name)
        if isinstance( myappinstance, ODAppInstanceBase ):
            log_app = await myappinstance.logContainerApp(pod_name, app_name)
        return log_app

    async def envContainerApp( self, authinfo:AuthInfo, userinfo:AuthUser, pod_name:str, app_name:str):
        assert isinstance(pod_name, str), f"podname has invalid type {type(pod_name)}"
        env_result = None
        myappinstance = await self.getAppInstanceKubernetes(authinfo, userinfo, pod_name, app_name)
        if isinstance( myappinstance, ODAppInstanceBase ):
            env_result = await myappinstance.envContainerApp(authinfo, userinfo, pod_name, app_name)
        return env_result

    async def stopContainerApp( self, authinfo:AuthInfo, userinfo:AuthUser, pod_name:str, app_name:str)->bool:
        assert isinstance(pod_name, str), f"podname has invalid type {type(pod_name)}"
        stop_result = None
        myappinstance = await self.getAppInstanceKubernetes(authinfo, userinfo, pod_name, app_name)
        if isinstance( myappinstance, ODAppInstanceBase ):
            stop_result = await myappinstance.stop(pod_name, app_name)
        return stop_result

    async def describe_application( self, authinfo:AuthInfo, userinfo:AuthUser, pod_name:str, app_name:str, apps:ODApps)->dict:
        assert isinstance(pod_name, str), f"podname has invalid type {type(pod_name)}"
        assert isinstance(app_name, str), f"app_name has invalid type {type(app_name)}"
        app_description = None
        myappinstance = await self.getAppInstanceKubernetes(authinfo, userinfo, pod_name, app_name)
        if isinstance( myappinstance, ODAppInstanceBase ):
            app_description = await myappinstance.describe(pod_name, app_name, apps)
        return app_description

    async def removeContainerApp( self, authinfo:AuthInfo, userinfo:AuthUser, pod_name:str, app_name:str)->bool:
        return await self.stopContainerApp( authinfo, userinfo, pod_name, app_name)

    """
    def read_configmap( self, name, entry ):
        data = None
        try:
            result = self.kubeapi.read_namespaced_config_map( name=name, namespace=self.namespace)      
            if isinstance( result, client.models.v1_config_map.V1ConfigMap):
                data = result.data
                data = json.loads( data.get(entry) )
        except ApiException as e:
            if e.status != 404:
                self.logger.info("Exception when calling read_namespaced_config_map: %s" % e)
        except Exception as e:
            self.logger.info("Exception when calling read_namespaced_config_map: %s" % e)
        return data
    """

        
    def isenablecontainerinpod( self, authinfo:AuthInfo, currentcontainertype:str)->bool:
        """isenablecontainerinpod
            read the desktop configuration and check if this currentcontainertype is allowed
            if currentcontainertype is allowed return True else False

        Args:
            authinfo (_type_): _description_
            currentcontainertype (str): type of container must be defined in list
            [ 'init', 'graphical', 'ssh', 'sound', 'printer', 'filter', 'storage' ]

        Returns:
            bool: True if enable, else False
        """

        bReturn =   isinstance( oc.od.settings.desktop_pod.get(currentcontainertype), dict ) is True and \
                    oc.od.acl.ODAcl().isAllowed( authinfo, oc.od.settings.desktop_pod[currentcontainertype].get('acl') ) is True and \
                    oc.od.settings.desktop_pod[currentcontainertype].get('enable') is True
        return bReturn

    async def createappinstance(self, myDesktop:ODDesktop, app:dict, authinfo:AuthInfo, userinfo:AuthUser={}, queue: asyncio.Queue=None,  userargs=None, **kwargs ):
        """createappinstance
            containerengine can be one of the values
                - 'ephemeral_container'
                - 'pod_application'
            the default containerengine value is 'ephemeralcontainer'

        Args:
            myDesktop (ODDesktop): _description_
            app (dict): _description_
            authinfo (AuthInfo): _description_
            userinfo (AuthUser, optional): _description_. Defaults to {}.
            userargs (_type_, optional): _description_. Defaults to None.

        Raises:
            ValueError: unknow containerengine value {containerengine}

        Returns:
            ODAppInstanceStatus: oc.od.appinstancestatus.ODAppInstanceStatus
        """
        self.logger.debug('')
        assert isinstance(myDesktop, ODDesktop),f"desktop has invalid type {type(myDesktop)}"
        assert isinstance(app,       dict),     f"app has invalid type {type(app)}"
        assert isinstance(authinfo,  AuthInfo), f"authinfo has invalid type {type(authinfo)}"
        # read the container enigne specific value from app properties
        containerengine = app.get('containerengine', 'ephemeral_container' )
        if containerengine not in self.appinstance_classes.keys():
            raise ValueError( f"unknow containerengine value {containerengine} must be defined in {list(self.appinstance_classes.keys())}")
        self.logger.debug(f"createappinstance containerengine={containerengine}")
        appinstance_class = self.appinstance_classes.get(containerengine)
        self.logger.debug(f"createappinstance appinstance_class={appinstance_class}")
        appinstance = appinstance_class(self)
        self.logger.debug(f"createappinstance containerengine={containerengine} type={appinstance.type}")
        appinstance_created = await appinstance.create(myDesktop, app, authinfo, userinfo, queue, userargs, **kwargs )
        return appinstance_created


    def labelfilter2str( self, labelfilter )->str:
        """labelfilter2str
            convert a dict filter to str

        Args:
            labelfilter (dict or str): labelfilter     
    
        Returns:
            str: labelfilter string formated
        """
        label_selector = ''
        if isinstance( labelfilter, dict ):
            for k in labelfilter:
                if len( label_selector ) > 0:
                    label_selector += ','
                label_selector += f"{k}={labelfilter[k]}"
        elif isinstance(labelfilter, str ):
            label_selector = labelfilter

        return label_selector

    async def alwaysgetPosixAccountUser(self, authinfo:AuthInfo, userinfo:AuthUser ) -> dict :
        """alwaysgetPosixAccountUser

        Args:
            userinfo (AuthUser): auth user info

        Returns:
            dict: posic account dict 
        """
        if not userinfo.isPosixAccount():
            # try to read a posix account from secret
            self.logger.debug('build a posixaccount secret trying')
            posixsecret = oc.od.secret.ODSecretPosixAccount( namespace=self.namespace, kubeapi=self.kubeapi )
            self.logger.debug('read the posixaccount secret trying')
            posixaccount = await posixsecret.read_alldata( authinfo, userinfo )
            if not isinstance( posixaccount, dict):
                self.logger.debug('posixaccount does not exist use localaccount default')
                localaccount = oc.od.secret.ODSecretLocalAccount( namespace=self.namespace, kubeapi=self.kubeapi )
                self.logger.debug('read the localaccount secret')
                localaccount_data = await localaccount.read_alldata( authinfo, userinfo )
                posixaccount = AuthUser.getPosixAccountfromlocalAccount(localaccount_data)
                userinfo['posix'] = posixaccount
            else:
                self.logger.debug('posixaccount reuse cached secret data')
                userinfo['posix'] = posixaccount
        else:
            self.logger.debug('posixaccount already decoded use userinfo dict')
            posixaccount = userinfo.getPosixAccount()

        return posixaccount


    def updateChevronDictWithmixedData( self, d, mixeddata:dict):
        if isinstance( d, dict):
            for k in d.keys():
                d[k] = self.updateChevronDictWithmixedData( d[k], mixeddata)
            return d
        if isinstance( d, list):
            for i in range(len(d)):
                d[i] = self.updateChevronDictWithmixedData( d[i], mixeddata)
            return d
        if isinstance( d, str):
            return chevron.render( d, mixeddata )
        else:
            return d

    async def chevronWithUserInfo( self, list_data:list, authinfo: AuthInfo, userinfo:AuthUser ) -> list:
        """chevronWithUserInfo

            replace uidNumber and gidNumber by posix account values
            chevron update command 
            'command': [ 'sh', '-c',  'chown {{ uidNumber }}:{{ gidNumber }} ~' ] 
            after chevron
            'command': [ 'sh', '-c',  'chown 1234:5432 ~' ] 
            return list [ 'sh', '-c',  'chown 1234:5432 ~' ] 
        Args:
            currentcontainertype (str): 'init'
            userinfo (AuthUser): AuthUser

        Returns:
            list: command line updated
        """
        list_command = list_data
        if isinstance( list_command, list ):
            new_list_command = []
            posixuser = await self.alwaysgetPosixAccountUser( authinfo, userinfo )
            for command in list_command:
                new_command  = chevron.render( command, posixuser )
                new_list_command.append( new_command )
            list_command = new_list_command
        return list_command


    async def updateSecurityContextWithUserInfo( self, currentcontainertype:str, authinfo:AuthInfo, userinfo:AuthUser ) -> dict:
        """updateSecurityContextWithUserInfo

        Args:
            currentcontainertype (str): type of container
            userinfo (AuthUser): userinfo

        Returns:
            dict: a securityContext dict with { 'runAsUser': UID , 'runAsGroup': GID } or None
        """
        securityContext = None
        securityContextConfig = oc.od.settings.desktop_pod.get(currentcontainertype, {}).get( 'securityContext')
        if isinstance( securityContextConfig, dict):
            securityContext = copy.deepcopy(securityContextConfig)
            runAsUser  = securityContext.get('runAsUser')
            runAsGroup = securityContext.get('runAsGroup')
            supplementalGroups = securityContext.get('supplementalGroups')
            posixuser = await self.alwaysgetPosixAccountUser( authinfo, userinfo )

            # replace 'runAsUser' if exist in configuration file
            if isinstance( runAsUser, str ): 
                securityContext['runAsUser']  = int( chevron.render( runAsUser, posixuser ) )
            
            # replace 'runAsGroup' if exist in configuration file
            if isinstance( runAsGroup, str ): 
                securityContext['runAsGroup'] = int( chevron.render( runAsGroup, posixuser ) )
            
            if securityContext.get('supplementalGroups'):
                # add 'supplementalGroups' if exist in configuration file
                # and posixuser.get('groups') is a list with element
                # add 'supplementalGroups' if exist in configuration file
                if isinstance( supplementalGroups, list ):
                    for i in range(0,len(supplementalGroups)):
                        # Replace  '{{ supplementalGroups }}' by the posic groups
                        if supplementalGroups[i] == '{{ supplementalGroups }}':
                            del supplementalGroups[i] 
                            posixuser_supplementalGroups =  AuthUser.mksupplementalGroups( posixuser )
                            if isinstance( posixuser_supplementalGroups, list ):
                                for posixuser_supplementalGroup in posixuser_supplementalGroups:
                                    supplementalGroups.append(posixuser_supplementalGroup)
                            break
                else:
                    del securityContext['supplementalGroups']

        return securityContext

    async def add_ephemeral_container_and_watch(
        self,
        pod_name: str,
        container_name: str,
        body: dict,
        timeout_seconds: int = 120,
    ):
        """add_ephemeral_container_and_watch

        Async generator that patches an existing pod with an ephemeral container,
        then watches Kubernetes events for that container and yields progress tuples
        until the container reaches Running, Terminated, or an error state.

        Args:
            pod_name (str): Name of the target pod.
            container_name (str): Name of the ephemeral container being added.
                Used to build the event field selector and to read back the final state.
            body (dict): Patch body in camelCase Kubernetes format, e.g.::

                {
                    "spec": {
                        "ephemeralContainers": [{ ... }]
                    }
                }

            timeout_seconds (int): Per-watch-stream timeout in seconds.
                The generator retries the stream until a terminal state is reached.
                Defaults to 120.

        Yields:
            tuple[int, str, dict]:
                * ``(200, reason, data)``  – normal progress event
                  (reason in {'Pulling', 'Pulled', 'Created', 'Scheduled', 'Started',
                  'Running', 'Terminated', 'Waiting', …})
                * ``(500, reason, data)``  – error/warning event
                * ``data`` always contains at minimum
                  ``{'pod_name': str, 'container_name': str, 'reason': str, 'message': str}``

        Raises:
            TypeError:  if ``pod_name``, ``container_name``, or ``body`` have the wrong type.
            ValueError: if ``patch_namespaced_pod_ephemeralcontainers`` does not return a V1Pod.
            ApiException: for unrecoverable Kubernetes API errors.
        """
        if not isinstance(pod_name, str):
            raise TypeError(f"pod_name must be str, got {type(pod_name)}")
        if not isinstance(container_name, str):
            raise TypeError(f"container_name must be str, got {type(container_name)}")
        if not isinstance(body, dict):
            raise TypeError(f"body must be dict, got {type(body)}")
        if not isinstance(timeout_seconds, int) or timeout_seconds <= 0:
            raise TypeError(f"timeout_seconds must be a positive int, got {timeout_seconds!r}")

        self.logger.debug(
            f"add_ephemeral_container_and_watch pod_name={pod_name} container_name={container_name}"
        )

        # ------------------------------------------------------------------ #
        # 1. Patch the pod to inject the ephemeral container                  #
        # ------------------------------------------------------------------ #
        try:
            pod = await self.kubeapi.patch_namespaced_pod_ephemeralcontainers(
                name=pod_name,
                namespace=self.namespace,
                body=body,
            )
        except ApiException as e:
            self.logger.error(
                f"patch_namespaced_pod_ephemeralcontainers failed for pod={pod_name} "
                f"container={container_name}: {e}"
            )
            raise

        if not isinstance(pod, V1Pod):
            raise ValueError(
                f"patch_namespaced_pod_ephemeralcontainers returned {type(pod)}, V1Pod expected"
            )

        self.logger.debug(
            f"ephemeral container {container_name} injected into pod {pod_name}"
        )

        base_data: dict = {
            "pod_name": pod_name,
            "container_name": container_name,
            "reason": "Injected",
            "message": f"Ephemeral container {container_name} injected into pod {pod_name}",
        }
        yield (200, "Injected", dict(base_data))

        # ------------------------------------------------------------------ #
        # 2. Watch Kubernetes events scoped to the ephemeral container        #
        # ------------------------------------------------------------------ #
        # The field selector targets events whose involvedObject.fieldPath
        # matches "spec.ephemeralContainers{<container_name>}".
        field_selector = (
            f"involvedObject.name={pod_name},"
            f"involvedObject.fieldPath=spec.ephemeralContainers{{{container_name}}}"
        )

        # Reasons that are only meaningful once (deduplicated with this set).
        _DEDUPLICATED_REASONS = frozenset({"Pulling", "Pulled", "Created", "Scheduled"})
        # Reasons that signal the watch loop must stop.
        _TERMINAL_EVENT_REASONS = frozenset({"Started", "Failed", "BackOff", "OOMKilling"})

        seen_reasons: set = set()
        continue_watching = True
        w = watch.Watch()

        try:
            while continue_watching:
                try:
                    async for event in w.stream(
                        self.kubeapi.list_namespaced_event,
                        namespace=self.namespace,
                        field_selector=field_selector,
                        timeout_seconds=timeout_seconds,
                    ):
                        # Guard: event must be a plain dict from the watch stream.
                        if not isinstance(event, dict):
                            self.logger.debug(
                                f"unexpected event type {type(event)}, skipping"
                            )
                            continue

                        event_object = event.get("object")
                        if not isinstance(event_object, CoreV1Event):
                            self.logger.debug(
                                f"event object is not CoreV1Event ({type(event_object)}), skipping"
                            )
                            continue

                        if not isinstance(event_object.involved_object, V1ObjectReference):
                            self.logger.debug(
                                "event_object.involved_object is not V1ObjectReference, skipping"
                            )
                            continue

                        reason: str = event_object.reason or "Unknown"
                        message: str = event_object.message or reason
                        ev_type: str = event_object.type or "Normal"  # "Normal" | "Warning"

                        data = dict(base_data)
                        data["reason"] = reason
                        data["message"] = message
                        data["event_type"] = ev_type

                        self.logger.debug(
                            f"event received type={ev_type} reason={reason} message={message}"
                        )

                        if ev_type == "Warning":
                            # A Warning event is not necessarily fatal but must be reported.
                            self.logger.warning(
                                f"Warning event for container={container_name} "
                                f"reason={reason} message={message}"
                            )
                            yield (500, reason, data)
                            # Non-fatal: let the loop continue unless it is a hard-stop reason.
                            if reason in _TERMINAL_EVENT_REASONS:
                                continue_watching = False
                                w.stop()
                                break

                        elif ev_type == "Normal":
                            if reason in _DEDUPLICATED_REASONS:
                                # Yield once per deduplicated reason.
                                if reason not in seen_reasons:
                                    seen_reasons.add(reason)
                                    self.logger.debug(f"yielding deduplicated reason={reason}")
                                    yield (200, reason, data)

                            elif reason == "Started":
                                # The container has started – stop watching events.
                                self.logger.debug(f"ephemeral container {container_name} started")
                                yield (200, reason, data)
                                continue_watching = False
                                w.stop()
                                break

                            else:
                                # Any other Normal reason: report and keep going.
                                self.logger.debug(
                                    f"normal event reason={reason} message={message}"
                                )
                                yield (200, reason, data)

                        else:
                            # Unknown event type – log and report but do not stop.
                            self.logger.warning(
                                f"unknown event type={ev_type} reason={reason} message={message}"
                            )
                            yield (200, reason, data)

                except ApiException as e:
                    if isinstance(e.reason, str) and e.reason.startswith(
                        "Handshake status 200 OK"
                    ):
                        # Known benign kubernetes-asyncio artefact – ignore and retry.
                        self.logger.debug(f"Handshake 200 ApiException (ignored): {e}")
                    elif (
                        hasattr(e, "status")
                        and e.status == 504
                        and hasattr(e, "reason")
                        and "Too large resource version" in (e.reason or "")
                    ):
                        # Kubernetes watch version drift – retry from scratch.
                        self.logger.debug(
                            f"Too large resource version, retrying watch: {e}"
                        )
                    else:
                        self.logger.error(
                            f"ApiException in list_namespaced_event "
                            f"pod={pod_name} container={container_name}: {e}"
                        )
                        err_data = dict(base_data)
                        err_data["reason"] = "ApiException"
                        err_data["message"] = str(e)
                        yield (500, "ApiException", err_data)
                        continue_watching = False

                except Exception as e:
                    self.logger.error(
                        f"Exception in list_namespaced_event "
                        f"pod={pod_name} container={container_name}: {e}"
                    )
                    err_data = dict(base_data)
                    err_data["reason"] = "Exception"
                    err_data["message"] = str(e)
                    yield (500, "Exception", err_data)
                    continue_watching = False

        finally:
            try:
                await w.close()
            except Exception as e:
                self.logger.error(f"Exception closing watch: {e}")

        # ------------------------------------------------------------------ #
        # 3. Read back the actual container state to confirm final status     #
        # ------------------------------------------------------------------ #
        self.logger.debug(
            f"reading final state for ephemeral container {container_name} in pod {pod_name}"
        )
        final_data = dict(base_data)
        try:
            pod_state = await self.kubeapi.read_namespaced_pod_ephemeralcontainers(
                name=pod_name,
                namespace=self.namespace,
            )
            if not isinstance(pod_state, V1Pod):
                raise ValueError(
                    f"read_namespaced_pod_ephemeralcontainers returned {type(pod_state)}, "
                    "V1Pod expected"
                )

            container_status: V1ContainerStatus | None = None
            if (
                isinstance(pod_state.status, V1PodStatus)
                and isinstance(pod_state.status.ephemeral_container_statuses, list)
            ):
                for cs in pod_state.status.ephemeral_container_statuses:
                    if isinstance(cs, V1ContainerStatus) and cs.name == container_name:
                        container_status = cs
                        break

            if container_status is None:
                # The container status may not be available yet immediately after patch.
                self.logger.debug(
                    f"ephemeral container {container_name} not yet visible in pod status"
                )
                final_data["reason"] = "Pending"
                final_data["message"] = "Container status not yet available"
                yield (200, "Pending", final_data)

            elif not isinstance(container_status.state, V1ContainerState):
                self.logger.warning(
                    f"container {container_name} has no state object"
                )
                final_data["reason"] = "UnknownState"
                final_data["message"] = "Container state object is missing"
                yield (500, "UnknownState", final_data)

            elif isinstance(container_status.state.running, V1ContainerStateRunning):
                started_at = container_status.state.running.started_at
                msg = (
                    started_at.strftime("%Y-%m-%dT%H:%M:%S")
                    if started_at is not None
                    else "Running"
                )
                self.logger.info(
                    f"ephemeral container {container_name} is Running since {msg}"
                )
                final_data["reason"] = "Running"
                final_data["message"] = msg
                yield (200, "Running", final_data)

            elif isinstance(container_status.state.terminated, V1ContainerStateTerminated):
                terminated = container_status.state.terminated
                exit_code: int = terminated.exit_code if terminated.exit_code is not None else -1
                reason_str: str = terminated.reason or "Completed"
                msg = f"{reason_str} (exit_code={exit_code})"
                self.logger.info(
                    f"ephemeral container {container_name} is Terminated: {msg}"
                )
                final_data["reason"] = "Terminated"
                final_data["message"] = msg
                final_data["exit_code"] = exit_code
                http_code = 200 if exit_code == 0 else 500
                yield (http_code, "Terminated", final_data)

            elif isinstance(container_status.state.waiting, V1ContainerStateWaiting):
                wait_reason: str = container_status.state.waiting.reason or "Waiting"
                wait_msg: str = (
                    container_status.state.waiting.message or wait_reason
                )
                self.logger.warning(
                    f"ephemeral container {container_name} is still Waiting: {wait_reason}"
                )
                final_data["reason"] = wait_reason
                final_data["message"] = wait_msg
                yield (500, wait_reason, final_data)

            else:
                self.logger.warning(
                    f"ephemeral container {container_name} has unrecognised state"
                )
                final_data["reason"] = "UnknownState"
                final_data["message"] = "Unrecognised container state"
                yield (500, "UnknownState", final_data)

        except ApiException as e:
            if isinstance(e.reason, str) and e.reason.startswith("Handshake status 200 OK"):
                self.logger.debug(f"Handshake 200 on final status read (ignored): {e}")
            else:
                self.logger.error(
                    f"ApiException reading final state of container={container_name}: {e}"
                )
                final_data["reason"] = "ApiException"
                final_data["message"] = str(e)
                yield (500, "ApiException", final_data)

        except Exception as e:
            self.logger.error(
                f"Exception reading final state of container={container_name}: {e}"
            )
            final_data["reason"] = "Exception"
            final_data["message"] = str(e)
            yield (500, "Exception", final_data)

        self.logger.debug(
            f"add_ephemeral_container_and_watch done pod={pod_name} container={container_name}"
        )

    def getimagecontainerfromauthlabels( self, currentcontainertype:str, authinfo:AuthInfo )->str:
        """getimagecontainerfromauthlabels
            return the name of image to use for a container

        Args:
            currentcontainertype (str): type of container
            authinfo (AuthInfo): authinfo

        Raises:
            ValueError: invalid image type

        Returns:
            str: name of the container image
        """
        assert_type(currentcontainertype, str)
        assert_type(authinfo, AuthInfo)

        imageforcurrentcontainertype = None
        image = oc.od.settings.desktop_pod.get(currentcontainertype,{}).get('image')
        if isinstance( image, str):
            imageforcurrentcontainertype = image
        elif isinstance( image, dict ):
            imageforcurrentcontainertype = image.get('default')
            labels = authinfo.get_labels()
            for k,v in labels.items():
                if image.get(k):
                    imageforcurrentcontainertype=v
                    break
        
        if not isinstance(imageforcurrentcontainertype, str):
            raise ValueError( f"invalid image type for {currentcontainertype} type={type(image)} data={image}")

        return imageforcurrentcontainertype


    @staticmethod
    def appendkubernetesfieldref(envlist:list)->None:
        """appendkubernetesfieldref
            add NODE_NAME POD_NAME POD_NAMESPACE POD_IP
            as
            env:
                - name: NODE_NAME
                    valueFrom:
                    fieldRef:
                        fieldPath: spec.nodeName
                - name: POD_NAME
                    valueFrom:
                    fieldRef:
                        fieldPath: metadata.name
                - name: POD_NAMESPACE
                    valueFrom:
                    fieldRef:
                        fieldPath: metadata.namespace
                - name: POD_IP
                    valueFrom:
                    fieldRef:
                        fieldPath: status.podIP
        Args:
            envlist (list): env list
        """
        assert isinstance(envlist, list),  f"env has invalid type {type(envlist)}, list is expected"
        # kubernetes env formated dict
        envlist.append( { 'name': 'NODE_NAME',      'valueFrom': { 'fieldRef': { 'fieldPath':'spec.nodeName' } } } )
        envlist.append( { 'name': 'POD_NAME',       'valueFrom': { 'fieldRef': { 'fieldPath':'metadata.name' } } } )
        envlist.append( { 'name': 'POD_NAMESPACE',  'valueFrom': { 'fieldRef': { 'fieldPath':'metadata.namespace' } } } )
        envlist.append( { 'name': 'POD_IP',         'valueFrom': { 'fieldRef': { 'fieldPath':'status.podIP' } } } )

    def getPodStartedMessage(self, containernameprefix:str, myPod:V1Pod )->str:
        """getPodStartedMessage

        Args:
            containernameprefix (str): containername
            myPod (V1Pod): pod
            myEvent (CoreV1Event): event

        Returns:
            str: started message

        """

        assert isinstance(containernameprefix, str),  f"env has invalid type {type(containernameprefix)}, str is expected"
        assert isinstance(myPod, V1Pod),  f"myPod has invalid type {type(myPod)}, V1Pod is expected"

        startedmsg = f"b.{myPod.status.phase.lower()}"
        c = self.getcontainerfromPod( containernameprefix, myPod )
        if isinstance( c, V1ContainerStatus):
            startedmsg += f": {c.name} "
            if  c.started is False: 
                startedmsg += "is starting"
            elif c.started is True and c.ready is False:
                startedmsg += "is started"
            elif c.started is True and c.ready is True:
                startedmsg += "is ready"
        return startedmsg

    @staticmethod
    def envdict_to_kuberneteslist(env:dict)->list:
        """ envdict_to_kuberneteslist
            convert env dictionnary to env list format for kubernes
            env = { 'KEY': 'VALUE' }
            return a list of dict key/valye
            envlist = [ { 'name': 'KEY', 'value': 'VALUE' } ]

        Args:
            env (dict): env var dict 

        Returns:
            list: list of { 'name': k, 'value': str(value) }
        """
        assert isinstance(env, dict),  f"env has invalid type {type(env)}, dict is expected"
        envlist = []
        for k, v in env.items():
            # need to convert v as str : kubernetes supports ONLY string type to env value
            envlist.append( { 'name': k, 'value': str(v) } )
        return envlist

    @staticmethod
    def expandchevron_envdict( env: dict, posixuser:dict )->None:
        """expandchevron_envdict
            replace in chevron key
            used for desktop.envlocal 
            env :  {
                'UID'                   : '{{ uidNumber }}',
                'GID'                   : '{{ gidNumber }}',
                'LOGNAME'               : '{{ uid }}'
            }
            by posix account value or default user account values
            example
            env :  {
                'UID'                   : '1024',
                'GID'                   : '2045',
                'LOGNAME'               : 'toto'
            }
        Args:
            env (dict): env var dict 
            posixuser (dict): posix accont dict 
        """
        assert isinstance(env, dict),  f"env has invalid type {type(env)}, dict is expected"
        assert isinstance(posixuser, dict),  f"posixuser has invalid type {type(posixuser)}, dict is expected"
        for k, v in env.items():
            if isinstance( v, str ):
                try:
                    new_value = chevron.render( v, posixuser )
                    env[k] = new_value 
                except Exception:
                    pass
    
    def get_ownerReferences( self, secrets:dict )->list:
        ownerReferences = []
        for name in secrets.keys():
            ownerReference = { 
                'kind': 'Secret', 
                'name': name, 
                'controller': False, 
                'apiVersion': 'v1', 
                'uid': secrets[name].get('uid') 
            }
            ownerReferences.append( ownerReference )
        return ownerReferences   

    def get_executeclasse_for_pod_spec( self, executeclass:dict )->dict:
        if not isinstance( executeclass, dict ):
            return executeclass

        executeclasse_for_pod_spec = executeclass.copy()
        # remove description key
        if executeclasse_for_pod_spec.get('description') is not None:
            del executeclasse_for_pod_spec['description']

        # remove containers key
        if executeclasse_for_pod_spec.get('containers') is not None: 
            del executeclasse_for_pod_spec['containers']
        
        return executeclasse_for_pod_spec
        
        
    def get_executeclasse( self, authinfo:AuthInfo, userinfo:AuthUser, executeclassname:str=None)->dict:
        """get_executeclasse

            return a dict like { 
                'nodeSelector':None, 
                'resources':{
                    'requests':{'memory':"256Mi",'cpu':"100m"},
                    'limits':  {'memory':"1Gi",'cpu':"1000m"}
                },
                'runtimeClassName' : None
            } 


        Args:
            authinfo (AuthInfo): AuthInfo
            userinfo (AuthUser): AuthUser
            executeclassname (str, optional): name of the executeclass. Defaults to None.

        Returns:
            dict: dict executeclasse
        """
        self.logger.debug('')
        executeclass = None
        selectedexecuteclassname = executeclassname

        # if executeclassname is set, read it
        if isinstance( executeclassname, str ):
            executeclass = oc.od.settings.executeclasses.get(executeclassname).copy()
        
        if not isinstance( executeclass, dict ):
            tagexecuteclassname = authinfo.get_labels().get('executeclassname','default')
            if isinstance( tagexecuteclassname, str ) and \
               isinstance( oc.od.settings.executeclasses.get(tagexecuteclassname), dict) :
                    selectedexecuteclassname = tagexecuteclassname
                    executeclass=oc.od.settings.executeclasses.get(tagexecuteclassname).copy()

        # we must return a dict to avoid error 
        if not isinstance( executeclass, dict ):
            executeclassname = 'default'
            executeclass =  oc.od.settings.executeclasses.get(executeclassname).copy()

        if isinstance( executeclass, dict ):
            if executeclass.get('nodeSelector') is None:
                executeclass['nodeSelector'] = oc.od.settings.desktop.get('nodeselector')

        # self.logger.debug(f"executeclass={executeclass}")
        return (selectedexecuteclassname, executeclass)
    


    def get_resources_for_container_type( self, currentcontainertype:str, executeclass:dict )->dict:
        """get_resources_for_container_type
            return the resources dict for a container type from executeclass and desktop settings
        Args:
            currentcontainertype (str): type of container
            executeclass (dict): executeclass dict
        Returns:
            dict: resources dict
        """
        self.logger.debug(locals())
        # rescources is always a dict
        resources = {}
        # read desktop settings resources from executeclass
        if isinstance( executeclass, dict ):
            resources = executeclass.get('containers',{}).get(currentcontainertype,{}).get('resources',{})
        # read desktop settings resources
        currentcontainertype_ressources = oc.od.settings.desktop_pod[currentcontainertype].get('resources')
        if isinstance( currentcontainertype_ressources, dict ):
            resources.update(currentcontainertype_ressources)
        self.logger.debug(f"get_resources_for_container_type {currentcontainertype} return {resources}")
        return resources

    async def read_pod_resources( self, pod_name:str)->dict:
        """read_pod_resources 
            read resource of graphicalcontainer container

        Args:
            pod_name (str): name of pod

        Returns:
            dict: resource of graphicalcontainer container, None if failed
            example {'limits': {'cpu': '1200m', 'memory': '6Gi'}, 'requests': {'cpu': '300m', 'memory': '56Mi'}}
        """
        resources=None
        # read pod 
        self.logger.debug('read_namespaced_pod creating' )  
        try:
            myPod = await self.kubeapi.read_namespaced_pod(namespace=self.namespace,name=pod_name)
            if isinstance(myPod, V1Pod ):
                c = self.getcontainerSpecfromPod( self.graphicalcontainernameprefix, myPod )
                if isinstance( c, V1Container ) and isinstance( c.resources, V1ResourceRequirements ):
                    resources = c.resources.to_dict()
        except ApiException as e:
            pass

        return resources

   
    async def notify_user( self, myDesktop:ODDesktop, method:str, data:dict )->bool:
        """notify_user

        Args:
            myDesktop (ODDesktop): ODDesktop
            method (str): string value can be [ 'ocrun', 'logout', 'container', 'download' ] 
            user pod: 
            from abcdesktopio/oc.user container image 
            source code /composer/node/broadcast-service/broadcast-service.js  
            web front:
            call containerNotificationInfo in webModules files js/launcher.js   
            data (dict): data description
            data = {    'type':  'error' 'warning' 'info' 'deny' 'place'
                        'message':  app.get('name'), 
                        'name':     app.get('name'),
                        'icondata': app.get('icondata'),
                        'icon':     app.get('icon'),
                        'image':    app.get('id'),
                        'launch':   app.get('launch')
            }
        """
        self.logger.debug('')
        bReturn = False
        if not isinstance( myDesktop, ODDesktop):
            return bReturn
        assert_type( method, str )
        assert_type( data, dict )
        command = [ 'node',  '/composer/node/occall/occall.js', method, json.dumps(data) ]
        result = await self.execwaitincontainer( desktop=myDesktop, command=command)
        if isinstance( result, dict):
            bReturn = result.get( 'ExitCode', 1)
        return bReturn

    def rewriteregistry_image( self, repository:str, image:str, registry:str )->str:
        """rewriteregistry_image
            rewrite the image with the registry
            if image is like 'registry.example.com/namespace/image:tag'
            return 'newregistry.example.com/{userid}/namespace/image:tag'

        Args:
            image (str): image name
            registry (str): registry name

        Returns:
            str: rewritten image name
        """
        assert_type( image, str )
        assert_type( registry, str )
        registry_image_split = image.split('/')
        image_name = registry_image_split[-1] # get the last part of the image
        image_name_split = image_name.split(':')
        image_name_no_tag = image_name_split[0] # image name without tag
        tag = image_name_split[-1] # tag is the last part of the image name after ':'
        if isinstance( tag, str ):
            tag_split = tag.split('-')
            if len(tag_split) > 1:
                # if image has a tag endwith 'version-timestamp'
                tag = tag_split[-1]
                if tag.isnumeric():
                    tag = '-'.join(tag_split[:-1])
            
        rewrited_image = f"{registry}/{repository}/{image_name_no_tag}:{tag}"
        return rewrited_image

    async def addcontainertopod( self, authinfo:AuthInfo, userinfo:AuthUser, currentcontainertype:str, myuuid:str, envlist:list, list_volumeMounts:list, workingdir:str=None, command:str=None, executeclass:dict={} )->dict:
        assert_type( authinfo, AuthInfo)
        assert_type( userinfo, AuthUser)
        assert_type( currentcontainertype, str)
        assert_type( myuuid, str)
        assert_type( list_volumeMounts, list )

        container_resources = self.get_resources_for_container_type( currentcontainertype, executeclass )

        self.logger.debug( f"pod container adding {currentcontainertype} to {myuuid}" )
        securityContext = await self.updateSecurityContextWithUserInfo( currentcontainertype, authinfo, userinfo )
        image = self.getimagecontainerfromauthlabels( currentcontainertype, authinfo )
        container = { 
            'name': self.get_containername( authinfo, userinfo, currentcontainertype, myuuid ),
            # 'name': currentcontainertype,
            'imagePullPolicy': oc.od.settings.desktop_pod[currentcontainertype].get('imagePullPolicy', 'IfNotPresent' ),
            'image': image,                             
            'env': envlist,
            'volumeMounts': list_volumeMounts,
            'resources': container_resources           
        }
        if oc.od.settings.desktop_pod.get(currentcontainertype,{}).get('lifecycle') is not None:
            container['lifecycle'] = oc.od.settings.desktop_pod[currentcontainertype]['lifecycle']
        if isinstance( workingdir, str):
            container['workingDir'] = workingdir
        if isinstance( command, list):
            container['command'] = command
        if isinstance( securityContext, dict ) :
            container['securityContext'] = securityContext
        return container



    async def create_vnc_secret( self, authinfo:AuthInfo, userinfo:AuthUser ):
        """create_vnc_secret
            create a random vnc password for a new desktop
            add the vnc password as kubernetes secret

        Args:
            authinfo (AuthInfo): AuthInfo
            userinfo (AuthUser): AuthUser

        Raises:
            ODAPIError: vnc kubernetes secret create failed 
        """
        self.logger.debug('create vnc password as kubernetes secret')
        plaintext_vnc_password = ODVncPassword().getplain()
        vnc_secret = oc.od.secret.ODSecretVNC( self.namespace, self.kubeapi )
        vnc_secret_password = await vnc_secret.create( authinfo=authinfo, userinfo=userinfo, data={ 'password' : plaintext_vnc_password } )
        if not isinstance( vnc_secret_password, V1Secret ):
            raise ODAPIError( f"create vnc kubernetes secret {plaintext_vnc_password} failed" )
        self.logger.debug(f"vnc kubernetes secret set to {plaintext_vnc_password}")


    async def buildinitcommand(self, authinfo:AuthInfo, userinfo:AuthUser )-> list :
        """buildinitcommand
            buildinitcommand to fix volume ownership
            chevronWithUserInfo to replace {} values

        Args:
            authinfo (AuthInfo): AuthInfo
            userinfo (AuthUser): AuthUser
            list_pod_allvolumes (list): list of volumes
            list_pod_allvolumeMounts (list): list of volumeMounts

        Returns:
            list: init command list of str
        """
        self.logger.debug('buildinitcommand to fix volume ownership')
        chevron_command_list = [] # empty list
        command_list = oc.od.settings.desktop_pod.get('init', {} ).get('command')
        if isinstance( command_list, list ):
            chevron_command_list = await self.chevronWithUserInfo( command_list, authinfo, userinfo )
        return chevron_command_list
       

    async def getPodIPAddress( self, pod_name:str )->str:
        """getPodIPAddress
            return the IP Address of the pod name or None
        Args:
            pod_name (str): name of pod

        Returns:
            str: IP Address of the pod, 
            None if Failed or empty value
        """
        IPAddress = None
        try:
            myPod = await self.kubeapi.read_namespaced_pod(namespace=self.namespace,name=pod_name)
            if isinstance( myPod, V1Pod ):
                if isinstance( myPod.status, V1PodStatus ):
                    #  myPod.status.pod_ip : Empty if not yet allocated.
                    if isinstance( myPod.status.pod_ip, str) and len(myPod.status.pod_ip) > 0:     
                        IPAddress = myPod.status.pod_ip
        except Exception as e:
            self.logger.error( e )
        self.logger.debug( f"pod_IPAddress is {IPAddress}" ) 
        return IPAddress

    async def init_snapregistry( self ):
        """init_snap_registry
            initialize the snapshot registry settings
            if not set, return None
        """
        snapshotregistrysecretname = oc.od.settings.desktop.get('snapshotregistrysecretname')
        if not isinstance( snapshotregistrysecretname, str):
            return None
        
        secretDockerConfigjson = oc.od.secret.ODSecretDockerConfigjson( namespace=self.namespace, kubeapi=self.kubeapi, secret_name=snapshotregistrysecretname )
        readdata = await secretDockerConfigjson.read_alldata( None, None )
        if not isinstance( readdata, dict ) or not isinstance( readdata.get('.dockerconfigjson'), dict):
            self.logger.error( f"error in reading snapshot registry secret {snapshotregistrysecretname} data={readdata}" )
            return None 
        try: 
            dockerconfigjson_auths = readdata.get('.dockerconfigjson').get('auths')
            registry_name = list(dockerconfigjson_auths.keys())[0]
            # build the oc.od.settings.snapshot_registry dict
            oc.od.settings.snapshot_registry = dockerconfigjson_auths.get(registry_name).copy() # copy the registry settings
            oc.od.settings.snapshot_registry['registry'] = registry_name # set the registry name
            oc.od.settings.snapshot_registry['protocol'] = oc.od.settings.snapshot_registry_protocol # https in most cases
        except (KeyError, IndexError) as e:
            self.logger.error( f"error in reading snapshot registry secret {snapshotregistrysecretname} data={oc.od.settings.snapshot_registry} {e}")
            return None
        
        self.logger.info( f"snapshot registry initialized registry={oc.od.settings.snapshot_registry.get('registry')} auth={oc.od.settings.snapshot_registry.get('auth')}" )
    
    def get_snapshoted_image( self, authinfo:AuthInfo, userinfo:AuthUser, image:str)->str:
        """get_snapshoted_image
            return the snapshoted image name for a user pod
            if not found, return the original image name

        Args:
            authinfo (AuthInfo): AuthInfo
            userinfo (AuthUser): AuthUser
            image (str): image name

        Returns:
            str: snapshoted image name or None if not found
        """
        assert_type( authinfo, AuthInfo )
        assert_type( userinfo, AuthUser )
        assert_type( image, str )

        new_image = None
        if not isinstance(oc.od.settings.snapshot_registry, dict):
            return None # no snapshot registry defined, return original image
        
        # transform image to a registry/image format
        # 'ghcr.io/abcdesktopio/oc.user.ubuntu.sudo.24.04:4.1'
        # to registy/{userid}/oc.user.ubuntu.sudo.24.04:4.1-{timestamp}
        image_split = image.split('/')
        image_name_only = image_split[-1] # get the last part of the image name
        image_no_tag = image_name_only.split(':')[0] # remove tag if any
        image_name = f"{userinfo.userid}/{image_no_tag}" # add userid to the image name'
        
        # list current images 
        snapshoted_tags = oc.od.registry.list_registry_tags( 
            image_name=image_name, 
            registry=oc.od.settings.snapshot_registry.get('registry'),
            username=oc.od.settings.snapshot_registry.get('username'),
            password=oc.od.settings.snapshot_registry.get('password'),
            protocol=oc.od.settings.snapshot_registry.get('protocol'),
        )

        self.logger.debug( f"snapshoted_tags={snapshoted_tags} for image {image}" )
        if isinstance( snapshoted_tags, str ):
            self.logger.debug( snapshoted_tags )
            return None # error in listing tags, return original image
        
        # current_tag = ''
        # split_image = image.split(':')
        # if len(split_image) > 1:
        #    # image has a tag
        #    current_tag = split_image[:-1]
        new_image = None # default image is None
        default_tag_timestamp = 0 # zero epoch timestamp
        if isinstance( snapshoted_tags, list ) and len(snapshoted_tags) > 0:
            self.logger.debug( f"found snapshoted tags {snapshoted_tags} for image {image}" )
            # find the latest snapshoted image for the user
            for tag in snapshoted_tags:
                if isinstance( tag, str ):
                    splitted_tag = tag.split('-') # tag is like userid-timestamp
                    if len(splitted_tag) > 1:
                        tag_timestamp = splitted_tag[-1]
                    else:
                        self.logger.error( f"invalid tag {tag} for image {image}" )
                        continue

                    # found a snapshoted image for the user
                    try:
                        tag_timestamp = int(tag_timestamp)
                    except ValueError:
                        self.logger.error( f"invalid tag timestamp {tag_timestamp} for image {image}" )
                        continue

                    if tag_timestamp > default_tag_timestamp:
                        default_tag_timestamp = tag_timestamp
                        # found a snapshoted image for the user with the latest timestamp
                        self.logger.debug( f"found a snapshoted image {image} with with the latest timestamp {tag}" )
                        new_image = f"{oc.od.settings.snapshot_registry.get('registry')}/{userinfo.userid}/{image_no_tag}:{tag}"
        
        self.logger.info( f"snapshoted image found {new_image} for {userinfo.userid}" )
        return new_image

    def get_volumemountlistfromcontainertype( self, volumemount:dict, currentcontainertype:str )-> dict:
        """get_volumemountlistfromcontainertype
            return the list of volumeMounts for a container type
        Args:
            volumemount (dict): volumemount dict
            currentcontainertype (str): type of container
        Returns:
            list: list of volumeMount dict
        """        
        assert_type( volumemount, dict )
        assert_type( currentcontainertype, str )
        volumemountlist = {}
        for volumeMount_name in oc.od.settings.desktop_pod.get( currentcontainertype, {}).get('volumes', []):
            if isinstance( volumemount.get( volumeMount_name ), dict ):
                volumemountlist[ volumeMount_name ] = volumemount.get( volumeMount_name )
            else:
                self.logger.warning( f"volumeMount {volumeMount_name} not found for container type {currentcontainertype}" )
        return volumemountlist


    async def areAllmyContainerStarted( self, pod_name:str )->bool:
        """areAllmyContainerstarted
            check if all containers in the pod are started
            return True if all containers in the pod are started, False otherwise

        Args:
            myPod (V1Pod): pod object
        Returns:
            bool: True if all containers are started, False otherwise
        """
        assert isinstance(pod_name, str), f"pod_name has invalid type {type(pod_name)}, str is expected"
        try:
            myPod = await self.kubeapi.read_namespaced_pod(namespace=self.namespace,name=pod_name) 
        except ApiException as e:
            self.logger.error( f"error in reading pod {pod_name} to check if all containers are started: {e}" )
            return False
        assert isinstance(myPod, V1Pod),  f"myPod has invalid type {type(myPod)}, V1Pod is expected"
        if not isinstance( myPod.status, V1PodStatus ):
            return False
        if not isinstance( myPod.status.container_statuses, list):
            return False
        for c in myPod.status.container_statuses:
            if c.started is not True:
                return False
        return True 

    async def createdesktop(self, authinfo:AuthInfo, userinfo:AuthUser, rolesinfo:AuthRoles,  queue:asyncio.Queue, **kwargs) :
        """createdesktop
            create the user pod 

        Args:
            authinfo (AuthInfo): authinfo
            userinfo (AuthUser): userinfo

        Raises:
            ValueError: _description_

        Returns:
            ODDesktop: ( ODDesktop | str ) desktop object or str  
        """
        self.logger.debug('createdesktop start' )
        assert isinstance(authinfo, AuthInfo),  f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo, AuthUser),  f"userinfo has invalid type {type(userinfo)}"

        myDesktop = None # default return object
        env = kwargs.get('env', {} )

        # get the execute class if user has a executeclassname tag
        (executeclassname, executeclasse) = self.get_executeclasse( authinfo, userinfo )
        executeclasse_for_pod_spec = self.get_executeclasse_for_pod_spec( executeclasse )
        self.logger.debug(f"executeclassname={executeclassname} executeclasse_for_pod_spec={executeclasse_for_pod_spec}")

        # add a new VNC Password as kubernetes secret
        await self.create_vnc_secret( authinfo=authinfo, userinfo=userinfo )

        # get posix account user
        posixuser = await self.alwaysgetPosixAccountUser( authinfo, userinfo )

        # create ENV var for pod 
        self.logger.debug('env creating')
        env[ 'XAUTH_KEY' ] = self.generate_xauthkey() # generate XAUTH_KEY
        env[ 'PULSEAUDIO_COOKIE' ] = self.generate_pulseaudiocookie()   # generate PULSEAUDIO cookie
        env[ 'BROADCAST_COOKIE' ] = self.generate_broadcastcookie()     # generate BROADCAST cookie 
        env[ 'HOME' ] = posixuser.get('homeDirectory')  # read HOME DIR 
        env[ 'USER' ] = posixuser.get('uid') # read uid
        env[ 'USERNAME' ] = posixuser.get('uid') # read uid
        env[ 'LOGNAME' ] = posixuser.get('uid') # read uid
        env[ 'PULSE_SERVER' ] = oc.od.settings.desktop['pulseaudiosocketpath'] # set PULSE_SERVER
        env[ 'ABCDESKTOP_EXECUTE_CLASSNAME' ] = executeclassname
        env[ 'ABCDESKTOP_EXECUTE_CLASS' ] = json.dumps(executeclasse)
        env[ 'ABCDESKTOP_RUNTIME_CLASSNAME' ] = executeclasse.get('runtimeClassName','')
        self.logger.debug('env created')

        # create labels for pod
        self.logger.debug('labels creating')
        # build label dictionnary
        labels = { 
            'abcdesktop/role': self.abcdesktop_role_desktop,
            'access_provider': authinfo.provider,
            'access_providertype': authinfo.providertype,
            'access_userid': userinfo.userid,
            'access_username': self.get_labelvalue(userinfo.name), # only for human readable label, not for logic use, because userinfo.name can contains special character and is not unique
            'netpol/ocuser': 'true',
            'xauthkey': env[ 'XAUTH_KEY' ], 
            'pulseaudio_cookie': env[ 'PULSEAUDIO_COOKIE' ],
            'broadcast_cookie': env[ 'BROADCAST_COOKIE' ],
            'type': self.x11servertype
        }
        # add authinfo labels and env 
        # could also use downward-api https://kubernetes.io/docs/concepts/workloads/pods/downward-api/
        for k,v in authinfo.get_labels().items():
            if k.isalnum(): # only add alpanum label to avoid issue with kubernetes label validation, and only for env var, not for labels because we can use normalize_name_label for labels
                abcdesktopvarenvname = oc.od.settings.ENV_PREFIX_LABEL_NAME + k.lower()
                env[ abcdesktopvarenvname ] = v
                labels[oc.auth.namedlib.normalize_label(k)] = oc.auth.namedlib.normalize_label(v)

        for k,v in rolesinfo.items():
            label_value = 'true'
            if v is not None: 
                label_value = oc.auth.namedlib.normalize_label(v) 
            labels[oc.auth.namedlib.normalize_label(k)] = label_value 

        # add enabled services in env dict 
        for currentcontainertype in self.nameprefixdict.keys() :
            if self.isenablecontainerinpod( authinfo, currentcontainertype ):
                abcdesktopvarenvname = oc.od.settings.ENV_PREFIX_SERVICE_NAME + currentcontainertype
                env[ abcdesktopvarenvname ] = 'enabled'
        self.logger.debug('labels created')

        # create pod name
        # pod uuid suffix
        myuuid = oc.lib.uuid_digits()
        pod_name = await self.get_podname( authinfo, userinfo, myuuid ) 

        self.logger.debug('envlist creating')
        # replace  'UID' : '{{ uidNumber }}' by value 
        # expanded chevron value to the user value
        ODOrchestratorKubernetes.expandchevron_envdict( env, posixuser )
        # convert env dictionnary to env list format for kubernetes
        envlist = ODOrchestratorKubernetes.envdict_to_kuberneteslist( env )
        ODOrchestratorKubernetes.appendkubernetesfieldref( envlist )
        self.logger.debug('envlist created')

        # look for desktop rules
        # apply network rules 
        self.logger.debug('rules creating')   
        rules = oc.od.settings.desktop['policies'].get('rules')
        self.logger.debug(f"policies.rules is defined {rules}")
        network_config = ODOrchestrator.applyappinstancerules_network( authinfo, rules )
        fillednetworkconfig = self.filldictcontextvalue(
            authinfo=authinfo, 
            userinfo=userinfo, 
            desktop=None, 
            network_config=copy.deepcopy(network_config), 
            network_name = None, 
            appinstance_id = None 
        )
        self.logger.debug('rules created')

        # new step
        # self.on_desktoplaunchprogress('b.Building data storage for your desktop')
        queue.put_nowait(( 100, 'b.Building data storage for your desktop' ))

        # get secrets_requirement for 'graphical'
        currentcontainertype = 'graphical'
        graphical_secrets_requirement = oc.od.settings.desktop_pod.get(currentcontainertype,{}).get('secrets_requirement')     
        # ownerReferences = self.get_ownerReferences(mysecretdict)

        self.logger.debug('volumes creating')
        shareProcessNamespace = oc.od.settings.desktop_pod.get('spec',{}).get('shareProcessNamespace', False)
        tolerations = oc.od.settings.desktop_pod.get('spec',{}).get('tolerations')

        # all volumes and secrets
        (pod_allvolumes, pod_allvolumeMounts) = await self.build_volumes( 
            authinfo, 
            userinfo, 
            queue, 
            volume_type='pod_desktop', 
            secrets_requirement=['all'], 
            rules=rules,  
            **kwargs)

        # graphical volumes
        ( _, graphical_volumeMounts) = await self.build_volumes( 
            authinfo, 
            userinfo, 
            queue, 
            volume_type='pod_desktop',
            secrets_requirement=graphical_secrets_requirement,
            rules=rules,
            **kwargs)
        
        self.logger.debug('volumes created')

        # snapshot volumes
        # check if snapshot is enabled for desktop pod
        snapshot_volumes = None
        snapshot_volumes_mount = None
        if oc.od.settings.desktop_pod.get('snapshot', {}).get('enable', False) is True:
            (snapshot_volumes, snapshot_volumes_mount) = self.build_volumes_snapshot()  # add snapshot volumes


        self.logger.debug('websocketrouting creating')
        # check if we have to build X509 certificat
        # need to build certificat if websocketrouting us bridge 
        # bridge can be a L2/L3 level like ipvlan, macvlan
        # use multus config
        websocketrouting = oc.od.settings.websocketrouting # set defautl value, can be overwritten 
        websocketroute = None
        if  fillednetworkconfig.get( 'websocketrouting' ) == 'bridge' :
            # no filter if container ip addr use a bridged network interface
            envlist.append( { 'name': 'DISABLE_REMOTEIP_FILTERING', 'value': 'enabled' })
            # if we need to request an X509 certificat on the fly
            external_dnsconfig = fillednetworkconfig.get( 'external_dns' )
            if  type( external_dnsconfig ) is dict and \
                type( external_dnsconfig.get( 'domain' ))   is str and \
                type( external_dnsconfig.get( 'hostname' )) is str :
                websocketrouting = fillednetworkconfig.get( 'websocketrouting' )
                websocketroute = f"{external_dnsconfig.get( 'hostname' )}.{external_dnsconfig.get( 'domain' )}"
                envlist.append( { 'name': 'USE_CERTBOT_CERTONLY', 'value': 'enabled' } )
                envlist.append( { 'name': 'EXTERNAL_DESKTOP_HOSTNAME', 'value': external_dnsconfig.get( 'hostname' ) } )
                envlist.append( { 'name': 'EXTERNAL_DESKTOP_DOMAIN', 'value': external_dnsconfig.get( 'domain' ) } )
                labels['websocketrouting'] = websocketrouting
                labels['websocketroute'] = websocketroute
        self.logger.debug('websocketrouting created')

        initContainers = []
        currentcontainertype = 'init'
        if self.isenablecontainerinpod( authinfo, currentcontainertype ):
            # build the init command to fix volume ownership
            command = await self.buildinitcommand( authinfo, userinfo )
            # get volumeMounts for init container
            list_containervolumeMounts = self.get_volumemountlistfromcontainertype( pod_allvolumeMounts, currentcontainertype )
            # get init_localaccount_volumes and init_localaccount_volumes_mount
            (init_localaccount_volumes, init_localaccount_volumes_mount) = await self.build_volumes_localaccount(authinfo, userinfo )
            # add init_localaccount_volumes to pod volumes
            pod_allvolumes.update( init_localaccount_volumes )
            # add init_localaccount_volumes_mount to init container
            list_containervolumeMounts.update( init_localaccount_volumes_mount )

            if len(command) > 0: # if the command line is requested by configuration file 
                init_container = await self.addcontainertopod( 
                    authinfo=authinfo, 
                    userinfo=userinfo, 
                    currentcontainertype=currentcontainertype, 
                    command=command,
                    myuuid=myuuid,
                    envlist=envlist,
                    list_volumeMounts=list( list_containervolumeMounts.values() ),
                    executeclass=executeclasse )
                initContainers.append( init_container )
                self.logger.debug( f"pod container added {currentcontainertype}" )
            else:
                self.logger.debug( f"skipping {currentcontainertype} init command={command}" )

        # default empty dict annotations
        annotations = {}
        # add last login datetime to annotations for garbage collector
        annotations.update( self.get_annotations_lastlogin_datetime() )
        # Check if a network annotations exists 
        network_annotations = network_config.get( 'annotations' )
        if isinstance( network_annotations, dict):
            annotations.update( network_annotations )

        # set default dns configuration 
        dnspolicy = oc.od.settings.desktop['dnspolicy']
        dnsconfig = oc.od.settings.desktop['dnsconfig']

        # overwrite default dns config by rules
        if type(network_config.get('internal_dns')) is dict:
            dnspolicy = 'None'
            dnsconfig = network_config.get('internal_dns')

        for currentcontainertype in oc.od.settings.desktop_pod.keys() :
            if self.isenablecontainerinpod( authinfo, currentcontainertype ):
                label_servicename = 'service_' + currentcontainertype
                # tcpport is a number, convert it as str for a label value
                label_value = str( oc.od.settings.desktop_pod[currentcontainertype].get('tcpport','enabled') )
                labels.update( { label_servicename: label_value } )

        specssecurityContext = await self.updateSecurityContextWithUserInfo( currentcontainertype='spec', authinfo=authinfo, userinfo=userinfo )

        # give the give pull secret for the desktop pod
        imagePullSecrets = self.giveme_an_imagePullSecrets()
        # set the hostname for the desktop pod
        hostname = oc.auth.namedlib.normalize_name_dnsname( userinfo.userid )

        if oc.od.settings.desktop_pod.get('snapshot', {}).get('enable') is True and isinstance(snapshot_volumes, dict) : 
            pod_allvolumes.update( snapshot_volumes.get('snapshot') ) 

        # define pod_manifest
        pod_manifest = {
            'apiVersion': 'v1',
            'kind': 'Pod',
            'metadata': {
                'name': pod_name,
                'namespace': self.namespace,
                'labels': labels,
                'annotations': annotations
                # 'ownerReferences': ownerReferences
            },
            'spec': {
                'hostname': hostname,
                'dnsPolicy' : dnspolicy,
                'dnsConfig' : dnsconfig,
                'subdomain': self.endpoint_domain,
                'automountServiceAccountToken': False,  # disable service account inside pod
                'shareProcessNamespace': shareProcessNamespace,
                'volumes': list( pod_allvolumes.values() ),                    
                'initContainers': initContainers,
                'imagePullSecrets': imagePullSecrets,
                'securityContext': specssecurityContext,
                'tolerations': tolerations,
                'containers': [],
                **executeclasse_for_pod_spec
            }
        }

        # Add graphical servives 
        currentcontainertype='graphical'
        if  self.isenablecontainerinpod( authinfo, currentcontainertype ):
            self.logger.debug( f"adding graphical container to pod {pod_name} with executeclasse={executeclasse}" )
            graphical_container = await self.addcontainertopod( 
                authinfo=authinfo, 
                userinfo=userinfo, 
                currentcontainertype=currentcontainertype, 
                myuuid=myuuid,
                envlist=envlist,
                workingdir=env['HOME'],
                list_volumeMounts=list( graphical_volumeMounts.values() ),
                executeclass=executeclasse
            )
            # overwrite image value if a snapshoted image exists for this user
            if oc.od.settings.desktop_pod.get('snapshot', {}).get('enable') is True:
                snapshoted_image = self.get_snapshoted_image( authinfo, userinfo, image=graphical_container['image'] )
                if isinstance( snapshoted_image, str ) and len(snapshoted_image) > 0:
                    # replace the image with the snapshoted image
                    graphical_container['image'] = snapshoted_image
                    # set imagePullPolicy to Always to always pull the snapshoted image
                    graphical_container['imagePullPolicy'] = 'Always' 
                    # and use the snapshotregistrysecretname if defined
                    self.logger.debug(f"snapshoted image {snapshoted_image} used for {currentcontainertype} container" )
            # add graphical container to pod manifest     
            pod_manifest['spec']['containers'].append( graphical_container )
            self.logger.debug(f"pod container created {currentcontainertype}" )

        localaccount_volume_name = await self.get_volumes_localaccount_name( authinfo=authinfo, userinfo=userinfo )
        assert isinstance(localaccount_volume_name, str),  f"localaccount secret volume is not found"
        
        containers_list = [ 'printer', 'sound', 'ssh', 'filer' ]
        
        for currentcontainertype in containers_list:
            if  self.isenablecontainerinpod( authinfo, currentcontainertype ):
                list_containervolumeMounts = self.get_volumemountlistfromcontainertype( pod_allvolumeMounts, currentcontainertype )
                new_container = await self.addcontainertopod( 
                    authinfo=authinfo, 
                    userinfo=userinfo, 
                    currentcontainertype=currentcontainertype, 
                    myuuid=myuuid,
                    envlist=envlist,
                    list_volumeMounts=list( list_containervolumeMounts.values() ),
                    executeclass=executeclasse
                )
                pod_manifest['spec']['containers'].append( new_container )
                self.logger.debug(f"container added {currentcontainertype} to pod {pod_name}")

        # add snapshot container if enabled
        # snasphot is a special container
        # it need some secrets env variables
        currentcontainertype = 'snapshot'
        if  self.isenablecontainerinpod( authinfo, currentcontainertype ) and \
            isinstance( snapshot_volumes_mount, dict) and \
            isinstance( oc.od.settings.snapshot_registry, dict) :
            snapshotenvlist = copy.deepcopy(envlist)
            for key in [ 'registry', 'username', 'password' ]:
                snapshotenvlist.append( { 'name': f'SNAPSHOT_REGISTRY_{key.upper()}', 'value': oc.od.settings.snapshot_registry.get(key) } )
            snapshotenvlist.append( { 'name': 'SNAPSHOT_REGISTRY_PROTOCOL', 'value': oc.od.settings.desktop.get('snapshotregistryprotocol', 'https') } ) # add snapshot registry protocol
            # add snapshot registry secret name if defined
            snapshotenvlist.append( { 'name': 'SNAPSHOT_CONTAINER_NAME', 'value': graphical_container.get('name')  } )
            rewrited_image = self.rewriteregistry_image( repository=userinfo.userid, image=graphical_container.get('image'), registry=oc.od.settings.snapshot_registry.get('registry') )
            snapshotenvlist.append( { 'name': 'SNAPSHOT_CONTAINER_TARGET_IMAGE', 'value': rewrited_image } )
            snapshotenvlist.append( { 'name': 'SNAPSHOT_CONTAINER_SOURCE_IMAGE', 'value': graphical_container.get('image') } )
            new_container = await self.addcontainertopod( 
                authinfo=authinfo,
                userinfo=userinfo, 
                currentcontainertype=currentcontainertype, 
                myuuid=myuuid,
                envlist=snapshotenvlist,
                list_volumeMounts=[ snapshot_volumes_mount.get('snapshot') ]
            )
            pod_manifest['spec']['containers'].append( new_container )
            self.logger.debug(f"container added {currentcontainertype} to pod {pod_name}")

        # we are ready to create our Pod 
        myDesktop = None
        queue.put_nowait((100, 'b.Building data storage for your desktop'))
        jsonpod_manifest = json.dumps( pod_manifest, indent=2 )
        # keep LOG LEVEL to INFO in yaml dump
        # to keep data in syslog 
        self.logger.info('dump create pod_manifest json pod')
        self.logger.info(jsonpod_manifest)

        pod = await self.kubeapi.create_namespaced_pod( namespace=self.namespace, body=pod_manifest )

        if not isinstance(pod, V1Pod ):
            raise ValueError( f"Invalid create_namespaced_pod type return {type(pod)} V1Pod is expecting")

        queue.put_nowait( (100, f"b.Watching for events") )
        self.logger.debug('watch list_namespaced_event pod creating' )
        pulled_counter = 0 
        expected_containers_len = 0
        if isinstance( pod.spec.init_containers, list ):
            expected_containers_len += len( pod.spec.init_containers )
        if isinstance( pod.spec.containers, list ):
            expected_containers_len += len( pod.spec.containers )

        continue_reading_events = True
        w = watch.Watch()
        while continue_reading_events:
            try:
                # watch list_namespaced_event
                async for event in w.stream(  self.kubeapi.list_namespaced_event, 
                                        namespace=self.namespace, 
                                        timeout_seconds=oc.od.settings.desktop['K8S_CREATE_POD_TIMEOUT_SECONDS'],
                                        field_selector=f'involvedObject.name={pod_name}'):
                    
                    if not isinstance(event, dict ): continue # safe type test event is a dict
                    if not isinstance(event.get('object'), CoreV1Event ): continue # safe type test event object is a CoreV1Event
                    event_object = event.get('object')
                    # self.logger.debug(f"{event_object.type} reason={event_object.reason} message={event_object.message}")
                    queue.put_nowait( (100, f"b.{event_object.message}") )

                    #
                    # https://github.com/kubernetes-client/python/blob/master/kubernetes/docs/CoreV1Event.md
                    # Type of this event (Normal, Warning), new types could be added in the future
                    # 'Normal':  Information only and will not cause any problems
                    # 'Warning': These events are to warn that something might go wrong

                    if event_object.type == 'Warning':  # event Warning
                        # something might goes wrong
                        self.logger.error(f"{event_object.type} reason={event_object.reason} message={event_object.message}")
                        w.stop()
                        queue.put_nowait( (100,  f"{event_object.type} {event_object.reason} {event_object.message}") )

                    elif event_object.type == 'Normal': # event Normal

                        if event_object.reason in [ 'Created', 'Pulling', 'Scheduled' ]:
                            continue # nothing to do

                        # check reason, read 
                        # https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/events/event.go
                        # reason should be a short, machine understandable string that gives the reason for the transition 
                        # into the object's current status.
                        if event_object.reason == 'Pulled':
                            self.logger.debug( f"Event Pulled received pulled_counter={pulled_counter}")
                            #pulledmyPod = self.kubeapi.read_namespaced_pod(namespace=self.namespace,name=pod_name) 
                            pulled_counter = pulled_counter + 1
                            # if all images are pulled 
                            self.logger.debug( f"counter pulled_counter={pulled_counter} expected_containers_len={expected_containers_len}")
                            if pulled_counter >= expected_containers_len :
                                self.logger.debug( f"counter pulled_counter={pulled_counter} >= expected_containers_len={expected_containers_len}")
                                # pod_IPAddress = self.getPodIPAddress( pod.metadata.name )
                                # if isinstance( pod_IPAddress, str ):
                                #    self.logger.debug( f"{pod.metadata.name} has an ip address: {pod_IPAddress}")
                                #    self.on_desktoplaunchprogress(f"b.Your pod {pod.metadata.name} gets ip address {pod_IPAddress} from network plugin")
                                #    self.logger.debug( f"stop watching event list_namespaced_event for pod {pod.metadata.name} ")
                                continue_reading_events = False
                                w.stop()

                        elif event_object.reason == 'Started':                      
                            if await self.areAllmyContainerStarted( pod_name=pod_name ) is True:
                                continue_reading_events = False
                                w.stop()
                            else: 
                                self.logger.debug(f"Event Started received but not all containers are started, continue watching {pod_name}")
                                continue
                        else:
                            # log the events
                            self.logger.debug(f"{event_object.type} reason={event_object.reason} message={event_object.message}")
                            queue.put_nowait( (100, f"b.Your pod gets event {event_object.message or event_object.reason}") )
                            # fix for https://github.com/abcdesktopio/oc.user/issues/52
                            # this is not an error
                            continue_reading_events = False
                            w.stop()
                        
                    else: 
                        # this event is not 'Normal' or 'Warning', unknow event received
                        self.logger.error(f"UNMANAGED EVENT pod type {event_object.type}")
                        continue_reading_events = False
                        w.stop()

            except ApiException as e:
                if hasattr(e, 'status') and e.status == 504 and \
                   hasattr(e, 'reason') and 'Too large resource version' in e.reason :
                    self.logger.debug( f"retrying after Timeout: Too large resource version ApiException {e}")
                else:
                    continue_reading_events = False
                    self.logger.error( f"{type(e)} {e}" )
    
            except Exception as e:
                self.logger.error( f"Exception: {e}" )
                continue_reading_events = False

        try:
            await w.close()
        except Exception as e:
            self.logger.error( f"Exception when closing watch: {e}" )

        #
        # list_namespaced_event done
        #
        self.logger.debug('watch list_namespaced_pod creating, waiting for pod quit Pending phase' )
        continue_reading_events = True
        w = watch.Watch()
        while continue_reading_events:
            try:               
                async for event in w.stream( 
                                    self.kubeapi.list_namespaced_pod, 
                                    namespace=self.namespace, 
                                    timeout_seconds=oc.od.settings.desktop['K8S_CREATE_POD_TIMEOUT_SECONDS'],
                                    field_selector=f"metadata.name={pod_name}" ):  
                     
                    if not isinstance(event,dict): continue # event must be a dict, else continue
                    event_type = event.get('type')  # event dict must contain a type 
                    pod_event = event.get('object') # event dict must contain a pod object 
                    if not isinstance( pod_event, V1Pod ): continue  # if podevent type must be a V1Pod
                    if not isinstance( pod_event.status, V1PodStatus ): continue
                    
                    queue.put_nowait( (100, f"b.Your {pod_event.kind.lower()} is {event_type.lower()}") )
                    self.logger.debug(f"The pod {pod_event.metadata.name} is in phase={pod_event.status.phase}" )
                    #
                    # from https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/
                    #
                    # possible values for phase
                    # Pending	The Pod has been accepted by the Kubernetes cluster, but one or more of the containers has not been set up and made ready to run. This includes time a Pod spends waiting to be scheduled as well as the time spent downloading container images over the network.
                    # Running	The Pod has been bound to a node, and all of the containers have been created. At least one container is still running, or is in the process of starting or restarting.
                    # Succeeded	All containers in the Pod have terminated in success, and will not be restarted.
                    # Failed	All containers in the Pod have terminated, and at least one container has terminated in failure.
                    # Unknown	For some reason the state of the Pod could not be obtained. This phase typically occurs due to an error in communicating with the node where the Pod should be running.
                    if pod_event.status.phase == 'Pending' :
                        queue.put_nowait( (100, f"b.Your pod {pod_event.metadata.name} is {pod_event.status.phase}") )
                        continue
                    elif pod_event.status.phase == 'Running' :
                        # look if graphicalcontainernameprefix is ready
                        startedmsg = self.getPodStartedMessage( containernameprefix=self.graphicalcontainernameprefix, myPod=pod_event)
                        queue.put_nowait( (100, startedmsg) )
                        continue_reading_events = False
                        w.stop()
                    elif pod_event.status.phase in {'Succeeded', 'Failed'} :
                        # pod data object is complete, stop reading event
                        # phase can be 'Running' 'Succeeded' 'Failed' 'Unknown'
                        self.logger.debug(f"The pod {pod_event.metadata.name} is not in Pending phase, phase={pod_event.status.phase} stop watching" )
                        continue_reading_events = False
                        w.stop()
                    else:
                        # pod_event.status.phase should be 'Unknow'
                        self.logger.error(f"UNMANAGED CASE pod {pod_event.metadata.name} is in unmanaged phase {pod_event.status.phase}")
                        self.logger.error(f"The pod {pod_event.metadata.name} is in phase={pod_event.status.phase} stop watching" )
                        continue_reading_events = False
                        w.stop()
            
            except ApiException as e:
                if hasattr(e, 'status') and e.status == 504 and \
                   hasattr(e, 'reason') and 'Too large resource version' in e.reason :
                    self.logger.debug( f"retrying after Timeout: Too large resource version ApiException {e}")
                else:
                    continue_reading_events = False
                    self.logger.error( f"{e}" )
    
            except Exception as e:
                self.logger.error( f"{e}" )
                continue_reading_events = False

        try:
            await w.close()
        except Exception as e:
            self.logger.error( f"Exception when closing watch: {e}" )

        self.logger.debug(f"watch list_namespaced_pod created, the pod is no more in Pending phase" )

        # read pod again
        self.logger.debug(f"read_namespaced_pod {pod_name} again" )
        myPod = await self.kubeapi.read_namespaced_pod(namespace=self.namespace,name=pod_name)   
        assert isinstance(myPod, V1Pod),  f"read_namespaced_pod returns type {type(myPod)} V1Pod is expected"
        assert isinstance(myPod.status, V1PodStatus), f"read_namespaced_pod returns pod.status type {type(myPod.status)} V1PodStatus is expected"
        self.logger.debug( f"myPod.metadata.name {myPod.metadata.name} is {myPod.status.phase} with ip {myPod.status.pod_ip}" )

        # The pod is not in Pending
        # read the status.phase, if it's not Running 
        if myPod.status.phase != 'Running':
            # something wrong 
            msg =  f"e.Your pod does not start, status is {myPod.status.phase} reason is {myPod.status.reason} message {myPod.status.message}" 
            if queue: queue.put_nowait( (500, msg ))
        else:
            if queue: queue.put_nowait( (100, f"b.Your pod is {myPod.status.phase}."))

        myDesktop = await self.pod2desktop( pod=myPod, authinfo=authinfo, userinfo=userinfo)
        self.logger.debug(f"desktop phase:{myPod.status.phase} has interfaces properties {myDesktop.desktop_interfaces}")
        self.logger.debug('watch filldictcontextvalue creating' )
        # set desktop web hook
        # webhook is None if network_config.get('context_network_webhook') is None
        fillednetworkconfig = self.filldictcontextvalue(authinfo=authinfo, 
                                                        userinfo=userinfo, 
                                                        desktop=myDesktop, 
                                                        network_config=network_config, 
                                                        network_name = None, 
                                                        appinstance_id = None )

        myDesktop.webhook = fillednetworkconfig.get('webhook')
        self.logger.debug('createdesktop end' )
        
        return myDesktop

  
    
    async def findPodByUser(self, authinfo:AuthInfo, userinfo:AuthUser )->V1Pod:
        """find a kubernetes pod for the user ( userinfo )
           if args is None, filter add always type=self.x11servertype
           if args is { 'pod_name'=name } add filter metadata.name=name without type selector

           findPodByUser return only Pod in running state 
           'Terminating' or 'Deleting' pod are skipped
            
        Args:
            authinfo (AuthInfo): authentification data
            userinfo (AuthUser): user data 
            args (dict, optional): { 'pod_name'=name of pod }. Defaults to None.

        Returns:
            V1Pod: kubernetes.V1Pod or None if not found
        """
        self.logger.debug('')
        assert isinstance(authinfo, AuthInfo),  f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo, AuthUser),  f"userinfo has invalid type {type(userinfo)}"

        access_userid = userinfo.userid

        try: 
            label_selector = 'access_userid=' + access_userid + ',type=' + self.x11servertype
        
            if isinstance( authinfo, AuthInfo) and oc.od.settings.desktop['authproviderneverchange'] is True:
                label_selector += ',' + 'access_provider='  + authinfo.provider   

            #
            # pod_name = None
            # if type(args) is dict:
            #     pod_name = args.get( 'pod_name' )
            # if pod_name is set, don't care about the type
            # type can be type=self.x11servertype or type=self.x11embededservertype
            # if type( pod_name ) is str :
            #    field_selector =  'metadata.name=' + pod_name
            # else :    
            #    label_selector += ',type=' + self.x11servertype
            #

            myPodList = await self.kubeapi.list_namespaced_pod(self.namespace, label_selector=label_selector)

            if isinstance(myPodList, V1PodList) :
                for myPod in myPodList.items:
                    myPhase = myPod.status.phase
                    # keep only Running pod
                    if isinstance( myPod.metadata.deletion_timestamp, datetime.datetime ):
                       continue
                    if myPhase in [ 'Running', 'Pending', 'Succeeded' ] :  # 'Init:0/1'
                        return myPod                    
                    
        except ApiException as e:
            self.logger.debug(e)
        
        return None

    async def isPodBelongToUser( self, authinfo:AuthInfo, userinfo:AuthUser, pod_name:str)->bool:
        """isPodBelongToUser
            return True if pod belongs to userinfo.userid and macth same auth provider
            else False
        Args:
            authinfo (AuthInfo): authinfo
            userinfo (AuthUser): userinfo
            pod_name (str): name of pod

        Returns:
            bool: boolean 
        """
        self.logger.debug('')
        assert isinstance(authinfo, AuthInfo),  f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo, AuthUser),  f"userinfo has invalid type {type(userinfo)}"
        assert isinstance(pod_name, str),       f"pod_name has invalid type {type(pod_name)}"

        belong = False # default value
        myPod = await self.kubeapi.read_namespaced_pod(namespace=self.namespace,name=pod_name )
        if isinstance( myPod, V1Pod ):
            (pod_authinfo,pod_userinfo) = self.extract_userinfo_authinfo_from_pod(myPod)
            if  authinfo.provider == pod_authinfo.provider and \
                userinfo.userid   == pod_userinfo.userid :
                belong = True
        return belong

    async def findDesktopByUser(self, authinfo:AuthInfo, userinfo:AuthUser )->ODDesktop:
        """findDesktopByUser
            find a desktop for authinfo and userinfo 
            return a desktop object
            return None if not found 
        Args:
            authinfo (AuthInfo): authinfo
            userinfo (AuthUser): userinfo

        Returns:
            ODDesktop: ODDesktop object
        """
        self.logger.debug('')
        assert isinstance(authinfo, AuthInfo),  f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo, AuthUser),  f"userinfo has invalid type {type(userinfo)}"
        myDesktop = None  # return Desktop Object
        myPod = await self.findPodByUser( authinfo, userinfo )
        if isinstance(myPod, V1Pod ):
            self.logger.debug( f"Pod is found {myPod.metadata.name}" )
            myDesktop = await self.pod2desktop( pod=myPod, authinfo=authinfo, userinfo=userinfo )
        return myDesktop

    def getcontainerfromPod( self,  prefix:str, pod:V1Pod ) -> V1ContainerStatus:
        """getcontainerfromPod
            return the v1_container_status of a container inside a pod

        Args:
            prefix (str): container prefix
            pod (V1Pod): pod

        Returns:
            V1ContainerStatus: return v1_container_status, None if unreadable
        """
        assert isinstance(prefix,str), f"prefix invalid type {type(prefix)}"
        assert isinstance(pod,V1Pod) , f"pod invalid type {type(pod)}"
        # get the container id for the desktop object
        if isinstance( pod.status, V1PodStatus):
            if isinstance( pod.status.container_statuses, list):
                for c in pod.status.container_statuses:
                    if hasattr( c, 'name') and isinstance(c.name, str ) and c.name[0] == prefix:
                        return c
        return None

    def getfirstcontainerfromPod( self, pod:V1Pod ) -> V1Container:
        """getcontainerfromPod
            return the v1_container_status of a container inside a pod

        Args:
            pod (V1Pod): pod

        Returns:
            V1ContainerStatus: return v1_container_status, None if unreadable
        """
        assert isinstance(pod,V1Pod) , f"pod invalid type {type(pod)}"
        # get the container id for the desktop object
        if isinstance( pod.spec, V1PodSpec):
            if isinstance( pod.spec.containers, list) and len(pod.spec.containers) > 0:
                return pod.spec.containers[0]
        return None

    def getcontainerSpecfromPod( self,  prefix:str, pod:V1Pod ) -> V1Container:
        """getcontainerfromPod
            return the v1_container_status of a container inside a pod

        Args:
            prefix (str): container prefix
            pod (V1Pod): pod

        Returns:
            V1PodSpec: return v1_container_status, None if unreadable
        """
        assert isinstance(prefix,str), f"prefix invalid type {type(prefix)}"
        assert isinstance(pod,V1Pod) , f"pod invalid type {type(pod)}"

        # get the container id for the desktop object
        if isinstance( pod.spec, V1PodSpec):
            if isinstance( pod.spec.containers, list):
                for c in pod.spec.containers:
                    if hasattr( c, 'name') and isinstance(c.name, str ) and c.name[0] == prefix:
                        return c
        return None

    def build_internalPodFQDN( self, myPod: V1Pod )->str:
        """build_internalPodFQDN

        Args:
            myPod (V1Pod): pod

        Returns:
            str: pod internal FQDH
        """
        assert isinstance(myPod,      V1Pod),    f"pod has invalid type {type(myPod)}"
        # From https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/#pods:
        # From https://github.com/coredns/coredns/issues/2409 
        # If there exists a headless service in the same namespace as the pod and with the same name
        # as the subdomain, the cluster’s KubeDNS Server also returns an A record for the Pod’s fully
        # qualified hostname. For example, given a Pod with the hostname set to “busybox-1” and the
        # subdomain set to “default-subdomain”, and a headless Service named “default-subdomain” in
        # the same namespace, the pod will see its own FQDN as
        # “busybox-1.default-subdomain.my-namespace.svc.cluster.local
        # 
        defaultFQDN = None
        if oc.od.settings.desktop['useinternalfqdn'] and isinstance(oc.od.settings.kubernetes_default_domain, str ):
            defaultFQDN = myPod.metadata.name + '.' + myPod.spec.subdomain + '.' + oc.od.settings.kubernetes_default_domain
        return defaultFQDN

    def pod2desktop_reduced( self, pod:V1Pod, authinfo:AuthInfo=None, userinfo:AuthUser=None )->ODDesktop:
        """pod2Desktop convert a Pod to Desktop Object
        Args:
            myPod ([V1Pod): kubernetes.V1Pod
            userinfo ([]): userinfo set to None by default
                           to obtain vnc_password, defined userinfo context 
        Returns:
            [ODesktop]: oc.od.desktop.ODDesktop Desktop Object
        """
        assert isinstance(pod,V1Pod),    f"pod has invalid type {type(pod)}"

        desktop_container_id   = None
        desktop_container_name = None
        desktop_interfaces     = None

        # read metadata annotations 'k8s.v1.cni.cncf.io/network-status'
        # to get the ip address of each netwokr interface
        network_status = None
        if isinstance(pod.metadata.annotations, dict):
            network_status = pod.metadata.annotations.get( 'k8s.v1.cni.cncf.io/network-status' )
            if isinstance( network_status, str ):
                # k8s.v1.cni.cncf.io/network-status is set
                # load json formated string
                network_status = json.loads( network_status )

            if isinstance( network_status, list ):
                desktop_interfaces = {}
                # self.logger.debug( f"network_status is {network_status}" )
                for interface in network_status :
                    # self.logger.debug( f"reading interface {interface}" )
                    if not isinstance( interface, dict ): 
                        continue
                    # read interface
                    name = interface.get('interface')
                    if not isinstance( name, str ): 
                        continue
                    # read ips
                    ips = interface.get('ips')
                    if not isinstance( ips, list ): 
                        continue
                    # read mac
                    mac = interface.get('mac')
                    if not isinstance( mac, str ) :
                         continue
                    # read default ips[0]
                    if len(ips) == 1:   
                        ips = str(ips[0])
                    desktop_interfaces.update( { name : { 'mac': mac, 'ips': ips } } )
 
        desktop_container = self.getcontainerfromPod( self.graphicalcontainernameprefix, pod )
        if isinstance(desktop_container, V1ContainerStatus) :
            desktop_container_id = desktop_container.container_id
            desktop_container_name = desktop_container.name
        
        # get pod fqdn
        internal_pod_fqdn = self.build_internalPodFQDN( pod )
        # read the creation timestamp from pod metadata        
        isoformat_creation_timestamp = self.read_pod_creation_timestamp( pod )
        # read lastlogin datetime from pod annotations and convert to isoformat
        isoformat_lastlogin_datetime = self.read_pod_annotations_lastlogin_datetime( pod )
        if isinstance( isoformat_lastlogin_datetime, datetime.datetime ):
            # convert to isoformat
            isoformat_lastlogin_datetime = isoformat_lastlogin_datetime.isoformat()
        else:
            isoformat_lastlogin_datetime = None

        # read the xauthkey from pod labels
        
        # Build the ODDesktop Object 
        myDesktop = oc.od.desktop.ODDesktop(
            nodehostname=pod.spec.node_name, 
            name=pod.metadata.name,
            hostname=pod.spec.hostname,
            ipAddr=pod.status.pod_ip, 
            status=pod.status.phase, 
            desktop_id=pod.metadata.name, 
            container_id=desktop_container_id,                                                   
            container_name=desktop_container_name,
            vncPassword=None,
            fqdn = internal_pod_fqdn,
            xauthkey = pod.metadata.labels.get('xauthkey'),
            pulseaudio_cookie = pod.metadata.labels.get('pulseaudio_cookie'),
            broadcast_cookie = pod.metadata.labels.get('broadcast_cookie'),
            desktop_interfaces = desktop_interfaces,
            websocketrouting = pod.metadata.labels.get('websocketrouting', oc.od.settings.websocketrouting),
            websocketroute = pod.metadata.labels.get('websocketroute'),
            labels = pod.metadata.labels,
            uid = pod.metadata.uid,
            creation_timestamp = isoformat_creation_timestamp,
            lastlogin_datetime = isoformat_lastlogin_datetime
        )
        return myDesktop

    async def pod2desktop( self, pod:V1Pod, authinfo:AuthInfo=None, userinfo:AuthUser=None )->ODDesktop:
        """pod2Desktop convert a Pod to Desktop Object
        Args:
            myPod ([V1Pod): kubernetes.V1Pod
            userinfo ([]): userinfo set to None by default
                           to obtain vnc_password, defined userinfo context 
        Returns:
            [ODesktop]: oc.od.desktop.ODDesktop Desktop Object
        """
        assert isinstance(pod,V1Pod),    f"pod has invalid type {type(pod)}"

        desktop_container_id   = None
        desktop_container_name = None
        desktop_interfaces     = None
        vnc_password           = None

        # read metadata annotations 'k8s.v1.cni.cncf.io/network-status'
        # to get the ip address of each netwokr interface
        network_status = None
        if isinstance(pod.metadata.annotations, dict):
            network_status = pod.metadata.annotations.get( 'k8s.v1.cni.cncf.io/network-status' )
            if isinstance( network_status, str ):
                # k8s.v1.cni.cncf.io/network-status is set
                # load json formated string
                network_status = json.loads( network_status )

            if isinstance( network_status, list ):
                desktop_interfaces = {}
                # self.logger.debug( f"network_status is {network_status}" )
                for interface in network_status :
                    # self.logger.debug( f"reading interface {interface}" )
                    if not isinstance( interface, dict ): 
                        continue
                    # read interface
                    name = interface.get('interface')
                    if not isinstance( name, str ): 
                        continue
                    # read ips
                    ips = interface.get('ips')
                    if not isinstance( ips, list ): 
                        continue
                    # read mac
                    mac = interface.get('mac')
                    if not isinstance( mac, str ) :
                         continue
                    # read default ips[0]
                    if len(ips) == 1:   
                        ips = str(ips[0])
                    desktop_interfaces.update( { name : { 'mac': mac, 'ips': ips } } )
 
        desktop_container = self.getcontainerfromPod( self.graphicalcontainernameprefix, pod )
        if isinstance(desktop_container, V1ContainerStatus) :
            desktop_container_id = desktop_container.container_id
            desktop_container_name = desktop_container.name
        
        internal_pod_fqdn = self.build_internalPodFQDN( pod )

        # read the vnc password from kubernetes secret  
        # Authuser can be None if this is a gabargecollector batch
        # then vnc_secret_password is not used 
        if isinstance(userinfo, AuthUser) and isinstance(authinfo, AuthInfo) : 
            vnc_secret = oc.od.secret.ODSecretVNC( self.namespace, self.kubeapi )
            vnc_secret_password = await vnc_secret.read( authinfo, userinfo )  
            if isinstance( vnc_secret_password, V1Secret ):
                vnc_password = oc.od.secret.ODSecret.read_data( vnc_secret_password, 'password' )

        # read the creation timestamp from pod metadata        
        isoformat_creation_timestamp = self.read_pod_creation_timestamp( pod )
        # read lastlogin datetime from pod annotations and convert to isoformat
        isoformat_lastlogin_datetime = self.read_pod_annotations_lastlogin_datetime( pod )
        if isinstance( isoformat_lastlogin_datetime, datetime.datetime ):
            # convert to isoformat
            isoformat_lastlogin_datetime = isoformat_lastlogin_datetime.isoformat()
        else:
            isoformat_lastlogin_datetime = None

        # read the xauthkey from pod labels
        
        # Build the ODDesktop Object 
        myDesktop = oc.od.desktop.ODDesktop(
            nodehostname=pod.spec.node_name, 
            name=pod.metadata.name,
            hostname=pod.spec.hostname,
            ipAddr=pod.status.pod_ip, 
            status=pod.status.phase, 
            desktop_id=pod.metadata.name, 
            container_id=desktop_container_id,                                                   
            container_name=desktop_container_name,
            vncPassword=vnc_password,
            fqdn = internal_pod_fqdn,
            xauthkey = pod.metadata.labels.get('xauthkey'),
            pulseaudio_cookie = pod.metadata.labels.get('pulseaudio_cookie'),
            broadcast_cookie = pod.metadata.labels.get('broadcast_cookie'),
            desktop_interfaces = desktop_interfaces,
            websocketrouting = pod.metadata.labels.get('websocketrouting', oc.od.settings.websocketrouting),
            websocketroute = pod.metadata.labels.get('websocketroute'),
            labels = pod.metadata.labels,
            uid = pod.metadata.uid,
            creation_timestamp = isoformat_creation_timestamp,
            lastlogin_datetime = isoformat_lastlogin_datetime
        )
        return myDesktop

    async def countdesktop(self)->int:
        """countdesktop
            count the number of desktop label_selector = 'type=' + self.x11servertype
        Returns:
            int: number of desktop
        """
        list_of_desktop = await self.list_desktop()
        return len(list_of_desktop)

    async def list_desktop(self, phase_filter:list=[ 'Running', 'Pending' ])->list:
        """list_desktop

        Returns:
            list: list of ODDesktop
        """
        myDesktopList = []   
        try:  
            list_label_selector = 'type=' + self.x11servertype
            myPodList = await self.kubeapi.list_namespaced_pod(self.namespace, label_selector=list_label_selector)
            if isinstance( myPodList, V1PodList):
                for myPod in myPodList.items:
                    if isinstance( myPod.status, V1PodStatus ):
                        myPhase = myPod.status.phase
                        # keep only Running pod
                        if myPod.metadata.deletion_timestamp is None: 
                            if myPhase in phase_filter :
                                mydesktop = await self.pod2desktop( myPod )
                                if isinstance( mydesktop, ODDesktop):
                                    myDesktopList.append( mydesktop.to_dict() )              
        except ApiException as e:
            self.logger.error(e)

        return myDesktopList
            
    async def isgarbagable( self, pod:V1Pod, expirein:int, force=False )->bool:
        """isgarbagable

        Args:
            pod (V1Pod): pod
            expirein (int): in seconds
            force (bool, optional): check if user is connected or not. Defaults to False.

        Returns:
            bool: True if pod is garbageable
        """
        self.logger.debug('')
        assert isinstance(expirein, int), f"expirein has invalid type {type(expirein)}"
        bReturn = False
        if not isinstance( pod, V1Pod ):
            self.logger.error(f"pod type error, V1Pod is expected, get type {type(pod)}")
            self.logger.debug( f"isgarbagable returns {bReturn}")
            return False
        
        if pod.status.phase == 'Failed' :
            bReturn = True
            self.logger.warning(f"pod {pod.metadata.name} is in phase {pod.status.phase} reason {pod.status.reason}" )
            self.logger.debug( f"pod {pod.metadata.name} isgarbagable returns {bReturn}")
            return bReturn
        
        if isinstance( pod.metadata.deletion_timestamp, datetime.datetime ):
            self.logger.warning(f"pod {pod.metadata.name} has deletion_timestamp {pod.metadata.deletion_timestamp}" )
            self.logger.debug( f"pod {pod.metadata.name} isgarbagable returns {bReturn}")
            return bReturn

        myDesktop = await self.pod2desktop( pod=pod )
        if not isinstance(myDesktop, ODDesktop):
            self.logger.debug( f"myDesktop has bad type, ODDesktop is expected, get {type(myDesktop)}")
            self.logger.debug( f"pod {pod.metadata.name} isgarbagable returns {bReturn}")
            return bReturn

        if force is False:
            nCount = await self.user_connect_count( myDesktop )
            self.logger.debug( f"ask if the user is connected, user_connect_count returns {nCount}")
            if nCount < 0: 
                # if something wrong nCount is equal to -1 
                # do not garbage this pod
                # this is an error, return False
                self.logger.debug( f"nCount={nCount} this is an error")
                self.logger.debug( f"pod {pod.metadata.name} isgarbagable returns {bReturn}")
                return bReturn 
            if nCount > 0 : 
                # if a user is connected do not garbage this pod
                # user is connected, return False
                self.logger.debug( f"the user is connected, nCount={nCount} nothing to do")
                self.logger.debug( f"pod {pod.metadata.name} isgarbagable returns {bReturn}")
                return bReturn 
            #
            # now nCount == 0 continue 
            # the garbage process
            # to test if we can delete this pod
        else:
            self.logger.debug( f"do not call user_connect_count because force={force}")

        # read the lastlogin datetime from metadata annotations
        lastlogin_datetime = self.read_pod_annotations_lastlogin_datetime( pod )
        if isinstance( lastlogin_datetime, datetime.datetime):
            # get the current time
            now_datetime = datetime.datetime.now()
            self.logger.debug( f"lastlogin_datetime={lastlogin_datetime}" )
            self.logger.debug( f"now_datetime={now_datetime}" )
            delta_datetime = now_datetime - lastlogin_datetime
            delta_second = delta_datetime.total_seconds()

            self.logger.debug( f"compare time is {delta_second} > {expirein}")
            # if delta_second is more than expirein in second
            if ( delta_second > expirein  ):
                # this pod is gabagable
                bReturn = True
        else:
            self.logger.error( f"unknow type for lastlogin_datetime {type(lastlogin_datetime)}, datetime.datetime is expected")

        self.logger.debug( f"pod {pod.metadata.name} isgarbagable returns {bReturn}")
        return bReturn


    def extract_userinfo_authinfo_from_pod( self, pod:V1Pod )->tuple:
        """extract_userinfo_authinfo_from_pod
            Read labels (authinfo,userinfo) from a pod
        Args:
            myPod (V1Pod): Pod

        Returns:
            (tuple): (authinfo,userinfo) AuthInfo, AuthUser
        """
        assert isinstance(pod,      V1Pod),    f"pod has invalid type {type(pod)}"

        # fake an authinfo object
        authinfo = AuthInfo( 
            provider=pod.metadata.labels.get('access_provider'), 
            providertype=pod.metadata.labels.get('access_providertype') 
        )
        # fake an userinfo object
        userinfo = AuthUser( {
            'userid':pod.metadata.labels.get('access_userid'),
            'name':  pod.metadata.labels.get('access_username')
        } )
        return (authinfo,userinfo)


    async def find_userinfo_authinfo_by_desktop_name( self, name:str )->tuple:
        """find_userinfo_authinfo_by_desktop_name

        Args:
            name (str): name of pod

        Returns:
            tuple: (authinfo,userinfo)
        """
        self.logger.debug('')
        assert isinstance(name, str), f"name has invalid type {type(str)}"
        authinfo = None
        userinfo = None
        try:
            myPod = await self.kubeapi.read_namespaced_pod(namespace=self.namespace,name=name )
            if isinstance( myPod, V1Pod ) :  
                (authinfo,userinfo) = self.extract_userinfo_authinfo_from_pod(myPod)
        except ApiException as e: 
            # not found
            pass
        return (authinfo,userinfo)

    async def find_userinfo_authinfo_desktop_by_desktop_name( self, name:str )->tuple:
        """find_userinfo_authinfo_by_desktop_name

        Args:
            name (str): name of pod

        Returns:
            tuple: (authinfo,userinfo,myDesktop)
        """
        self.logger.debug('')
        assert isinstance(name, str), f"name has invalid type {type(str)}"
        authinfo  = None # default returns value
        userinfo  = None # default returns value
        myDesktop = None # default returns value
        try:
            myPod = await self.kubeapi.read_namespaced_pod(namespace=self.namespace,name=name )
            if isinstance( myPod, V1Pod ) :  
                (authinfo,userinfo) = self.extract_userinfo_authinfo_from_pod(myPod)
                myDesktop = await self.pod2desktop( pod=myPod )
        except ApiException as e: 
            # not found
            pass
        return (authinfo,userinfo,myDesktop)
    
    async def describe_desktop_byname( self, name:str )->dict:
        return await self.describe_pod_byname( name )

    async def describe_pod_byname( self, name:str )->dict:
        """describe_desktop_byname

        Args:
            name (str): name of the pod

        Returns:
            dict: dict of the desktop's pod loaded from json data
        """
        self.logger.debug('')
        assert isinstance(name, str), f"name has invalid type {type(str)}"
        # Looking at the source code for core_v1_api.py. 
        # The method calls accept a kwarg named _preload_content.
        # Setting the argument _preload_content to False instructs the method to return the urllib3.HTTPResponse object instead of a processed str. 
        # You can then work directly with the data, which cooperates with json.loads().
        describe = None
        try:
            myPod = await self.kubeapi.read_namespaced_pod(namespace=self.namespace, name=name, _preload_content=False)
            # if isinstance( myPod, urllib3.response.HTTPResponse ) :  
            if isinstance( myPod, aiohttp.client_reqrep.ClientResponse ):
                describe = await myPod.json()
        except ApiException as e: 
            # not found
            pass 
        return describe
    
    def giveme_an_imagePullSecrets( self )->list:
        imagePullSecrets = [] # default value 
        if oc.od.settings.desktop_pod.get('spec').get('imagePullSecrets') is not None:
            imagePullSecrets = oc.od.settings.desktop_pod.get('spec').get('imagePullSecrets')

            # if config imagePullSecrets is a str, convert to dict  { 'name': imagePullSecrets }
            if isinstance(imagePullSecrets, str):
                # convert str to list
                imagePullSecrets = { 'name': imagePullSecrets }

            # if config imagePullSecrets is not a list, convert to list
            if not isinstance(imagePullSecrets, list):
                # convert str to list
                imagePullSecrets = [ imagePullSecrets ]
            
        snapshotregistrysecretname = oc.od.settings.desktop.get('snapshotregistrysecretname')
        if isinstance( snapshotregistrysecretname, str):
            imagePullSecrets.append( { 'name': snapshotregistrysecretname } )
            
        return imagePullSecrets


@oc.logging.with_logger()
class ODAppInstanceBase(object):
    def __init__(self,orchestrator):
        self.orchestrator = orchestrator
        self.type=None # default value overwrited by class instance 
        self.executeclassename='default' # default value overwrited by class instance 

    def findRunningAppInstanceforUserandImage( self, authinfo, userinfo, app):
        raise NotImplementedError(f"{type(self)}.build_volumes")

    def get_DISPLAY( self, desktop_ip_addr:str='' ):
        raise NotImplementedError('get_DISPLAY')

    def get_PULSE_SERVER( self, desktop_ip_addr:str=None ):
        raise NotImplementedError('get_PULSE_SERVER')

    def get_CUPS_SERVER( self, desktop_ip_addr:str=None ):
        raise NotImplementedError('get_CUPS_SERVER')
    
    async def overwrite_environment_variable_for_application( self, myDesktop:ODDesktop )->dict:
        self.logger.debug('')
        dictenv = None
        assert isinstance(myDesktop,  ODDesktop),  f"desktop has invalid type {type(myDesktop)}"
    
        # get overwrite_environment_variable_for_application from config file 
        command_overwrite_environment_variable_for_application = oc.od.settings.desktop.get('overwrite_environment_variable_for_application')
        # if overwrite_environment_variable_for_application is set in config file and is str
        if not isinstance( command_overwrite_environment_variable_for_application, str ):
            return dictenv
        # add type as parameter
        # ./overwrite_environment_variable_for_application.sh --type ephemeral_container
        # ./overwrite_environment_variable_for_application.sh --type pod_application
        command = [ command_overwrite_environment_variable_for_application, "--type", self.type ]
        # run the command and wait for stdout
        result = await self.orchestrator.execwaitincontainer( myDesktop, command )
        if not isinstance(result,dict):
            return dictenv

        self.logger.debug( f"command={command} returns exitcode={result.get('ExitCode')} output={result.get('stdout')}" )
        if result.get('ExitCode') == 0 and result.get('stdout'):
            try:
                dictenv = json.loads( result.get('stdout') )
            except ApiException as e:
                self.logger.error(e)

        return dictenv

    async def get_env_for_appinstance(self, myDesktop, app, authinfo, userinfo={}, userargs=None, **kwargs ):
        assert isinstance(myDesktop,  ODDesktop),  f"desktop has invalid type {type(myDesktop)}"
        assert isinstance(authinfo,   AuthInfo),   f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo,   AuthUser),   f"userinfo has invalid type {type(userinfo)}"

        posixuser = await self.orchestrator.alwaysgetPosixAccountUser( authinfo, userinfo )

        # make sure env DISPLAY, PULSE_SERVER,CUPS_SERVER exist
        # read the desktop (oc.user) ip address
        desktop_ip_addr = myDesktop.get_default_ipaddr('eth0')
        self.logger.debug( f"desktop_ip_addr={desktop_ip_addr}" )
        # clone env 
        env = oc.od.settings.desktop['environmentlocal'].copy()
        # update env with desktop_ip_addr if need
        env['DISPLAY'] = self.get_DISPLAY(desktop_ip_addr)
        env['CONTAINER_IP_ADDR'] = desktop_ip_addr   # CONTAINER_IP_ADDR is used by ocrun node js command
        env['XAUTH_KEY'] = myDesktop.xauthkey
        env['BROADCAST_COOKIE'] = myDesktop.broadcast_cookie
        env['PULSEAUDIO_COOKIE'] = myDesktop.pulseaudio_cookie
        env['PULSE_SERVER'] = self.get_PULSE_SERVER(desktop_ip_addr)
        env['CUPS_SERVER'] = self.get_CUPS_SERVER(desktop_ip_addr)
        env['UNIQUERUNKEY'] = app.get('uniquerunkey')
        env['HOME'] = posixuser.get('homeDirectory')
        env['LOGNAME'] = posixuser.get('uid')
        env['USER'] = posixuser.get('uid')
    
        #
        # update env with cuurent http request user LANG values
        # read locale language from USER AGENT
        language = userinfo.get('locale', 'en_US')
        # LC_ALL is the environment variable that overrides all the other localisation settings 
        # (except $LANGUAGE under some circumstances).
        env['LANGUAGE'] = language
        env['LANG'] = language + '.UTF-8'
        env['LC_ALL']= language + '.UTF-8'

        # add PARENT_ID PARENT_HOSTNAME for ocrun nodejs script 
        env['PARENT_ID']=myDesktop.id
        env['PARENT_HOSTNAME']=myDesktop.nodehostname

        # update env APP to run command in /composer/apply-docker-entrypoint.sh
        env['APP'] = app.get('path')
        # Add specific vars
        if isinstance( kwargs, dict ):
            timezone = kwargs.get('timezone')
            if isinstance(timezone, str) and len(timezone) > 1:
                env['TZ'] = timezone
        if isinstance(userargs, str) and len(userargs) > 0:
            env['APPARGS'] = userargs
        if isinstance( app.get('args'), str) and len(app.get('args')) > 0:
            env['ARGS'] = app.get('args')
        if hasattr(authinfo, 'data') and isinstance( authinfo.data, dict ):
            env.update(authinfo.data.get('identity', {}))

        overwrite_environment_env = self.overwrite_environment_variable_for_application( myDesktop )
        if isinstance( overwrite_environment_env, list ):
            for new_env in overwrite_environment_env :
                if isinstance( new_env, dict ):
                    env.update( new_env )
        if isinstance( overwrite_environment_env, dict ):
            env.update( overwrite_environment_env )

        # convert env dictionnary to env list format for kubernetes
        envlist = ODOrchestratorKubernetes.envdict_to_kuberneteslist( env )
        ODOrchestratorKubernetes.appendkubernetesfieldref( envlist )
        
        return envlist

    async def get_securitycontext(self, authinfo:AuthInfo, userinfo:AuthUser, app:dict  ):
        assert isinstance(authinfo,   AuthInfo),   f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo,   AuthUser),   f"userinfo has invalid type {type(userinfo)}"
        assert isinstance(app,  dict),             f"desktop has invalid type  {type(app)}"
        securitycontext = {}
        user_securitycontext = await self.orchestrator.updateSecurityContextWithUserInfo( self.type, authinfo, userinfo )
        app_securitycontext = app.get('securitycontext',{}) or {} 
        securitycontext.update( user_securitycontext )
        securitycontext.update( app_securitycontext )
        self.logger.debug( f"securitycontext={securitycontext}")
        return securitycontext

    def get_resources( self, authinfo:AuthInfo, userinfo:AuthUser, executeclassname:str )->dict:
        """get_resources

        Args:
            authinfo (AuthInfo): AuthInfo
            userinfo (AuthUser): AuthUser
            executeclassname (str): name of the execute class can be None

        Returns:
            dict: resources for the pod 
        """
        assert isinstance(authinfo,   AuthInfo),   f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo,   AuthUser),   f"userinfo has invalid type {type(userinfo)}"
        # executeclassname can be None if executeclassname is not defined 
        # then assum this is the default executeclass
        (apply_executeclassname, executeclass) = self.orchestrator.get_executeclasse( authinfo, userinfo, executeclassname )
        self.logger.debug( f"requested executeclassname={executeclassname} apply executeclassname={apply_executeclassname} executeclass={executeclass}")
        resources = self.orchestrator.get_resources_for_container_type( self.type, executeclass )
        self.logger.debug( f"resources={resources}")
        return resources



    def get_default_affinity( self, authinfo:AuthInfo, userinfo:AuthUser, app:dict, desktop:ODDesktop )->dict:
        assert isinstance(desktop, ODDesktop), f"invalid desktop type {type(desktop)}"
        affinity = {
            'nodeAffinity': {
                'preferredDuringSchedulingIgnoredDuringExecution': [
                    {   'weight': 1,
                        'preference': {
                            'matchExpressions': [
                                {   'key': 'kubernetes.io/hostname',
                                    'operator': 'In',
                                    'values': [ desktop.nodehostname ]
                                }
                            ]
                        }
                    }
                ]
            }
        }
        return affinity

    def get_affinity( self, authinfo:AuthInfo, userinfo:AuthUser, app:dict, desktop:ODDesktop )->dict:
        assert isinstance(desktop, ODDesktop), f"invalid desktop type {type(desktop)}"
        affinity = self.get_default_affinity(authinfo, userinfo, app, desktop)
        default_config_affinity = oc.od.settings.desktop_pod[self.type].get('affinity', {}) or {}
        affinity.update(default_config_affinity)
        return affinity


    async def get_resources_usage( self, myPod:V1Pod, container_name:str=None ) -> dict:
        resources_usage = { 'timestamp': time.time() }
        cgroup_map = oc.od.settings.desktop['resources_usage_cgroup_map'].copy()
        
        if not isinstance(container_name, str ):
            self.logger.error( f"container_name is not a str, gets {type(container_name)}" )
            return resources_usage

        if isinstance(myPod, V1Pod ):
            threads = {}
            threads_results = {}
            for r in cgroup_map.keys():
                threads_results[r] = None

            
            for r in cgroup_map.keys():
                command = [ 'cat',  cgroup_map.get(r) ]
                threads[r] = threading.Thread( 
                                target=self.orchestrator._execwaitincontainer, 
                                args=[ myPod.metadata.name, container_name, command, threads_results, r ] )
                threads[r].start()
            
            '''
            tasks: list[asyncio.Task[object]] = []
            async with asyncio.TaskGroup() as tg:
                for r in cgroup_map.keys():
                    command = [ 'cat',  cgroup_map.get(r) ]
                    task = tg.create_task( self.orchestrator._execwaitincontainer(myPod.metadata.name, container_name, command, threads_results, r ) )
                    tasks.append(task)
            ''' 
            
            # parse results
            for r in cgroup_map.keys():
                try: 
                    result = threads_results.get(r)
                    if isinstance(result, dict):
                        if result.get('ExitCode') != 0:
                            self.logger.error( f"command {cgroup_map.get(r)} failed with ExitCode={result.get('ExitCode')}" )
                            continue
                        # get the stdout of the command
                        stdout = result.get('stdout')
                        if isinstance( stdout, str):
                            resources_usage[r] = stdout.strip()

                            # check if cgroup_version is 'cgroup v2'
                            if oc.od.settings.cgroup_version == 'cgroup v2':
                                # if cgroup_version is 'cgroup v2', we need to parse the output
                                # of cpuacct.usage and cpu.cfs_quota_us
                                # in cgroup v2
                                # 'cpuacct.usage':    '/sys/fs/cgroup/cpu.stat',
                                # 'cpu.cfs_quota_us': '/sys/fs/cgroup/cpu.max'
                                if r == 'cpuacct.usage' :
                                    # read the first list line of the output like
                                    # usage_usec 43151084\nuser_usec 33631998\nsystem_usec 9519085\ncore_sched.force_idle_usec 0\nnr_periods 0\nnr_throttled 0\nthrottled_usec 0\nnr_bursts 0\nburst_usec 0
                                    rsplit = stdout.strip().split('\n')
                                    if len(rsplit) > 0:
                                        # get the first line
                                        rsplit = rsplit[0].split()
                                        if len(rsplit) > 1:
                                            # get the second value of line 
                                            # usage_usec 43151084
                                            # This prints a file with a value called usage_usec. 
                                            # As with value returned by the cgroup v1 cpuacct.usage file, this value must be converted into a CPU usage percentage to be useful.
                                            # With cgroup v2 the usage_usec value is measured in milliseconds, unlike the value returned by the cpuacct.usage file, which is in nanoseconds. 
                                            # Convert the usage_usec value to nanoseconds by multiplying it by 1000, at which point it can be used in the same calculations returned by the cpuacct.usage file.
                                            resources_usage[r] = str( int(rsplit[1]) * 1000 )
                                    else:
                                        self.logger.error( f"stdout is empty {stdout}" )
                                elif r == 'cpu.cfs_quota_us' :
                                    # get the second value of line 
                                    # passmax 100000
                                    # more /sys/fs/cgroup/cpu.max 
                                    # 200000 1000000
                                    # This command sets CPU time distribution controls so that all processes
                                    # collectively in the file /sys/fs/cgroup/cpu.max on the CPU
                                    # for only 0.2 seconds of every 1 second. 
                                    rsplit = stdout.strip().split()
                                    if len(rsplit) > 0:
                                        if len(rsplit) > 1:
                                            resources_usage[r] = str( int(rsplit[0])*1000 ) # convert to nanoseconds
                                            # resources_usage[r] = str( rsplit[0] )
                                        elif len(rsplit) == 1:
                                            resources_usage[r] = str( int(rsplit[0])*1000 )
                                        else:
                                            self.logger.error( f"stdout is empty {stdout}" )
                except Exception as e:
                    self.logger.error( f"error {e} in getdesktop_resources_usage for {r} with stdout={stdout}" )
                    resources_usage[r] = None # default value because an error occurs
        return resources_usage

  
@oc.logging.with_logger()
class ODAppInstanceKubernetesEphemeralContainer(ODAppInstanceBase):

    def __init__(self, orchestrator):
        super().__init__(orchestrator)
        self.type = self.orchestrator.ephemeral_container

    def get_DISPLAY(  self, desktop_ip_addr:str=None ):
        return ':0.0'

    def get_PULSE_SERVER(  self, desktop_ip_addr:str='' ):
        return  oc.od.settings.desktop['pulseaudiosocketpath']

    def get_CUPS_SERVER( self, desktop_ip_addr:str ):
        return desktop_ip_addr + ':' + str(DEFAULT_CUPS_TCP_PORT)

    async def envContainerApp(self, authinfo:AuthInfo, userinfo:AuthUser, pod_name:str, containerid:str )->dict:
        """get_env
            return a dict of env VAR of an ephemeral container

        Args:
            pod_name (str): name of the pod
            container_name (str): name of the container

        Raises:
            ValueError: ValueError( 'Invalid read_namespaced_pod_ephemeralcontainers')
            if pod_ephemeralcontainers can not be read

        Returns:
            dict: VAR_NAME : VAR_VALUE
            or None if failed
        """
        assert isinstance(pod_name, str),    f"pod_name has invalid type {type(pod_name)}"
        assert isinstance(containerid, str), f"containerid has invalid type {type(containerid)}"
        env_result = None
        pod_ephemeralcontainers = await self.orchestrator.kubeapi.read_namespaced_pod_ephemeralcontainers(
            name=pod_name, 
            namespace=self.orchestrator.namespace )
        if not isinstance(pod_ephemeralcontainers, V1Pod ):
            raise ValueError( 'Invalid read_namespaced_pod_ephemeralcontainers')

        if isinstance(pod_ephemeralcontainers.spec.ephemeral_containers, list):
            for c in pod_ephemeralcontainers.spec.ephemeral_containers:
                if c.name == containerid :
                    env_result = {}
                    #  convert name= value= to dict
                    for e in c.env:
                        if isinstance( e, V1EnvVar ):
                            env_result[ e.name ] =  e.value
                    break
        return env_result

    async def logContainerApp(self, pod_name:str, container_name:str)->str:
        assert isinstance(pod_name,  str),  f"pod_name has invalid type  {type(pod_name)}"
        assert isinstance(container_name,  str),  f"container_name has invalid type {type(container_name)}"
        strlogs = 'no logs read'
        try:
            strlogs = await self.orchestrator.kubeapi.read_namespaced_pod_log( 
                name=pod_name, 
                namespace=self.orchestrator.namespace, 
                container=container_name, 
                pretty='true' )
        except ApiException as e:
            self.logger.error( e )
        except Exception as e:
            self.logger.error( e )
        return strlogs
        

    def get_status( self, pod_ephemeralcontainers:V1Pod, container_name:str ):
        """get_status

        Args:
            pod_ephemeralcontainers (V1Pod): pod_ephemeralcontainers
            container_name (str): name of the container to return

        Returns:
            _type_: _description_
        """
        assert isinstance(pod_ephemeralcontainers, V1Pod), f"pod_ephemeralcontainers has invalid type {type(pod_ephemeralcontainers)}"
        assert isinstance(container_name,  str),  f"container_name has invalid type {type(container_name)}"
        pod_ephemeralcontainer = None

        if isinstance( pod_ephemeralcontainers.status, V1PodStatus ) and \
           isinstance( pod_ephemeralcontainers.status.ephemeral_container_statuses, list):
                for c in pod_ephemeralcontainers.status.ephemeral_container_statuses :
                    if c.name == container_name:
                        pod_ephemeralcontainer = c
                        break
        return pod_ephemeralcontainer

    def get_phase( self, ephemeralcontainer:V1ContainerStatus ):
        """get_phase
            return a Phase like as pod for ephemeral_container
            string 'Terminated' 'Running' 'Waiting' 'Error'
        Args:
            ephemeralcontainer (V1ContainerStatus): V1ContainerStatus

        Returns:
            str: str phase of ephemeral_container status can be one of 'Terminated' 'Running' 'Waiting' 'Error'
        """
        text_state = 'Error' # defalut value shoud never be return

        if isinstance( ephemeralcontainer, V1ContainerStatus ):
            if  isinstance(ephemeralcontainer.state.terminated, V1ContainerStateTerminated ):
                text_state = 'Terminated'
            elif isinstance(ephemeralcontainer.state.running, V1ContainerStateRunning ):
                text_state = 'Running'
            elif isinstance(ephemeralcontainer.state.waiting, V1ContainerStateWaiting):
                text_state = 'Waiting'
        return text_state


    async def stop(self, pod_name:str, container_name:str)->bool:
        """stop
            stop an ephemeral container by removing it from the pod ephemeralcontainers list    
        Args:
            pod_name (str): name of the pod
            container_name (str): name of the container to stop 
        Raises:
            ValueError: ValueError( 'Invalid read_namespaced_pod_ephemeralcontainers')
            if pod_ephemeralcontainers can not be read
            ValueError: ValueError( 'Invalid patch_namespaced_pod_ephemeralcontainers')
            if pod_ephemeralcontainers can not be patched
        Returns:
            bool: True if the ephemeral container has been removed from the pod ephemeralcontainers list        
        """
        self.logger.debug('')
        assert isinstance(pod_name,  str),  f"pod_name has invalid type {type(pod_name)}"
        assert isinstance(container_name,  str),  f"container_name has invalid type {type(container_name)}"

        pod_ephemeralcontainers =  await self.orchestrator.kubeapi.read_namespaced_pod_ephemeralcontainers(
            name=pod_name, 
            namespace=self.orchestrator.namespace )
        if not isinstance(pod_ephemeralcontainers, V1Pod ):
            raise ValueError( 'Invalid read_namespaced_pod_ephemeralcontainers')

        if isinstance(pod_ephemeralcontainers.spec.ephemeral_containers, list):
            for i in range( len(pod_ephemeralcontainers.spec.ephemeral_containers) ):
                if pod_ephemeralcontainers.spec.ephemeral_containers[i].name == container_name :
                    pod_ephemeralcontainers.spec.ephemeral_containers.pop(i)
                    break

        # replace ephemeralcontainers
        pod=await self.orchestrator.kubeapi.patch_namespaced_pod_ephemeralcontainers(
            name=pod_name, 
            namespace=self.orchestrator.namespace, 
            body=pod_ephemeralcontainers )
        if not isinstance(pod, V1Pod ):
            raise ValueError( 'Invalid patch_namespaced_pod_ephemeralcontainers')

        stop_result = True

        return stop_result

    async def get_resources_usage( self, authinfo:AuthInfo, userinfo:AuthUser, ephemeralcontainer_name:str ) -> dict:
        """get_resources_usage
            return a dict of resources usage of an ephemeral container
            resources_usage = { 'timestamp': time.time(), 'cpuacct.usage': '123456789', 'memory.usage_in_bytes': '123456789', 'memory.max_usage_in_bytes': '123456789', 'memory.limit_in_bytes': '123456789', 'cpu.cfs_quota_us': '123456', 'cpu.cfs_period_us': '100000' }
        Args:
            authinfo (AuthInfo): AuthInfo
            userinfo (AuthUser): AuthUser
            ephemeralcontainer_name (str): name of the ephemeral container  
        Returns:
            dict: dict of resources usage of an ephemeral container
        """
        assert isinstance(authinfo,   AuthInfo),   f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo,   AuthUser),   f"userinfo has invalid type {type(userinfo)}"
        assert isinstance(ephemeralcontainer_name, str), f" ephemeralcontainer_name has invalid type {type(ephemeralcontainer_name)}"   
        resources_usage = { 'timestamp': time.time() }
        myPod = await self.orchestrator.findPodByUser(authinfo, userinfo )

        if not isinstance(ephemeralcontainer_name, str ):
            self.logger.error( f"ephemeralcontainer_name is not a str, gets {type(ephemeralcontainer_name)}" )
            return resources_usage

        if isinstance(myPod, V1Pod ):
            resources_usage = await super().get_resources_usage( myPod=myPod, container_name=ephemeralcontainer_name  )
        return resources_usage


    def to_dict( self, myPod:V1Pod, c_spec:V1EphemeralContainer,  c_status:V1ContainerStatus, phase:str, apps:ODApps )->dict:
        """to_dict
            convert an ephemeralcontainers container to json by filter entries
            Args:
                myPod (V1Pod): Pod
                c_spec (V1EphemeralContainer): V1EphemeralContainer spec
                c_status (V1ContainerStatus): V1ContainerStatus status
                phase (str): phase of the container
                apps (ODApps): ODApps
            Returns:    
                dict: dict of the ephemeral container
        """
        # convert an ephemeralcontainers container to json by filter entries
        app = {}
        if isinstance(apps, ODApps):
            app = apps.find_app_by_id( c_status.image ) or {}

        mycontainer = {}
        mycontainer['podname']  = myPod.metadata.name
        mycontainer['id']       = c_status.name
        mycontainer['short_id'] = c_status.container_id
        mycontainer['status']   = c_status.ready
        mycontainer['image']    = c_status.image
        mycontainer['oc.path']  = c_spec.command
        mycontainer['nodehostname'] = myPod.spec.node_name
        mycontainer['architecture'] = app.get('architecture')
        mycontainer['os']           = app.get('os')
        mycontainer['oc.icondata']  = app.get('icondata')
        mycontainer['oc.args']      = app.get('args')
        mycontainer['oc.icon']      = app.get('icon')
        mycontainer['oc.launch']    = app.get('launch')
        mycontainer['oc.displayname'] = app.get('displayname')
        mycontainer['runtime']        = 'kubernetes'
        mycontainer['type']           = self.type
        mycontainer['status']         = phase
        return mycontainer

    async def list( self, authinfo, userinfo, myDesktop, phase_filter=[ 'Running', 'Waiting'], apps:ODApps=None )->list:
        """list
            list ephemeral containers of a desktop pod filtered by phase
        Args:
            authinfo (AuthInfo): AuthInfo
            userinfo (AuthUser): AuthUser
            myDesktop (ODDesktop): ODDesktop
            phase_filter (list, optional): list of phase to filter. Defaults to [ 'Running, 'Waiting'].
            apps (ODApps, optional): ODApps. Defaults to None.
        Raises:
            ValueError: ValueError( 'Invalid read_namespaced_pod_ephemeralcontainers')
            if pod_ephemeralcontainers can not be read
        Returns:
            list: list of dict of ephemeral containers
        """
        self.logger.debug('')
        assert isinstance(myDesktop,  ODDesktop),  f"desktop has invalid type  {type(myDesktop)}"
        assert isinstance(authinfo,   AuthInfo),   f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo,   AuthUser),   f"userinfo has invalid type {type(userinfo)}"
        assert isinstance(phase_filter, list),     f"phase_filter has invalid type {type(phase_filter)}"

        result = []
        myPod =  await self.orchestrator.kubeapi.read_namespaced_pod_ephemeralcontainers(name=myDesktop.id, namespace=self.orchestrator.namespace )
        if not isinstance(myPod, V1Pod ):
            raise ValueError( 'Invalid read_namespaced_pod_ephemeralcontainers')

        if isinstance(myPod.spec.ephemeral_containers, list):
            for c_spec in myPod.spec.ephemeral_containers:
                c_status = self.get_status( myPod, c_spec.name )
                if isinstance( c_status, V1ContainerStatus ):
                    phase = self.get_phase( c_status )
                    if phase in phase_filter:
                        # convert an ephemeralcontainers container to json by filter entries
                        mycontainer = self.to_dict( myPod, c_spec, c_status, phase, apps )
                        # add the object to the result array
                        result.append( mycontainer )

        return result


    def create_thread_to_watch_for_pulling_event( self, myDesktop:ODDesktop, pod_name:str, app_container_name:str, app:dict ):
        self.logger.debug( '')
        return asyncio.ensure_future(self.watch_for_pulling_event(myDesktop, pod_name, app_container_name, app))


    def create_thread_to_watch_for_end_of_pod_initializing( self, myDesktop:ODDesktop, pod_name:str, app_container_name:str, app:dict ):
        self.logger.debug( '')
        return asyncio.ensure_future(self.watch_for_end_of_pod_initializing(myDesktop, pod_name, app_container_name, app))

    async def watch_for_end_of_pod_initializing( self, myDesktop:ODDesktop, pod_name:str, app_container_name:str, app:dict )->None:
        self.logger.debug('')
          
        # default message data
        data = {    'message':  app.get('name'), 
                    'name':     app.get('name'),
                    'icondata': app.get('icondata'),
                    'icon':     app.get('icon'),
                    'image':    app.get('id'),
                    'launch':   app.get('launch'),
                    'id':       app_container_name
        }
        # check if app_container_name is running
        try:
            pod = await self.orchestrator.kubeapi.read_namespaced_pod_ephemeralcontainers(namespace=self.orchestrator.namespace,name=pod_name)
            if  isinstance( pod, V1Pod ) and \
                isinstance( pod.status, V1PodStatus ) and \
                isinstance( pod.status.ephemeral_container_statuses, list):
                    for c in pod.status.ephemeral_container_statuses:
                        if isinstance( c, V1ContainerStatus ) :
                            if c.name == app_container_name:
                                # self.logger.debug( f"{app_container_name} is found in ephemeral_container_statuses {c}")
                                if isinstance( c.state, V1ContainerState ):
                                    if isinstance(c.state.waiting, V1ContainerStateWaiting):
                                        data['reason'] =  c.state.waiting.reason
                                        data['message'] =  c.state.waiting.reason
                                        await self.orchestrator.notify_user( myDesktop, 'container', data )
                                    
                                    if isinstance(c.state.terminated, V1ContainerStateTerminated ):
                                        data['message'] =  c.state.terminated.reason
                                        data['reason'] =  c.state.terminated.reason
                                        await self.orchestrator.notify_user( myDesktop, 'container', data )

                                    if isinstance(c.state.running, V1ContainerStateRunning ):
                                        data['reason'] =  'Started'
                                        data['message'] =  c.state.running.started_at.strftime("%Y-%m-%d %H:%M:%S")
                                        await self.orchestrator.notify_user( myDesktop, 'container', data )
                                break
        except ApiException as e:
            if isinstance( e.reason, str) and e.reason.startswith('Handshake status 200 OK'):
                # Handshake status 200 OK 
                # -+-+- 
                # {'audit-id': '5b6c78ce-4412-48e4-b58d-d96e5186f416', 
                # 'cache-control': 'no-cache, private', 
                # 'content-type': 'application/json', 
                # 'x-kubernetes-pf-flowschema-uid': 'b63302af-83ee-4663-8bc2-f188e4236cf7', 
                # 'x-kubernetes-pf-prioritylevel-uid': '9a4a998a-bb63-4f75-b75a-cedd6a81f010', 
                # 'date': 'Wed, 08 Oct 2025 15:01:34 GMT', 
                # 'transfer-encoding': 'chunked'} 
                # -+-+- None
                # self.logger.error( f"ApiException {e} is ignored because it is a known issue with some kubernetes versions" )
                pass
            else:
                self.logger.error( e )
                data['reason'] = 'Error'
                data['message'] =  str(e)
                # report error to the user 
                await self.orchestrator.notify_user( myDesktop, 'container', data )
        except Exception as e:
            self.logger.error( e )  
        self.logger.debug('end of watch_for_end_of_pod_initializing')


    async def watch_for_pulling_event( self, myDesktop:ODDesktop, pod_name:str, app_container_name:str, app:dict )->None:
        """
            thread to watch for pulling event of an ephemeral container
            if a pulling event is received, notify the user that the application is being pulled
            if a warning event is received, notify the user that the application failed to start
            if no pulling event is received after oc.od.settings.desktop['K8S_NOTIFY_USER_APPLICATION_PULLED_DELAY_SECONDS']
            notify the user that the application has started
        Args:
            myDesktop (ODDesktop): ODDesktop
            pod_name (str): name of the pod
            app_container_name (str): name of the ephemeral container
            app (dict): app dict    
        Returns:
            None
        """
        self.logger.debug('')

        # field_path = f"spec.ephemeralContainers{{{app_container_name}}}"  # 'spec.ephemeralContainers{philip-j--fry-2048-alpine-0ece1}'

        # start
        data = {    'message':  app.get('name'), 
                    'id':       app_container_name,
                    'name':     app.get('name'),
                    'icondata': app.get('icondata'),
                    'icon':     app.get('icon'),
                    'image':    app.get('id'),
                    'launch':   app.get('launch')
        }
       
        # field_selector=f'involvedObject.name={pod_name}'
        # timeout_seconds=oc.od.settings.desktop['K8S_CREATE_POD_TIMEOUT_SECONDS'],
        # send_initial_events=False,
        # pod_resource_version = int(pod.metadata.resource_version)
        # self.logger.debug(f"resource_version = {pod_resource_version}")
        # 
        field_selector=f'involvedObject.name={pod_name},involvedObject.fieldPath=spec.ephemeralContainers{{{app_container_name}}}'
        # field_selector='reason=Pulling'
        # send_initial_events=False, sendInitialEvents is forbidden for watch unless the WatchList feature gate is enabled
        self.logger.debug(f"w.stream kubeapi.list_namespaced_event starting field_selector={field_selector}")

        continue_reading_events = True
        dict_state_exec_only_once = {}
        self.logger.debug(f"start watching")
        w = watch.Watch()
        while continue_reading_events:
            timeout_seconds = 5 # seconds
            try:
                # watch list_namespaced_event
                async for event in w.stream( 
                            self.orchestrator.kubeapi.list_namespaced_event, 
                            namespace=self.orchestrator.namespace,
                            field_selector=field_selector,
                            timeout_seconds=timeout_seconds ):
                    self.logger.debug(f"new event received {event}")
                    if not isinstance(event, dict ): 
                        continue # safe type test event is a dict
                    event_object = event.get('object')
                    
                    if not isinstance(event_object, CoreV1Event ): 
                        continue # safe type test event object is a CoreV1Event
                    
                    if not isinstance (event_object.involved_object, V1ObjectReference ):
                        self.logger.debug(f"event_object.involved_object is not a V1ObjectReference")
                        continue
                    
                    # always update data
                    data['name'] = event_object.involved_object.name
                    data['reason'] = event_object.reason
                    data['message'] = event_object.message
        
                    if event_object.reason in [ 'Pulling', 'Pulled', 'Created', 'Scheduled']:
                        if dict_state_exec_only_once.get( event_object.reason, False ) is False:
                            dict_state_exec_only_once[ event_object.reason ] = True
                            self.logger.debug(f"{event_object.reason} notify_user")
                            await self.orchestrator.notify_user( myDesktop, 'container', data )
                    elif event_object.reason == 'Started':
                        # always stop the watch on Started event
                        # if dict_state_exec_only_once.get( event_object.reason, False ) is False:
                        # dict_state_exec_only_once[ event_object.reason ] = True
                        self.logger.debug(f"{event_object.reason} notify_user")
                        await self.orchestrator.notify_user( myDesktop, 'container', data )
                        continue_reading_events = False
                        w.stop()
                        break
                    else:       
                        self.logger.debug(f"stop because {event_object.reason}")
                        continue_reading_events = False
                        w.stop()
                        break
            except ApiException as e:
                self.logger.debug( f"ApiException list_namespaced_event {e}")
                if isinstance( e.reason, str) and e.reason.startswith('Handshake status 200 OK'):
                    # event:anonymous read_namespaced_pod_ephemeralcontainers ApiException list_namespaced_event (0)
                    # Reason: Handshake status 200 OK -+-+- 
                    # {'audit-id': '1bb8710e-76ad-4d1b-aa9b-fb7aa4609140', 'cache-control': 'no-cache, private', 
                    # 'content-type': 'application/json', 'x-kubernetes-pf-flowschema-uid': '6691937b-ac4b-40a7-9b62-687cc3ed279d', 
                    # 'x-kubernetes-pf-prioritylevel-uid': '8e7aebf3-6f9a-4889-bcfb-4f273ff65f1a', 
                    # 'date': 'Thu, 11 Jun 2026 20:50:29 GMT', 'transfer-encoding': 'chunked'} 
                    # -+-+- None
                    self.logger.debug( f"Handshake status 200 {e}")

                elif hasattr(e, 'status') and e.status == 504 and hasattr(e, 'reason') and 'Too large resource version' in e.reason :
                    self.logger.debug( f"retrying after Timeout: Too large resource version ApiException {e}")
                    break
                else:
                    self.logger.error( f"ApiException list_namespaced_event {e}" )
                    break
            except Exception as e:
                self.logger.debug( f"Exception list_namespaced_event {e}")
                data['reason'] = 'exception'
                data['message'] = 'exception'
                await self.orchestrator.notify_user( myDesktop, 'container', data )
                continue_reading_events = False
                self.logger.error( f"Exception {e}" )

            self.logger.debug( f"read_namespaced_pod_ephemeralcontainers {pod_name} {app_container_name}")

            try:
                pod = await self.orchestrator.kubeapi.read_namespaced_pod_ephemeralcontainers(
                    namespace=self.orchestrator.namespace, name=pod_name)
                c = self.get_status(pod, app_container_name)
                if isinstance(c, V1ContainerStatus) and isinstance(c.state, V1ContainerState):
                    data['name'] = app_container_name
                    if isinstance(c.state.waiting, V1ContainerStateWaiting):
                        data['reason'] = data['message'] = c.state.waiting.reason
                        await self.orchestrator.notify_user(myDesktop, 'container', data)
                    elif isinstance(c.state.terminated, V1ContainerStateTerminated):
                        continue_reading_events = False
                        data['reason'] = data['message'] = c.state.terminated.reason
                        await self.orchestrator.notify_user(myDesktop, 'container', data)
                    elif isinstance(c.state.running, V1ContainerStateRunning):
                        continue_reading_events = False
                        data['reason'] = 'Started'
                        data['message'] = c.state.running.started_at.strftime("%Y-%m-%d %H:%M:%S")
                        await self.orchestrator.notify_user(myDesktop, 'container', data)
            except ApiException as e:
                if isinstance(e.reason, str) and e.reason.startswith('Handshake status 200 OK'):
                    pass
                else:
                    self.logger.error(e)
                    data['reason'] = 'Error'
                    data['message'] = str(e)
                    continue_reading_events = False
                    await self.orchestrator.notify_user(myDesktop, 'container', data)
            except Exception as e:
                continue_reading_events = False
                self.logger.error(e)

        try:
            await w.close()
        except Exception as e:
            self.logger.error( f"Exception when closing watch: {e}" )

        data['message'] = 'end of watching'
        data['reason'] = 'end'
        await self.orchestrator.notify_user( myDesktop, 'container', data )

        self.logger.debug('thread_to_watch_for_pulling_event end')


    async def create(self, myDesktop:ODDesktop, app:dict, authinfo:AuthInfo, userinfo:AuthUser={}, queue:asyncio.Queue=None, userargs=None, **kwargs ):
        """create
            create an ephemeral container in a desktop pod
        Args:
            myDesktop (ODDesktop): ODDesktop
            app (dict): app dict
            authinfo (AuthInfo): AuthInfo       
            userinfo (AuthUser, optional): AuthUser. Defaults to {}.
            userargs (_type_, optional): userargs. Defaults to None.
        Raises:
            ValueError: ValueError('Invalid desktop')
                if myDesktop is not a valid ODDesktop
            ValueError: ValueError('Invalid app')
                if app is not a valid app dict
            ValueError: ValueError('Invalid authinfo')
                if authinfo is not a valid AuthInfo
            ValueError: ValueError('Invalid userinfo')                  
                if userinfo is not a valid AuthUser
        Returns:                    
            bool: True if the ephemeral container has been created
        """
        self.logger.debug('')
        assert isinstance(myDesktop,  ODDesktop),  f"desktop has invalid type  {type(myDesktop)}"
        assert isinstance(authinfo,   AuthInfo),   f"authinfo has invalid type {type(authinfo)}"

        app_container_name = \
            self.orchestrator.get_normalized_username(userinfo.get('name', 'name')) + \
            self.orchestrator.containernameseparator + \
            app['name'] + \
            self.orchestrator.containernameseparator + \
            oc.lib.uuid_digits()
        app_container_name = oc.auth.namedlib.normalize_name_dnsname( app_container_name )
        self.logger.debug( f"normalized app_container_name={app_container_name}" )

        desktoprules = oc.od.settings.desktop['policies'].get('rules', {})
        rules = copy.deepcopy( desktoprules )
        apprules = app.get('rules', {} ) or {} # app['rules] can be set to None
        rules.update( apprules )

        self.logger.debug( f"reading pod desktop desktop.id={myDesktop.id} myDesktop.container_name={myDesktop.container_name} app_container_name={app_container_name}")
        envlist = await self.get_env_for_appinstance(  myDesktop, app, authinfo, userinfo, userargs, **kwargs )

        # add EXECUTION CONTEXT env var inside the container
        envlist.append( { 'name': 'ABCDESKTOP_EXECUTE_RUNTIME', 'value': self.type} )
        resources = await self.orchestrator.read_pod_resources(myDesktop.name)
        envlist.append( { 'name': 'ABCDESKTOP_EXECUTE_RESOURCES', 'value': json.dumps(resources) } )

        kwargs['uid'] = myDesktop.uid
        kwargs['container_name'] = myDesktop.container_name
        (volumeBinds, volumeMounts) = await self.orchestrator.build_volumes( 
            authinfo,
            userinfo,
            queue,
            volume_type=self.type,
            secrets_requirement=app.get('secrets_requirement'),
            rules=rules,
            **kwargs
        )
        list_volumeBinds = list( volumeBinds.values() )
        list_volumeMounts = list( volumeMounts.values() )
        self.logger.debug( f"list volume binds pod desktop {list_volumeBinds}")
        self.logger.debug( f"list volume mounts pod desktop {list_volumeMounts}")

        workingDir = await self.orchestrator.get_user_homedirectory( authinfo, userinfo )
        self.logger.debug( f"user workingDir={workingDir}")

        # remove subPath
        # Pod volumes to mount into the container's filesystem.
        # Subpath mounts are not allowed for ephemeral containers.
        # Can not be updated.
        #
        # Forbidden: can not be set for an Ephemeral Container",
        # "reason":"FieldValueForbidden",
        # "message":"Forbidden: can not be set for an Ephemeral Container",
        # "field":"spec.ephemeralContainers[8].volumeMounts[0].subPath"}]},
        # "code":422}
        # https://github.com/kubernetes-client/python/blob/master/kubernetes/docs/V1EphemeralContainer.md
        # Pod volumes to mount into the container's filesystem. Subpath mounts are not allowed for ephemeral containers
        assert oc.od.settings.desktop['persistentvolumeclaimforcesubpath'] is False, \
            f"desktop.persistentvolumeclaimforcesubpath is {oc.od.settings.desktop['persistentvolumeclaimforcesubpath']} \
            Subpath mounts are not allowed for ephemeral containers"

        securitycontext = await self.get_securitycontext( authinfo, userinfo, app )
        
        # Fix python kubernetes
        # Ephemeral container not added to pod #1859
        # https://github.com/kubernetes-client/python/issues/1859
        #
        image_pull_policy = oc.od.settings.desktop_pod[self.type].get('imagePullPolicy')
        ephemeralcontainer = V1EphemeralContainer(  
            name=app_container_name,
            security_context=securitycontext,
            env=envlist,
            image=app['id'],
            command=app.get('cmd'),
            args=app.get('args'),
            target_container_name=myDesktop.container_name,
            image_pull_policy=image_pull_policy,
            volume_mounts = list_volumeMounts,
            working_dir = workingDir
        )

        # This succeeds and the ephemeral container is added but without any volume mounts or messages
        # because its sending the dictionary as snake_case and k8s is expecting camelCase, 
        # solved this by just making a raw dictionary with the proper casing
        ephemeralcontainer_dict = ephemeralcontainer.to_dict()
        #  snake_case to camelCase entries
        ephemeralcontainer_dict_CamelCase = oc.auth.namedlib.dictSnakeCaseToCamelCase( ephemeralcontainer_dict )
        # create ther request fixed body
        body = {
            'spec': {
                'ephemeralContainers': [
                    ephemeralcontainer_dict_CamelCase
                ]
            }
        }

        pod_name = myDesktop.id

        # patch_namespaced_pod_ephemeralcontainers 
        pod = await self.orchestrator.kubeapi.patch_namespaced_pod_ephemeralcontainers(   
            name=pod_name,
            namespace=self.orchestrator.namespace, 
            body=body)
        
        if not isinstance(pod, V1Pod ):
            raise ValueError( 'Invalid patch_namespaced_pod_ephemeralcontainers')
        
        data = {    
            'type': self.type,
            'name': app.get('name'),
            'icondata': app.get('icondata'),
            'icon': app.get('icon'),
            'image': app.get('id'),
            'launch': app.get('launch')
        }
       
        data['reason'] = 'Patched'
        queue.put_nowait( (100, data) )

        field_selector=f'involvedObject.name={pod_name},involvedObject.fieldPath=spec.ephemeralContainers{{{app_container_name}}}'
        continue_reading_events = True
        dict_state_exec_only_once = {}
        self.logger.debug(f"start watching")
        w = watch.Watch()
        
        timeout_seconds = oc.od.settings.desktop['K8S_CREATE_EPHEMERALCONTAINER_TIMEOUT_SECONDS'] # seconds
        try:
            # watch list_namespaced_event
            async for event in w.stream( self.orchestrator.kubeapi.list_namespaced_event, 
                                            namespace=self.orchestrator.namespace,
                                            field_selector=field_selector,
                                            timeout_seconds=timeout_seconds ):
                # self.logger.debug( f"event: {event}" )
                if not isinstance(event, dict ): 
                    continue # safe type test event is a dict
                event_object = event.get('object')
                
                if not isinstance(event_object, CoreV1Event ): 
                    continue # safe type test event object is a CoreV1Event
                
                if not isinstance (event_object.involved_object, V1ObjectReference ):
                    self.logger.debug(f"event_object.involved_object is not a V1ObjectReference")
                    continue
                
                # always update data
                data['name'] = event_object.involved_object.name
                data['reason'] = event_object.reason
                data['message'] = event_object.message
    
                if event_object.reason in [ 'Pulling', 'Scheduled', 'Created' ]:
                    if dict_state_exec_only_once.get( event_object.reason, False ) is False:
                        dict_state_exec_only_once[ event_object.reason ] = True
                        queue.put_nowait( (100, data) )
                    continue

                if event_object.reason in [ 'Started', 'Pulled' ]:
                    continue_reading_events = False
                    queue.put_nowait( (100, data) )
                    w.stop()
                    continue
                        
                self.logger.debug(f"stop because {event_object.reason}")
                continue_reading_events = False
                w.stop()
                
        except ApiException as e:
            self.logger.debug( f"ApiException list_namespaced_event {e}")
            if isinstance( e.reason, str) and e.reason.startswith('Handshake status 200 OK'):
                # event:anonymous read_namespaced_pod_ephemeralcontainers ApiException list_namespaced_event (0)
                # Reason: Handshake status 200 OK -+-+- 
                # {'audit-id': '1bb8710e-76ad-4d1b-aa9b-fb7aa4609140', 'cache-control': 'no-cache, private', 
                # 'content-type': 'application/json', 'x-kubernetes-pf-flowschema-uid': '6691937b-ac4b-40a7-9b62-687cc3ed279d', 
                # 'x-kubernetes-pf-prioritylevel-uid': '8e7aebf3-6f9a-4889-bcfb-4f273ff65f1a', 
                # 'date': 'Thu, 11 Jun 2026 20:50:29 GMT', 'transfer-encoding': 'chunked'} 
                # -+-+- None
                self.logger.debug( f"Handshake status 200 {e}")

            elif hasattr(e, 'status') and e.status == 504 and hasattr(e, 'reason') and 'Too large resource version' in e.reason :
                self.logger.debug( f"retrying after Timeout: Too large resource version ApiException {e}")
            else:
                self.logger.error( f"ApiException list_namespaced_event {e}" )

        except Exception as e:
            self.logger.debug( f"Exception list_namespaced_event {e}")
            self.logger.error( f"Exception list_namespaced_event {e}")
            data['reason'] = 'exception'
            data['message'] = 'exception'
            continue_reading_events = False
            if queue : queue.put_nowait( (500, f"ephemeral container {app_container_name} exception", data) )
            self.logger.error( f"e.Exception {e}" )

        self.logger.debug( f"list_namespaced_event {pod_name} {app_container_name}")

        try:
            await w.close()
        except Exception as e:
            self.logger.error( f"Exception when closing watch: {e}" )
        
        '''
        # we must catch exception because 
        # if the pod is deleted while we are watching, it will raise an exception and we want to catch it and stop the thread             
        # if kubernetes.client.exceptions.ApiException: (504) Reason: Timeout: Timeout: Too large resource version: 135065452, current: 135065439
        try:          
            w = watch.Watch()
            field_selector=f"metadata.name={pod_name}"
            async for event in w.stream(  
                    self.orchestrator.kubeapi.list_namespaced_pod, 
                    namespace=self.orchestrator.namespace, 
                    timeout_seconds=oc.od.settings.desktop['K8S_CREATE_POD_TIMEOUT_SECONDS'],
                    field_selector=field_selector ):
                # event must be a dict, else continue
                if not isinstance(event,dict): continue
                self.logger.debug( f"event type is {event.get('type')}")
                # event dict must contain a pod object 
                pod_event = event.get('object')
                # if podevent type must be a V1Pod, we use kubeapi.list_namespaced_pod
                if not isinstance( pod_event, V1Pod ): continue
                if not isinstance( pod_event.status, V1PodStatus ): continue

                # from https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/
                # possible values for phase
                # Pending	The Pod has been accepted by the Kubernetes cluster, but one or more of the containers has not been set up and made ready to run. This includes time a Pod spends waiting to be scheduled as well as the time spent downloading container images over the network.
                # Running	The Pod has been bound to a node, and all of the containers have been created. At least one container is still running, or is in the process of starting or restarting.
                # Succeeded	All containers in the Pod have terminated in success, and will not be restarted.
                # Failed	All containers in the Pod have terminated, and at least one container has terminated in failure.
                # Unknown	For some reason the state of the Pod could not be obtained. This phase typically occurs due to an error in communicating with the node where the Pod should be running.
                
                if pod_event.status.phase == 'Running':
                    data['reason'] = pod_event.status.phase
                    data['message'] = pod_event.status.message or pod_event.status.phase
                    queue.put_nowait( (100, data) )
                    w.stop()
                    continue

                if pod_event.status.phase == 'Pending':
                    if pod_event.status.reason in [ 'Pulling', 'Pulled', 'Started' ]:
                        data['reason'] = pod_event.status.phase
                        data['message'] = pod_event.status.message or pod_event.status.phase
                        queue.put_nowait( (100, data) )
                    continue

                if pod_event.status.phase == 'Warning':
                    data['reason'] = pod_event.status.phase
                    data['message'] = pod_event.status.message 
                    if queue : queue.put_nowait( (500, data) )
                    w.stop()

                elif pod_event.status.phase in [ 'Failed', 'Unknown', 'Warning', 'Succeeded'] :
                    # pod data object is complete, stop reading event
                    # phase can be 'Running' 'Succeeded' 'Failed' 'Unknown'
                    # an error occurs
                    data['reason'] = pod_event.status.type
                    data['message'] = pod_event.status.reason
                    if queue : queue.put_nowait( (500, data) )
                    self.logger.debug(f"The pod is not in Pending phase, phase={pod_event.status.phase} stop watching" )
                    w.stop()

        except Exception as e:
            self.logger.error( f"Exception in watch_for_end_of_pod_initializing: {e}" )
    
        try:
            await w.close()
        except Exception as e:
            self.logger.error( f"Exception when closing watch: {e}" )

        self.logger.debug('end of watch_for_end_of_pod_initializing')
        '''
        
        try:
            pod = await self.orchestrator.kubeapi.read_namespaced_pod_ephemeralcontainers(namespace=self.orchestrator.namespace,name=pod_name)
            if  isinstance( pod, V1Pod ) and \
                isinstance( pod.status, V1PodStatus ) and \
                isinstance( pod.status.ephemeral_container_statuses, list):
                    for c in pod.status.ephemeral_container_statuses:
                        if isinstance( c, V1ContainerStatus ) :
                            if c.name == app_container_name:
                                # always update data
                                data['name'] =  app_container_name
                                # self.logger.debug( f"{app_container_name} is found in ephemeral_container_statuses {c}")
                                if isinstance( c.state, V1ContainerState ):
                                    if isinstance(c.state.waiting, V1ContainerStateWaiting):
                                        data['reason'] =  c.state.waiting.reason
                                        data['message'] =  c.state.waiting.reason
                                        queue.put_nowait( (100, data) )
                                    if isinstance(c.state.terminated, V1ContainerStateTerminated ):
                                        continue_reading_events = False
                                        data['message'] =  c.state.terminated.reason
                                        data['reason'] =  c.state.terminated.reason
                                        queue.put_nowait( (500, data) )
                                    if isinstance(c.state.running, V1ContainerStateRunning ):
                                        continue_reading_events = False
                                        data['reason'] =  'Running'
                                        data['message'] =  c.state.running.started_at.strftime("%Y-%m-%d %H:%M:%S")
                                        queue.put_nowait( (200, data) )
                                break
        except ApiException as e:
            # self.logger.debug( e )
            # Reason: Handshake status 200 OK -+-+- 
            # {'audit-id': '16b378ec-f2ba-4310-b2e0-a3c3ef301587', 'cache-control': 'no-cache, private', 'content-type': 'application/json', 'x-kubernetes-pf-flowschema-uid': 'b63302af-83ee-4663-8bc2-f188e4236cf7', 'x-kubernetes-pf-prioritylevel-uid': '9a4a998a-bb63-4f75-b75a-cedd6a81f010', 'date': 'Thu, 07 May 2026 12:39:35 GMT', 'transfer-encoding': 'chunked'} -+-+- None
            self.logger.debug( f"read_namespaced_pod_ephemeralcontainers ApiException {e}")
            if isinstance( e.reason, str) and e.reason.startswith('Handshake status 200 OK'):
                pass
            else:
                self.logger.error( e )
                data['reason'] = 'Error'
                data['message'] =  str(e)
                continue_reading_events = False
                queue.put_nowait( (500, f"error {e}") )
        except Exception as e:
            continue_reading_events = False
            self.logger.error( e )  

        try:
            await w.close()
        except Exception as e:
            self.logger.error( f"Exception when closing watch: {e}" )


        # default return 
        appinstancestatus = ODAppInstanceStatus( id=app_container_name, type=self.type, wm_class=app.get('launch'), icon=app.get('icon'), icondata=app.get('icondata') )
        appinstancestatus.message = "Application" # default message 

        pod = await self.orchestrator.kubeapi.read_namespaced_pod_ephemeralcontainers(namespace=self.orchestrator.namespace,name=pod_name)
        if  isinstance( pod, V1Pod ) and \
            isinstance( pod.status, V1PodStatus ) and \
            isinstance( pod.status.ephemeral_container_statuses, list):
                for c in pod.status.ephemeral_container_statuses:
                    if isinstance( c, V1ContainerStatus ) :
                        if c.name == app_container_name:
                            # self.logger.debug( f"{app_container_name} is found in ephemeral_container_statuses {c}")
                            if isinstance( c.state, V1ContainerState ):
                                if isinstance(c.state.terminated, V1ContainerStateTerminated ):
                                    # report error to the user 
                                    appinstancestatus.message = 'Terminated'
                                    data[ 'message' ] = 'Application is terminated'
                                elif isinstance(c.state.running, V1ContainerStateRunning ):
                                    appinstancestatus.message = 'Running'
                                elif isinstance(c.state.waiting, V1ContainerStateWaiting):
                                    appinstancestatus.message = c.state.waiting.reason
                            break

        # if oc.od.settings.imagenotificationconfig.get( self.type ):
        # self.create_thread_to_watch_for_end_of_pod_initializing(myDesktop, pod_name, app_container_name, app )

        self.logger.debug(f"create done container_id={appinstancestatus.id} state={appinstancestatus.message} type={appinstancestatus.type} wm_class={appinstancestatus.wm_class} icon={appinstancestatus.icon} ")
        queue.put_nowait( (200, f"create done container_id={appinstancestatus.id} state={appinstancestatus.message}") )
        return appinstancestatus
        
        
    async def describe( self, pod_name:str, app_name:str, apps:ODApps ):
        description = None
        myPod = await self.orchestrator.kubeapi.read_namespaced_pod(namespace=self.orchestrator.namespace,name=pod_name)
        if  isinstance( myPod, V1Pod ) and \
            isinstance( myPod.spec, V1PodSpec ) and \
            isinstance( myPod.spec.ephemeral_containers, list):
                for c in myPod.spec.ephemeral_containers:
                    if c.name == app_name:
                        if isinstance( c, V1EphemeralContainer ) :
                            c_status = self.get_status( myPod, c.name )
                            if isinstance( c_status, V1ContainerStatus ):
                                phase = self.get_phase( c_status )
                                description = self.to_dict( myPod, c, c_status, phase, apps )
                                break
        return description

    async def findRunningAppInstanceforUserandImage( self, authinfo:AuthInfo, userinfo:AuthUser, app):
        self.logger.debug('')
        assert isinstance(authinfo,   AuthInfo),   f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo,   AuthUser),   f"userinfo has invalid type {type(userinfo)}"

        myephemeralContainerList = []
        uniquerunkey = app.get('uniquerunkey')

        # if the applicattion does nit set the uniquerunkey value
        # find result is always an empty list
        if not isinstance( uniquerunkey ,str):
            return myephemeralContainerList

        myDesktop = self.orchestrator.findDesktopByUser(authinfo, userinfo)
        if not isinstance(myDesktop, ODDesktop):
            self.logger.error('Desktop not found')
            raise ValueError( 'Desktop not found')

        pod_ephemeralcontainers =  await self.orchestrator.kubeapi.read_namespaced_pod_ephemeralcontainers(name=myDesktop.id, namespace=self.orchestrator.namespace )
        if not isinstance(pod_ephemeralcontainers, V1Pod ):
            self.logger.error(f"Invalid read_namespaced_pod_ephemeralcontainers {myDesktop.id} not found: pod_ephemeralcontainers is not a V1Pod")
            raise ValueError("Invalid read_namespaced_pod_ephemeralcontainers {myDesktop.id} not found")

        if isinstance(pod_ephemeralcontainers.spec.ephemeral_containers, list):
            for spec_ephemeralcontainer in pod_ephemeralcontainers.spec.ephemeral_containers:
                for v in spec_ephemeralcontainer.env:
                    if isinstance( v, V1EnvVar ):
                        if v.name == 'UNIQUERUNKEY' and v.value == uniquerunkey:
                            # check if the ephemeralcontainer is running
                            ephemeralcontainer = self.get_status( pod_ephemeralcontainers, spec_ephemeralcontainer.name )
                            if isinstance( ephemeralcontainer, V1ContainerStatus) and ephemeralcontainer.state.running:
                                # append it
                                myephemeralContainerList.append( spec_ephemeralcontainer )
                                break

        return myephemeralContainerList
        


@oc.logging.with_logger()
class ODAppInstanceKubernetesPod(ODAppInstanceBase):
    def __init__(self, orchestrator):
        super().__init__(orchestrator)
        self.type = self.orchestrator.pod_application

    def get_DISPLAY( self, desktop_ip_addr:str )->str:
        return desktop_ip_addr + ':0'
    
    def get_PULSE_SERVER( self, desktop_ip_addr:str )->str:
        return desktop_ip_addr + ':' + str(DEFAULT_PULSE_TCP_PORT)

    def get_CUPS_SERVER( self, desktop_ip_addr:str )->str:
        return desktop_ip_addr + ':' + str(DEFAULT_CUPS_TCP_PORT)
    
    async def describe( self, pod_name:str, app_name:str, apps:ODApps ):
        description = {}
        myPod = await self.orchestrator.kubeapi.read_namespaced_pod(namespace=self.orchestrator.namespace,name=app_name)
        if isinstance( myPod, V1Pod ):
            if isinstance( myPod.spec.containers, list):
                if isinstance( myPod.spec.containers[0], V1Container ):
                    description = self.to_dict( myPod, apps )
        return description
    
    def get_appnodeSelector( self, authinfo:AuthInfo, userinfo:AuthUser,  app:dict ):
        """get_appnodeSelector
            get the node selector merged data from 
            desktop.pod['pod_application'] + app['nodeSelector']
        Args:
            app (dict): application dict 

        Returns:
            dict: dict 
        """
        assert isinstance(app, dict),  f"app has invalid type {type(app)}"
        nodeSelector = {}
        executeclassname =  app.get('executeclassname')
        self.logger.debug( f"app name={app.get('name')} has executeclassname={executeclassname}")
        (executeclassname, executeclass) = self.orchestrator.get_executeclasse( authinfo, userinfo, executeclassname )
        executeclass_nodeSelector = executeclass.get('nodeSelector',{}) or {}
        nodeSelector.update(executeclass_nodeSelector)
        self.logger.debug( f"nodeSelector for name={app.get('name')} is nodeSelector={nodeSelector}")
        return nodeSelector
    

    def to_dict( self, myPod:V1Pod, apps:ODApps )->dict:
        mycontainer = {}
        assert isinstance(myPod, V1Pod), f"myPod has invalid type {type(myPod)}"

        app = {}
        if isinstance(apps, ODApps):
            if isinstance( myPod.spec.containers, list):
                if isinstance( myPod.spec.containers[0], V1Container ):
                    app = apps.find_app_by_id( myPod.spec.containers[0].image ) or {}

        # convert a container to json by filter entries
        mycontainer['podname']  = myPod.metadata.name
        mycontainer['name']     = myPod.metadata.name
        mycontainer['id']       = myPod.metadata.name # myPod.metadata.uid
        mycontainer['short_id'] = myPod.metadata.name
        mycontainer['status']   = myPod.status.phase
        mycontainer['image']    = myPod.spec.containers[0].image
        mycontainer['oc.path']  = myPod.spec.containers[0].command
        mycontainer['nodehostname'] = myPod.spec.node_name
        mycontainer['architecture'] = app.get('architecture')
        mycontainer['os']           = app.get('os')
        mycontainer['oc.icondata']  = app.get('icondata')
        mycontainer['oc.args']      = app.get('args')
        mycontainer['oc.icon']      = app.get('icon')
        mycontainer['oc.launch']    = app.get('launch')
        mycontainer['oc.displayname'] = app.get('displayname')
        mycontainer['runtime']      = 'kubernetes'
        mycontainer['type']         = self.type
        mycontainer['status']       = myPod.status.phase
        return mycontainer

    async def list( self, authinfo:AuthInfo, userinfo:AuthUser, myDesktop:ODDesktop, phase_filter=[ 'Running', 'Waiting'], apps:ODApps=None ):
        self.logger.debug('')

        assert isinstance(authinfo,   AuthInfo),   f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo,   AuthUser),   f"userinfo has invalid type {type(userinfo)}"
        assert isinstance(myDesktop, ODDesktop),   f"invalid desktop parameter {type(myDesktop)}"
        assert isinstance(phase_filter,  list),    f"invalid phase_filter parameter {type(phase_filter)}"

        result = []
        access_userid = userinfo.userid
        access_provider = authinfo.provider
        try:
            field_selector = ''
            label_selector = 'access_userid=' + access_userid + ',type=' + self.type
            label_selector += ',access_provider='  + access_provider

            # use list_namespaced_pod to filter user pod
            myPodList = await self.orchestrator.kubeapi.list_namespaced_pod(self.orchestrator.namespace, label_selector=label_selector, field_selector=field_selector)
            if isinstance( myPodList, V1PodList ):
                for myPod in myPodList.items:
                    phase = myPod.status.phase
                    # keep only Running pod
                    if isinstance( myPod.metadata.deletion_timestamp, datetime.datetime ):
                        phase = 'Terminating'

                    if phase in phase_filter:
                        # convert myPod to dict with icon 
                        mycontainer = self.to_dict( myPod, apps )
                        # add the object to the result array
                        result.append( mycontainer )
        except ApiException as e:
            self.logger.debug(f"Exception when calling list_namespaced_pod:{e}")
        return result


    async def envContainerApp( self, authinfo:AuthInfo, userinfo:AuthUser, pod_name:str, containerid:str )->dict:
        '''get the environment vars exec for the containerid '''
        env_result = None

        # define filters
        access_userid = userinfo.userid
        access_provider = authinfo.provider
        field_selector = f"metadata.name={pod_name}"
        label_selector = f"access_userid={access_userid},type={self.type},access_provider={access_provider}"

        myPodList = await self.orchestrator.kubeapi.list_namespaced_pod(
            self.orchestrator.namespace, 
            label_selector=label_selector, 
            field_selector=field_selector)

        if isinstance( myPodList, V1PodList ) and len(myPodList.items) > 0 :
            local_env = myPodList.items[0].spec.containers[0].env
            env_result = {}
            #  convert name= value= to dict
            for e in local_env:
                if isinstance( e, V1EnvVar ):
                    env_result[ e.name ] =  e.value
        return env_result

    async def logContainerApp(self, pod_name:str, container_name:str)->str:
        assert isinstance(pod_name,  str),  f"pod_name has invalid type  {type(pod_name)}"
        assert isinstance(container_name,  str),  f"container_name has invalid type {type(container_name)}"
        strlogs = 'no logs read'
        try:
            strlogs = await self.orchestrator.kubeapi.read_namespaced_pod_log( 
                name=pod_name, 
                namespace=self.orchestrator.namespace, 
                container=container_name, 
                pretty='true' )
        except ApiException as e:
            self.logger.error( e )
        except Exception as e:
            self.logger.error( e )
        return strlogs

    async def stop( self, pod_name:str, container_name:str=None )->bool:
        '''get the user's containerid stdout and stderr'''
        result = None
        propagation_policy = 'Foreground'
        grace_period_seconds = 0
        delete_options = V1DeleteOptions(
            propagation_policy = propagation_policy, 
            grace_period_seconds=grace_period_seconds )

        v1status = await self.orchestrator.kubeapi.delete_namespaced_pod(  
            name=container_name,
            namespace=self.orchestrator.namespace,
            body=delete_options,
            propagation_policy=propagation_policy )

        result = isinstance( v1status, V1Pod )

        return result


    async def removeAppInstanceKubernetesPod( self, authinfo, userinfo ):
        '''get the user's containerid stdout and stderr'''
        result = True
        access_userid = userinfo.userid
        access_provider = authinfo.provider
        label_selector = f"access_userid={access_userid},type={self.type},access_provider={access_provider}"

        myPodList = await self.orchestrator.kubeapi.list_namespaced_pod(self.orchestrator.namespace, label_selector=label_selector)
        if isinstance( myPodList, V1PodList ) and len(myPodList.items) > 0 :
            for pod in myPodList.items:
                # propagation_policy = 'Background'
                propagation_policy = 'Foreground'
                grace_period_seconds = 0
                delete_options = V1DeleteOptions( 
                    propagation_policy = propagation_policy, 
                    grace_period_seconds=grace_period_seconds )
                try:
                    v1status = await self.orchestrator.kubeapi.delete_namespaced_pod(  
                        name=pod.metadata.name,
                        namespace=self.orchestrator.namespace,
                        body=delete_options,
                        propagation_policy=propagation_policy )
                    result = isinstance( v1status, V1Pod ) and result
                except Exception as e:
                    self.logger.error( e )

        return result

    async def get_resources_usage(self, authinfo:AuthInfo, userinfo:AuthUser, pod_name:str)->dict:
        """ 
        """
        resources_usage = { 'timestamp': time.time() }
        access_userid = userinfo.userid
        access_provider = authinfo.provider
        field_selector = f"metadata.name={pod_name}"
        label_selector = f"access_userid={access_userid},type={self.type},access_provider={access_provider}"

        myPodList = await self.orchestrator.kubeapi.list_namespaced_pod( self.orchestrator.namespace, label_selector=label_selector, field_selector=field_selector)
        if isinstance( myPodList, V1PodList ) and len(myPodList.items) > 0 :
            # take only the first one, there is only one
            myPod = myPodList.items[0]
            firstcontainer = self.orchestrator.getfirstcontainerfromPod( myPod )
            if isinstance( firstcontainer, V1Container ):
                container_name = firstcontainer.name
                resources_usage = await super().get_resources_usage( myPod=myPod, container_name=container_name)
        return resources_usage

    async def list_and_stop( self, authinfo:AuthInfo, userinfo:AuthUser, pod_name:str )->bool:
        
        result = None
        access_userid = userinfo.userid
        access_provider = authinfo.provider
        field_selector = f"metadata.name={pod_name}"
        label_selector = f"access_userid={access_userid},type={self.type},access_provider={access_provider}"

        myPodList = await self.orchestrator.kubeapi.list_namespaced_pod(self.orchestrator.namespace, label_selector=label_selector, field_selector=field_selector)
        if isinstance( myPodList, V1PodList ) and len(myPodList.items) > 0 :
            # propagation_policy = 'Background'
            propagation_policy = 'Foreground'
            grace_period_seconds = 0
            delete_options = V1DeleteOptions( 
                propagation_policy = propagation_policy, 
                grace_period_seconds=grace_period_seconds )

            v1status = await self.orchestrator.kubeapi.delete_namespaced_pod(  
                name=pod_name,
                namespace=self.orchestrator.namespace,
                body=delete_options,
                propagation_policy=propagation_policy )

            result = isinstance( v1status, V1Pod ) or isinstance(v1status,V1Status)

        return result

    async def findRunningPodforUserandImage( self, authinfo, userinfo, app):
        self.logger.debug('')

        myrunningPodList = []
        access_userid = userinfo.userid
        access_provider = authinfo.provider
        try: 
            field_selector = ''
            label_selector = f"access_userid={access_userid},type={self.type}"
            if isinstance(app.get('uniquerunkey'), str ):
                label_selector += f",uniquerunkey={app.get('uniquerunkey')}"

            if oc.od.settings.desktop['authproviderneverchange'] is True:
                label_selector += f",access_provider={access_provider}"

            myPodList = await self.orchestrator.kubeapi.list_namespaced_pod(
                self.orchestrator.namespace, 
                label_selector=label_selector, 
                field_selector=field_selector
            )

            if len(myPodList.items)> 0:
                for myPod in myPodList.items:
                    # keep only Running pod
                    if myPod.metadata.deletion_timestamp is None and myPod.status.phase == 'Running':
                        myrunningPodList.append(myPod)

        except ApiException as e:
            self.logger.debug(f"Exception when calling list_namespaced_pod: {e}")
        return myrunningPodList


    async def findRunningAppInstanceforUserandImage( self, authinfo, userinfo, app):
        pod = None
        podlist = await self.findRunningPodforUserandImage( authinfo, userinfo, app)
        if len(podlist) > 0:
            pod = podlist[0]
            pod.id = pod.metadata.name # add an id for container compatibility
        return pod


    
    def create_thread_to_watch_for_end_of_pod_initializing( self, myDesktop:ODDesktop, app_pod_name:str, app:dict ):
        self.logger.debug( '')
        return asyncio.ensure_future(self.watch_for_end_of_pod_initializing(myDesktop, app_pod_name, app))

    async def watch_for_end_of_pod_initializing( self, myDesktop:ODDesktop, app_pod_name:str, app:dict )->None:
        self.logger.debug('')

        # pod data object is complete, stop reading event
        # phase can be 'Running' 'Succeeded' 'Failed' 'Unknown'
        data = { 
            'id': app_pod_name,
            'message':  app.get('name'), 
            'name':     app.get('name'),
            'icondata': app.get('icondata'),
            'icon':     app.get('icon'),
            'image':    app.get('id'),
            'launch':   app.get('launch')
        }

        # we must catch exception because 
        # if the pod is deleted while we are watching, it will raise an exception and we want to catch it and stop the thread             
        # if kubernetes.client.exceptions.ApiException: (504) Reason: Timeout: Timeout: Too large resource version: 135065452, current: 135065439
        try:          
            w = watch.Watch()
            async for event in w.stream(  self.orchestrator.kubeapi.list_namespaced_pod, 
                                    namespace=self.orchestrator.namespace, 
                                    timeout_seconds=oc.od.settings.desktop['K8S_CREATE_POD_TIMEOUT_SECONDS'],
                                    field_selector=f"metadata.name={app_pod_name}" ):   
                # event must be a dict, else continue
                if not isinstance(event,dict): continue
                self.logger.debug( f"event type is {event.get('type')}")
                # event dict must contain a pod object 
                pod_event = event.get('object')
                # if podevent type must be a V1Pod, we use kubeapi.list_namespaced_pod
                if not isinstance( pod_event, V1Pod ): continue
                if not isinstance( pod_event.status, V1PodStatus ): continue

                # from https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/
                # possible values for phase
                # Pending	The Pod has been accepted by the Kubernetes cluster, but one or more of the containers has not been set up and made ready to run. This includes time a Pod spends waiting to be scheduled as well as the time spent downloading container images over the network.
                # Running	The Pod has been bound to a node, and all of the containers have been created. At least one container is still running, or is in the process of starting or restarting.
                # Succeeded	All containers in the Pod have terminated in success, and will not be restarted.
                # Failed	All containers in the Pod have terminated, and at least one container has terminated in failure.
                # Unknown	For some reason the state of the Pod could not be obtained. This phase typically occurs due to an error in communicating with the node where the Pod should be running.
                
                if pod_event.status.phase == 'Running':
                    data['reason'] = pod_event.status.phase
                    data['message'] = pod_event.status.message or pod_event.status.phase
                    await self.orchestrator.notify_user( myDesktop, 'container', data )
                    w.stop()
                    continue

                if pod_event.status.phase == 'Pending':
                    if pod_event.status.reason in [ 'Pulling', 'Pulled', 'Started' ]:
                        data['reason'] = pod_event.status.phase
                        data['message'] = pod_event.status.message or pod_event.status.phase
                        await self.orchestrator.notify_user( myDesktop, 'container', data )
                    continue

                if pod_event.status.phase == 'Warning':
                    data['reason'] = pod_event.status.phase
                    data['message'] = pod_event.status.message 
                    await self.orchestrator.notify_user( myDesktop, 'container', data )
                    w.stop()

                elif pod_event.status.phase in [ 'Failed', 'Unknown', 'Warning', 'Succeeded'] :
                    # pod data object is complete, stop reading event
                    # phase can be 'Running' 'Succeeded' 'Failed' 'Unknown'
                    # an error occurs
                    data['reason'] = pod_event.status.type
                    data['message'] = pod_event.status.reason
                    await self.orchestrator.notify_user( myDesktop, 'container', data )
                    self.logger.debug(f"The pod is not in Pending phase, phase={pod_event.status.phase} stop watching" )
                    w.stop()

        except Exception as e:
            self.logger.error( f"Exception in watch_for_end_of_pod_initializing: {e}" )
    
        try:
            await w.close()
        except Exception as e:
            self.logger.error( f"Exception when closing watch: {e}" )

        self.logger.debug('end of watch_for_end_of_pod_initializing')


    def create_thread_to_watch_for_pulling_event( self, myDesktop:ODDesktop, app_pod_name:str, app:dict ):
        return asyncio.ensure_future(self.watch_for_pulling_event(myDesktop, app_pod_name, app))

    async def watch_for_pulling_event( self, myDesktop:ODDesktop, app_pod_name:str, app:dict )->None:
        """
            thread to watch for pulling event of an ephemeral container
            if a pulling event is received, notify the user that the application is being pulled
            if a warning event is received, notify the user that the application failed to start
            if no pulling event is received after oc.od.settings.desktop['K8S_NOTIFY_USER_APPLICATION_PULLED_DELAY_SECONDS']
            notify the user that the application has started
        Args:
            myDesktop (ODDesktop): ODDesktop
            pod_name (str): name of the pod
            app_container_name (str): name of the ephemeral container
            app (dict): app dict    
        Returns:
            None
        """
        self.logger.debug('')
        # data for notify_user
        data = {    'id': app_pod_name,
                    'message': app.get('name'), 
                    'name': app_pod_name,
                    'icondata': app.get('icondata'),
                    'icon': app.get('icon'),
                    'image': app.get('id'),
                    'launch': app.get('launch')
        }

        # we must catch exception because 
        # if the pod is deleted while we are watching, it will raise an exception and we want to catch it and stop the thread             
        # if kubernetes.client.exceptions.ApiException: (504) Reason: Timeout: Timeout: Too large resource version: 135065452, current: 135065439
        try:     
            w = watch.Watch()     
            async for event in w.stream(  self.orchestrator.kubeapi.list_namespaced_event, 
                                    namespace=self.orchestrator.namespace, 
                                    timeout_seconds=oc.od.settings.desktop['K8S_CREATE_POD_TIMEOUT_SECONDS'],
                                    field_selector=f'involvedObject.name={app_pod_name}' ):  
                # safe type check 
                if not isinstance(event, dict ): continue
                if not isinstance(event.get('object'), CoreV1Event ): continue

                # Valid values for event types (new types could be added in future)
                #    EventTypeNormal  string = "Normal"     // Information only and will not cause any problems
                #    EventTypeWarning string = "Warning"    // These events are to warn that something might go wrong

                event_object = event.get('object')
                data['reason'] = event_object.reason
                data['message'] = event_object.message

                if event_object.type == 'Normal':
                    if event_object.reason == 'Pulling':
                        data['message'] =  f"{event_object.reason} {app.get('name')}, please wait"             
                        await self.orchestrator.notify_user( myDesktop, 'container', data )
                    elif event_object.reason == 'Pulled':
                        self.logger.debug( f"Event Pulled received")
                        await self.orchestrator.notify_user( myDesktop, 'container', data )
                    elif event_object.reason == 'Started': 
                        await self.orchestrator.notify_user( myDesktop, 'container', data )
                        w.stop()
                    elif event_object.reason in [ 'Scheduled', 'Created' ]:
                        await self.orchestrator.notify_user( myDesktop, 'container', data )
                    else:
                        data['message'] = f"{event_object.reason} {event_object.message}"
                        await self.orchestrator.notify_user( myDesktop, 'container', data )
                        self.logger.error(f"{event_object.type} reason={event_object.reason} message={event_object.message}")
                        w.stop()
                    
                else: # event_object.type == 'Warning':
                    # an error occurs
                    data['name'] = event_object.type
                    data['message'] = event_object.reason
                    await self.orchestrator.notify_user( myDesktop, 'container', data )
                    w.stop()
        except Exception as e:
            self.logger.error( f"Exception in watch_for_end_of_pod_initializing: {e}" )

        try:
            await w.close()
        except Exception as e:
            self.logger.error( f"Exception when closing watch: {e}" )
        
        self.logger.debug('end of watch_for_pulling_event')
        



    async def create(self, myDesktop:ODDesktop, app:dict, authinfo:AuthInfo, userinfo:AuthUser={}, queue: asyncio.Queue=None, userargs=None, **kwargs ):
        self.logger.debug('')

        rules = app.get('rules', {}) or {} # app['rules] can be set to None
        desktop_rules = oc.od.settings.desktop['policies'].get('rules')
        if isinstance( desktop_rules, dict ):
            rules.update( desktop_rules )
        network_config = self.orchestrator.applyappinstancerules_network( authinfo, rules )

        (volumeBinds, volumeMounts) = await self.orchestrator.build_volumes(   
            authinfo,
            userinfo,
            queue,
            volume_type='pod_application',
            secrets_requirement=app.get('secrets_requirement'),
            rules=rules,
            **kwargs)

        envlist = self.get_env_for_appinstance( myDesktop, app, authinfo, userinfo, userargs, **kwargs )

        command = [ '/composer/appli-docker-entrypoint.sh' ]
        labels = {
            'access_providertype':  authinfo.providertype,
            'access_provider':  authinfo.provider,
            'access_userid':    userinfo.userid,
            'access_username':  self.orchestrator.get_labelvalue(userinfo.name), # 
            'type':             self.type,
            'uniquerunkey':     app.get('uniquerunkey'),
            'netpol/ocapplication': 'true'
        }

        myuuid = oc.lib.uuid_digits()
        pod_sufix = 'app_' + app['name'] + '_' +  myuuid
        app_pod_name = await self.orchestrator.get_podname( authinfo, userinfo, pod_sufix)

        # default empty dict annotations
        annotations = {}
        # Check if a network annotations exists
        network_annotations = network_config.get( 'annotations' )
        if isinstance( network_annotations, dict):
            annotations.update( network_annotations )

        # get the node selector merged data from desktop.pod['pod_application'] and app['nodeSelector']
        nodeSelector = self.get_appnodeSelector( authinfo, userinfo, app)
        securitycontext = await self.get_securitycontext( authinfo, userinfo, app )
        workingDir = await self.orchestrator.get_user_homedirectory( authinfo, userinfo )
        resources = self.get_resources( authinfo, userinfo, app.get('executeclassname') )
        affinity = self.get_affinity( authinfo, userinfo, app, myDesktop )

        # init container for the pod apps 
        initContainers = []
        currentcontainertype = 'init'
        # build the init command 
        init_command = await self.orchestrator.buildinitcommand( authinfo, userinfo )
        # init_command can be a str or a list
        if len(init_command) > 0:
            # get volumeMounts for init container
            init_volumeMounts =  volumeMounts.copy()
            # get init_localaccount_volumes and init_localaccount_volumes_mount
            (init_localaccount_volumes, init_localaccount_volumes_mount) = await self.orchestrator.build_volumes_localaccount(authinfo, userinfo )
            # add init_localaccount_volumes to pod volumes
            volumeBinds.update( init_localaccount_volumes )
            # add init_localaccount_volumes_mount to init container 
            # and only for init container to prevent user access to localaccount files
            init_volumeMounts.update( init_localaccount_volumes_mount )
            
            init_container = await self.orchestrator.addcontainertopod( 
                authinfo=authinfo, 
                userinfo=userinfo, 
                currentcontainertype=currentcontainertype, 
                command=init_command,
                myuuid=myuuid,
                envlist=envlist,
                list_volumeMounts=list( init_volumeMounts.values() )
            )
            initContainers.append( init_container )
            self.logger.debug( f"pod container added {currentcontainertype}" )
        else:
            self.logger.debug( f"skipping {currentcontainertype} init command={init_command}" )


        imagePullSecrets = self.orchestrator.giveme_an_imagePullSecrets()
        runtimeClassName = app.get('runtimeClassName') or oc.od.settings.desktop_pod.get(self.type, {}).get('runtimeClassName')

        # update envlist
        # add EXECUTION CONTEXT env var inside the container
        envlist.append( { 'name': 'ABCDESKTOP_EXECUTE_RUNTIME',   'value': self.type} )
        envlist.append( { 'name': 'ABCDESKTOP_EXECUTE_RESOURCES', 'value': json.dumps(resources) } )
        envlist.append( { 'name': 'ABCDESKTOP_RUNTIME_CLASSNAME', 'value': runtimeClassName } )
        
        pod_manifest = {
            'apiVersion': 'v1',
            'kind': 'Pod',
            'metadata': {
                'name': app_pod_name,
                'namespace': self.orchestrator.namespace,
                'labels': labels,
                'annotations': annotations
            },
            'spec': {
                'terminationGracePeriodSeconds': 0,  # Time to wait before moving from a TERM signal to the pod's main process to a KILL signal.
                'restartPolicy' : 'Never',
                'securityContext': securitycontext,
                'affinity': affinity,
                'automountServiceAccountToken': False,  # disable service account inside pod
                'volumes': list( volumeBinds.values() ),
                'nodeSelector': nodeSelector,
                'initContainers': initContainers,
                'tolerations': oc.od.settings.desktop_pod.get('tolerations'),
                'imagePullSecrets': imagePullSecrets,
                'runtimeClassName': runtimeClassName,
                'containers': [ {   
                    'imagePullPolicy': oc.od.settings.desktop_pod[self.type].get('imagePullPolicy','IfNotPresent'),
                    'image': app['id'],
                    'name': app_pod_name,
                    'command': command,
                    'env': envlist,
                    'volumeMounts': list( volumeMounts.values() ),
                    'resources': resources,
                    'workingDir' : workingDir
                } ]
            }
        }

        # keep LOG LEVEL to INFO in yaml dump
        # to keep data in syslog 
        self.logger.info(f"dump create pod_manifest json {self.type}")
        self.logger.info( json.dumps( pod_manifest, indent=2 ) )
        try:
            pod = await self.orchestrator.kubeapi.create_namespaced_pod(
                namespace=self.orchestrator.namespace,
                body=pod_manifest )
        except ApiException as e:
            self.logger.error('== ApiException ==')
            self.logger.error(e)
            message = oc.lib.try_to_read_json_entry( 'message', e.body )
            self.logger.debug(f"message={message}")
            raise ODError( status=500, message=message )
        except Exception as e:
            self.logger.error('== Exception ==')
            self.logger.error(e)
            raise ODError( status=500, message=f"{e}" )
        
        if not isinstance(pod, V1Pod ):
            raise ValueError( f"Invalid create_namespaced_pod type return {type(pod)} V1Pod is expecting")

        # if oc.od.settings.imagenotificationconfig.get( self.type ):
        # create a thread to watch for pulling event of an ephemeral container
        # self.create_thread_to_watch_for_pulling_event( myDesktop, app_pod_name, app )
        # self.create_thread_to_watch_for_end_of_pod_initializing( myDesktop, app_pod_name, app )

        pod = await self.orchestrator.kubeapi.read_namespaced_pod_ephemeralcontainers(namespace=self.orchestrator.namespace,name=app_pod_name)
        phase = 'Unknown'
        if isinstance( pod, V1Pod ) :
            phase = pod.status.phase
            
        appinstancestatus = ODAppInstanceStatus(
            id=app_pod_name,
            message=phase,
            webhook = None, # webhooking is not supported for pod application
            type=self.type,
            wm_class=app.get('launch'),
            icon=app.get('icon'), 
            icondata=app.get('icondata')
        )
        
        return appinstancestatus
