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
from oc.od.apps import ODApps
import oc.od.error
import oc.od.settings
import oc.lib 
import oc.auth.namedlib
import os
import time
import datetime
import binascii
import urllib3


import yaml
import json
import uuid
import chevron
import requests
import copy
import threading
import hashlib

from kubernetes import client, config, watch
from kubernetes.stream import stream
from kubernetes.stream.ws_client import ERROR_CHANNEL
from kubernetes.client.rest import ApiException

from kubernetes.client.models.v1_pod import V1Pod
# from kubernetes.client.models.v1_pod_spec import V1PodSpec
from kubernetes.client.models.v1_pod_status import V1PodStatus
# from kubernetes.client.models.v1_container import V1Container
from kubernetes.client.models.v1_ephemeral_container import V1EphemeralContainer
from kubernetes.client.models.v1_status import V1Status
from kubernetes.client.models.v1_container import V1Container

# kubernetes.client.models.v1_container
from kubernetes.client.models.v1_container_status import V1ContainerStatus
from kubernetes.client.models.v1_container_state import V1ContainerState
from kubernetes.client.models.v1_container_state_terminated import V1ContainerStateTerminated
from kubernetes.client.models.v1_container_state_running import V1ContainerStateRunning
from kubernetes.client.models.v1_container_state_waiting import V1ContainerStateWaiting

# Volume
#from kubernetes.client.models.v1_volume import V1Volume
#from kubernetes.client.models.v1_volume_mount import V1VolumeMount
#from kubernetes.client.models.v1_local_volume_source import V1LocalVolumeSource
#from kubernetes.client.models.v1_flex_volume_source import V1FlexVolumeSource
#from kubernetes.client.models.v1_host_path_volume_source import V1HostPathVolumeSource
#from kubernetes.client.models.v1_secret_volume_source import V1SecretVolumeSource

# Secret
from kubernetes.client.models.v1_secret import V1Secret
#from kubernetes.client.models.v1_secret_list import V1SecretList

from kubernetes.client.models.core_v1_event import CoreV1Event
from kubernetes.client.models.v1_node_list import V1NodeList
from kubernetes.client.models.v1_env_var import V1EnvVar 
from kubernetes.client.models.v1_pod_list import V1PodList
#from kubernetes.client.models.v1_config_map import V1ConfigMap
#from kubernetes.client.models.v1_endpoint import V1Endpoint
from kubernetes.client.models.v1_endpoints import V1Endpoints
#from kubernetes.client.models.v1_endpoints_list import V1EndpointsList
from kubernetes.client.models.v1_endpoint_subset import V1EndpointSubset 
from kubernetes.client.models.core_v1_endpoint_port import CoreV1EndpointPort
from kubernetes.client.models.v1_endpoint_address import V1EndpointAddress
from kubernetes.client.models.v1_object_meta import V1ObjectMeta
from kubernetes.client.models.v1_resource_requirements import V1ResourceRequirements

from kubernetes.client.models.v1_delete_options import V1DeleteOptions


import oc.lib
import oc.od.acl
import oc.od.volume         # manage volume for desktop
import oc.od.secret         # manage secret for kubernetes
import oc.od.configmap
import oc.od.appinstancestatus
from   oc.od.error          import ODAPIError   # import all error classes
from   oc.od.desktop        import ODDesktop
from   oc.auth.authservice  import AuthInfo, AuthUser # to read AuthInfo and AuthUser
from   oc.od.vnc_password   import ODVncPassword

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
        # storage name is o-UUID
        self.storagecontainernameprefix     = 'o'   # storage container letter prefix o for secret storage
        # ssh name is h-UUID
        self.sshcontainernameprefix         = 'h'   # ssh container letter prefix h for ssh
        # webshell name is w-UUID
        self.webshellcontainernameprefix    = 'w'   # webshell container letter prefix w
        # name separtor only for human read 
        self.rdpcontainernameprefix         = 'r'   # file container letter prefix r for xrdp
        # name separtor only for human read 
        self.containernameseparator         = '-'   # separator

        self.nameprefixdict = { 'graphical' : self.graphicalcontainernameprefix,
                                'spawner'   : self.spawnercontainernameprefix,
                                'webshell'  : self.webshellcontainernameprefix,
                                'printer'   : self.printercontainernameprefix,
                                'sound'     : self.soundcontainernameprefix,  
                                'filer'     : self.filercontainernameprefix,
                                'init'      : self.initcontainernameprefix,
                                'storage'   : self.storagecontainernameprefix,
                                'ssh'       : self.sshcontainernameprefix,
                                'rdp'       : self.rdpcontainernameprefix 
        }
        self.name                   = 'base'
        self.desktoplaunchprogress  = oc.pyutils.Event()        
        self.x11servertype          = 'x11server'        
        self.applicationtype        = 'pod_application'
        self.applicationtypepull    = 'pod_application_pull'
        self.endpoint_domain        = 'desktop'
        self.ephemeral_container    = 'ephemeral_container'

    def get_containername( self, authinfo, userinfo, currentcontainertype, myuuid ):
        prefix = self.nameprefixdict[currentcontainertype]
        name = prefix + self.containernameseparator + authinfo.provider + self.containernameseparator + userinfo.userid
        name = oc.auth.namedlib.normalize_name_dnsname( name )
        # return self.get_basecontainername( prefix, userid, myuuid )
        return name

    # def get_basecontainername( self, containernameprefix, userid, container_name ):
    #    user_container_name = self.containernameseparator
    #    if isinstance( userid, str ):
    #        user_container_name = userid + self.containernameseparator
    #    name = containernameprefix + self.containernameseparator + user_container_name + container_name
    #    name = oc.auth.namedlib.normalize_name_dnsname( name )
    #    return name

    def get_normalized_username(self, name ):
        """[get_normalized_username]
            return a username without accent to be use in label and container name
        Args:
            name ([str]): [username string]

        Returns:
            [str]: [username correct value]
        """
        return oc.lib.remove_accents( name ) 
   
    def resumedesktop(self, authinfo, userinfo, **kwargs):
        raise NotImplementedError('%s.resumedesktop' % type(self))

    def createdesktop(self, authinfo, userinfo, **kwargs):
        raise NotImplementedError('%s.createdesktop' % type(self))

    def build_volumes( self, authinfo, userinfo, volume_type, secrets_requirement, rules, **kwargs):
        raise NotImplementedError('%s.build_volumes' % type(self))

    def findDesktopByUser( self, authinfo, userinfo ):
        raise NotImplementedError('%s.findDesktopByUser' % type(self))

    def removedesktop(self, authinfo, userinfo, args={}):
        raise NotImplementedError('%s.removedesktop' % type(self))

    def get_auth_env_dict( self, authinfo, userinfo ):
        raise NotImplementedError('%s.get_auth_env_dict' % type(self))

    def getsecretuserinfo(self, authinfo, userinfo):
        raise NotImplementedError('%s.getsecretuserinfo' % type(self))

    def garbagecollector( self, timeout ):
        raise NotImplementedError(f"{type(self)}.garbagecollector")

    def execwaitincontainer( self, desktop, command, timeout):
        raise NotImplementedError(f"{type(self)}.execwaitincontainer")

    def is_configured( self):
        raise NotImplementedError(f"{type(self)}.is_configured")

    def countdesktop(self):
        raise NotImplementedError(f"{type(self)}.countdesktop")

    def listContainerApps( self, authinfo, userinfo, apps ):
        raise NotImplementedError('%s.listContainerApps' % type(self))

    def countRunningContainerforUser( self, authinfo, userinfo):  
        raise NotImplementedError('%s.countRunningContainerforUser' % type(self))

    def envContainerApp( self, authinfo:AuthInfo, userinfo:AuthUser, pod_name:str, containerid:str):
        raise NotImplementedError('%s.envContainerApp' % type(self))
    
    def removeContainerApp( self, authinfo, userinfo, containerid):
        raise NotImplementedError('%s.removeContainerApp' % type(self))

    def logContainerApp( self, authinfo, userinfo, podname, containerid):
        raise NotImplementedError('%s.logContainerApp' % type(self))

    def stopContainerApp( self, authinfo, userinfo, myDesktop, podname, containerid, timeout=5 ):
        raise NotImplementedError('%s.stopContainerApp' % type(self))

    def get_volumename(self, prefix, userinfo):
        if not isinstance(prefix,str):
             raise ValueError('invalid prefix value %s' % type(prefix))

        if not isinstance(userinfo, oc.auth.authservice.AuthUser):
             raise ValueError('invalid userinfo value %s' % type(userinfo))

        name = prefix + '-' + userinfo.get('userid')
        normalize_name = oc.auth.namedlib.normalize_name( name )
        return normalize_name

    def user_connect_count(self, desktop:ODDesktop, timeout=10):
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
        result = self.execwaitincontainer( desktop, command, timeout)
        if not isinstance(result,dict):
            # do not raise exception 
            return nReturn

        self.logger.info( f"command={command} exitcode {result.get('ExitCode')} output={result.get('stdout')}" )
        if result.get('ExitCode') == 0 and result.get('stdout'):
            try:
                nReturn = int(result.get('stdout'))
            except ApiException as e:
                self.logger.error(str(e))
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

    def waitForDesktopProcessReady(self, desktop, callback_notify):
        self.logger.debug('')

        nCountMax = 42
        # check if supervisor has stated all processs
        nCount = 1
        bListen = { 'graphical': False, 'spawner': False }
        # loop
        # wait for a listen dict { 'x11server': True, 'spawner': True }

        while nCount < nCountMax:

            for service in ['graphical', 'spawner']: 
                self.logger.debug( f"desktop services status bListen {bListen}" ) 
                # check if WebSockifyListening id listening on tcp port 6081
                if bListen[service] is False:
                    messageinfo = f"c.Waiting for desktop {service} service {nCount}/{nCountMax}"
                    callback_notify(messageinfo)
                    bListen[service] = self.waitForServiceListening( desktop, service=service)
                    if bListen[service] is False:
                        messageinfo = f"c.Desktop {service} service is not ready."
                        time.sleep(1)
            nCount += 1
            
            if bListen['graphical'] is True and bListen['spawner'] is True:     
                self.logger.debug( "desktop services are ready" )                  
                callback_notify( f"c.Desktop services are running after {nCount} s" )              
                return True
        
        # Can not chack process status     
        self.logger.warning( f"waitForDesktopProcessReady not ready services status:{bListen}" )
        return False


    def waitForServiceHealtz(self, desktop, service, timeout=5):
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
        
        if type(desktop) is not ODDesktop:
            raise ValueError('invalid desktop object type' )

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
        result = self.execwaitincontainer( desktop, command, timeout)
        self.logger.debug( 'command %s , return %s output %s', command, str(result.get('exit_code')), result.get('stdout') )

        if isinstance(result, dict):
            return result.get('ExitCode') == 0
        else:
            return False

      
    def waitForServiceListening(self, desktop:ODDesktop, service:str, timeout:int=2)-> bool:
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

        self.logger.debug(locals())
        # Note the same timeout value is used twice
        # for the wait_port command and for the exec command         
        
        if type(desktop) is not ODDesktop:
            raise ValueError('invalid desktop object type' )

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
        result = self.execwaitincontainer( desktop, command, timeout)
     
        if isinstance(result, dict):
            self.logger.debug( f"command={command} exit_code={result.get('ExitCode')} stdout={result.get('stdout')}" )
            isportready = result.get('ExitCode') == 0
            self.logger.debug( f"isportready={isportready}")
            if isportready is True:
                self.logger.debug( f"binding {binding} is up")
                return self.waitForServiceHealtz(desktop, service, timeout)

        self.logger.info( f"binding {binding} is down")
        return False

    @staticmethod
    def generate_xauthkey():
        # generate key, xauth requires 128 bit hex encoding
        # xauth add ${HOST}:0 . $(xxd -l 16 -p /dev/urandom)
        key = binascii.b2a_hex(os.urandom(15))
        return key.decode( 'utf-8' )

    @staticmethod
    def generate_pulseaudiocookie():
        # generate key, PULSEAUDIO requires PA_NATIVE_COOKIE_LENGTH 256
        # use cat /etc/pulse/cookie | openssl rc4 -K "$PULSEAUDIO_COOKIE" -nopad -nosalt > ~/.config/pulse/cookie
        # use os.urandom(24) as key -> hex string is too long, ignoring excess
        key = binascii.b2a_hex(os.urandom(16))
        return key.decode( 'utf-8' )

    @staticmethod
    def generate_broadcastcookie():
        # generate key, SPAWNER and BROADCAT service
        # use os.urandom(24) as key 
        key = binascii.b2a_hex(os.urandom(24))
        return key.decode( 'utf-8' )


@oc.logging.with_logger()
class ODOrchestrator(ODOrchestratorBase):
    
    def __init__(self ):
        super().__init__()
        self.name = 'docker'
        
    def prepareressources(self, authinfo:AuthInfo, userinfo:AuthUser):
        self.logger.info('externals ressources are not supported in docker mode')  

    def getsecretuserinfo(self, authinfo:AuthInfo, userinfo:AuthUser):  
        ''' cached userinfo are not supported in docker mode '''    
        ''' return an empty dict '''
        self.logger.info('get cached userinfo are not supported in docker mode')
        return {} 

    def build_volumes( self, authinfo:AuthInfo, userinfo:AuthUser, volume_type, secrets_requirement, rules, **kwargs):
        raise NotImplementedError('%s.build_volumes' % type(self))
  
    def countdesktop(self):
        raise NotImplementedError('%s.countdesktop' % type(self))

    def removedesktop(self, authinfo, userinfo, args={}):
        raise NotImplementedError('%s.removedesktop' % type(self))

    def is_instance_app( self, appinstance ):
        raise NotImplementedError('%s.is_instance_app' % type(self))

    def execwaitincontainer( self, desktop, command, timeout=1000):
        raise NotImplementedError('%s.removedesktop' % type(self))

    def execininstance( self, container_id, command):
        raise NotImplementedError('%s.execininstance' % type(self))

    def getappinstance( self, authinfo, userinfo, app ):        
        raise NotImplementedError('%s.getappinstance' % type(self))

    def get_auth_env_dict( self, authinfo, userinfo  ):
        return {}

    @staticmethod
    def applyappinstancerules_homedir( authinfo, rules ):
        homedir_enabled = False      # by default application do not share the user homedir

        # Check if there is a specify rules to start this application
        if type(rules) is dict  :
            # Check if there is a homedir rule
            rule_homedir =  rules.get('homedir')
            if type(rule_homedir) is dict:

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
        raise NotImplementedError('%s.createappinstance' % type(self))

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
        
        self.logger.debug( f"type(app) is {type(app)}" )

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
            self.logger.debug( f"type(desktop_interfaces) is {type(app.desktop_interfaces)}" )
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
        raise NotImplementedError('%s.logs' % type(self))

    def isgarbagable( self, container, expirein, force=False ):
        raise NotImplementedError('%s.isgarbagable' % type(self))

    def garbagecollector( self, expirein, force=False ):
        raise NotImplementedError('%s.garbagecollector' % type(self))

@oc.logging.with_logger()
class ODOrchestratorKubernetes(ODOrchestrator):

    def __init__(self):
        super().__init__()

        self.DEFAULT_K8S_CREATE_TIMEOUT_SECONDS = 30

        self.appinstance_classes = {    'ephemeral_container': ODAppInstanceKubernetesEphemeralContainer,
                                        'pod_application': ODAppInstanceKubernetesPod }
        self.all_phases_status = [ 'Running', 'Terminated', 'Waiting', 'Completed', 'Succeeded']
        self.all_running_phases_status = [ 'Running', 'Waiting' ]

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
        if os.getenv('KUBERNETES_SERVICE_HOST') and os.getenv('KUBERNETES_SERVICE_PORT') :
            # self.logger.debug( 'env has detected $KUBERNETES_SERVICE_HOST and $KUBERNETES_SERVICE_PORT' )
            # self.logger.debug( 'config.load_incluster_config start')
            config.load_incluster_config() # set up the client from within a k8s pod
            # self.logger.debug( 'config.load_incluster_config kubernetes mode done')
        else:
            # self.logger.debug( 'config.load_kube_config not in cluster mode')
            config.load_kube_config()
            # self.logger.debug( 'config.load_kube_config done')
        
        # 
        # previous line is 
        #   from kubernetes.client import configuration 
        #   SSL hostname verification failure with websocket-client #138
        #   https://github.com/kubernetes-client/python/issues/138#
        # 
        #   you're using minikube for development purpose. It is not able to recognise your hostname. 
        #   https://stackoverflow.com/questions/54050504/running-connect-get-namespaced-pod-exec-using-kubernetes-client-corev1api-give
        #
        client.configuration.assert_hostname = False
        self.kubeapi = client.CoreV1Api()
        self.namespace = oc.od.settings.namespace
        self.bConfigure = True
        self.name = 'kubernetes'

        # defined remapped tmp volume
        # if app is a pod use a specifed path in /var/abcdesktop/pods
        # if app id a docker container use an empty
        # if oc.od.settings.desktopusepodasapp :
        # volume_tmp =      { 'name': 'tmp', 'emptyDir': { 'sizeLimit': '8Gi' } }
        # volume_tmp_path = { 'name': 'tmp', 'mountPath': '/tmp', 'subPathExpr': '$(POD_NAME)' }
        # volumemount_tmp =  {'mountPath': '/tmp',       'name': 'tmp'} ]
        # volumemount_tmp_path = {'mountPath': '/tmp',       'name': 'tmp', 'subPathExpr': '$(POD_NAME)'}
        # self.volume
        # no pods

        self.default_volumes = {}
        self.default_volumes_mount  = {}
        
        #
        # POSIX shared memory requires that a tmpfs be mounted at /dev/shm. 
        # The containers in a pod do not share their mount namespaces so we use volumes 
        # to provide the same /dev/shm into each container in a pod. 
        # read https://docs.openshift.com/container-platform/3.6/dev_guide/shared_memory.html
        # Here is the information of a pod on the cluster, we can see that the size of /dev/shm is 64MB, and when writing data to the shared memory via dd, it will throw an exception when it reaches 64MB: “No space left on device”.
        #
        # $ dd if=/dev/zero of=/dev/shm/test
        # dd: writing to '/dev/shm/test': No space left on device
        # 131073+0 records in
        # 131072+0 records out
        # 67108864 bytes (67 MB, 64 MiB) copied, 0.386939 s, 173 MB/s

        # 
        shareProcessMemorySize = oc.od.settings.desktop_pod.get('spec',{}).get('shareProcessMemorySize', oc.od.settings.DEFAULT_SHM_SIZE)
        self.default_volumes['shm']       = { 'name': 'shm', 'emptyDir': {  'medium': 'Memory', 'sizeLimit': shareProcessMemorySize } }
        self.default_volumes_mount['shm'] = { 'name': 'shm', 'mountPath' : '/dev/shm' }

        self.default_volumes['tmp']       = { 'name': 'tmp',  'emptyDir': { 'medium': 'Memory', 'sizeLimit': '8Gi' } }
        self.default_volumes_mount['tmp'] = { 'name': 'tmp',  'mountPath': '/tmp' }

        self.default_volumes['cache']          = { 'name': 'cache',  'emptyDir': { 'medium': 'Memory', 'sizeLimit': '8Gi' } }
        # self.default_volumes_mount['cache'] = { 'name': 'cache',  'mountPath': '/cache' }

        self.default_volumes['run']       = { 'name': 'run',  'emptyDir': { 'medium': 'Memory', 'sizeLimit': '1M' } }
        self.default_volumes_mount['run'] = { 'name': 'run',  'mountPath': '/var/run/desktop' }

        self.default_volumes['log']       = { 'name': 'log',  'emptyDir': { 'medium': 'Memory', 'sizeLimit': '8M' } }
        self.default_volumes_mount['log'] = { 'name': 'log',  'mountPath': '/var/log/desktop' }

        self.default_volumes['rundbus']       = { 'name': 'rundbus',  'emptyDir': { 'medium': 'Memory', 'sizeLimit': '8M' } }
        self.default_volumes_mount['rundbus'] = { 'name': 'rundbus',  'mountPath': '/var/run/dbus' }

        self.default_volumes['runuser']       = { 'name': 'runuser',  'emptyDir': { 'medium': 'Memory', 'sizeLimit': '8M' } }
        self.default_volumes_mount['runuser'] = { 'name': 'runuser',  'mountPath': '/run/user/' }

        self.default_volumes['x11socket'] = { 'name': 'x11socket',  'emptyDir': { 'medium': 'Memory' } }
        self.default_volumes_mount['x11socket'] = { 'name': 'x11socket',  'mountPath': '/tmp/.X11-unix' }

        self.default_volumes['pulseaudiosocket'] = { 'name': 'pulseaudiosocket',  'emptyDir': { 'medium': 'Memory' } }
        self.default_volumes_mount['pulseaudiosocket'] = { 'name': 'pulseaudiosocket',  'mountPath': '/tmp/.pulseaudio' }

        self.default_volumes['cupsdsocket'] = { 'name': 'cupsdsocket',  'emptyDir': { 'medium': 'Memory' } }
        self.default_volumes_mount['cupsdsocket'] = { 'name': 'cupsdsocket',  'mountPath': '/tmp/.cupsd' }

        self.default_volumes['passwd']      = { 'name': 'passwd',  'emptyDir': { 'medium': 'Memory', 'sizeLimit': '16Ki' } }
        self.default_volumes_mount['passwd']= { 'name': 'passwd',  'mountPath': '/etc/passwd' }

        self.default_volumes['shadow']       = { 'name': 'shadow',  'emptyDir': { 'medium': 'Memory', 'sizeLimit': '16Ki' } }
        self.default_volumes_mount['shadow'] = { 'name': 'shadow',  'mountPath': '/etc/shadow' }

        self.default_volumes['group']       = { 'name': 'group',  'emptyDir': { 'medium': 'Memory', 'sizeLimit': '16Ki' } }
        self.default_volumes_mount['group'] = { 'name': 'group',  'mountPath': '/etc/group' }

        self.default_volumes['gshadow']       = { 'name': 'gshadow',  'emptyDir': { 'medium': 'Memory', 'sizeLimit': '16Ki' } }
        self.default_volumes_mount['gshadow'] = { 'name': 'gshadow',  'mountPath': '/etc/gshadow' }

        self.default_volumes['local']       = { 'name': 'local',  'emptyDir': { 'medium': 'Memory', 'sizeLimit': '8Gi' } }
        self.default_volumes_mount['local'] = { 'name': 'local',  'mountPath': '/home/balloon/.local' }

        # self.logger.debug( f"ODOrchestratorKubernetes done configure={self.bConfigure}" )


    def close(self):
        #self.kupeapi.close()
        pass

    def is_configured(self)->bool: 
        """[is_configured]
            return True if kubernetes is configured 
            call list_node() API  
        Returns:
            [bool]: [True if kubernetes is configured, else False]
        """
        bReturn = False
        try:
            if self.bConfigure :
                # run a dummy node list to check if kube is working
                node_list = self.kubeapi.list_node()
                if isinstance( node_list, V1NodeList) and len(node_list.items) > 0:
                    bReturn = True
        except Exception as e:
            self.logger.error( str(e) )
        return bReturn


    def listEndpointAddresses( self, endpoint_name:str )->tuple:
        list_endpoint_addresses = None
        list_endpoint_port = None
        endpoint = self.kubeapi.read_namespaced_endpoints( name=endpoint_name, namespace=self.namespace )
        if isinstance( endpoint, V1Endpoints ):
            if not isinstance( endpoint.subsets, list) or len(endpoint.subsets) == 0:
                return list_endpoint_addresses

            endpoint_subset = endpoint.subsets[0]
            if isinstance( endpoint_subset, V1EndpointSubset ) :
                list_endpoint_addresses = []
                # read the uniqu port number
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


    def findAllSecretsByUser( self, authinfo:AuthInfo, userinfo:AuthUser)->dict:
        """[findAllSecretsByUser]
            list all user secret for all supported type
        Args:
            authinfo ([type]): [description]
            userinfo ([type]): [description]

        Returns:
            [dict]: [dict of secret]
            key is the secret type
            value is the secret value
        """
        mysecretdict = self.list_dict_secret_data( authinfo, userinfo, access_type='auth' )
        return mysecretdict

    def get_podname( self, authinfo:AuthInfo, userinfo:AuthUser, pod_sufix:str )->str:
        """[get_podname]
            return a pod name from authinfo, userinfo and uuid 
        Args:
            authinfo (AuthInfo): authentification data
            userinfo (AuthUser): user data 
            pod_sufix ([str]): [uniqu sufix]

        Returns:
            [str]: [name of the user pod]
        """
        userid = userinfo.userid
        if authinfo.provider == 'anonymous':
            userid = 'anonymous'
        return oc.auth.namedlib.normalize_name_dnsname( userid + self.containernameseparator + pod_sufix)[0:252]       
 
    def get_labelvalue( self, label_value:str)->str:
        """[get_labelvalue]

        Args:
            label_value ([str]): [label_value name]

        Returns:
            [str]: [return normalized label name]
        """
        assert isinstance(label_value, str),  f"label_value has invalid type {type(label_value)}"
        normalize_data = oc.auth.namedlib.normalize_label( label_value )
        no_accent_normalize_data = oc.lib.remove_accents( normalize_data )
        return no_accent_normalize_data

    def logs( self, authinfo:AuthInfo, userinfo:AuthUser )->str:
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
                myDesktop = self.pod2desktop( pod=myPod )
                pod_name = myPod.metadata.name  
                container_name = myDesktop.container_name
                strlogs = self.kubeapi.read_namespaced_pod_log( name=pod_name, namespace=self.namespace, container=container_name, pretty='true' )
            except ApiException as e:
                self.logger.error( str(e) )
        else:
            self.logger.info( f"No pod found for user {userinfo.userid}" )
        return strlogs

    def build_volumes_secrets( self, authinfo:AuthInfo, userinfo:AuthUser, volume_type:str, secrets_requirement:list, rules={}, **kwargs:dict)->dict:
        self.logger.debug('')
        assert isinstance(authinfo, AuthInfo),  f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo, AuthUser),  f"userinfo has invalid type {type(userinfo)}"

        volumes = {}        # set empty dict of V1Volume dict by default
        volumes_mount = {}  # set empty dict of V1VolumeMount by default
        #
        # mount secret in /var/secrets/abcdesktop
        #
        self.logger.debug( "listing list_dict_secret_data access_type='auth'" )
        mysecretdict = self.list_dict_secret_data( authinfo, userinfo, access_type='auth' )
        for secret_auth_name in mysecretdict.keys():
            # https://kubernetes.io/docs/concepts/configuration/secret
            # create an entry eq: 
            # /var/secrets/abcdesktop/ntlm
            # /var/secrets/abcdesktop/cntlm
            # /var/secrets/abcdesktop/kerberos
            # 
            
            self.logger.debug( f"checking {secret_auth_name} access_type='auth' " )
            # only mount secrets_requirement
            if isinstance( secrets_requirement, list ):
                if secret_auth_name not in secrets_requirement:
                    self.logger.debug( f"{secret_auth_name} is not in {secrets_requirement}" )
                    self.logger.debug( f"{secret_auth_name} is skipped" )
                    continue

            self.logger.debug( f"adding secret type {mysecretdict[secret_auth_name]['type']} to volume pod" )
            secretmountPath = oc.od.settings.desktop['secretsrootdirectory'] + mysecretdict[secret_auth_name]['type'] 
            # mode is 644 -> rw-r--r--
            # Owing to JSON limitations, you must specify the mode in decimal notation.
            # 644 in decimal equal to 420
            volumes[secret_auth_name] = {
                'name':secret_auth_name, 
                'secret': { 
                    'secretName': secret_auth_name, 
                    'defaultMode': 420
                }
            }
            volumes_mount[secret_auth_name] = {
                'name':secret_auth_name, 
                'mountPath':secretmountPath 
            }        
        return (volumes, volumes_mount)

    def build_volumes_flexvolumes( self, authinfo, userinfo, volume_type, secrets_requirement, rules={}, **kwargs):
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


                # mount the remote home dir as a flexvol
                # WARNING ! if the flexvol mount failed, the pod must start
                # abcdesktop/cifs always respond a success
                # in case of failure access right is denied                
                # the flexvolume driver abcdesktop/cifs MUST be deploy on each node

                # Flex volume use kubernetes secret                    
                # Kubernetes secret as already been created by prepareressource function call 
                # Read the secret and use it

                secret = oc.od.secret.selectSecret( self.namespace, self.kubeapi, prefix=mountvol.name, secret_type=fstype )
                if isinstance( secret, oc.od.secret.ODSecret):
                    driver_type =  self.namespace + '/' + fstype
                    self.on_desktoplaunchprogress('b.Building flexVolume storage data for driver ' + driver_type )

                    # read the container mount point from the secret
                    # for example /home/balloon/U             
                    # Read data from secret    
                    secret_name         = secret.get_name( authinfo, userinfo )
                    secret_dict_data    = secret.read_alldata( authinfo, userinfo )
                    mountPath           = secret_dict_data.get( 'mountPath')
                    networkPath         = secret_dict_data.get( 'networkPath' )
                    
                    # Check if the secret contains valid datas 
                    if not isinstance( mountPath, str) :
                        # skipping bad values
                        self.logger.error( f"Invalid value for mountPath read from secret={secret_name} type={str(type(mountPath))}" )
                        continue

                    if not isinstance( networkPath, str) :
                        # skipping bad values
                        self.logger.error( f"Invalid value for networkPath read from secret={secret_name}  type={str(type(networkPath))}" )
                        continue

                    volumes_mount[mountvol.name] = {'name': volume_name, 'mountPath': mountPath }     
                    posixaccount = self.alwaysgetPosixAccountUser( authinfo, userinfo )
                    # Default mount options
                    mountOptions = 'uid=' + str( posixaccount.get('uidNumber') ) + ',gid=' + str( posixaccount.get('gidNumber')  )
                    # concat mountOptions for the volume if exists 
                    if mountvol.has_options():
                        mountOptions += ',' + mountvol.mountOptions

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

    def get_user_homedirectory(self, authinfo:AuthInfo, userinfo:AuthUser )->str:
        self.logger.debug('')
        assert isinstance(authinfo, AuthInfo),  f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo, AuthUser),  f"userinfo has invalid type {type(userinfo)}"
        localaccount = oc.od.secret.ODSecretLocalAccount( namespace=self.namespace, kubeapi=self.kubeapi )
        localaccount_secret = localaccount.read( authinfo,userinfo )
        homeDirectory = oc.od.secret.ODSecretLocalAccount.read_data( localaccount_secret, 'homeDirectory' )
        if not isinstance( homeDirectory, str ):
            homeDirectory = oc.od.settings.getballoon_homedirectory()
        return homeDirectory

    def build_volumes_home( self, authinfo:AuthInfo, userinfo:AuthUser, volume_type:str, secrets_requirement, rules={}, **kwargs):
        self.logger.debug('')
        assert isinstance(authinfo, AuthInfo),  f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo, AuthUser),  f"userinfo has invalid type {type(userinfo)}"
        volumes = {}        # set empty volume dict by default
        volumes_mount = {}  # set empty volume_mount dict by default
        self.on_desktoplaunchprogress('Building home dir data storage')
        volume_home_name = self.get_volumename( 'home', userinfo )
        # by default hostpath
        homedirectorytype = oc.od.settings.desktop['homedirectorytype']
        subpath_name = oc.auth.namedlib.normalize_name( userinfo.userid )
        user_homedirectory = self.get_user_homedirectory(authinfo, userinfo)

        # set default value 
        # home is emptyDir
        # cache is emptyDir Memory
        volumes['home']         = { 'name': volume_home_name, 'emptyDir': {} }
        volumes_mount['home']   = { 'name': volume_home_name, 'mountPath': user_homedirectory }

        # 'cache' volume
        # dotcache_user_homedirectory = user_homedirectory + '/.cache'
        # volumes['cache']       = { 'name': 'cache',  'emptyDir': { 'medium': 'Memory', 'sizeLimit': '8Gi' } }
        # volumes_mount['cache'] = { 'name': 'cache',  'mountPath': dotcache_user_homedirectory }

        # now ovewrite home values
        if homedirectorytype == 'persistentVolumeClaim':
            # Map the home directory
            volumes['home'] = {
                'name': volume_home_name,
                'persistentVolumeClaim': {
                    'claimName': oc.od.settings.desktop['persistentvolumeclaim'] 
                }
            }
            volumes_mount['home'] = { 
                'name':volume_home_name, 
                'mountPath':user_homedirectory, 
                'subPath': subpath_name 
            }
        elif homedirectorytype == 'hostPath':
            # Map the home directory
            # mount_volume = '/mnt/abcdesktop/$USERNAME' on host
            # volume type is 'DirectoryOrCreate'
            # same as 'subPath' but use hostpath
            # 'subPath' is not supported for ephemeral container
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

        self.logger.debug( f"volumes_mount['home']: {volumes_mount.get('home')}" )
        self.logger.debug( f"volumes['home']: {volumes.get('home')}")
        self.logger.debug( f"volumes_mount['cache']: {volumes_mount.get('cache')}" )
        self.logger.debug( f"volumes['cache']: {volumes.get('cache')}")
        return (volumes, volumes_mount)


    def build_volumes_vnc( self, authinfo:AuthInfo, userinfo:AuthUser, volume_type, secrets_requirement, rules={}, **kwargs):
        self.logger.debug('')
        assert isinstance(authinfo, AuthInfo),  f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo, AuthUser),  f"userinfo has invalid type {type(userinfo)}"
        volumes = {}        # set empty volume dict by default
        volumes_mount = {}  # set empty volume_mount dict by default
         # Add VNC password
        mysecretdict = self.list_dict_secret_data( authinfo, userinfo, access_type='vnc' )
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
        volumes[secret_auth_name] = {
            'name': secret_auth_name,
            'secret': { 
                'secretName': secret_auth_name, 
                'defaultMode':420 }
        }
        volumes_mount[secret_auth_name] = {
            'name':secret_auth_name, 
            'mountPath': secretmountPath
        } 
        return (volumes, volumes_mount)

    def build_volumes_localaccount( self, authinfo:AuthInfo, userinfo:AuthUser, volume_type, secrets_requirement, rules={}, **kwargs):
        self.logger.debug('')
        assert isinstance(authinfo, AuthInfo),  f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo, AuthUser),  f"userinfo has invalid type {type(userinfo)}"
        volumes = {}        # set empty volume dict by default
        volumes_mount = {}  # set empty volume_mount dict by default

        #
        # mount secret in /var/secrets/abcdesktop
        #
        mysecretdict = self.list_dict_secret_data( authinfo, userinfo, access_type='localaccount' )
        #secret = oc.od.secret.ODSecretLocalAccount( namespace=self.namespace, kubeapi=self.kubeapi )
        #localaccountsecret = secret.read_alldata
        for secret_auth_name in mysecretdict.keys():
            # https://kubernetes.io/docs/concepts/configuration/secret
            # create an entry eq: 
            # /var/secrets/abcdesktop/localaccount
           
            self.logger.debug( 'adding secret type %s to volume pod', mysecretdict[secret_auth_name]['type'] )
            secretmountPath = oc.od.settings.desktop['secretsrootdirectory'] + mysecretdict[secret_auth_name]['type'] 
            # mode is 644 -> rw-r--r--
            # Owing to JSON limitations, you must specify the mode in decimal notation.
            # 644 in decimal equal to 420
            volumes[secret_auth_name]       = { 'name': secret_auth_name, 'secret': { 'secretName': secret_auth_name, 'defaultMode': 420  } }
            volumes_mount[secret_auth_name] = { 'name': secret_auth_name, 'mountPath':  secretmountPath }

        return (volumes, volumes_mount)

    def build_volumes( self, authinfo:AuthInfo, userinfo:AuthUser, volume_type, secrets_requirement, rules={}, **kwargs):
        """[build_volumes]

        Args:
            authinfo ([type]): [description]
            userinfo (AuthUser): user data
            volume_type ([str]): 'container_desktop' 'pod_desktop', 'pod_application', 'ephemeral_container'
            rules (dict, optional): [description]. Defaults to {}.

        Returns:
            [type]: [description]
        """
        volumes = {}        # set empty volume dict by default
        volumes_mount = {}  # set empty volume_mount dict by default
        #
        # Set localtime to server time
        #
        if oc.od.settings.desktop['uselocaltime'] is True:
            volumes['localtime']       = { 'name': 'localtime', 'hostPath': { 'path': '/etc/localtime' } }
            volumes_mount['localtime'] = { 'name': 'localtime', 'mountPath' : '/etc/localtime' }

        #
        # volume shared between all container inside the desktop pod
        #
        if volume_type in [ 'pod_desktop', 'ephemeral_container' ]:
            
            # # add local account
            # for vol_name in [ 'passwd', 'group', 'shadow', 'gshadow']:
            #    volumes[vol_name]       = self.default_volumes[vol_name]
            #    volumes_mount[vol_name] = self.default_volumes_mount[vol_name]

            # add socket service 
            for vol_name in [ 'x11socket', 'pulseaudiosocket', 'cupsdsocket' ]:
                volumes[vol_name]       = self.default_volumes[vol_name]
                volumes_mount[vol_name] = self.default_volumes_mount[vol_name]

            # add tmp run log to support readonly filesystem
            for vol_name in [ 'tmp', 'run', 'log' ]:
                volumes[vol_name]       = self.default_volumes[vol_name]
                volumes_mount[vol_name] = self.default_volumes_mount[vol_name]

            # add dbus
            for vol_name in [ 'rundbus', 'runuser' ]:
                volumes[vol_name]       = self.default_volumes[vol_name]
                volumes_mount[vol_name] = self.default_volumes_mount[vol_name]

        #
        # shm volume is shared between all container inside the desktop pod
        #
        if volume_type in [ 'pod_desktop', 'container_desktop', 'ephemeral_container' ]:
            volumes['shm']       = self.default_volumes['shm']
            volumes_mount['shm'] = self.default_volumes_mount['shm']

        #
        # mount localaccount config map
        #
        if volume_type in [ 'pod_desktop', 'pod_application',  'ephemeral_container' ] :
            (configmap_localaccount_volumes, configmap_localaccount_volumes_mount) = \
                self.build_volumes_localaccount(authinfo, userinfo, volume_type, secrets_requirement, rules, **kwargs)
            volumes.update( configmap_localaccount_volumes )
            volumes_mount.update( configmap_localaccount_volumes_mount )

        #
        # mount secret in /var/secrets/abcdesktop
        # always add vnc secret for 'pod_desktop'
        if volume_type in [ 'pod_desktop'  ] :
            (vnc_volumes, vnc_volumes_mount) = \
                self.build_volumes_vnc(authinfo, userinfo, volume_type, secrets_requirement, rules, **kwargs)
            volumes.update(vnc_volumes )
            volumes_mount.update( vnc_volumes_mount )

        #
        # mount secret in /var/secrets/abcdesktop
        #
        (secret_volumes, secret_volumes_mount) = \
            self.build_volumes_secrets(authinfo, userinfo, volume_type, secrets_requirement, rules, **kwargs)
        volumes.update(secret_volumes)
        volumes_mount.update(secret_volumes_mount)

        #
        # mount home volume
        #
        (home_volumes, home_volumes_mount) = \
            self.build_volumes_home(authinfo, userinfo, volume_type, secrets_requirement, rules, **kwargs)
        volumes.update(home_volumes)
        volumes_mount.update(home_volumes_mount)

        #
        # mount flexvolume
        #
        (flex_volumes, flex_volumes_mount) = \
            self.build_volumes_flexvolumes(authinfo, userinfo, volume_type, secrets_requirement, rules, **kwargs)
        volumes.update(flex_volumes)
        volumes_mount.update(flex_volumes_mount)
        self.logger.debug('volumes end')        
        return (volumes, volumes_mount)

        
    def execwaitincontainer( self, desktop:ODDesktop, command:str, timeout:int=5):
        self.logger.info('')
        result = { 'ExitCode': -1, 'stdout': None } # default value 
        #
        # calling exec and wait for response.
        # read https://github.com/kubernetes-client/python/blob/master/examples/pod_exec.py
        # for more example
        #   
        try:            
            resp = stream(  self.kubeapi.connect_get_namespaced_pod_exec, 
                            name=desktop.name, 
                            namespace=self.namespace, 
                            command=command,                                                                
                            container=desktop.container_name,
                            stderr=True, stdin=False,
                            stdout=True, tty=False,
                            _preload_content=False, #  need a client object websocket           
            )
            resp.run_forever(timeout) # timeout in seconds
            err = resp.read_channel(ERROR_CHANNEL, timeout=timeout)
            self.logger.debug( f"exec in desktop.name={desktop.name} container={desktop.container_name} command={command} return code {err}")
            respdict = yaml.load(err, Loader=yaml.BaseLoader )        
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

        return result

    def removePod( self, myPod:V1Pod, propagation_policy:str='Foreground', grace_period_seconds:int=None) -> V1Pod:
        """_summary_
            Remove a pod
            like command 'kubectl delete pods'
        Args:
            myPod (_type_): _description_
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
            deletedPod = self.kubeapi.delete_namespaced_pod(  
                name=myPod.metadata.name, 
                namespace=self.namespace, 
                grace_period_seconds=grace_period_seconds, 
                propagation_policy=propagation_policy 
            ) 
        except ApiException as e:
            self.logger.error( str(e) )

        return deletedPod

    def removesecrets( self, authinfo:AuthInfo, userinfo:AuthUser )->bool:
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
        dict_secret = self.list_dict_secret_data( authinfo, userinfo, access_type=None)
        for secret_name in dict_secret.keys():
            try:            
                v1status = self.kubeapi.delete_namespaced_secret( name=secret_name, namespace=self.namespace )
                if not isinstance(v1status,V1Status) :
                    self.logger.error( 'invalid V1Status type return by delete_namespaced_secret')
                    continue
                self.logger.debug(f"secret={secret_name} status={v1status.status}") 
                if v1status.status != 'Success':
                    self.logger.error(f"secret {secret_name} can not be deleted {v1status}" ) 
                    bReturn = bReturn and False
            except ApiException as e:
                self.logger.error(f"secret {secret_name} can not be deleted {e}") 
                bReturn = bReturn and False
        self.logger.debug(f"removesecrets for {userinfo.userid} return {bReturn})" ) 
        return bReturn 
   


    def removeconfigmap( self, authinfo:AuthInfo, userinfo:AuthUser )->bool:
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
        dict_configmap = self.list_dict_configmap_data( authinfo, userinfo, access_type=None)
        for configmap_name in dict_configmap.keys():
            try:            
                v1status = self.kubeapi.delete_namespaced_config_map( name=configmap_name, namespace=self.namespace )
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

    def removepodindesktop(self, authinfo:AuthInfo, userinfo:AuthUser , myPod:V1Pod=None )->bool:
        self.logger.debug('')
        assert isinstance(authinfo, AuthInfo),  f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo, AuthUser),  f"userinfo has invalid type {type(userinfo)}"
        # get the user's pod
        if not isinstance(myPod, V1Pod ):
            myPod = self.findPodByUser(authinfo, userinfo )

        if isinstance(myPod, V1Pod ):
            # delete this pod immediatly
            v1status = self.removePod( myPod, propagation_policy='Foreground', grace_period_seconds=0 )
            if isinstance(v1status,V1Pod) :
                return True
        return False

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
            deletedPod = self.removePod( myPod, propagation_policy='Foreground', grace_period_seconds=0 )
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
            
    def removedesktop(self, authinfo:AuthInfo, userinfo:AuthUser , myPod:V1Pod=None)->bool:
        """removedesktop
            remove kubernetes pod for a give user
            then remove kubernetes user's secrets and configmap
        Args:
            authinfo (AuthInfo): _description_
            userinfo (AuthUser): _description_
            myPod (V1Pod, optional): _description_. Defaults to None.

        Returns:
            bool: _description_
        """
        self.logger.debug('')
        assert isinstance(authinfo, AuthInfo),  f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo, AuthUser),  f"userinfo has invalid type {type(userinfo)}"
        deletedpod = False # default value 
        self.logger.debug('')
        self.logger.info( f"removedesktop for {authinfo.provider} {userinfo.userid}" )

        # get the user's pod
        if not isinstance(myPod, V1Pod ):
            myPod = self.findPodByUser(authinfo, userinfo )

        if isinstance(myPod, V1Pod ):
            # deletedpod = self.removePod( myPod )
            # remove all application pod
            myappinstance = ODAppInstanceKubernetesPod( self )
            deletedpod = myappinstance.remove_all( authinfo, userinfo )
            deletedpod = self.removePodSync( authinfo, userinfo, myPod ) and deletedpod
        
            # if isinstance(deletedpod,V1Pod) :
            #    removedesktopStatus['pod'] = deletedpod
            # else:
            #    removedesktopStatus['pod'] = False

            removethreads =  [  { 'fct':self.removesecrets,   'args': [ authinfo, userinfo ], 'thread':None },
                                { 'fct':self.removeconfigmap, 'args': [ authinfo, userinfo ], 'thread':None } ]
   
            for removethread in removethreads:
                self.logger.debug( f"calling thread {removethread['fct'].__name__}" )
                removethread['thread']=threading.Thread(target=removethread['fct'], args=removethread['args'])
                removethread['thread'].start()
 
            # need to wait for removethread['thread'].join()
            for removethread in removethreads:
                removethread['thread'].join()

        else:
            self.logger.error( f"removedesktop can not find desktop {authinfo} {userinfo}" )
        return deletedpod

    def preparelocalaccount( self, localaccount:dict )->dict:
        assert isinstance(localaccount, dict),f"invalid localaccount type {type(localaccount)}"    
        mydict_config = { 
            'passwd' : AuthUser.mkpasswd(localaccount), 
            'shadow' : AuthUser.mkshadow(localaccount), 
            'group'  : AuthUser.mkgroup(localaccount),
            'gshadow': AuthUser.mkgshadow(localaccount), 
        }
        return mydict_config
            
    def prepareressources(self, authinfo:AuthInfo, userinfo:AuthUser):
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
        # auth_secret = secret.create( arguments )
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
        createdsecret = secret.create( authinfo, userinfo, data=userinfo )
        if not isinstance( createdsecret, V1Secret):
            self.logger.error(f"cannot create secret {secret.get_name(authinfo, userinfo)}")
        else:
            self.logger.debug(f"LDIF secret.create {secret.get_name(authinfo, userinfo)} created")
        self.logger.debug('create oc.od.secret.ODSecretLDIF created')

        # create files as secret 
        # - /etc/passwd 
        # - /etc/shadow 
        # - /etc/group 
        # - /etc/gshadow
        localaccount_data = authinfo.get_localaccount()
        localaccount_files = self.preparelocalaccount( localaccount_data )
        self.logger.debug('localaccount secret.create creating')
        secret = oc.od.secret.ODSecretLocalAccount( namespace=self.namespace, kubeapi=self.kubeapi )
        createdsecret = secret.create( authinfo, userinfo, data=localaccount_files )
        if not isinstance( createdsecret, V1Secret):
            self.logger.error(f"cannot create secret {secret.get_name(authinfo, userinfo)}")
        else:
            self.logger.debug(f"localaccount secret.create {secret.get_name(authinfo, userinfo)} created")

        if userinfo.isPosixAccount():
            self.logger.debug('posixaccount secret.create creating')
            secret = oc.od.secret.ODSecretPosixAccount( namespace=self.namespace, kubeapi=self.kubeapi )
            createdsecret = secret.create( authinfo, userinfo, data=userinfo.getPosixAccount())
            if not isinstance( createdsecret, V1Secret):
                self.logger.error(f"cannot create secret {secret.get_name(authinfo, userinfo)}")
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
                    createdsecret = secret.create( authinfo, userinfo, data=identity_data )
                    if not isinstance( createdsecret, V1Secret):
                        self.logger.error(f"cannot create secret {secret.get_name(authinfo, userinfo)}")
                    else:
                        self.logger.debug(f"secret.create {secret.get_name(authinfo, userinfo)} created")
    
        # Create flexvolume secrets
        self.logger.debug('flexvolume secrets creating')
        rules = oc.od.settings.desktop['policies'].get('rules')
        if isinstance(rules, dict):
            mountvols = oc.od.volume.selectODVolumebyRules( authinfo, userinfo,  rules.get('volumes') )
            for mountvol in mountvols:
                # use as a volume defined and the volume is mountable
                fstype = mountvol.fstype # Get the fstype: for example 'cifs' or 'cifskerberos' or 'webdav' or 'nfs'
                # find a secret class, can return None if fstype does not need a auth
                secret = oc.od.secret.selectSecret( self.namespace, self.kubeapi, prefix=mountvol.name, secret_type=fstype)
                if isinstance( secret, oc.od.secret.ODSecret):
                    # Flex volume use kubernetes secret, add mouting path
                    arguments = { 'mountPath': mountvol.containertarget, 'networkPath': mountvol.networkPath, 'mountOptions': mountvol.mountOptions }
                    # Build the kubernetes secret 
                    auth_secret = secret.create( authinfo, userinfo, arguments )
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
        str_lastlogin_datetime = pod.metadata.annotations.get('lastlogin_datetime')
        if isinstance(str_lastlogin_datetime,str):
            resumed_datetime = datetime.datetime.strptime(str_lastlogin_datetime, "%Y-%m-%dT%H:%M:%S")
        return resumed_datetime

    def resumedesktop(self, authinfo:AuthInfo, userinfo:AuthUser)->ODDesktop:
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
        myPod =  self.findPodByUser(authinfo, userinfo)
        if isinstance(myPod, V1Pod ):
            # update the metadata.annotations ['lastlogin_datetime'] in pod
            annotations = myPod.metadata.annotations
            new_lastlogin_datetime = self.get_annotations_lastlogin_datetime()
            annotations['lastlogin_datetime'] = new_lastlogin_datetime['lastlogin_datetime']
            newmetadata=V1ObjectMeta(annotations=annotations)
            body = V1Pod(metadata=newmetadata)
            v1newPod = self.kubeapi.patch_namespaced_pod(   
                name=myPod.metadata.name, 
                namespace=self.namespace, 
                body=body )
            if isinstance(v1newPod, V1Pod ):
                myDesktop = self.pod2desktop( pod=v1newPod, authinfo=authinfo, userinfo=userinfo )
            else:
                self.logger.error( 'Patch annontation lastlogin_datetime failed' )
                # reread the non updated desktop if patch failed
                myDesktop = self.pod2desktop( pod=myPod, authinfo=authinfo, userinfo=userinfo )
        return myDesktop

    def getsecretuserinfo(self, authinfo:AuthInfo, userinfo:AuthUser)->dict:
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
        dict_secret = self.list_dict_secret_data( authinfo, userinfo )
        raw_secrets = {}
        for key in dict_secret.keys():
            secret = dict_secret[key]
            if isinstance(secret, dict) and secret.get('type') == 'abcdesktop/ldif':
                raw_secrets.update( secret )
                break
        return raw_secrets

    def getldifsecretuserinfo(self, authinfo:AuthInfo, userinfo:AuthUser)->dict:
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
        data = secret.read_alldata(authinfo,userinfo)
        return data


    def list_dict_configmap_data( self, authinfo:AuthInfo, userinfo:AuthUser, access_type=None, hidden_empty=False )->dict:
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
           
            kconfigmap_list = self.kubeapi.list_namespaced_config_map(self.namespace, label_selector=label_selector)
          
            for myconfigmap in kconfigmap_list.items:
                if hidden_empty :
                    # check if mysecret.data is None or an emtpy dict 
                    if myconfigmap.data is None :
                        continue
                    if isinstance( myconfigmap.data, dict) and len( myconfigmap.data ) == 0: 
                        continue
                configmap_dict[myconfigmap.metadata.name] = { 'data': myconfigmap.data }
      
        except ApiException as e:
            self.logger.error("Exception %s", str(e) )
    
        return configmap_dict

    def list_dict_secret_data( self, authinfo:AuthInfo, userinfo:AuthUser, access_type=None, hidden_empty=False )->dict:
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
           
            ksecret_list = self.kubeapi.list_namespaced_secret(self.namespace, label_selector=label_selector)
          
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
            self.logger.error("Exception %s", str(e) )
    
        return secret_dict

    def get_auth_env_dict( self, authinfo:AuthInfo, userinfo:AuthUser )->dict:
        """get_auth_env_dict

        Args:
            authinfo (AuthInfo): _description_
            userinfo (AuthUser): _description_

        Returns:
            dict: return a dict without secret name, merge all data 
        """
        self.logger.debug('')
        assert isinstance(authinfo, AuthInfo),  f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo, AuthUser),  f"userinfo has invalid type {type(userinfo)}"
        dict_secret = self.list_dict_secret_data( authinfo, userinfo, access_type='auth')
        raw_secrets = {}
        for key in dict_secret.keys():
            raw_secrets.update( dict_secret[key] )
        return raw_secrets


    def filldictcontextvalue( self, authinfo:AuthInfo, userinfo:AuthUser, desktop:ODDesktop, network_config:str, network_name=None, appinstance_id=None ):
        self.logger.debug('')
        assert isinstance(authinfo, AuthInfo),  f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo, AuthUser),  f"userinfo has invalid type {type(userinfo)}"
        fillvalue = network_config
        self.logger.debug( f"type(network_config) is {type(network_config)}" )
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
    
        self.logger.debug(f"filldictcontextvalue return fillvalue={fillvalue}")
        return fillvalue



    def is_instance_app( self, appinstance ):
        for app in self.appinstance_classes.values():
            if app(self).isinstance( appinstance ):
                return True
        return False

    def countRunningAppforUser( self, authinfo:AuthInfo, userinfo:AuthUser, myDesktop:ODDesktop)->int:
        """countRunningAppforUser

        Args:
            authinfo (AuthInfo): _description_
            userinfo (AuthUser): _description_
            myDesktop (ODDesktop): _description_

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
            count += len( myappinstance.list(authinfo, userinfo, myDesktop ) )
        return count

    def listContainerApps( self, authinfo:AuthInfo, userinfo:AuthUser, myDesktop:ODDesktop, apps:ODApps ):
        """listContainerApps

        Args:
            authinfo (AuthInfo): _description_
            userinfo (AuthUser): _description_
            myDesktop (ODDesktop): _description_
            apps (ODApps): _description_

        Returns:
            list: list of applications
        """
        assert isinstance(authinfo, AuthInfo),   f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo, AuthUser),   f"userinfo has invalid type {type(userinfo)}"
        assert isinstance(myDesktop, ODDesktop), f"myDesktop has invalid type {type(myDesktop)}"
        assert isinstance(apps, ODApps), f"apps has invalid type {type(apps)}"
        self.logger.debug('')
        list_apps = []
        for appinstance in self.appinstance_classes.values() :
            myappinstance = appinstance( self )
            list_apps += myappinstance.list(authinfo, userinfo, myDesktop, phase_filter=self.all_phases_status, apps=apps)
        return list_apps


    def getAppInstanceKubernetes( self, authinfo:AuthInfo, userinfo:AuthUser, pod_name:str, containerid:str):
        """getAppInstanceKubernetes
            return the AppInstanceKubernetes of an appliction
        Args:
            authinfo (_type_): _description_
            userinfo (_type_): _description_
            pod_name (_type_): _description_
            containerid (_type_): _description_

        Returns:
            ODAppInstanceBase can be :
                - ODAppInstanceKubernetesEphemeralContainer(ODAppInstanceBase): ephemeral container application
                - ODAppInstanceKubernetesPod(ODAppInstanceBase): pod application
        """
        assert isinstance(pod_name, str), f"podname has invalid type {type(pod_name)}"
        myappinstance = None
        myPod = self.kubeapi.read_namespaced_pod(namespace=self.namespace,name=pod_name)
        if isinstance( myPod, V1Pod ):
            # if type is x11server app is an ephemeral container
            pod_type = myPod.metadata.labels.get( 'type' )
            if pod_type == self.x11servertype:
                myappinstance = ODAppInstanceKubernetesEphemeralContainer( self )
            elif pod_type in self.appinstance_classes.keys() :
                myappinstance = ODAppInstanceKubernetesPod( self )
        return myappinstance

    def logContainerApp( self, authinfo:AuthInfo, userinfo:AuthUser, pod_name:str, containerid:str):
        assert isinstance(pod_name, str), f"podname has invalid type {type(pod_name)}"
        log_app = None
        myappinstance = self.getAppInstanceKubernetes(authinfo, userinfo, pod_name, containerid)
        if isinstance( myappinstance, ODAppInstanceBase ):
            log_app = myappinstance.logContainerApp(pod_name, containerid)
        return log_app

    def envContainerApp( self, authinfo:AuthInfo, userinfo:AuthUser, pod_name:str, containerid:str):
        assert isinstance(pod_name, str), f"podname has invalid type {type(pod_name)}"
        env_result = None
        myappinstance = self.getAppInstanceKubernetes(authinfo, userinfo, pod_name, containerid)
        if isinstance( myappinstance, ODAppInstanceBase ):
            env_result = myappinstance.envContainerApp(authinfo, userinfo, pod_name, containerid)
        return env_result

    def stopContainerApp( self, authinfo:AuthInfo, userinfo:AuthUser, pod_name:str, containerid:str):
        assert isinstance(pod_name, str), f"podname has invalid type {type(pod_name)}"
        stop_result = None
        myappinstance = self.getAppInstanceKubernetes(authinfo, userinfo, pod_name, containerid)
        if isinstance( myappinstance, ODAppInstanceBase ):
            stop_result = myappinstance.stop(pod_name, containerid)
        return stop_result

    def removeContainerApp( self, authinfo:AuthInfo, userinfo:AuthUser, pod_name:str, containerid:str):
        return self.stopContainerApp( authinfo, userinfo, pod_name, containerid)

    def getappinstance( self, authinfo, userinfo, app ):    
        self.logger.debug('')
        for app_class in self.appinstance_classes.values():
            app_object = app_class( orchestrator=self )
            appinstance = app_object.findRunningAppInstanceforUserandImage( authinfo, userinfo, app )
            if app_object.isinstance( appinstance ):
                return appinstance

    def execininstance( self, container, command):
        self.logger.info('')

        if isinstance( container, V1Pod  ):
            desktop = self.pod2desktop( container )
            
        result = { 'ExitCode': -1, 'stdout':None }
        timeout=5
        # calling exec and wait for response.
        # exec_command = [
        #    '/bin/sh',
        #        '-c',
        #        'echo This message goes to stderr >&2; echo This message goes to stdout']
        # str connect_get_namespaced_pod_exec(name, namespace, command=command, container=container, stderr=stderr, stdin=stdin, stdout=stdout, tty=tty)     
        #
        # Todo
        # read https://github.com/kubernetes-client/python/blob/master/examples/pod_exec.py
        #   
        # container_name = self.get
        try:            
            resp = stream(  self.kubeapi.connect_get_namespaced_pod_exec,
                                name=desktop.name, 
                                container=desktop.container_name, 
                                namespace=self.namespace, 
                                command=command,
                                stderr=True, stdin=False,
                                stdout=True, tty=False,
                                _preload_content=False )
            resp.run_forever(timeout=timeout) 
            if resp.returncode is None:
                # A None value indicates that the process hasn't terminated yet.
                # do not wait 
                result = { 'ExitCode': None, 'stdout': None, 'status': 'Success' }
                resp.close()
            else:
                err = resp.read_channel(ERROR_CHANNEL, timeout=timeout)
                pod_exec_result = yaml.load(err, Loader=yaml.BaseLoader )  
                result['stdout'] = resp.read_stdout(timeout=timeout)
                # should be like:
                # {"metadata":{},"status":"Success"}
                if isinstance(pod_exec_result, dict):
                    if pod_exec_result.get('status') == 'Success':
                        result['status'] = pod_exec_result.get('status')
                        result['ExitCode'] = 0
                    exit_code = pod_exec_result.get('ExitCode')
                    if exit_code is not None:
                        result['ExitCode'] = exit_code
                resp.close()

        except Exception as e:
            self.logger.error( 'command exec failed %s', str(e)) 

        return result

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
            [ 'init', 'graphical', 'ssh', 'rdpgw', 'sound', 'printer', 'filter', 'storage' ]

        Returns:
            bool: True if enable, else False
        """

        bReturn =   isinstance( oc.od.settings.desktop_pod.get(currentcontainertype), dict ) is True and \
                    oc.od.acl.ODAcl().isAllowed( authinfo, oc.od.settings.desktop_pod[currentcontainertype].get('acl') ) is True and \
                    oc.od.settings.desktop_pod[currentcontainertype].get('enable') is True
        return bReturn

    def createappinstance(self, myDesktop:ODDesktop, app:dict, authinfo:AuthInfo, userinfo:AuthUser={}, userargs=None, **kwargs )->oc.od.appinstancestatus.ODAppInstanceStatus:
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
        assert isinstance(myDesktop, ODDesktop),f"desktop has invalid type {type(myDesktop)}"
        assert isinstance(app,dict),            f"app has invalid type {type(app)}"
        assert isinstance(authinfo, AuthInfo),  f"authinfo has invalid type {type(authinfo)}"
        # read the container enigne specific value from app properties
        containerengine = app.get('containerengine', 'ephemeral_container' )
        if containerengine not in self.appinstance_classes.keys():
            raise ValueError( f"unknow containerengine value {containerengine} must be defined in {list(self.appinstance_classes.keys())}")
        appinstance_class = self.appinstance_classes.get(containerengine)
        appinstance = appinstance_class(self)
        appinstancestatus = appinstance.create(myDesktop, app, authinfo, userinfo, userargs, **kwargs )
        return appinstancestatus

    def pullimage_on_all_nodes(self, app:dict):
        """pullimage_on_all_nodes
            pullimage app to all nodes
        Args:
            app (dict): app

        Returns:
            None
        """
        self.logger.info('')
        label_selector=oc.od.settings.desktop.get('nodeselector')
        listnode = self.kubeapi.list_node(label_selector=label_selector)
        self.logger.info(f"pulling image on nodelist={listnode}")
        if isinstance( listnode, V1NodeList ):
            if len(listnode.items) < 1:
                self.logger.error( f"nodeSelector={label_selector} return empty list" )
            for node in listnode.items :
                self.pullimage( app, node.metadata.name )
        else:
            self.logger.error(
                f"Can not get list of node. V1NodeList Error in config file \n\
                desktop.nodeselector={label_selector} is wrong"
            )

    def pullimage(self, app:dict, nodename:str )->V1Pod:
        self.logger.info(f"pull by creating pod image={app['name']} on nodename={nodename}")
        self.logger.info(f"app unique id {app.get('_id')}")
        h = hashlib.new('sha256')
        h.update( str(app).encode() )
        digest = h.hexdigest()
        id = nodename + '_' + str( digest )
        _containername = 'pull_' + oc.auth.namedlib.normalize_imagename( app['name'] + '_' + id )
        podname =  oc.auth.namedlib.normalize_name_dnsname( _containername )
        self.logger.debug( f"pullimage define podname={podname}" )

        '''
        # check if a running podname is already exist
        try:
            pod = self.kubeapi.read_namespaced_pod(namespace=self.namespace,name=podname)
            if isinstance( pod, V1Pod ):
                self.logger.info( f"podname={podname} already exists")
                return pod
        except client.exceptions.ApiException as e:
            # Pod does not exist
            if e.status == 404:
                # Pod does not exist
                pass
            else:
                self.logger.error( e )

        except Exception as e:
            self.logger.error( e )
        '''
        labels = { 'type': self.applicationtypepull }

        pod_manifest = {
            'apiVersion': 'v1',
            'kind': 'Pod',
            'metadata': {
                'name': podname,
                'namespace': self.namespace,
                'labels': labels
            },
            'spec': {
                'nodeName': nodename,
                'automountServiceAccountToken': False,  # disable service account inside pod
                'restartPolicy' : 'Never',
                'containers':[ {   
                    'name': podname,
                    # When imagePullSecrets hasn’t been set, 
                    # the secrets of the default service account in the current namespace is used instead. 
                    # If those aren’t defined either, default or no credentials are used
                    'imagePullSecrets': oc.od.settings.desktop_pod.get(self.applicationtype,{}).get('imagePullSecrets'),
                    'imagePullPolicy': 'Always',
                    'image': app['id'],
                    'command': ['/bin/sleep'],
                    'args': [ '42' ]
                } ]
            }
        }

        pod = None
        try:
            pod = self.kubeapi.create_namespaced_pod(namespace=self.namespace,body=pod_manifest )
            if isinstance(pod, V1Pod ):
                self.logger.info( f"create_namespaced_pod pull image ask to run on {pod.spec.node_name}" )
        except client.exceptions.ApiException as e:
             self.logger.error( e )
        except Exception as e:
            self.logger.error( e )

        return pod

    def alwaysgetPosixAccountUser(self, authinfo:AuthInfo, userinfo:AuthUser ) -> dict :
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
            posixaccount = posixsecret.read_alldata( authinfo, userinfo )
            if not isinstance( posixaccount, dict):
                self.logger.debug('posixaccount does not exist use localaccount default')
                localaccount = oc.od.secret.ODSecretLocalAccount( namespace=self.namespace, kubeapi=self.kubeapi )
                self.logger.debug('read the localaccount secret')
                localaccount_data = localaccount.read_alldata( authinfo, userinfo )
                posixaccount = AuthUser.getPosixAccountfromlocalAccount(localaccount_data)
                userinfo['posix'] = posixaccount
            else:
                self.logger.debug('posixaccount reuse cached secret data')
                userinfo['posix'] = posixaccount
        else:
            self.logger.debug('posixaccount already decoded use userinfo dict')
            posixaccount = userinfo.getPosixAccount()

        return posixaccount

    def updateCommandWithUserInfo( self, currentcontainertype:str, authinfo: AuthInfo, userinfo:AuthUser ) -> list:
        """updateCommandWithUserInfo

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
        list_command = oc.od.settings.desktop_pod[currentcontainertype].get( 'command' )
        if isinstance( list_command, list ):
            new_list_command = []
            posixuser = self.alwaysgetPosixAccountUser( authinfo, userinfo )
            for command in list_command:
                new_command  = chevron.render( command, posixuser )
                new_list_command.append( new_command )
            list_command = new_list_command
        return list_command
            

    def updateSecurityContextWithUserInfo( self, currentcontainertype:str, authinfo:AuthInfo, userinfo:AuthUser ) -> dict:
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
            posixuser = self.alwaysgetPosixAccountUser( authinfo, userinfo )

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
        assert isinstance(currentcontainertype, str),  f"currentcontainertype has invalid type {type(currentcontainertype)}, str is expected"
        assert isinstance(authinfo, AuthInfo),  f"authinfo has invalid type {type(authinfo)}"
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
            containernameprefix (str): _description_
            myPod (V1Pod): _description_

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

    def get_executeclasse( self, authinfo:AuthInfo, userinfo:AuthUser, executeclassname:str=None)->dict:
        """get_executeclasse

            return a dict like { 
                'nodeSelector':None, 
                'resources':{
                'requests':{'memory':"256Mi",'cpu':"100m"},
                'limits':  {'memory':"1Gi",'cpu':"1000m"} 
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
        
        if isinstance( executeclassname, str ):
            executeclass = oc.od.settings.executeclasses.get(executeclassname)

        if not isinstance( executeclass, dict ):
            tagexecuteclassname = authinfo.get_labels().get('executeclassname','default')
            if isinstance( tagexecuteclassname, str ) and \
               isinstance( oc.od.settings.executeclasses.get(tagexecuteclassname), dict) :
                    executeclass=oc.od.settings.executeclasses.get(tagexecuteclassname)
        
        #
        self.logger.debug(f"executeclass={executeclass}")
        return executeclass


    def get_resources( self, currentcontainertype:str, executeclass:dict )->dict:
        self.logger.debug('')
        resources = {} # resource is a always a dict 
        currentcontainertype_ressources = oc.od.settings.desktop_pod[currentcontainertype].get('resources')
        if isinstance( currentcontainertype_ressources, dict ):
            resources.update(currentcontainertype_ressources)

        executeclass_ressources = executeclass.get('resources')
        if isinstance( executeclass_ressources, dict ):
            resources.update(executeclass_ressources)
 
        self.logger.debug(f" get_resources return {resources}")
        return resources

    def read_pod_resources( self, pod_name:str)->dict:
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
            myPod = self.kubeapi.read_namespaced_pod(namespace=self.namespace,name=pod_name)
            if isinstance(myPod, V1Pod ):
                c = self.getcontainerSpecfromPod( self.graphicalcontainernameprefix, myPod )
                if isinstance( c, V1Container ) and isinstance( c.resources, V1ResourceRequirements ):
                    resources = c.resources.to_dict()
        except ApiException as e:
            pass

        return resources

    def createdesktop(self, authinfo:AuthInfo, userinfo:AuthUser, **kwargs)->ODDesktop:
        """createdesktop
            create the user pod 

        Args:
            authinfo (AuthInfo): authinfo
            userinfo (AuthUser): userinfo

        Raises:
            ValueError: _description_

        Returns:
            ODDesktop: desktop object
        """
        self.logger.debug('createdesktop start' )
        assert isinstance(authinfo, AuthInfo),  f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo, AuthUser),  f"userinfo has invalid type {type(userinfo)}"

        myDesktop = None # default return object
        env      = kwargs.get('env', {} )

        # get the execute class if user has a executeclassname tag
        executeclasse = self.get_executeclasse( authinfo, userinfo )

        # add a new VNC Password to env var
        self.logger.debug(' vnc kubernetes secret checking')
        plaintext_vnc_password = ODVncPassword().getplain()
        vnc_secret = oc.od.secret.ODSecretVNC( self.namespace, self.kubeapi )
        vnc_secret_password = vnc_secret.create( authinfo, userinfo, data={ 'password' : plaintext_vnc_password } )
        if not isinstance( vnc_secret_password, V1Secret ):
            raise ODAPIError( f"create vnc kubernetes secret {plaintext_vnc_password} failed" )
        self.logger.debug(f"vnc kubernetes secret set to {plaintext_vnc_password}")

        # generate XAUTH key
        self.logger.debug('env creating')
        env[ 'XAUTH_KEY' ] = self.generate_xauthkey() # generate XAUTH_KEY
        env[ 'PULSEAUDIO_COOKIE' ] = self.generate_pulseaudiocookie()   # generate PULSEAUDIO cookie
        env[ 'BROADCAST_COOKIE' ] = self.generate_broadcastcookie()     # generate BROADCAST cookie 
        env[ 'HOME'] = self.get_user_homedirectory(authinfo, userinfo)  # read HOME DIR 
        env[ 'USER' ] = userinfo.userid         # add USER 
        env[ 'LOGNAME' ] = userinfo.userid      # add LOGNAME 
        self.logger.debug( f"HOME={env[ 'HOME']}")
        self.logger.debug('env created')

        self.logger.debug('labels creating')
        # build label dictionnary
        labels = {  
            'access_provider':      authinfo.provider,
            'access_providertype':  authinfo.providertype,
            'access_userid':        userinfo.userid,
            'access_username':      self.get_labelvalue(userinfo.name),
            'domain':               self.endpoint_domain,
            'netpol/ocuser' :       'true',
            'xauthkey':             env[ 'XAUTH_KEY' ], 
            'pulseaudio_cookie':    env[ 'PULSEAUDIO_COOKIE' ],
            'broadcast_cookie':     env[ 'BROADCAST_COOKIE' ] 
        }

        # add authinfo labels and env 
        # could also use downward-api https://kubernetes.io/docs/concepts/workloads/pods/downward-api/
        for k,v in authinfo.get_labels().items():
            abcdesktopvarenvname = oc.od.settings.ENV_PREFIX_LABEL_NAME + k.lower()
            env[ abcdesktopvarenvname ] = v
            labels[k] = v

        for currentcontainertype in self.nameprefixdict.keys() :
            if self.isenablecontainerinpod( authinfo, currentcontainertype ):
                abcdesktopvarenvname = oc.od.settings.ENV_PREFIX_SERVICE_NAME + currentcontainertype
                env[ abcdesktopvarenvname ] = 'enabled'
    
        # create a desktop
        # set value as default type x11servertype
        labels['type'] = self.x11servertype
        kwargs['type'] = self.x11servertype
        self.logger.debug('labels created')

        myuuid = oc.lib.uuid_digits()

        pod_name = self.get_podname( authinfo, userinfo, myuuid ) 
        self.logger.debug('pod name is %s', pod_name )

        self.logger.debug('envlist creating')
        posixuser = self.alwaysgetPosixAccountUser( authinfo, userinfo )
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

        self.on_desktoplaunchprogress('b.Building data storage for your desktop')
        self.logger.debug('secrets_requirement creating for graphical')
        currentcontainertype = 'graphical'
        secrets_requirement = None # default value add all secret if no filter 
        # get all secrets
        mysecretdict = self.list_dict_secret_data( authinfo, userinfo )
        # by default give the abcdesktop/kerberos and abcdesktop/cntlm secrets inside the pod, if exist
        secrets_type_requirement = oc.od.settings.desktop_pod.get(currentcontainertype,{}).get('secrets_requirement')
        if isinstance( secrets_type_requirement, list ):
            # list the secret entry by requirement type 
            secrets_requirement = ['abcdesktop/vnc'] # always add the vnc password in the secret list 
            for secretdictkey in mysecretdict.keys():
                if mysecretdict.get(secretdictkey,{}).get('type') in secrets_type_requirement:
                    secrets_requirement.append( secretdictkey )
        self.logger.debug('secrets_requirement created for graphcial')

        # ownerReferences = self.get_ownerReferences(mysecretdict)

        self.logger.debug('volumes creating')
        shareProcessNamespace = oc.od.settings.desktop_pod.get('spec',{}).get('shareProcessNamespace', False)
        kwargs['shareProcessNamespace'] = shareProcessNamespace
        shareProcessMemory = oc.od.settings.desktop_pod.get('spec',{}).get('shareProcessMemory', False)
        kwargs['shareProcessMemory'] = shareProcessMemory

        # all volumes and secrets
        (pod_allvolumes, pod_allvolumeMounts) = self.build_volumes( authinfo, userinfo, volume_type='pod_desktop', secrets_requirement=None, rules=rules,  **kwargs)
        list_pod_allvolumes = list( pod_allvolumes.values() )
        list_pod_allvolumeMounts = list( pod_allvolumeMounts.values() )

       
        # graphical volumes
        (volumes, volumeMounts) = self.build_volumes( authinfo, userinfo, volume_type='pod_desktop', secrets_requirement=secrets_requirement, rules=rules,  **kwargs)
        list_volumeMounts = list( volumeMounts.values() )
        self.logger.info( 'volumes=%s', volumes.values() )
        self.logger.info( 'volumeMounts=%s', volumeMounts.values() )
        self.logger.debug('volumes created')


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
                websocketroute = external_dnsconfig.get( 'hostname' ) + '.' + external_dnsconfig.get( 'domain' )
                envlist.append( { 'name': 'USE_CERTBOT_CERTONLY',        'value': 'enabled' } )
                envlist.append( { 'name': 'EXTERNAL_DESKTOP_HOSTNAME',   'value': external_dnsconfig.get( 'hostname' ) } )
                envlist.append( { 'name': 'EXTERNAL_DESKTOP_DOMAIN',     'value': external_dnsconfig.get( 'domain' ) } )

                labels['websocketrouting']  = websocketrouting
                labels['websocketroute']    = websocketroute
        self.logger.debug('websocketrouting created')

        initContainers = []
        currentcontainertype = 'init'
        if  self.isenablecontainerinpod( authinfo, currentcontainertype ):
            # init container chown to change the owner of the home directory
            # init runAsUser 0 (root)
            # to allow chmod 'command':  [ 'sh', '-c',  'chown 4096:4096 /home/balloon /tmp' ] 
            self.logger.debug( f"pod container creating {currentcontainertype}" )
            securityContext = oc.od.settings.desktop_pod[currentcontainertype].get('securityContext', { 'runAsUser': 0 } )
            self.logger.debug( f"pod container {currentcontainertype} use securityContext {securityContext}" )
            image = self.getimagecontainerfromauthlabels( currentcontainertype, authinfo )
            command = self.updateCommandWithUserInfo( currentcontainertype, authinfo, userinfo )

            initcontainer = {
                'name': self.get_containername( authinfo, userinfo, currentcontainertype, myuuid ),
                'imagePullPolicy': oc.od.settings.desktop_pod[currentcontainertype].get('imagePullPolicy','IfNotPresent'),
                'imagePullSecrets': oc.od.settings.desktop_pod[currentcontainertype].get('imagePullSecrets'),
                'image': image,       
                'command': command,
                'volumeMounts': list_pod_allvolumeMounts,
                'env': envlist,
                'securityContext': securityContext
            }
            initContainers.append( initcontainer )

            self.logger.debug('pod container created %s', currentcontainertype )


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

        specssecurityContext = self.updateSecurityContextWithUserInfo( 
            currentcontainertype='spec', 
            authinfo=authinfo, 
            userinfo=userinfo )

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
                'dnsPolicy' : dnspolicy,
                'dnsConfig' : dnsconfig,
                'automountServiceAccountToken': False,  # disable service account inside pod
                'subdomain': self.endpoint_domain,
                'shareProcessNamespace': shareProcessNamespace,
                'volumes': list_pod_allvolumes,                    
                'nodeSelector': executeclasse.get('nodeSelector'), 
                'initContainers': initContainers,
                'securityContext': specssecurityContext,
                'containers': []
            }
        }


         # Add graphical servives 
        currentcontainertype='graphical'
        if  self.isenablecontainerinpod( authinfo, currentcontainertype ):
            self.logger.debug('pod container creating %s', currentcontainertype )
            image = self.getimagecontainerfromauthlabels( currentcontainertype, authinfo ) 
            securityContext = self.updateSecurityContextWithUserInfo( currentcontainertype, authinfo, userinfo )
            resources = self.get_resources( currentcontainertype, executeclasse )
            pod_manifest['spec']['containers'].append( { 
                'name': self.get_containername( authinfo, userinfo, currentcontainertype, myuuid ),
                'imagePullPolicy':  oc.od.settings.desktop_pod[currentcontainertype].get('imagePullPolicy', 'IfNotPresent'),
                'imagePullSecrets': oc.od.settings.desktop_pod[currentcontainertype].get('imagePullSecrets'),
                'image':image,                                    
                'env': envlist,
                'workingDir': env['HOME'],
                'volumeMounts': list_volumeMounts,
                'securityContext': securityContext,
                'resources': resources              
            } )
            self.logger.debug('pod container created %s', currentcontainertype )
            
            # by default remove anonymous home directory content at stop 
            # or if oc.od.settings.desktop['removehomedirectory'] is True
            if oc.od.settings.desktop['removehomedirectory'] is True \
               or userinfo.name == 'Anonymous':
                pod_manifest['spec']['containers'][0]['lifecycle'] = {  
                    'preStop': {
                        'exec': {
                            'command':  [ "/bin/bash", "-c", "rm -rf ~/*" ] 
                        }
                    }   
                }
          
        # Add printer sound servives 
        currentcontainertype='printer'
        if  self.isenablecontainerinpod( authinfo, currentcontainertype ):
            self.logger.debug('pod container creating %s', currentcontainertype )
            image = self.getimagecontainerfromauthlabels( currentcontainertype, authinfo ) 
            securityContext = self.updateSecurityContextWithUserInfo( currentcontainertype, authinfo, userinfo )
            pod_manifest['spec']['containers'].append( { 
                'name': self.get_containername( authinfo, userinfo, currentcontainertype, myuuid ),
                'imagePullPolicy':  oc.od.settings.desktop_pod[currentcontainertype].get('imagePullPolicy','IfNotPresent'),
                'imagePullSecrets': oc.od.settings.desktop_pod[currentcontainertype].get('imagePullSecrets'),
                'image':image,                                    
                'env': envlist,
                'volumeMounts': [ pod_allvolumeMounts['tmp'] ],
                'securityContext': securityContext,
                'resources': oc.od.settings.desktop_pod[currentcontainertype].get('resources')                             
            } )
            self.logger.debug('pod container created %s', currentcontainertype )

        # Add printer sound servives 
        currentcontainertype= 'sound'
        if  self.isenablecontainerinpod( authinfo, currentcontainertype ):
            self.logger.debug('pod container creating %s', currentcontainertype )
            image = self.getimagecontainerfromauthlabels( currentcontainertype, authinfo ) 
            securityContext = self.updateSecurityContextWithUserInfo( currentcontainertype, authinfo, userinfo  )
            pod_manifest['spec']['containers'].append( { 
                'name': self.get_containername( authinfo, userinfo, currentcontainertype, myuuid ),
                'imagePullPolicy':  oc.od.settings.desktop_pod[currentcontainertype].get('imagePullPolicy','IfNotPresent'),
                'imagePullSecrets': oc.od.settings.desktop_pod[currentcontainertype].get('imagePullSecrets'),
                'image': image,                                    
                'env': envlist,
                'volumeMounts': [ pod_allvolumeMounts['tmp'], pod_allvolumeMounts['home'], pod_allvolumeMounts['log'], ],
                'securityContext': securityContext,
                'resources': oc.od.settings.desktop_pod[currentcontainertype].get('resources')                             
            } )
            self.logger.debug( "pod container created {currentcontainertype}" )

        # Add ssh service 
        currentcontainertype = 'ssh'
        if  self.isenablecontainerinpod( authinfo, currentcontainertype ):
            self.logger.debug('pod container creating %s', currentcontainertype )
            securityContext = self.updateSecurityContextWithUserInfo( currentcontainertype, authinfo, userinfo )
            image = self.getimagecontainerfromauthlabels( currentcontainertype, authinfo ) 
            pod_manifest['spec']['containers'].append( { 
                'name': self.get_containername( authinfo, userinfo, currentcontainertype, myuuid ),
                'imagePullPolicy':  oc.od.settings.desktop_pod[currentcontainertype].get('imagePullPolicy','IfNotPresent'),
                'imagePullSecrets': oc.od.settings.desktop_pod[currentcontainertype].get('imagePullSecrets'),
                'image': image,                                    
                'env': envlist,
                'securityContext': securityContext,
                'volumeMounts': list_volumeMounts,
                'resources': oc.od.settings.desktop_pod[currentcontainertype].get('resources')                             
            } )
            self.logger.debug( "pod container created {currentcontainertype}" )

        # Add filer service 
        currentcontainertype = 'filer'
        if  self.isenablecontainerinpod( authinfo, currentcontainertype ):
            # volume_home_name = self.get_volumename( 'home', userinfo ) # get the volume name created for homedir
            # # retrieve the home user volume name
            # # to set volumeMounts value
            # homedirvolume = None        # set default value
            # for v in list_volumeMounts:
            #     if v.get('name') == volume_home_name:
            #         homedirvolume = v   # find homedirvolume is v
            #         break
            
            # if a volume exists
            # use this volume as homedir to filer service 
            # if homedirvolume  :
            self.logger.debug('pod container creating %s', currentcontainertype )
            securityContext = self.updateSecurityContextWithUserInfo( currentcontainertype, authinfo, userinfo )
            image = self.getimagecontainerfromauthlabels( currentcontainertype, authinfo ) 
            pod_manifest['spec']['containers'].append( { 
                'name': self.get_containername( authinfo, userinfo, currentcontainertype, myuuid ),
                'imagePullPolicy':  oc.od.settings.desktop_pod[currentcontainertype].get('imagePullPolicy','IfNotPresent'),
                'imagePullSecrets': oc.od.settings.desktop_pod[currentcontainertype].get('imagePullSecrets'),
                'image': image,                                  
                'env': envlist,
                'volumeMounts': list_volumeMounts,
                'securityContext': securityContext,
                'resources': oc.od.settings.desktop_pod[currentcontainertype].get('resources')                                      
            } )
            self.logger.debug( "pod container created {currentcontainertype}" )

        # Add storage service 
        currentcontainertype = 'storage'
        if  self.isenablecontainerinpod( authinfo, currentcontainertype ):
            self.logger.debug('pod container creating %s', currentcontainertype )
            securityContext = self.updateSecurityContextWithUserInfo( currentcontainertype, authinfo, userinfo )
            image = self.getimagecontainerfromauthlabels( currentcontainertype, authinfo ) 
            pod_manifest['spec']['containers'].append( { 
                'name': self.get_containername( authinfo, userinfo, currentcontainertype, myuuid ),
                'imagePullPolicy': oc.od.settings.desktop_pod[currentcontainertype].get('imagePullPolicy'),
                'imagePullSecrets': oc.od.settings.desktop_pod[currentcontainertype].get('imagePullSecrets'),
                'image': image,                                 
                'env': envlist,
                'volumeMounts':  list_pod_allvolumeMounts,
                'securityContext': securityContext,
                'resources': oc.od.settings.desktop_pod[currentcontainertype].get('resources')
            } )
            self.logger.debug( "pod container created {currentcontainertype}" )

        # Add rdp service 
        currentcontainertype = 'rdp'
        if  self.isenablecontainerinpod( authinfo, currentcontainertype ):
            self.logger.debug('pod container creating %s', currentcontainertype )
            securityContext = self.updateSecurityContextWithUserInfo( currentcontainertype, authinfo, userinfo )
            image = self.getimagecontainerfromauthlabels( currentcontainertype, authinfo ) 
            pod_manifest['spec']['containers'].append( { 
                'name': self.get_containername( authinfo, userinfo, currentcontainertype, myuuid ),
                'imagePullPolicy': oc.od.settings.desktop_pod[currentcontainertype].get('imagePullPolicy'),
                'imagePullSecrets': oc.od.settings.desktop_pod[currentcontainertype].get('imagePullSecrets'),
                'image': image, 
                'securityContext': securityContext,                                
                'env': envlist,
                'volumeMounts':  list_volumeMounts,
                'resources': oc.od.settings.desktop_pod[currentcontainertype].get('resources')                      
            } )
            self.logger.debug( "pod container created {currentcontainertype}" )

        # we are ready to create our Pod 
        myDesktop = None
        self.on_desktoplaunchprogress('b.Creating your desktop')
        self.logger.info( 'dump yaml %s', json.dumps( pod_manifest, indent=2 ) )
        pod = self.kubeapi.create_namespaced_pod(namespace=self.namespace,body=pod_manifest )

        if not isinstance(pod, V1Pod ):
            self.on_desktoplaunchprogress('e.Create pod failed.' )
            raise ValueError( 'Invalid create_namespaced_pod type')

        number_of_container_started = 0
        number_of_container_to_start = len( pod_manifest.get('spec').get('initContainers') ) + len( pod_manifest.get('spec').get('containers') )
        self.on_desktoplaunchprogress(f"b.Watching for events from services {number_of_container_started}/{number_of_container_to_start}" )
        object_type = None
        message = 'read list_namespaced_event'
        number_of_container_started = 0

        self.logger.debug('watch list_namespaced_event pod creating' )
        # watch list_namespaced_event
        w = watch.Watch()                 
        # read_namespaced_pod
        for event in w.stream(  self.kubeapi.list_namespaced_event, 
                                namespace=self.namespace, 
                                timeout_seconds=self.DEFAULT_K8S_CREATE_TIMEOUT_SECONDS,
                                field_selector=f'involvedObject.name={pod_name}' ):  
            if not isinstance(event, dict ):
                self.logger.error( f"event type is type(event), and should be a dict, skipping event" )
                continue

            event_object = event.get('object')
            if not isinstance(event_object, CoreV1Event ):
                self.logger.error( f"event_object type is {type(event_object)} skipping event waiting for CoreV1Event")
                continue

            # Valid values for event types (new types could be added in future)
            #    EventTypeNormal  string = "Normal"     // Information only and will not cause any problems
            #    EventTypeWarning string = "Warning"    // These events are to warn that something might go wrong
            object_type = event_object.type
            self.logger.info( f"object_type={object_type} reason={event_object.reason}")

            message = f"b.{event_object.reason} {event_object.message.lower()}" 
                
            self.on_desktoplaunchprogress( message )

            if object_type == 'Warning':
                # These events are to warn that something might go wrong
                self.logger.warning( f"something might go wrong object_type={object_type} reason={event_object.reason} message={event_object.message}")
                self.on_desktoplaunchprogress( f"b.Something might go wrong {object_type} reason={event_object.reason} message={event_object.message}" )
                w.stop()
                continue

            if object_type == 'Normal' and event_object.reason == 'Started':
                myPod = self.kubeapi.read_namespaced_pod(namespace=self.namespace,name=pod_name)
                # count number_of_container_started
                number_of_container_started = 0
                number_of_container_ready = 0
                for c in myPod.status.container_statuses:
                    if c.started is True:
                        number_of_container_started = number_of_container_started + 1
                    if c.ready is True:
                        number_of_container_ready = number_of_container_ready + 1

                if number_of_container_started < number_of_container_to_start:
                    # we need to wait for started containers
                    startedmsg =  f"b.Waiting for started containers {number_of_container_started}/{number_of_container_to_start}" 
                    self.logger.debug( startedmsg )
                    self.on_desktoplaunchprogress( startedmsg )
                    # continue

                # startedmsg =  f"b.Ready containers {number_of_container_ready}/{number_of_container_to_start}" 
                # self.logger.debug( startedmsg )
                # self.on_desktoplaunchprogress( startedmsg )

                # check if container_graphical_name is started and running
                # if it is stop event
                startedmsg = self.getPodStartedMessage(self.graphicalcontainernameprefix, myPod)
                self.on_desktoplaunchprogress( startedmsg )

                if isinstance( myPod.status.pod_ip, str) and len(myPod.status.pod_ip) > 0:     
                    self.on_desktoplaunchprogress(f"Your pod gets ip address {myPod.status.pod_ip} from network plugin")
                    w.stop()

                c = self.getcontainerfromPod( self.graphicalcontainernameprefix, myPod )
                if isinstance( c, V1ContainerStatus ):
                    if c.ready is True and c.started is True :
                        self.on_desktoplaunchprogress( startedmsg )
                        w.stop()

        self.logger.debug( f"watch list_namespaced_event pod created object_type={object_type}")

        self.logger.debug('watch list_namespaced_pod creating, waiting for pod quit Pending phase' )
        # watch list_namespaced_pod waiting for a valid ip addr
        w = watch.Watch()                 
        for event in w.stream(  self.kubeapi.list_namespaced_pod, 
                                namespace=self.namespace, 
                                timeout_seconds=self.DEFAULT_K8S_CREATE_TIMEOUT_SECONDS,
                                field_selector=f"metadata.name={pod_name}" ):   
            # event must be a dict, else continue
            if not isinstance(event,dict):
                self.logger.error( f"event type is {type( event )}, and should be a dict, skipping event")
                continue

            # event dict must contain a type 
            event_type = event.get('type')
            # event dict must contain a object 
            pod_event = event.get('object')
            # if podevent type must be a V1Pod, we use kubeapi.list_namespaced_pod
            if not isinstance( pod_event, V1Pod ) :  
                # pod_event is not a V1Pod :
                # something go wrong  
                w.stop()
                continue

            self.on_desktoplaunchprogress( f"b.Your {pod_event.kind.lower()} is {event_type.lower()} " )    
            self.logger.info( f"pod_event.status.phase={pod_event.status.phase}" )
            #if isinstance( pod_event.status.pod_ip, str):     
            #    self.on_desktoplaunchprogress(f"c.Your pod gets ip address {pod_event.status.pod_ip} from network plugin")  
            #
            # from https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/
            #
            # Pending	The Pod has been accepted by the Kubernetes cluster, but one or more of the containers has not been set up and made ready to run. This includes time a Pod spends waiting to be scheduled as well as the time spent downloading container images over the network.
            # Running	The Pod has been bound to a node, and all of the containers have been created. At least one container is still running, or is in the process of starting or restarting.
            # Succeeded	All containers in the Pod have terminated in success, and will not be restarted.
            # Failed	All containers in the Pod have terminated, and at least one container has terminated in failure.
            # Unknown	For some reason the state of the Pod could not be obtained. This phase typically occurs due to an error in communicating with the node where the Pod should be running.
            if pod_event.status.phase == 'Running' :
                startedmsg = self.getPodStartedMessage(self.graphicalcontainernameprefix, pod_event)
                self.on_desktoplaunchprogress( startedmsg )

            if pod_event.status.phase != 'Pending' :
                # pod data object is complete, stop reading event
                # phase can be 'Running' 'Succeeded' 'Failed' 'Unknown'
                self.logger.debug(f"The pod is not in Pending phase, phase={pod_event.status.phase} stop watching" )
                w.stop()

        self.logger.debug('watch list_namespaced_pod created, the pod is no more in Pending phase' )

        # read pod again
        self.logger.debug('watch read_namespaced_pod creating' )
        myPod = self.kubeapi.read_namespaced_pod(namespace=self.namespace,name=pod_name)    
        self.logger.info( f"myPod.metadata.name {myPod.metadata.name} is {myPod.status.phase} with ip {myPod.status.pod_ip}" )
        # The pod is not in Pending
        # read the status.phase, if it's not Running 
        if myPod.status.phase != 'Running':
            # something wrong 
            msg =  f"Your pod does not start, status is {myPod.status.phase} reason is {myPod.status.reason} message {myPod.status.message}" 
            self.on_desktoplaunchprogress( msg )
            return msg
        else:
            self.on_desktoplaunchprogress(f"b.Your pod is {myPod.status.phase}.")

        myDesktop = self.pod2desktop( pod=myPod, authinfo=authinfo, userinfo=userinfo)
        self.logger.debug('watch read_namespaced_pod created')

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
        self.logger.debug('watch filldictcontextvalue created' )

        self.logger.debug('createdesktop end' )
        return myDesktop

  
    
    def findPodByUser(self, authinfo:AuthInfo, userinfo:AuthUser )->V1Pod:
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
        self.logger.info('')
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

            myPodList = self.kubeapi.list_namespaced_pod(self.namespace, label_selector=label_selector)

            if isinstance(myPodList, V1PodList) :
                for myPod in myPodList.items:
                    myPhase = myPod.status.phase
                    # keep only Running pod
                    if myPod.metadata.deletion_timestamp is not None:
                       myPhase = 'Terminating'
                    if myPhase in [ 'Running', 'Pending', 'Succeeded' ] :  # 'Init:0/1'
                        return myPod                    
                    
        except ApiException as e:
            self.logger.info("Exception when calling list_namespaced_pod: %s" % e)
        
        return None

    def isPodBelongToUser( self, authinfo:AuthInfo, userinfo:AuthUser, pod_name:str)->bool:
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
        assert isinstance(pod_name,  str),      f"pod_name has invalid type {type(pod_name)}"

        belong = False
        myPod = self.kubeapi.read_namespaced_pod(namespace=self.namespace,name=pod_name )
        if isinstance( myPod, V1Pod ):
            (pod_authinfo,pod_userinfo) = self.extract_userinfo_authinfo_from_pod(myPod)

        if  authinfo.provider == pod_authinfo.provider and \
            userinfo.userid   == pod_userinfo.userid :
            belong = True

        return belong

    def findDesktopByUser(self, authinfo:AuthInfo, userinfo:AuthUser )->ODDesktop:
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
        myPod = self.findPodByUser( authinfo, userinfo )
        if isinstance(myPod, V1Pod ):
            self.logger.debug( f"Pod is found {myPod.metadata.name}" )
            myDesktop = self.pod2desktop( pod=myPod, authinfo=authinfo, userinfo=userinfo )
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
                    if hasattr( c, 'name') and c.name[0] == prefix:
                        return c
        return None

    def getcontainerSpecfromPod( self,  prefix:str, pod:V1Pod ) -> V1Container:
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
        if isinstance( pod.spec.containers, list):
            for c in pod.spec.containers:
                if hasattr( c, 'name') and c.name[0] == prefix:
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

    def pod2desktop( self, pod:V1Pod, authinfo=None, userinfo=None )->ODDesktop:
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
        storage_container_id   = None
        desktop_container_name = None
        desktop_interfaces     = None
        vnc_password           = None

        # read metadata annotations 'k8s.v1.cni.cncf.io/networks-status'
        # to get the ip address of each netwokr interface
        network_status = None
        if isinstance(pod.metadata.annotations, dict):
            network_status = pod.metadata.annotations.get( 'k8s.v1.cni.cncf.io/networks-status' )
            if isinstance( network_status, str ):
                # k8s.v1.cni.cncf.io/networks-status is set
                # load json formated string
                network_status = json.loads( network_status )

            if isinstance( network_status, list ):
                desktop_interfaces = {}
                self.logger.debug( f"network_status is {network_status}" )
                for interface in network_status :
                    self.logger.debug( f"reading interface {interface}" )
                    if not isinstance( interface, dict ): 
                        continue
                    # read interface
                    name = interface.get('interface')
                    if not isinstance( name, str ): 
                        continue
                    # read ips
                    ips = interface.get('ips')
                    if  not isinstance( ips, list ): 
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
            vnc_secret_password = vnc_secret.read( authinfo, userinfo )  
            if isinstance( vnc_secret_password, V1Secret ):
                vnc_password = oc.od.secret.ODSecret.read_data( vnc_secret_password, 'password' )

        storage_container = self.getcontainerfromPod( self.storagecontainernameprefix, pod )
        if isinstance(storage_container, V1ContainerStatus):
           storage_container_id = storage_container.container_id

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
            storage_container_id = storage_container_id,
            labels = pod.metadata.labels 
        )
        return myDesktop

    def countdesktop(self)->int:
        """countdesktop
            count the number of desktop label_selector = 'type=' + self.x11servertype
        Returns:
            int: number of desktop
        """
        list_of_desktop = self.list_desktop()
        return len(list_of_desktop)

    def list_desktop(self)->list:
        """list_desktop

        Returns:
            list: list of ODDesktop
        """
        myDesktopList = []   
        try:  
            list_label_selector = 'type=' + self.x11servertype
            myPodList = self.kubeapi.list_namespaced_pod(self.namespace, label_selector=list_label_selector)
            if isinstance( myPodList, V1PodList):
                for myPod in myPodList.items:
                    mydesktop = self.pod2desktop( myPod )
                    if isinstance( mydesktop, ODDesktop):
                        myDesktopList.append( mydesktop.to_dict() )              
        except ApiException as e:
            self.logger.error(e)

        return myDesktopList
            
    def isgarbagable( self, pod:V1Pod, expirein:int, force=False )->bool:
        """isgarbagable

        Args:
            pod (V1Pod): pod
            expirein (int): in seconds
            force (bool, optional): check if user is connected or not. Defaults to False.

        Returns:
            bool: True if pod is garbageable
        """
        self.logger.debug('')
        bReturn = False
        assert isinstance(pod, V1Pod),    f"pod has invalid type {type(pod)}"
        assert isinstance(expirein, int), f"expirein has invalid type {type(expirein)}"
        if pod.status.phase == 'Failed':
            self.logger.warning(f"pod {pod.metadata.name} is in phase {pod.status.phase} reason {pod.status.reason}" )
            return True

        myDesktop = self.pod2desktop( pod=pod )
        if not isinstance(myDesktop, ODDesktop):
            return False

        if force is False:
            nCount = self.user_connect_count( myDesktop )
            if nCount < 0: 
                # if something wrong nCount is equal to -1 
                # do not garbage this pod
                # this is an error, return False
                return bReturn 
            if nCount > 0 : 
                # if a user is connected do not garbage this pod
                # user is connected, return False
                return bReturn 
            #
            # now nCount == 0 continue 
            # the garbage process
            # to test if we can delete this pod

        # read the lastlogin datetime from metadata annotations
        lastlogin_datetime = self.read_pod_annotations_lastlogin_datetime( pod )
        if isinstance( lastlogin_datetime, datetime.datetime):
            # get the current time
            now_datetime = datetime.datetime.now()
            delta_datetime = now_datetime - lastlogin_datetime
            delta_second = delta_datetime.total_seconds()
            # if delta_second is more than expirein in second
            if ( delta_second > expirein  ):
                # this pod is gabagable
                bReturn = True
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
        authinfo = AuthInfo( provider=pod.metadata.labels.get('access_provider') )
        # fake an userinfo object
        userinfo = AuthUser( {
            'userid':pod.metadata.labels.get('access_userid'),
            'name':  pod.metadata.labels.get('access_username')
        } )
        return (authinfo,userinfo)


    def find_userinfo_authinfo_by_desktop_name( self, name:str )->tuple:
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
        myPod = self.kubeapi.read_namespaced_pod(namespace=self.namespace,name=name )
        if isinstance( myPod, V1Pod ) :  
            (authinfo,userinfo) = self.extract_userinfo_authinfo_from_pod(myPod)
        return (authinfo,userinfo)

    def describe_desktop_byname( self, name:str )->dict:
        """describe_desktop_byname

        Args:
            name (str): name of the pod

        Returns:
            dict: dict of the desktop's pod loaded from json data
        """
        self.logger.debug('')
        assert isinstance(name, str), f"name has invalid type {type(str)}"
        myPod = self.kubeapi.read_namespaced_pod(namespace=self.namespace, name=name, _preload_content=False)
        if isinstance( myPod, urllib3.response.HTTPResponse ) :  
            myPod = json.loads( myPod.data )
        return myPod

    def garbagecollector( self, expirein:int, force=False )-> list :
        """garbagecollector

        Args:
            expirein (int): garbage expired in millisecond 
            force (bool, optional): force event if user is connected. Defaults to False.

        Returns:
            list: list of str, list of pod name garbaged
        """
        self.logger.debug('')
        assert isinstance(expirein, int), f"expirein has invalid type {type(expirein)}"

        garbaged = [] # list of garbaged pod
        list_label_selector = [ 'type=' + self.x11servertype ]
        for label_selector in list_label_selector:
            myPodList = self.kubeapi.list_namespaced_pod(self.namespace, label_selector=label_selector)
            if isinstance( myPodList, V1PodList):
                for pod in myPodList.items:
                    try: 
                        if self.isgarbagable( pod, expirein, force ) is True:
                            # pod is garbageable, remove it
                            self.logger.info( f"{pod.metadata.name} is garbageable, remove it" )
                            # fake an authinfo object
                            (authinfo,userinfo) = self.extract_userinfo_authinfo_from_pod(pod)
                            # remove desktop
                            self.removedesktop( authinfo, userinfo, pod )
                            # log remove desktop
                            self.logger.info( f"{pod.metadata.name} is removed" )
                            # add the name of the pod to the list of garbaged pod
                            garbaged.append( pod.metadata.name )
                        else:
                            self.logger.info( f"{pod.metadata.name} isgarbagable return False, keep it running" )

                    except ApiException as e:
                        self.logger.error(e)
        return garbaged


@oc.logging.with_logger()
class ODAppInstanceBase(object):
    def __init__(self,orchestrator):
        self.orchestrator = orchestrator
        self.type=None # default value overwrited by class instance 
        self.executeclassename='default' # default value overwrited by class instance 

    def findRunningAppInstanceforUserandImage( self, authinfo, userinfo, app):
        raise NotImplementedError('%s.build_volumes' % type(self))

    @staticmethod
    def isinstance( app ):
        raise NotImplementedError('isinstance' % type(app))

    def get_DISPLAY( self, desktop_ip_addr:str='' ):
        raise NotImplementedError('get_DISPLAY')

    def get_PULSE_SERVER(  self, desktop_ip_addr:str='' ):
        raise NotImplementedError('get_PULSE_SERVER')

    def get_CUPS_SERVER(  self, desktop_ip_addr:str='' ):
        raise NotImplementedError('get_CUPS_SERVER')

    def get_env_for_appinstance(self, myDesktop, app, authinfo, userinfo={}, userargs=None, **kwargs ):
        assert isinstance(myDesktop,  ODDesktop),  f"desktop has invalid type  {type(myDesktop)}"
        assert isinstance(authinfo,   AuthInfo),   f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo,   AuthUser),   f"userinfo has invalid type {type(userinfo)}"

        posixuser = self.orchestrator.alwaysgetPosixAccountUser( authinfo, userinfo )

        # make sure env DISPLAY, PULSE_SERVER,CUPS_SERVER exist
        desktop_ip_addr = myDesktop.get_default_ipaddr('eth0')

        env = oc.od.settings.desktop['environmentlocal'].copy()

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
        lang     = language + '.UTF-8'
        env['LANGUAGE']=language
        env['LANG']=lang
        env['LC_ALL']=lang
        env['LC_PAPER']=lang
        env['LC_ADDRESS']=lang
        env['LC_MONETARY']=lang
        env['LC_TIME']=lang
        env['LC_MEASUREMENT']=lang
        env['LC_TELEPHONE']=lang
        env['LC_NUMERIC']=lang
        env['LC_IDENTIFICATION']=lang
        env['PARENT_ID']=myDesktop.id
        env['PARENT_HOSTNAME']=myDesktop.nodehostname
               

        # Add specific vars
        if isinstance( kwargs, dict ):
            timezone = kwargs.get('timezone')
            if isinstance(timezone, str) and len(timezone) > 1:
                env['TZ'] = timezone
        if isinstance(userargs, str) and len(userargs) > 0:
            env['APPARGS'] = userargs
        if hasattr(authinfo, 'data') and isinstance( authinfo.data, dict ):
            env.update(authinfo.data.get('identity', {}))


        # convert env dictionnary to env list format for kubernetes
        envlist = ODOrchestratorKubernetes.envdict_to_kuberneteslist( env )
        ODOrchestratorKubernetes.appendkubernetesfieldref( envlist )
        
        return envlist

    def get_securitycontext(self, authinfo:AuthInfo, userinfo:AuthUser, app:dict  ):
        assert isinstance(authinfo,   AuthInfo),   f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo,   AuthUser),   f"userinfo has invalid type {type(userinfo)}"
        assert isinstance(app,  dict),             f"desktop has invalid type  {type(app)}"
        securitycontext = {}
        user_securitycontext = self.orchestrator.updateSecurityContextWithUserInfo( self.type, authinfo, userinfo )
        app_securitycontext = app.get('securitycontext',{}) or {} 
        securitycontext.update( user_securitycontext )
        securitycontext.update( app_securitycontext )
        return securitycontext

    def get_resources( self, authinfo:AuthInfo, userinfo:AuthUser, app:dict ):
        assert isinstance(authinfo,   AuthInfo),   f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo,   AuthUser),   f"userinfo has invalid type {type(userinfo)}"
        assert isinstance(app,        dict),       f"desktop has invalid type  {type(app)}"
       
        executeclassname =  app.get('executeclassname')
        self.logger.debug( f"app name={app.get('name')} has executeclassname={executeclassname}")
        executeclass = self.orchestrator.get_executeclasse( authinfo, userinfo, executeclassname )
        self.logger.debug( f"executeclass={executeclass}")
        resources = self.orchestrator.get_resources( self.type, executeclass )
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
                                    'values': [ desktop.hostname ]
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
  
@oc.logging.with_logger()
class ODAppInstanceKubernetesEphemeralContainer(ODAppInstanceBase):

    def __init__(self, orchestrator):
        super().__init__(orchestrator)
        self.type = self.orchestrator.ephemeral_container

    @staticmethod
    def isinstance( ephemeralcontainer ):
        bReturn =   isinstance( ephemeralcontainer, V1Pod ) or \
                    isinstance( ephemeralcontainer, V1ContainerState ) or \
                    isinstance( ephemeralcontainer, V1ContainerStatus )
        return bReturn

    def get_DISPLAY(  self, desktop_ip_addr:str='' ):
        return ':0.0'

    def get_PULSE_SERVER(  self, desktop_ip_addr:str='' ):
        return  '/tmp/.pulse.sock'

    def get_CUPS_SERVER(  self, desktop_ip_addr:str='' ):
        return '/tmp/.cups.sock'

    def envContainerApp(self, authinfo:AuthInfo, userinfo:AuthUser, pod_name:str, containerid:str )->dict:
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
        pod_ephemeralcontainers = self.orchestrator.kubeapi.read_namespaced_pod_ephemeralcontainers(
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

    def logContainerApp(self, pod_name:str, container_name:str)->str:
        assert isinstance(pod_name,  str),  f"pod_name has invalid type  {type(pod_name)}"
        assert isinstance(container_name,  str),  f"container_name has invalid type {type(container_name)}"
        strlogs = 'no logs read'
        try:
            strlogs = self.orchestrator.kubeapi.read_namespaced_pod_log( 
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
        assert isinstance(pod_ephemeralcontainers, V1Pod), f"pod_ephemeralcontainers has invalid type  {type(pod_ephemeralcontainers)}"
        assert isinstance(container_name,  str),  f"container_name has invalid type  {type(container_name)}"
        pod_ephemeralcontainer = None
        if isinstance(pod_ephemeralcontainers.status.ephemeral_container_statuses, list):
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


    def stop(self, pod_name:str, container_name:str)->bool:
        self.logger.debug('')
        assert isinstance(pod_name,  str),  f"pod_name has invalid type  {type(pod_name)}"
        assert isinstance(container_name,  str),  f"container_name has invalid type  {type(container_name)}"

        pod_ephemeralcontainers =  self.orchestrator.kubeapi.read_namespaced_pod_ephemeralcontainers(
            name=pod_name, 
            namespace=self.namespace )
        if not isinstance(pod_ephemeralcontainers, V1Pod ):
            raise ValueError( 'Invalid read_namespaced_pod_ephemeralcontainers')

        if isinstance(pod_ephemeralcontainers.spec.ephemeral_containers, list):
            for i in range( len(pod_ephemeralcontainers.spec.ephemeral_containers) ):
                if pod_ephemeralcontainers.spec.ephemeral_containers[i].name == container_name :
                    pod_ephemeralcontainers.spec.ephemeral_containers.pop(i)
                    break

        # replace ephemeralcontainers
        pod=self.orchestrator.kubeapi.patch_namespaced_pod_ephemeralcontainers(
            name=pod_name, 
            namespace=self.namespace, 
            body=pod_ephemeralcontainers )
        if not isinstance(pod, V1Pod ):
            raise ValueError( 'Invalid patch_namespaced_pod_ephemeralcontainers')

        stop_result = True

        return stop_result


    def list( self, authinfo, userinfo, myDesktop, phase_filter=[ 'Running', 'Waiting'], apps:ODApps=None )->list:
        self.logger.debug('')
        assert isinstance(myDesktop,  ODDesktop),  f"desktop has invalid type  {type(myDesktop)}"
        assert isinstance(authinfo,   AuthInfo),   f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo,   AuthUser),   f"userinfo has invalid type {type(userinfo)}"
        assert isinstance(phase_filter, list),     f"phase_filter has invalid type {type(phase_filter)}"

        result = []
        pod_ephemeralcontainers =  self.orchestrator.kubeapi.read_namespaced_pod_ephemeralcontainers(name=myDesktop.id, namespace=self.orchestrator.namespace )
        if not isinstance(pod_ephemeralcontainers, V1Pod ):
            raise ValueError( 'Invalid read_namespaced_pod_ephemeralcontainers')

        if isinstance(pod_ephemeralcontainers.spec.ephemeral_containers, list):
            for c_spec in pod_ephemeralcontainers.spec.ephemeral_containers:
                app = None
                c_status = self.get_status( pod_ephemeralcontainers, c_spec.name )
                if isinstance( c_status, V1ContainerStatus ):
                    phase = self.get_phase( c_status )
                    if phase in phase_filter:
                        if hasattr( apps, 'find_app_by_id' ):
                            app = apps.find_app_by_id( c_status.image )
                        if not isinstance(app,dict):
                            app = {}
                        #
                        # convert an ephemeralcontainers container to json by filter entries
                        mycontainer = {}
                        mycontainer['podname']  = myDesktop.id
                        mycontainer['id']       = c_status.name # myPod.metadata.uid
                        mycontainer['short_id'] = c_status.container_id
                        mycontainer['status']   = c_status.ready
                        mycontainer['image']    = c_status.image
                        mycontainer['oc.path']  =  c_spec.command
                        mycontainer['nodehostname'] = myDesktop.nodehostname
                        mycontainer['oc.icondata']  = app.get('icondata')
                        mycontainer['oc.args']      = app.get('args')
                        mycontainer['oc.icon']      = app.get('icon')
                        mycontainer['oc.launch']    = app.get('launch')
                        mycontainer['oc.displayname'] = c_status.name
                        mycontainer['runtime']        = 'kubernetes'
                        mycontainer['type']           = 'ephemeralcontainer'
                        mycontainer['status']         = phase

                        # add the object to the result array
                        result.append( mycontainer )

        return result



    def create(self, myDesktop, app, authinfo, userinfo={}, userargs=None, **kwargs ):
        self.logger.debug('')
        assert isinstance(myDesktop,  ODDesktop),  f"desktop has invalid type  {type(myDesktop)}"
        assert isinstance(authinfo,   AuthInfo),   f"authinfo has invalid type {type(authinfo)}"

        self.logger.debug("create {self.type} getting shareProcessNamespace and shareProcessMemory options from desktop config")
        shareProcessNamespace = oc.od.settings.desktop_pod.get('spec',{}).get('shareProcessNamespace', False)
        shareProcessMemory = oc.od.settings.desktop_pod.get('spec',{}).get('shareProcessMemory', False)
        self.logger.debug(f"shareProcessNamespace={shareProcessNamespace} shareProcessMemory={shareProcessMemory}")

        _app_container_name = app['name'] + '_' +  oc.lib.uuid_digits()
        _app_container_name = self.orchestrator.get_normalized_username(userinfo.get('name', 'name')) + '_' + oc.auth.namedlib.normalize_imagename( _app_container_name )
        app_container_name =  oc.auth.namedlib.normalize_name_dnsname( _app_container_name )

        desktoprules = oc.od.settings.desktop['policies'].get('rules', {})
        rules = copy.deepcopy( desktoprules )
        apprules = app.get('rules', {} ) or {} # app['rules] can be set to None
        rules.update( apprules )

        self.logger.debug( f"reading pod desktop desktop={myDesktop.id} app_container_name={app_container_name}")

        # resources = self.get_resources( authinfo, userinfo, app )
        envlist = self.get_env_for_appinstance(  myDesktop, app, authinfo, userinfo, userargs, **kwargs )
        # add EXECUTION CONTEXT env var inside the container
        envlist.append( { 'name': 'ABCDESKTOP_EXECUTE_RUNTIME',   'value': self.type} )
        resources = self.orchestrator.read_pod_resources(myDesktop.name)
        envlist.append( { 'name': 'ABCDESKTOP_EXECUTE_RESOURCES', 'value': json.dumps(resources) } )

        (volumeBinds, volumeMounts) = self.orchestrator.build_volumes( 
            authinfo,
            userinfo,
            volume_type=self.type,
            secrets_requirement=app.get('secrets_requirement'),
            rules=rules,
            **kwargs
        )
        list_volumeBinds = list( volumeBinds.values() )
        list_volumeMounts = list( volumeMounts.values() )
        self.logger.debug( f"list volume binds pod desktop {list_volumeBinds}")
        self.logger.debug( f"list volume mounts pod desktop {list_volumeMounts}")

        workingDir = self.orchestrator.get_user_homedirectory( authinfo, userinfo )
        self.logger.debug( f"user workingDir={workingDir}")

        # remove subPath
        # Pod volumes to mount into the container's filesystem.
        # Subpath mounts are not allowed for ephemeral containers.
        # Cannot be updated.
        #
        # Forbidden: cannot be set for an Ephemeral Container",
        # "reason":"FieldValueForbidden",
        # "message":"Forbidden: cannot be set for an Ephemeral Container",
        # "field":"spec.ephemeralContainers[8].volumeMounts[0].subPath"}]},
        # "code":422}
        securitycontext = self.get_securitycontext( authinfo, userinfo, app )

        # apply network rules
        # network_config = self.applyappinstancerules_network( authinfo, rules )
        # apply homedir rules
        # homedir_disabled = self.applyappinstancerules_homedir( authinfo, rules )
        
        # Fix python kubernetes
        # Ephemeral container not added to pod #1859
        # https://github.com/kubernetes-client/python/issues/1859
        #
        ephemeralcontainer = V1EphemeralContainer(  
            name=app_container_name,
            security_context=securitycontext,
            env=envlist,
            image=app['id'],
            command=app.get('cmd'),
            target_container_name=myDesktop.container_name,
            image_pull_policy=app.get('image_pull_policy'),
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
        # patch_namespaced_pod_ephemeralcontainers 
        pod = self.orchestrator.kubeapi.patch_namespaced_pod_ephemeralcontainers(   
            name=myDesktop.id,
            namespace=self.orchestrator.namespace, 
            body=body)
        
        if not isinstance(pod, V1Pod ):
            raise ValueError( 'Invalid patch_namespaced_pod_ephemeralcontainers')

        """
        # watch list_namespaced_event
        w = watch.Watch()                 
        # read_namespaced_pod
        for event in w.stream(  self.orchestrator.kubeapi.read_namespaced_pod, 
                                namespace=self.orchestrator.namespace, 
                                name=pod.metadata.name ):  
            event_object = event.get('object')
            if not isinstance(event_object, CoreV1Event ):
                self.logger.error( 'event_object type is %s skipping event waiting for CoreV1Event', type(event_object))
                continue
            
            # Valid values for event types (new types could be added in future)
            #    EventTypeNormal  string = "Normal"     // Information only and will not cause any problems
            #    EventTypeWarning string = "Warning"    // These events are to warn that something might go wrong
            object_type = event_object.type
            self.logger.info( f"object_type={object_type} reason={event_object.reason}")
            message = f"b.{event_object.reason} {event_object.message.lower()}"
        """

        appinstancestatus = None
        for wait_time in [ 0.1, 0.2, 0.4, 0.8, 1.6, 3.2 ]:
            self.logger.debug( f"pod.status.ephemeral_container_statuses={pod.status.ephemeral_container_statuses}")
            if isinstance(pod.status.ephemeral_container_statuses, list):
                for c in pod.status.ephemeral_container_statuses:
                    if isinstance( c, V1ContainerStatus ) and c.name == app_container_name:
                        appinstancestatus = oc.od.appinstancestatus.ODAppInstanceStatus( id=c.name, type=self.type )
                        if isinstance( c.state, V1ContainerState ):
                            appinstancestatus.message = self.get_phase(c)
                            break

            if isinstance( appinstancestatus, oc.od.appinstancestatus.ODAppInstanceStatus):
                self.logger.info(f"read_namespaced_pod_ephemeralcontainers status.ephemeral_container_statuses updated in {wait_time}s" )
                break
            else:
                self.logger.debug( f"waiting for {wait_time}" )
                time.sleep( wait_time )

            # re read again
            pod = self.orchestrator.kubeapi.read_namespaced_pod_ephemeralcontainers(
                    name=myDesktop.id, 
                    namespace=self.orchestrator.namespace )
            if not isinstance(pod, V1Pod ):
                raise ValueError( 'Invalid read_namespaced_pod_ephemeralcontainers')
        
        return appinstancestatus

    def findRunningAppInstanceforUserandImage( self, authinfo:AuthInfo, userinfo:AuthUser, app):
        self.logger.info('')
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

        pod_ephemeralcontainers =  self.orchestrator.kubeapi.read_namespaced_pod_ephemeralcontainers(name=myDesktop.id, namespace=self.orchestrator.namespace )
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
        super().__init__( orchestrator)
        self.type = self.orchestrator.applicationtype

    @staticmethod
    def isinstance( pod:V1Pod ):
        bReturn =  isinstance( pod, V1Pod )
        return bReturn

    def get_DISPLAY( self, desktop_ip_addr:str=None ):
        return desktop_ip_addr + ':0'

    def get_PULSE_SERVER( self, desktop_ip_addr:str=None ):
        return  desktop_ip_addr + ':' + str(DEFAULT_PULSE_TCP_PORT)

    def get_CUPS_SERVER( self, desktop_ip_addr=None ):
        return desktop_ip_addr + ':' + str(DEFAULT_CUPS_TCP_PORT)

    def get_nodeSelector( self ):
        """get_nodeSelector

        Returns:
            dict: dict of nodeSelector for self.type 

        """
        nodeSelector = oc.od.settings.desktop_pod.get(self.type, {}).get('nodeSelector',{})
        return nodeSelector
    
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
        executeclass = self.orchestrator.get_executeclasse( authinfo, userinfo, executeclassname )
        executeclass_nodeSelector = executeclass.get('nodeSelector',{}) or {}
        nodeSelector.update(executeclass_nodeSelector)
        self.logger.debug( f"nodeSelector for name={app.get('name')} is nodeSelector={nodeSelector}")
        return nodeSelector

    def list( self, authinfo, userinfo, myDesktop, phase_filter=[ 'Running', 'Waiting'], apps=None ):
        self.logger.info('')

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
            myPodList = self.orchestrator.kubeapi.list_namespaced_pod(self.orchestrator.namespace, label_selector=label_selector, field_selector=field_selector)
            if isinstance( myPodList, V1PodList ):
                for myPod in myPodList.items:
                    phase = myPod.status.phase
                    # keep only Running pod
                    if myPod.metadata.deletion_timestamp is not None:
                        phase = 'Terminating'

                    mycontainer = {}
                    if phase in phase_filter:
                        #
                        # convert a container to json by filter entries
                        mycontainer['podname']  = myPod.metadata.name
                        mycontainer['id']       = myPod.metadata.name # myPod.metadata.uid
                        mycontainer['short_id'] = myPod.metadata.name
                        mycontainer['status']   = myPod.status.phase
                        mycontainer['image']    = myPod.spec.containers[0].image
                        mycontainer['oc.path']  = myPod.spec.containers[0].command
                        mycontainer['nodehostname']     = myPod.spec.node_name
                        mycontainer['oc.args']          = myPod.metadata.labels.get('args')
                        mycontainer['oc.icon']          = myPod.metadata.labels.get('icon')
                        mycontainer['oc.icondata']      = myPod.metadata.labels.get('icondata')
                        mycontainer['oc.launch']        = myPod.metadata.labels.get('launch')
                        mycontainer['oc.displayname']   = myPod.metadata.labels.get('displayname')
                        mycontainer['runtime']          = 'kubernetes'
                        mycontainer['type']             = self.type
                        mycontainer['status']           = phase
                        # add the object to the result array
                        result.append( mycontainer )
        except ApiException as e:
            self.logger.info(f"Exception when calling list_namespaced_pod:{e}")
        return result


    def envContainerApp( self, authinfo:AuthInfo, userinfo:AuthUser, pod_name:str, containerid:str )->dict:
        '''get the environment vars exec for the containerid '''
        env_result = None

        # define filters
        access_userid = userinfo.userid
        access_provider = authinfo.provider
        field_selector = f"metadata.name={pod_name}"
        label_selector = f"access_userid={access_userid},type={self.type},access_provider={access_provider}"

        myPodList = self.orchestrator.kubeapi.list_namespaced_pod(
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

    def logContainerApp(self, pod_name:str, container_name:str)->str:
        assert isinstance(pod_name,  str),  f"pod_name has invalid type  {type(pod_name)}"
        assert isinstance(container_name,  str),  f"container_name has invalid type {type(container_name)}"
        strlogs = 'no logs read'
        try:
            strlogs = self.orchestrator.kubeapi.read_namespaced_pod_log( 
                name=pod_name, 
                namespace=self.orchestrator.namespace, 
                container=container_name, 
                pretty='true' )
        except ApiException as e:
            self.logger.error( e )
        except Exception as e:
            self.logger.error( e )
        return strlogs

    def stop( self, pod_name, container_name:None ):
        '''get the user's containerid stdout and stderr'''
        result = None
        propagation_policy = 'Foreground'
        grace_period_seconds = 0
        delete_options = V1DeleteOptions(
            propagation_policy = propagation_policy, 
            grace_period_seconds=grace_period_seconds )

        v1status = self.orchestrator.kubeapi.delete_namespaced_pod(  
            name=pod_name,
            namespace=self.orchestrator.namespace,
            body=delete_options,
            propagation_policy=propagation_policy )

        result = isinstance( v1status, V1Pod ) or isinstance(v1status,V1Status)

        return result


    def remove_all( self, authinfo, userinfo ):
        '''get the user's containerid stdout and stderr'''
        result = True
        access_userid = userinfo.userid
        access_provider = authinfo.provider
        label_selector = f"access_userid={access_userid},type={self.type},access_provider={access_provider}"

        myPodList = self.orchestrator.kubeapi.list_namespaced_pod(self.orchestrator.namespace, label_selector=label_selector)
        if isinstance( myPodList, V1PodList ) and len(myPodList.items) > 0 :
            for pod in myPodList.items:
                # propagation_policy = 'Background'
                propagation_policy = 'Foreground'
                grace_period_seconds = 0
                delete_options = V1DeleteOptions( 
                    propagation_policy = propagation_policy, 
                    grace_period_seconds=grace_period_seconds )
                try:
                    v1status = self.orchestrator.kubeapi.delete_namespaced_pod(  
                        name=pod.metadata.name,
                        namespace=self.orchestrator.namespace,
                        body=delete_options,
                        propagation_policy=propagation_policy )
                    result = isinstance( v1status, V1Pod ) and result
                except Exception as e:
                    self.logger.error( e )

        return result

    def list_and_stop( self, authinfo, userinfo, pod_name ):
        '''get the user's containerid stdout and stderr'''
        result = None
        access_userid = userinfo.userid
        access_provider = authinfo.provider
        field_selector = f"metadata.name={pod_name}"
        label_selector = f"access_userid={access_userid},type={self.type},access_provider={access_provider}"

        myPodList = self.orchestrator.kubeapi.list_namespaced_pod(self.orchestrator.namespace, label_selector=label_selector, field_selector=field_selector)
        if isinstance( myPodList, V1PodList ) and len(myPodList.items) > 0 :
            # propagation_policy = 'Background'
            propagation_policy = 'Foreground'
            grace_period_seconds = 0
            delete_options = V1DeleteOptions( 
                propagation_policy = propagation_policy, 
                grace_period_seconds=grace_period_seconds )

            v1status = self.kubeapi.delete_namespaced_pod(  
                name=pod_name,
                namespace=self.orchestrator.namespace,
                body=delete_options,
                propagation_policy=propagation_policy )

            result = isinstance( v1status, V1Pod ) or isinstance(v1status,V1Status)

        return result

    def findRunningPodforUserandImage( self, authinfo, userinfo, app):
        self.logger.info('')

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

            myPodList = self.orchestrator.kubeapi.list_namespaced_pod(
                self.orchestrator.namespace, 
                label_selector=label_selector, 
                field_selector=field_selector
            )

            if len(myPodList.items)> 0:
                for myPod in myPodList.items:
                    myPhase = myPod.status.phase
                    # keep only Running pod
                    if myPod.metadata.deletion_timestamp is not None:
                       myPhase = 'Terminating'
                    if myPhase != 'Running':
                       continue # This pod is Terminating or not Running, skip it
                    myrunningPodList.append(myPod)
        except ApiException as e:
            self.logger.info(f"Exception when calling list_namespaced_pod: {e}")
        return myrunningPodList


    def findRunningAppInstanceforUserandImage( self, authinfo, userinfo, app):
        pod = None
        podlist = self.findRunningPodforUserandImage( authinfo, userinfo, app)
        if len(podlist) > 0:
            pod = podlist[0]
            pod.id = pod.metadata.name # add an id for container compatibility
        return pod

    def create(self, myDesktop, app, authinfo, userinfo={}, userargs=None, **kwargs ):
        self.logger.debug('')

        rules = app.get('rules', {}) or {} # app['rules] can be set to None


        network_config = self.orchestrator.applyappinstancerules_network( authinfo, rules )

        (volumeBinds, volumeMounts) = self.orchestrator.build_volumes(   
            authinfo,
            userinfo,
            volume_type='pod_application',
            secrets_requirement=app.get('secrets_requirement'),
            rules=rules,
            **kwargs)

        list_volumeBinds = list( volumeBinds.values() )
        list_volumeMounts = list( volumeMounts.values() )
        self.logger.debug( f"list volume binds pod desktop {list_volumeBinds}")
        self.logger.debug( f"list volume mounts pod desktop {list_volumeMounts}")

        # apply network rules
        # network_config = self.applyappinstancerules_network( authinfo, rules )
        # apply homedir rules
        # homedir_disabled = self.applyappinstancerules_homedir( authinfo, rules )
        envlist = self.get_env_for_appinstance( myDesktop, app, authinfo, userinfo, userargs, **kwargs )

        command = [ '/composer/appli-docker-entrypoint.sh' ]
        labels = {  
            'access_providertype':  authinfo.providertype,
            'access_provider':  authinfo.provider,
            'access_userid':    userinfo.userid,
            'access_username':  self.orchestrator.get_labelvalue(userinfo.name),
            'type':             self.type,
            'uniquerunkey':     app.get('uniquerunkey'),
            'launch':           app.get('launch'),
            'icon':             app.get('icon')
        }

        pod_sufix = 'app_' + app['name'] + '_' +  oc.lib.uuid_digits()
        app_pod_name = self.orchestrator.get_podname( authinfo, userinfo, pod_sufix)

        # default empty dict annotations
        annotations = {}
        # Check if a network annotations exists
        network_annotations = network_config.get( 'annotations' )
        if isinstance( network_annotations, dict):
            annotations.update( network_annotations )

        # get the node selector merged data from desktop.pod['pod_application'] and app['nodeSelector']
        nodeSelector = self.get_appnodeSelector( authinfo, userinfo, app)
        securitycontext = self.get_securitycontext( authinfo, userinfo, app )
        workingDir = self.orchestrator.get_user_homedirectory( authinfo, userinfo )
        resources = self.get_resources( authinfo, userinfo, app )
        affinity = self.get_affinity( authinfo, userinfo, app, myDesktop )

        # update envlist
        # add EXECUTION CONTEXT env var inside the container
        envlist.append( { 'name': 'ABCDESKTOP_EXECUTE_RUNTIME',   'value': self.type} )
        envlist.append( { 'name': 'ABCDESKTOP_EXECUTE_RESOURCES', 'value': json.dumps(resources) } )

        pod_manifest = {
            'apiVersion': 'v1',
            'kind': 'Pod',
            'metadata': {
                'name':         app_pod_name,
                'namespace':    self.orchestrator.namespace,
                'labels':       labels,
                'annotations':  annotations
            },
            'spec': {
                'restartPolicy' : 'Never',
                'securityContext': securitycontext,
                'affinity': affinity,
                'automountServiceAccountToken': False,  # disable service account inside pod
                'volumes': list_volumeBinds,
                'nodeSelector': nodeSelector,
                'containers': [ {   
                    'imagePullSecrets': oc.od.settings.desktop_pod[self.type].get('imagePullSecrets'),
                    'imagePullPolicy':  oc.od.settings.desktop_pod[self.type].get('imagePullPolicy','IfNotPresent'),
                    'image': app['id'],
                    'name': app_pod_name,
                    'command': command,
                    'env': envlist,
                    'volumeMounts': list_volumeMounts,
                    'resources': resources,
                    'workingDir' : workingDir
                } ]
            }
        }

        self.logger.info( 'dump yaml %s', json.dumps( pod_manifest, indent=2 ) )
        pod = self.orchestrator.kubeapi.create_namespaced_pod(namespace=self.orchestrator.namespace,body=pod_manifest )

        if not isinstance(pod, V1Pod ):
            raise ValueError( 'Invalid create_namespaced_pod type')

        # set desktop web hook
        # webhook is None if network_config.get('context_network_webhook') is None
        fillednetworkconfig = self.orchestrator.filldictcontextvalue(   
            authinfo=authinfo,
            userinfo=userinfo,
            desktop=myDesktop,
            network_config=network_config,
            network_name = None,
            appinstance_id = None )

        appinstancestatus = oc.od.appinstancestatus.ODAppInstanceStatus(
            id=pod.metadata.name,
            message=pod.status.phase,
            webhook = fillednetworkconfig.get('webhook'),
            type=self.type
        )

        return appinstancestatus