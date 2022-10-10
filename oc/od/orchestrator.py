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
from oc.od.error import ODError
import oc.od.settings
import oc.lib 
import oc.auth.namedlib
import os
import time
import binascii
import urllib3

import time
import random
import datetime
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

import oc.lib
import oc.od.acl
import oc.od.volume         # manage volume for desktop
import oc.od.secret         # manage secret for kubernetes
import oc.od.configmap
import oc.od.appinstancestatus
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

        self.desktoplaunchprogress  = oc.pyutils.Event()        
        self.x11servertype          = 'x11server'        
        self.x11servertype_embeded  = 'x11serverembeded' 
        self.applicationtype        = 'pod_application'
        self.printerservertype      = 'cupsserver'
        self.soundservertype        = 'pulseserver'
        self.endpoint_domain        = 'desktop'
        self.ephemeral_container    = 'ephemeral_container'
        self.name = 'base'

    def get_containername( self, currentcontainertype, userid, myuuid ):
        prefix = self.nameprefixdict[currentcontainertype]
        return self.get_basecontainername( prefix, userid, myuuid )
  
    def get_initcontainername( self, userid, container_name ):
        return self.get_basecontainername( self.initcontainernameprefix, userid, container_name )

    def get_graphicalcontainername( self, userid, container_name ):
        return self.get_basecontainername( self.graphicalcontainernameprefix, userid, container_name )

    def get_printercontainername( self, userid, container_name ):
        return self.get_basecontainername( self.printercontainernameprefix, userid, container_name )

    def get_soundcontainername( self, userid, container_name ):
        return self.get_basecontainername( self.soundcontainernameprefix, userid, container_name )
       
    def get_filercontainername( self, userid, container_name ):
        return self.get_basecontainername( self.filercontainernameprefix, userid, container_name )

    def get_storagecontainername( self, userid, container_name ):
        return self.get_basecontainername( self.storagecontainernameprefix, userid, container_name )

    def get_basecontainername( self, containernameprefix, userid, container_name ):
        user_container_name = self.containernameseparator
        if isinstance( userid, str ):
            user_container_name = userid + self.containernameseparator
        name = containernameprefix + self.containernameseparator + user_container_name + container_name
        name = oc.auth.namedlib.normalize_name_dnsname( name )
        return name


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
        raise NotImplementedError('%s.desktop' % type(self))

    def createdesktop(self, authinfo, userinfo, **kwargs):
        raise NotImplementedError('%s.createdesktop' % type(self))

    def build_volumes( self, authinfo, userinfo, volume_type, secrets_requirement, rules, **kwargs):
        raise NotImplementedError('%s.build_volumes' % type(self))

    def findDesktopByUser( self, authinfo, userinfo, **kwargs ):
        raise NotImplementedError('%s.findDesktopByUser' % type(self))

    def removedesktop(self, authinfo, userinfo, args={}):
        raise NotImplementedError('%s.removedesktop' % type(self))

    def get_auth_env_dict( self, authinfo, userinfo ):
        raise NotImplementedError('%s.get_auth_env_dict' % type(self))

    def getsecretuserinfo(self, authinfo, userinfo):
        raise NotImplementedError('%s.getsecretuserinfo' % type(self))

    def garbargecollector( self, timeout ):
        raise NotImplementedError(f"{type(self)}.garbargecollector")

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

    def envContainerApp( self, authinfo, userinfo, containerid):
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

    def user_connect_count(self, desktop:ODDesktop, timeout=2000):
        """user_connect_count
            call bash script /composer/connectcount.sh inside a desktop
        Args:
            desktop (ODDesktop): ODDesktop
            timeout (int, optional): in milliseconds. Defaults to 2000.

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

    def waitForDesktopProcessReady(self, desktop, callback_notify, nTimeout=1000):
        self.logger.debug('')

        nCountMax = nTimeout
        # check if supervisor has stated all processs
        nCount = 1
        bListen = { 'x11server': False, 'spawner': False }
        # loop
        # wait for a listen dict { 'x11server': True, 'spawner': True }
        while nCount < 42:

            self.logger.debug( f"desktop services status bListen {bListen}" ) 
            # check if WebSockifyListening id listening on tcp port 6081
            if bListen['x11server'] is False:
                service='graphical'
                messageinfo = f"c.Starting desktop {service} service {nCount}/{nCountMax}"
                callback_notify(messageinfo)
                bListen['x11server'] = self.waitForServiceListening( desktop, service='graphical' )
                self.logger.info(f"service:x11server return {bListen['x11server']}")

            # check if spawner is ready 
            if bListen['spawner'] is False:
                service='spawner'
                messageinfo = f"c.Starting desktop {service} service {nCount}/{nCountMax}"
                callback_notify(messageinfo)
                bListen['spawner']  = self.waitForServiceListening( desktop, service='spawner' )
                self.logger.info(f"service:spawner return {bListen['spawner']}")  
            
            if bListen['x11server'] is True and bListen['spawner'] is True:     
                self.logger.debug( "desktop services are ready" )                  
                callback_notify( f"c.Desktop services are running after {nCount} s" )              
                return True

            nCount += 1

            # wait 0.1    
            self.logger.debug( 'sleeping for 0.5')
            time.sleep(0.5)
        
        # Can not chack process status     
        self.logger.warning( f"waitForDesktopProcessReady not ready services status:{bListen}" )
        return False


    def waitForServiceHealtz(self, desktop, service, timeout=100):
        '''    waitForServiceListening tcp port '''
        self.logger.debug('')
        # Note the same timeout value is used twice
        # for the wait_port command and for the exec command         
        
        if type(desktop) is not ODDesktop:
            raise ValueError('invalid desktop object type' )

        if not isinstance( oc.od.settings.desktop_pod[service].get('healtzbin'), str):
            # no healtz binary command has been set
            # no need to run command
            return True
        
        port = port=oc.od.settings.desktop_pod[service].get('tcpport')
        binding = f"http://{desktop.ipAddr}:{port}/{service}/healtz"
        # ccurl --max-time 1 https://example.com/
        command = [ oc.od.settings.desktop_pod[service].get('healtzbin'), '--max-time', str(timeout), binding ]       
        result = self.execwaitincontainer( desktop, command, timeout)
        self.logger.debug( 'command %s , return %s output %s', command, str(result.get('exit_code')), result.get('stdout') )

        if isinstance(result, dict):
            return result.get('ExitCode') == 0
        else:
            return False

      
    def waitForServiceListening(self, desktop, service, timeout=1000):     
        '''    waitForServiceListening tcp port '''

        self.logger.debug(locals())
        # Note the same timeout value is used twice
        # for the wait_port command and for the exec command         
        
        if type(desktop) is not ODDesktop:
            raise ValueError('invalid desktop object type' )

        waitportbincommand = oc.od.settings.desktop_pod[service].get('waitportbin')
        if not isinstance( waitportbincommand, str):
            # no healtz binary command has been set
            # no need to run command
            self.logger.error(f"error in configuration file 'waitportbin' must be a string. Type read in config {type(waitportbincommand)}" )
            raise oc.od.infra.ODAPIError( f"error in configuration file 'waitportbin' must be a string defined as healtz command line. type defined {type(waitportbincommand)}" )
        
        port = oc.od.settings.desktop_pod[service].get('tcpport')
        if not isinstance( port, int):
            # no healtz binary command has been set
            # no need to run command
            self.logger.error(f"error in configuration file 'tcpport' must be a int. Type read in config {type(port)}" )
            raise oc.od.infra.ODAPIError( f"error in configuration file 'tcpport' must be a int. Type read in config {type(port)}" )
        
        binding = '{}:{}'.format(desktop.ipAddr, str(port))
        command = [ oc.od.settings.desktop_pod[service].get('waitportbin'), '-t', str(timeout), binding ]       
        result = self.execwaitincontainer( desktop, command, timeout)
     
        if isinstance(result, dict):
            self.logger.debug( f"command={command} exit_code={result.get('ExitCode')} stdout={result.get('stdout')}" )
            isportready = result.get('ExitCode') == 0
            self.logger.debug( f"isportready={isportready}")
            if isportready is True:
                self.logger.debug( f"binding {binding} is up")
                return self.waitForServiceHealtz(desktop, service, timeout)

        self.logger.debug( f"binding {binding} is down")
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

    def createvolume(self, prefix:str, authinfo:AuthInfo, userinfo:AuthUser, removeifexist: bool=False ):
        raise NotImplementedError('%s.createvolume' % type(self))
        
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
        
    def removecontainer( self, desktopid, remove_volume_home=False ):
        raise NotImplementedError('%s.removecontainer' % type(self))

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


    def resumedesktop(self, authinfo, userinfo, **kwargs):
        raise NotImplementedError('%s.resumedesktop' % type(self))

    def createdesktop(self, authinfo, userinfo, **kwargs):
        raise NotImplementedError('%s.createdesktop' % type(self))
    
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

        self.DEFAULT_K8S_TIMEOUT_SECONDS = 15
        self.DEFAULT_K8S_CREATE_TIMEOUT_SECONDS = 30

        self.appinstance_classes = {    'ephemeral_container': ODAppInstanceKubernetesEphemeralContainer,
                                        'pod_application': ODAppInstanceKubernetesPod }
        self.all_phases_status = [ 'Running', 'Terminated', 'Waiting', 'Completed', 'Succeeded']
        self.all_running_phases_status = [ 'Running', 'Waiting' ]

        # self.appinstance_classes = appinstance_classes_dict.
        # Configs can be set in Configuration class directly or using helper
        # utility. If no argument provided, the config will be loaded from
        # default location.
        try:
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
                self.logger.debug( 'config.load_incluster_config kubernetes mode done')
            else:
                # self.logger.debug( 'config.load_kube_config not in cluster mode')
                config.load_kube_config()
                self.logger.debug( 'config.load_kube_config done')
            
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
            # 
            self.default_volumes['shm'] = { 'name': 'shm', 'emptyDir': { 'medium': 'Memory', 'sizeLimit': oc.od.settings.desktophostconfig.get('shm_size','64Mi') } }
            self.default_volumes_mount['shm'] = { 'name': 'shm', 'mountPath' : '/dev/shm' }

            # if oc.od.settings.desktopusepodasapp is True:
            #   self.default_volumes['tmp']       = { 'name': 'tmp',  'hostPath': { 'path': '/var/run/abcdesktop/pods/tmp' } }
            #    self.default_volumes_mount['tmp'] = { 'name': 'tmp',  'mountPath': '/tmp', 'subPathExpr': '$(POD_NAME)' }
            #    self.default_volumes['home']      = { 'name': 'home', 'hostPath': { 'path': '/var/run/abcdesktop/pods/home' } }
            #    self.default_volumes_mount['home']= { 'name': 'home', 'mountPath': '/home/balloon', 'subPathExpr': '$(POD_NAME)' }
            # else:

            self.default_volumes['tmp']       = { 'name': 'tmp',  'emptyDir': { 'medium': 'Memory', 'sizeLimit': '8Gi' } }
            self.default_volumes_mount['tmp'] = { 'name': 'tmp',  'mountPath': '/tmp' }

            self.default_volumes['run']       = { 'name': 'run',  'emptyDir': { 'medium': 'Memory', 'sizeLimit': '1M' } }
            self.default_volumes_mount['run'] = { 'name': 'run',  'mountPath': '/var/run/desktop' }

            self.default_volumes['log']       = { 'name': 'log',  'emptyDir': { 'medium': 'Memory', 'sizeLimit': '1G' } }
            self.default_volumes_mount['log'] = { 'name': 'log',  'mountPath': '/var/log/desktop' }

            self.default_volumes['x11socket'] = { 'name': 'x11socket',  'emptyDir': { 'medium': 'Memory' } }
            self.default_volumes_mount['x11socket'] = { 'name': 'x11socket',  'mountPath': '/tmp/.X11-unix' }
            self.default_volumes['pulseaudiosocket'] = { 'name': 'pulseaudiosocket',  'emptyDir': { 'medium': 'Memory' } }
            self.default_volumes_mount['pulseaudiosocket'] = { 'name': 'pulseaudiosocket',  'mountPath': '/tmp/.pulseaudio' }
            self.default_volumes['cupsdsocket'] = { 'name': 'cupsdsocket',  'emptyDir': { 'medium': 'Memory' } }
            self.default_volumes_mount['cupsdsocket'] = { 'name': 'cupsdsocket',  'mountPath': '/tmp/.cupsd' }

        except Exception as e:
            self.bConfigure = False
            self.logger.info( '%s', str(e) ) # this is not an error but kubernetes is not supported
        self.logger.debug( "ODOrchestratorKubernetes done configure={self.bConfigure}" )


    def close(self):
        #self.kupeapi.close()
        pass

    def is_configured(self): 
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
                if isinstance( node_list, client.models.V1NodeList) and len(node_list.items) > 0:
                    bReturn = True
        except Exception as e:
            self.logger.error( str(e) )
        return bReturn


    def listEndpointAddresses( self, endpoint_name ):
        list_endpoint_addresses = None
        list_endpoint_port = None
        endpoint = self.kubeapi.read_namespaced_endpoints( name=endpoint_name, namespace=self.namespace )
        if isinstance( endpoint, client.V1Endpoints ):
            if not isinstance( endpoint.subsets, list) or len(endpoint.subsets) == 0:
                return list_endpoint_addresses

            endpoint_subset = endpoint.subsets[0]
            if isinstance( endpoint_subset, client.V1EndpointSubset ) :
                list_endpoint_addresses = []
                # read the uniqu port number
                endpoint_port = endpoint_subset.ports[0]
                if isinstance( endpoint_port, client.CoreV1EndpointPort ):
                    list_endpoint_port = endpoint_port.port

                # read add addreses
                for address in endpoint_subset.addresses :
                    if isinstance( address, client.V1EndpointAddress):
                        list_endpoint_addresses.append( address.ip )

        return (list_endpoint_port, list_endpoint_addresses)


    def findAllSecretsByUser( self,  authinfo, userinfo ):
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

    def findSecretByUser( self,  authinfo, userinfo, secret_type ):
        secret = oc.od.secret.selectSecret( self.namespace, self.kubeapi, secret_type )
        return secret.read_credentials(userinfo)

    def get_podname( self, authinfo, userinfo, pod_uuid ):
        """[get_podname]
            return a pod name from authinfo, userinfo and uuid 
        Args:
            authinfo (AuthInfo): authentification data
            userinfo (AuthUser): user data 
            pod_uuid ([str]): [uniqu uuid]

        Returns:
            [str]: [name of the user pod]
        """
        userid = userinfo.userid
        if authinfo.provider == 'anonymous':
            userid = 'anonymous'
        return oc.auth.namedlib.normalize_name( userid + self.containernameseparator + pod_uuid)[0:252]       
 
    def get_labelvalue( self, label_value):
        """[get_labelvalue]

        Args:
            label_value ([str]): [label_value name]

        Returns:
            [str]: [return normalized label name]
        """
        normalize_data = oc.auth.namedlib.normalize_label( label_value )
        no_accent_normalize_data = oc.lib.remove_accents( normalize_data )
        return no_accent_normalize_data

    def logs( self, authinfo, userinfo ):
        strlogs = ''
        myPod =  self.findPodByUser(authinfo, userinfo)

        if myPod is None :            
            self.logger.info( 'No pod found for user %s ',  userinfo.userid )
            return strlogs

        try:
            myDesktop = self.pod2desktop( pod=myPod )
            pod_name = myPod.metadata.name  
            container_name = myDesktop.container_name
            strlogs = self.kubeapi.read_namespaced_pod_log( name=pod_name, namespace=self.namespace, container=container_name, pretty='true' )
        except ApiException as e:
            self.logger.error( str(e) )

        return strlogs




    '''
    'volumes': [
                                {
                                    'name': volume_home_name,
                                    'persistentVolumeClaim': {
                                        'claimName': 'task-pv-claim'
                                    }
                                }
                ],
    'volumeMounts': [ 
                                { 
                                    'name': volume_mount_name,
                                    'mountPath' : balloon_home_dir_path,
                                    'subPath'  : name
                                }
                    ]
    ''' 


    def build_volumes_secrets( self, authinfo, userinfo, volume_type, secrets_requirement, rules={}, **kwargs):
        self.logger.debug('')
        volumes = {}        # set empty volume dict by default
        volumes_mount = {}  # set empty volume_mount dict by default
        #
        # mount secret in /var/secrets/abcdesktop
        #
        self.logger.debug( f"listing list_dict_secret_data access_type='auth'" )
        mysecretdict = self.list_dict_secret_data( authinfo, userinfo, access_type='auth' )
        for secret_auth_name in mysecretdict.keys():
            # https://kubernetes.io/docs/concepts/configuration/secret
            # create an entry eq: 
            # /var/secrets/abcdesktop/ntlm
            # /var/secrets/abcdesktop/cntlm
            # /var/secrets/abcdesktop/kerberos
            
            self.logger.debug( f"checking {secret_auth_name} access_type='auth' " )
            # only mount secrets_requirement
            if isinstance( secrets_requirement, list ):
                if secret_auth_name not in secrets_requirement:
                    self.logger.debug( f"{secret_auth_name} is not in {secrets_requirement}" )
                    self.logger.debug( f"{secret_auth_name} is skipped" )
                    continue

            self.logger.debug( 'adding secret type %s to volume pod', mysecretdict[secret_auth_name]['type'] )
            secretmountPath = oc.od.settings.desktop['secretsrootdirectory'] + mysecretdict[secret_auth_name]['type'] 
            # mode is 644 -> rw-r--r--
            # Owing to JSON limitations, you must specify the mode in decimal notation.
            # 644 in decimal equal to 420
            volumes[secret_auth_name]       = { 'name': secret_auth_name, 'secret': { 'secretName': secret_auth_name, 'defaultMode': 420  } }
            volumes_mount[secret_auth_name] = { 'name': secret_auth_name, 'mountPath':  secretmountPath }

        return (volumes, volumes_mount)

    def build_volumes_flexvolumes( self, authinfo, userinfo, volume_type, secrets_requirement, rules={}, **kwargs):
        self.logger.debug('')
        volumes = {}        # set empty volume dict by default
        volumes_mount = {}  # set empty volume_mount dict by default
        if isinstance( rules, dict ):
            self.logger.debug( f"selecting volume by rules" )
            mountvols = oc.od.volume.selectODVolumebyRules( authinfo, userinfo, rules=rules.get('volumes') )
            self.logger.debug( f"selected volume by rules" )
            for mountvol in mountvols:
                fstype = mountvol.fstype
                volume_name = self.get_volumename( mountvol.name, userinfo )
                # mount the remote home dir as a flexvol
                # WARNING ! if the flexvol mount failed, the pod must start
                # abcdesktop/cifs always respond a success
                # in case of failure access right is denied                
                # the flexvolume driver abcdesktop/cifs MUST be deploy on each node

                # Flex volume use kubernetes secret                    
                # Kubernetes secret as already been created by prepareressource function call 
                # Read the secret and use it

                driver_type =  self.namespace + '/' + fstype

                self.on_desktoplaunchprogress('b.Building flexVolume storage data for driver ' + driver_type )

                secret = oc.od.secret.selectSecret( self.namespace, self.kubeapi, prefix=mountvol.name, secret_type=fstype )
                
                # read the container mount point from the secret
                # for example /home/balloon/U             
                # Read data from secret    
                secret_name         = secret.get_name( userinfo )
                secret_dict_data    = secret.read_data( userinfo )
                mountPath           = secret_dict_data.get( 'mountPath')
                networkPath         = secret_dict_data.get( 'networkPath' )
                
                # Check if the secret contains valid datas 
                if not isinstance( mountPath, str) :
                    self.logger.error( 'Invalid value for mountPath read from secret' )
                    continue

                if not isinstance( networkPath, str) :
                    self.logger.error( 'Invalid value for networkPath read from secret' )
                    continue

                volumes_mount[mountvol.name] = {'name': volume_name, 'mountPath': mountPath }     

                # Default mount options
                mountOptions = 'uid=' + str( oc.od.settings.getballoon_uid() ) + ',gid=' + str( oc.od.settings.getballoon_gid() )
                # concat mountOptions for the volume if exists 
                if mountvol.has_options():
                    mountOptions += ',' + mountvol.mountOptions

                # dump for debug
                self.logger.debug( f"flexvolume: {mountvol.name} set option {mountOptions}" )
                self.logger.debug( f"flexvolume: read secret {secret_name} to mount {networkPath}")
                # add dict volumes entry mountvol.name
                volumes[mountvol.name] = { 'name': volume_name,
                                            'flexVolume' : {
                                                'driver': driver_type,
                                                'fsType': fstype,
                                                'secretRef' : { 'name': secret_name },
                                                'options'   : { 'networkPath':  networkPath, 
                                                                'mountOptions': mountOptions }
                                            }
                }
                # dump for debug
                self.logger.debug( f"volumes {mountvol.name} use volume {volumes[mountvol.name]} and volume mount {volumes_mount[mountvol.name]}")
        return (volumes, volumes_mount)


    def build_volumes_home( self, authinfo, userinfo, volume_type, secrets_requirement, rules={}, **kwargs):
        self.logger.debug('')
        volumes = {}        # set empty volume dict by default
        volumes_mount = {}  # set empty volume_mount dict by default
        #
        # if type is self.x11servertype then keep user home dir data
        # else do not use the default home dir to metapplimode
        homedir_enabled = True

        # if the pod or container is not an x11servertype
        if kwargs.get('type') != self.x11servertype:
            homedir_enabled = ODOrchestratorKubernetes.applyappinstancerules_homedir( authinfo, rules )

        if not homedir_enabled:
            return (volumes, volumes_mount)

        self.on_desktoplaunchprogress('Building home dir data storage')
        volume_home_name = self.get_volumename( 'home', userinfo )
        # by default hostpath
        homedirectorytype = oc.od.settings.desktop['homedirectorytype']

        if authinfo.provider == 'anonymous':
            # anonymous doest not store data
            homedirectorytype = 'emptyDir'

        subpath_name = oc.auth.namedlib.normalize_name( userinfo.name )

        if  homedirectorytype == 'emptyDir':
            volumes['home'] = { 'name': volume_home_name, # home + userid
                                'emptyDir': {}
            }
            volumes_mount['home'] = {   'name'      : volume_home_name,
                                        'mountPath' : oc.od.settings.getballoon_homedirectory(), # /home/balloon
            }
        elif homedirectorytype == 'persistentVolumeClaim':
            # Map the home directory
            volumes['home'] = {
                'name': volume_home_name,
                'persistentVolumeClaim': {'claimName': oc.od.settings.desktop['persistentvolumeclaim'] }
            }
            volumes_mount['home'] = {
                'name'      : volume_home_name,
                'mountPath' : oc.od.settings.getballoon_homedirectory(), # /home/balloon
                'subPath'  : subpath_name                                # userid
            }
        elif homedirectorytype == 'hostPath':
            # Map the home directory
            # mount_volume = '/mnt/abcdesktop/$USERNAME' on host
            # volume type is 'DirectoryOrCreate'
            # same as 'subPath' but bot hostpath
            # 'subPath' is not supported for ephemeral container
            mount_volume = oc.od.settings.desktop['hostPathRoot'] + '/' + subpath_name
            
            volumes['home']= {  'name': volume_home_name,
                                'hostPath': {
                                    'path': mount_volume,
                                    'type': 'DirectoryOrCreate'
                                }
            }

            volumes_mount['home'] = {
                'name'      : volume_home_name,
                'mountPath' : oc.od.settings.getballoon_homedirectory(), # /home/balloon
            }

        self.logger.debug( 'volume mount : %s %s', 'home', volumes_mount['home'] )
        self.logger.debug( 'volumes      : %s %s', 'home', volumes['home'] )

        return (volumes, volumes_mount)


    def build_volumes_vnc( self, authinfo, userinfo, volume_type, secrets_requirement, rules={}, **kwargs):
        
        self.logger.debug('')
        volumes = {}        # set empty volume dict by default
        volumes_mount = {}  # set empty volume_mount dict by default
         # Add VNC password
        mysecretdict = self.list_dict_secret_data( authinfo, userinfo, access_type='vnc' )
        # the should only be one secret type vnc
        secret_auth_name = next(iter(mysecretdict)) # first entry of the dict
        # create an entry /var/secrets/abcdesktop/vnc
        secretmountPath = oc.od.settings.desktop['secretsrootdirectory'] + mysecretdict[secret_auth_name]['type']
        # mode is 644 -> rw-r--r--
        # Owing to JSON limitations, you must specify the mode in decimal notation.
        # 644 in decimal equal to 420
        volumes[secret_auth_name]       = { 'name': secret_auth_name, 'secret': { 'secretName': secret_auth_name, 'defaultMode': 420  } }
        volumes_mount[secret_auth_name] = { 'name': secret_auth_name, 'mountPath':  secretmountPath }

        return (volumes, volumes_mount)

    def build_volumes_localaccount( self, authinfo, userinfo, volume_type, secrets_requirement, rules={}, **kwargs):

        volumes = {}        # set empty volume dict by default
        volumes_mount = {}  # set empty volume_mount dict by default
        #
        # mount secret in /var/secrets/abcdesktop
        #
        mysecretdict = self.list_dict_secret_data( authinfo, userinfo, access_type='localaccount' )
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

    def build_volumes( self, authinfo, userinfo, volume_type, secrets_requirement, rules={}, **kwargs):
        """[build_volumes]

        Args:
            authinfo ([type]): [description]
            userinfo (AuthUser): user data
            volume_type ([str]): 'container_desktop' 'pod_desktop', 'container_app', 'pod_application', 'ephemeral_container'
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
        # tmp volume is shared between all container inside the desktop pod
        #
        if volume_type in [ 'pod_desktop', 'container_app', 'ephemeral_container' ] :
            # set tmp volume
            volumes['tmp']       = self.default_volumes['tmp']
            volumes_mount['tmp'] = self.default_volumes_mount['tmp']
            # set x11unix socket, pulseaudiosocket and cupsdsocket
            volumes['x11socket']   = self.default_volumes['x11socket']
            volumes_mount['x11socket'] = self.default_volumes_mount['x11socket']
            # pulseaudiosocket
            volumes['pulseaudiosocket']   = self.default_volumes['pulseaudiosocket']
            volumes_mount['pulseaudiosocket'] = self.default_volumes_mount['pulseaudiosocket']
            # cupsdsocket
            volumes['cupsdsocket']   = self.default_volumes['cupsdsocket']
            volumes_mount['cupsdsocket'] = self.default_volumes_mount['cupsdsocket']
            # set run volume use to write run files
            volumes['run']       = self.default_volumes['run']
            volumes_mount['run'] = self.default_volumes_mount['run']
            # set log volume use to write log files
            volumes['log']       = self.default_volumes['log']
            volumes_mount['log'] = self.default_volumes_mount['log']


        #
        # shm volume is shared between all container inside the desktop pod
        #
        if volume_type in [ 'pod_desktop', 'container_desktop', 'ephemeral_container' ] \
            and oc.od.settings.desktophostconfig.get('shm_size'):
                # set shm memory volume
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

        
    def execwaitincontainer( self, desktop, command, timeout=1000):
        self.logger.info('')
        result = { 'ExitCode': -1, 'stdout':None }
        
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
        try:            
            resp = stream(  self.kubeapi.connect_get_namespaced_pod_exec, 
                            name=desktop.name, 
                            namespace=self.namespace, 
                            command=command,                                                                
                            container=desktop.container_name,
                            stderr=True, stdin=False,
                            stdout=True, tty=False,
                            _preload_content=False              #  need a client object websocket
            )
            resp.run_forever(timeout) 
            err = resp.read_channel(ERROR_CHANNEL, timeout=timeout)
            self.logger.debug( f"desktop.name={desktop.name} container={desktop.container_name} command={command} return code {err}")
            respdict = yaml.load(err, Loader=yaml.BaseLoader )  
            result['ExitCode'] = -1 # default value          
            result['stdout'] = resp.read_stdout()

            #
            # /composer/node/wait-port/node_modules/.bin/wait-port 10.1.101.196:6081
            # Waiting for 10.1.101.196:6081.
            # Connected!
            #
            # ExitCode is 0 if timeout 
            # we must read the stdout to read Connected string
            # this is bad
            # need to fix the wait-port timeout exit code
            #
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
        self.logger.debug( f"{command} return code={result}")
        return result


    def removePod( self, myPod, propagation_policy = 'Foreground', grace_period_seconds = None ):
        """_summary_
            Remove a pod
            like command 'kubectl delete pods'
        Args:
            myPod (_type_): _description_
            propagation_policy (str, optional): propagation_policy. Defaults to 'Foreground'.
            propagation_policy = 'Background' or 
            propagation_policy = 'Foreground'


        Returns:
            v1status: v1status
        """
        self.logger.debug('')
        v1status = None
        try:
            #   The Kubernetes propagation_policy is 'Foreground'
            #   Default 'Foreground' means that child Pods to the Job will be deleted
            #   before the Job is marked as deleted.
            
            pod_name = myPod.metadata.name                
            self.logger.info( 'removing pod_name %s', pod_name)

            # propagation_policy = 'Background'
            # propagation_policy = 'Foreground'
            # delete_options = client.V1DeleteOptions( propagation_policy = propagation_policy )
            delete_options = client.V1DeleteOptions( 
                propagation_policy = propagation_policy, 
                grace_period_seconds = grace_period_seconds )
            
            v1status = self.kubeapi.delete_namespaced_pod(  name=pod_name, 
                                                            namespace=self.namespace, 
                                                            body=delete_options, 
                                                            propagation_policy=propagation_policy )
                                                            # grace_period_seconds=grace_period_seconds )

        except ApiException as e:
            self.logger.error( str(e) )

        return v1status

    def removesecrets( self, authinfo, userinfo ):
        ''' remove all kubernetes secrets for a give user '''
        ''' access_type is None will list all user secret '''
        bReturn = True
        dict_secret = self.list_dict_secret_data( authinfo, userinfo, access_type=None)
        for secret_name in dict_secret.keys():
            try:            
                v1status = self.kubeapi.delete_namespaced_secret( name=secret_name, namespace=self.namespace )
                if not isinstance(v1status,client.models.v1_status.V1Status) :
                    raise ValueError( 'Invalid V1Status type return by delete_namespaced_secret')
                self.logger.debug('secret %s status %s', secret_name, v1status.status) 
                if v1status.status != 'Success':
                    self.logger.error(f"secret {secret_name} can not be deleted {v1status}" ) 
                    bReturn = bReturn and False
                
            except ApiException as e:
                self.logger.error(f"secret {secret_name} can not be deleted {e}") 
                bReturn = bReturn and False
        self.logger.debug(f"removesecrets for {userinfo.userid} return {bReturn})" ) 
        return bReturn 
   


    def removeconfigmap( self, authinfo, userinfo ):
        ''' remove all kubernetes secrets for a give user '''
        ''' access_type is None will list all user secret '''
        bReturn = True
        dict_configmap = self.list_dict_configmap_data( authinfo, userinfo, access_type=None)
        for configmap_name in dict_configmap.keys():
            try:            
                v1status = self.kubeapi.delete_namespaced_config_map( name=configmap_name, namespace=self.namespace )
                if not isinstance(v1status,client.models.v1_status.V1Status) :
                    raise ValueError( 'Invalid V1Status type return by delete_namespaced_config_map')
                self.logger.debug('configmap %s status %s', configmap_name, v1status.status) 
                if v1status.status != 'Success':
                    self.logger.error('configmap name %s can not be deleted %s', configmap_name, str(v1status) ) 
                    bReturn = bReturn and False
                    
            except ApiException as e:
                self.logger.error('configmap name %s can not be deleted: error %s', configmap_name, e ) 
                bReturn = bReturn and False
        return bReturn 

    def removepodindesktop(self, authinfo, userinfo, myPod=None ):
        # get the user's pod
        if not isinstance(myPod, client.models.v1_pod.V1Pod ):
            myPod = self.findPodByUser(authinfo, userinfo )

        if isinstance(myPod, client.models.v1_pod.V1Pod ):
            # delete this pod immediatly
            v1status = self.removePod( myPod, propagation_policy='Foreground', grace_period_seconds=0 )
            if isinstance(v1status,client.models.v1_pod.V1Pod) :
                # todo
                # add test
                return True
        return False
        

    def removedesktop(self, authinfo, userinfo, myPod=None ):
        """_summary_

        Args:
            authinfo (AuthInfo): authentification data
            userinfo (AuthUser): user data 
            myPod (_type_, optional): _description_. Defaults to None.

        Returns:
            _type_: _description_
        """
        ''' remove kubernetes pod for a give user '''
        ''' then remove kubernetes user's secrets '''
        bReturn = False # default value 
        removedesktopStatus = {}
        self.logger.debug('')

        # get the user's pod
        if not isinstance(myPod, client.models.v1_pod.V1Pod ):
            myPod = self.findPodByUser(authinfo, userinfo )

        if isinstance(myPod, client.models.v1_pod.V1Pod ):
            v1status = self.removePod( myPod )
            removedesktopStatus['pod'] = isinstance(v1status,client.models.v1_pod.V1Pod) or isinstance(v1status,client.models.v1_status.V1Status)

            removetheads    =  [ { 'fct':self.removesecrets,   'args': [ authinfo, userinfo ], 'thread':None },
                                 { 'fct':self.removeconfigmap, 'args': [ authinfo, userinfo ], 'thread':None } ]
   
            for removethread in removetheads:
                self.logger.debug( 'calling webhook cmd %s', str(removethread['fct']) )
                removethread['thread']=threading.Thread(target=removethread['fct'], args=removethread['args'])
                removethread['thread'].start()
 
            # need to wait for removethread['thread'].join()
            for removethread in removetheads:
                removethread['thread'].join()

            bReturn = all( removedesktopStatus.values() )
        else:
            self.logger.error( "removedesktop can not find desktop %s %s", authinfo, userinfo )
        return bReturn


    def preparelocalaccount( self, localaccount ):
        assert isinstance(localaccount, dict),f"invalid localaccount type {type(localaccount)}"
        # read localaccount dict values
        uid = localaccount.get('uid' )
        sha512 = localaccount.get('sha512')
        uidNumber =  localaccount.get('uidNumber' )
        gidNumber =  localaccount.get('gidNumber' )

        # crate dedicated line for each file
        passwd_line = f"{uid}:x:{uidNumber}:{gidNumber}::{oc.od.settings.getballoon_homedirectory()}:{oc.od.settings.getballoon_shell()}"
        group_line = f"{uid}:x:{gidNumber}\nsudo:x:27:{uid}"
        shadow_line = f"{uid}:{sha512}:19080:0:99999:7:::"

        # concat user information to file
        # passwd 
        # group
        # shadow
        passwd_file = oc.od.settings.DEFAULT_PASSWD_FILE + '\n' + passwd_line
        group_file = oc.od.settings.DEFAULT_GROUP_FILE + '\n' + group_line
        shadow_file = oc.od.settings.DEFAULT_SHADOW_FILE + '\n' + shadow_line
        
        mydict_config = { 
            'passwd' : passwd_file, 
            'shadow' : shadow_file, 
            'group': group_file 
        }

        return mydict_config
            
    def prepareressources(self, authinfo:AuthInfo, userinfo:AuthUser):
        """[prepareressources]

        Args:
            authinfo (AuthInfo): authentification data
            userinfo (AuthUser): user data

        """
        self.logger.debug('')
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
        secret = oc.od.secret.ODSecretLDIF( self.namespace, self.kubeapi )
        secret.create( authinfo, userinfo, data=userinfo )
        self.logger.debug('create oc.od.secret.ODSecretLDIF created')

        # look if the current account is a posix local account
        localaccount_data = authinfo.get_localaccount()
        localaccount_files = self.preparelocalaccount( localaccount_data )
        self.logger.debug('localaccount secret.create creating')
        secret = oc.od.secret.selectSecret( self.namespace, self.kubeapi, prefix=None, secret_type='localaccount' )
        # build a kubernetes secret with the auth values 
        # values can be empty to be updated later
        createdsecret = secret.create( authinfo, userinfo, data=localaccount_files )
        if not isinstance( createdsecret, client.models.v1_secret.V1Secret):
            mysecretname = self.get_name( userinfo )
            self.logger.error((f"cannot create secret {mysecretname}"))
        self.logger.debug('localaccount secret.create created')

        # for each auth protocol enabled
        local_secrets = authinfo.get_secrets()
        if isinstance( local_secrets, dict ) :
            self.logger.debug('secret.create creating')
            for auth_env_built_key in local_secrets.keys():   
                secret = oc.od.secret.selectSecret( self.namespace, self.kubeapi, prefix=None, secret_type=auth_env_built_key )
                # build a kubernetes secret with the auth values 
                # values can be empty to be updated later
                createdsecret = secret.create( authinfo, userinfo, data=local_secrets.get(auth_env_built_key) )
                if not isinstance( createdsecret, client.models.v1_secret.V1Secret):
                    mysecretname = self.get_name( userinfo )
                    self.logger.error((f"cannot create secret {mysecretname}"))
            self.logger.debug('secret.create created')
    
        # Create flexvolume secrets
        self.logger.debug('flexvolume secrets creating')
        rules = oc.od.settings.desktop['policies'].get('rules')
        if rules is not None:
            mountvols = oc.od.volume.selectODVolumebyRules( authinfo, userinfo,  rules.get('volumes') )
            for mountvol in mountvols:
                # use as a volume defined and the volume is mountable
                fstype = mountvol.fstype # Get the fstype: for example 'cifs' or 'cifskerberos' or 'webdav'
                # Flex volume use kubernetes secret, add mouting path
                arguments = { 'mountPath': mountvol.containertarget, 'networkPath': mountvol.networkPath }
                # Build the kubernetes secret
                secret = oc.od.secret.selectSecret( self.namespace, self.kubeapi, prefix=mountvol.name, secret_type=fstype)
                auth_secret = secret.create( authinfo, userinfo, arguments )
                if auth_secret is None:
                    self.logger.error( f"Failed to build auth secret fstype={fstype}" )
        self.logger.debug('flexvolume secrets created')

    def get_annotations_lastlogin_datetime(self):
        """get a new lastlogin datetime dict formated as "%Y-%m-%dT%H:%M:%S")

        Returns:
            dict: a dict with annotations lastlogindatetime.now()
                    format is {'annotations':{'lastlogin_datetime': datetime.datetime.now() } }
        """
        lastlogin_datetime = datetime.datetime.now()
        str_lastlogin_datetime = lastlogin_datetime.strftime("%Y-%m-%dT%H:%M:%S")
        annotations = { 'lastlogin_datetime': str_lastlogin_datetime } 
        return annotations

    def read_pod_annotations_lastlogin_datetime(self, pod ):
        """read pod annotations data lastlogin_datetime value

        Args:
            pod (pod): kubernetes pod

        Returns:
            datetime: a datetime from pod.metadata.annotations.get('lastlogin_datetime') None if not set
        """
        resumed_datetime = None
        str_lastlogin_datetime = pod.metadata.annotations.get('lastlogin_datetime')
        if isinstance(str_lastlogin_datetime,str):
            resumed_datetime = datetime.datetime.strptime(str_lastlogin_datetime, "%Y-%m-%dT%H:%M:%S")
        return resumed_datetime

    def resumedesktop(self, authinfo, userinfo, **kwargs):
        """resume desktop update the lastconnectdatetime annotations data
           findPodByuser and update the lastconnectdatetime using patch_namespaced_pod
        Args:
            authinfo (AuthInfo): authentification data
            userinfo (AuthUser): user data 

        Returns:
            [ODesktop]: Desktop Object updated annotations data
        """
        self.logger.debug('')
        myDesktop = None
        myPod =  self.findPodByUser(authinfo, userinfo)

        if myPod is None :            
            self.logger.info( 'Pod name not found for user %s ',  userinfo.userid )
        else:
            new_metadata = myPod.metadata
            new_lastlogin_datetime = self.get_annotations_lastlogin_datetime()
            # update the metadata ['lastlogin_datetime'] in pod
            new_metadata.annotations['lastlogin_datetime'] = new_lastlogin_datetime['lastlogin_datetime']
            v1newPod = self.kubeapi.patch_namespaced_pod(   name=myPod.metadata.name, 
                                                            namespace=self.namespace, 
                                                            body=new_metadata )
            myDesktop = self.pod2desktop( pod=v1newPod, userinfo=userinfo )
        return myDesktop

    def getsecretuserinfo(self, authinfo, userinfo):
        """read cached user info dict from a ldif secret

        Args:
            authinfo (AuthInfo): authentification data
            userinfo (AuthUser): user data 

        Returns:
            [dict]: cached user info dict from ldif secret
                    empty dict if None
        """
        dict_secret = self.list_dict_secret_data( authinfo, userinfo )
        raw_secrets = {}
        for key in dict_secret.keys():
            secret = dict_secret[key]
            if isinstance(secret, dict) and secret.get('type') == 'abcdesktop/ldif':
                raw_secrets.update( secret )
                break
        return raw_secrets


    def list_dict_configmap_data( self, authinfo, userinfo, access_type=None, hidden_empty=False ):
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

    def get_auth_env_dict( self, authinfo, userinfo ):
        ''' remove the secret name from the dict secret to read only key value  '''
        ''' return a dict without secret name, merge all data                   '''
        dict_secret = self.list_dict_secret_data( authinfo, userinfo, access_type='auth')
        raw_secrets = {}
        for key in dict_secret.keys():
            raw_secrets.update( dict_secret[key] )
        return raw_secrets


    def filldictcontextvalue( self, authinfo, userinfo, desktop, network_config, network_name=None, appinstance_id=None ):

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

    def countRunningAppforUser( self, authinfo, userinfo, myDesktop):
        self.logger.debug('')
        count = 0
        for appinstance in self.appinstance_classes.values() :
            myappinstance = appinstance( self )
            count += len( myappinstance.list(authinfo, userinfo, myDesktop ) )
        return count

    def listContainerApps( self, authinfo, userinfo, myDesktop:ODDesktop, apps:ODApps ):
        self.logger.debug('')
        list_apps = []
        for appinstance in self.appinstance_classes.values() :
            myappinstance = appinstance( self )
            list_apps += myappinstance.list(authinfo, userinfo, myDesktop, phase_filter=self.all_phases_status, apps=apps)
        return list_apps

    def envContainerApp( self, authinfo, userinfo, pod_name, containerid):
        '''get the environment vars exec for the containerid '''
        # check that the pod belongs to use current user
        env_result = None
        myPod = self.kubeapi.read_namespaced_pod(namespace=self.namespace,name=pod_name)
        if isinstance( myPod, client.models.v1_pod.V1Pod ):
            # if type is x11server app is an ephemeral container
            pod_type = myPod.metadata.labels.get( 'type' )
            if pod_type == self.x11servertype:
                myappinstance = ODAppInstanceKubernetesEphemeralContainer( self )
                env_result = myappinstance.envContainerApp(pod_name, containerid)
            elif pod_type in self.appinstance_classes.keys() :
                myappinstance = ODAppInstanceKubernetesPod( self )
                env_result = myappinstance.envContainerApp(pod_name, containerid)
        return env_result

    def stopContainerApp( self, authinfo, userinfo, pod_name, containerid):
        stop_result = None
        myPod = self.kubeapi.read_namespaced_pod(namespace=self.namespace,name=pod_name)
        if isinstance( myPod, client.models.v1_pod.V1Pod ):
            # if type is x11server app is an ephemeral container
            pod_type = myPod.metadata.labels.get( 'type' )
            if pod_type == self.x11servertype:
                myappinstance = ODAppInstanceKubernetesEphemeralContainer( self )
                stop_result = myappinstance.stop(pod_name, containerid)
            elif pod_type in self.appinstance_classes.keys() :
                myappinstance = ODAppInstanceKubernetesPod( self )
                stop_result = myappinstance.stop(pod_name)
        return stop_result

    def removeContainerApp( self, authinfo, userinfo, pod_name, containerid):
        self.stopContainerApp( authinfo, userinfo, pod_name, containerid)

    def getappinstance( self, authinfo, userinfo, app ):    
        self.logger.debug('')

        for app_class in self.appinstance_classes.values():
            app_object = app_class( orchestrator=self )
            appinstance = app_object.findRunningAppInstanceforUserandImage( authinfo, userinfo, app )
            if app_object.isinstance( appinstance ):
                return appinstance


    def execininstance( self, container, command):
        self.logger.info('')

        if isinstance( container, client.models.v1_pod.V1Pod  ):
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

        
    def isenablecontainerinpod( self, authinfo, currentcontainertype):
        """isenablecontainerinpod
            read the desktop configuration
            and check if this currentcontainertype is allowed

        Args:
            authinfo (_type_): _description_
            currentcontainertype (str): type of container must be defined in list
            [ 'init', 'graphical', 'ssh', 'rdpgw', 'sound', 'printer', 'filter', 'storage' ]

        Returns:
            bool: True if enable, else False
        """
        bReturn =   isinstance(  oc.od.settings.desktop_pod.get(currentcontainertype), dict ) and \
                    oc.od.acl.ODAcl().isAllowed( authinfo, oc.od.settings.desktop_pod[currentcontainertype].get('acl') ) and \
                    oc.od.settings.desktop_pod[currentcontainertype].get('enable') == True
        return bReturn



    def createappinstance(self, myDesktop, app, authinfo, userinfo={}, userargs=None, **kwargs ):
        # containerengine can be one of the values
        # - 'ephemeral_container'
        # - 'pod_application'
        #
        # the default value is 'ephemeralcontainer'

        assert isinstance(myDesktop, ODDesktop),f"desktop has invalid type {type(myDesktop)}"
        assert isinstance(app,dict),            f"app has invalid type {type(app)}"
        assert isinstance(authinfo, AuthInfo),  f"authinfo has invalid type {type(authinfo)}"

        # "run_inside_pod": true,
        # read the container enigne specific value from app properties
        containerengine = app.get('containerengine', 'ephemeral_container' )
        if containerengine not in self.appinstance_classes.keys():
            raise ValueError( f"unknow containerengine value {containerengine} must be defined in {list(self.appinstance_classes.keys())}")
        appinstance_class = self.appinstance_classes.get(containerengine)
        appinstance = appinstance_class(self)
        appinstancestatus = appinstance.create(myDesktop, app, authinfo, userinfo, userargs, **kwargs )
        return appinstancestatus

    def pullimage_on_all_nodes(self, app):
        self.logger.info('')
        label_selector=oc.od.settings.desktop.get('nodeselector')
        listnode = self.kubeapi.list_node(label_selector=label_selector)
        self.logger.debug(listnode)
        if isinstance( listnode, client.models.v1_node_list.V1NodeList ):
            if len(listnode.items) < 1:
                self.logger.error( f"nodeselector={oc.od.settings.desktop.get('nodeselector')} return empty list" )
            for node in listnode.items :
                self.pullimage( app, node.metadata.name )


    def pullimage(self, app, nodename ):
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
            if isinstance( pod, client.models.v1_pod.V1Pod ):
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
        labels = { 'type': self.applicationtype }

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
                'containers': [ {   'name': podname,
                                    'imagePullPolicy': 'Always',
                                    'image': app['id'],
                                    'command': ['/bin/sleep'],
                                    'args': [ '42' ]
                                }                                                             
                ]
            }
        }

        pod = None
        try:
            pod = self.kubeapi.create_namespaced_pod(namespace=self.namespace,body=pod_manifest )
            if isinstance(pod, client.models.v1_pod.V1Pod ):
                self.logger.info( f"create_namespaced_pod pull image ask to run on {podname} return {pod.spec.hostname}" )
        except client.exceptions.ApiException as e:
             self.logger.error( e )
        except Exception as e:
            self.logger.error( e )

        return pod

    def alwaysgetPosixAccountUser(self, userinfo:AuthUser ) -> dict :
        """alwaysgetPosixAccountUser

        Args:
            userinfo (AuthUser): auth user info

        Returns:
            dict: posic account dict 
        """
        if userinfo.isPosixAccount():
            self.logger.debug("user is a posix account")
            posixuser = userinfo.getPosixAccount()
        else:
            self.logger.debug("user is not a posix account, use configuration default values")
            posixuser = AuthUser.getdefaultPosixAccount( 
                uid=oc.od.settings.getballoon_name(),
                uidNumber=oc.od.settings.getballoon_uid(),
                gidNumber=oc.od.settings.getballoon_gid(),
                homeDirectory=oc.od.settings.getballoon_homedirectory() 
            )
        return posixuser

    def updateSecurityContextWithUserInfo( self, currentcontainertype:str, userinfo:AuthUser ) -> dict:
        """updateSecurityContextWithUserInfo

        Args:
            currentcontainertype (str): type of container
            userinfo (AuthUser): auth user info

        Returns:
            dict: a securityContext dict with { 'runAsUser': UID , 'runAsGroup': GID }
        """
        securityContext = oc.od.settings.desktop_pod[currentcontainertype].get( 'securityContext', { 'runAsUser':  '{{ uidNumber }}', 'runAsGroup': '{{ gidNumber }}' } )
        runAsUser  = securityContext.get('runAsUser')
        runAsGroup = securityContext.get('runAsGroup')
        
        posixuser = self.alwaysgetPosixAccountUser( userinfo )
        #
        # replace runAsUser and runAsGroup by posix account values
        # if 'runAsUser' exist in configuration file
        #
        if isinstance( runAsUser, str ): 
            securityContext['runAsUser']  = int( chevron.render( runAsUser, posixuser ) )
        # if 'runAsGroup' exist in configuration file
        if isinstance( runAsGroup, str ): 
            securityContext['runAsGroup'] = int( chevron.render( runAsGroup, posixuser ) )
        return securityContext

    def getimagecontainerfromauthlabels( self, currentcontainertype, authinfo ):
        imageforcurrentcontainertype = None
        image = oc.od.settings.desktop_pod[currentcontainertype].get('image')
        if isinstance( image, str):
            imageforcurrentcontainertype = image
        elif isinstance( image, dict ):
            imageforcurrentcontainertype = image.get('default')
            labels = authinfo.get_labels()
            for k,v in labels.items():
                if image.get(k):
                    imageforcurrentcontainertype=v
                    break
        
        if imageforcurrentcontainertype is None:
            raise ValueError( f"invalid image type for {currentcontainertype} type={type(image)} data={image}")

        return imageforcurrentcontainertype


    @staticmethod
    def appendkubernetesfieldref(envlist):
        assert isinstance(envlist, list),  f"env has invalid type {type(envlist)}, list is expected"
        # kubernetes env formated dict
        '''
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
        '''
        envlist.append( { 'name': 'NODE_NAME',      'valueFrom': { 'fieldRef': { 'fieldPath':'spec.nodeName' } } } )
        envlist.append( { 'name': 'POD_NAME',       'valueFrom': { 'fieldRef': { 'fieldPath':'metadata.name' } } } )
        envlist.append( { 'name': 'POD_NAMESPACE',  'valueFrom': { 'fieldRef': { 'fieldPath':'metadata.namespace' } } } )
        envlist.append( { 'name': 'POD_IP',         'valueFrom': { 'fieldRef': { 'fieldPath':'status.podIP' } } } )


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
    def expandchevron_envdict( env: dict, posixuser:dict ):
        """expandchevron_envdict
            replace in chevron key
            desktop.envlocal :  {
                'UID'                   : '{{ uidNumber }}',
                'GID'                   : '{{ gidNumber }}',
                'LOGNAME'               : '{{ uid }}'
            }
            by posix account value or default user account values
        Args:
            env (dict): env var dict 
            posixuser (dict): posix accont dict 
        """
        assert isinstance(env, dict),  f"env has invalid type {type(env)}, dict is expected"
        assert isinstance(posixuser, dict),  f"posixuser has invalid type {type(posixuser)}, dict is expected"
        for k, v in env.items():
            new_value = chevron.render( v, posixuser )
            env[k] = new_value 

                
    def createdesktop(self, authinfo, userinfo, **kwargs):
        self.logger.info('')
        """createdesktop for the user
            create the user pod 

        Args:
            authinfo (AuthInfo): authentification data
            userinfo (AuthUser): user data 

        Raises:
            ValueError: [description]

        Returns:
            [type]: [description]
        """
        self.logger.debug('createdesktop start' )
        assert isinstance(authinfo, AuthInfo),  f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo, AuthUser),  f"userinfo has invalid type {type(userinfo)}"

        myDesktop       = None # default return object
        args     = kwargs.get('args')    
        command  = kwargs.get('command')
        env      = kwargs.get('env', {} )
        appname  = kwargs.get('appname')

        # add a new VNC Password to env var
        self.logger.debug('ODVncPassword creating')
        vnc_password = ODVncPassword()
        vnc_secret = oc.od.secret.ODSecretVNC( self.namespace, self.kubeapi )
        vnc_secret.create( authinfo, userinfo, data={ 'password' : vnc_password.getplain() } )
        self.logger.debug('ODVncPassword created')

        # building env
        # generate XAUTH key
        self.logger.debug('env creating')
        xauth_key = self.generate_xauthkey()
        env[ 'XAUTH_KEY' ] = xauth_key    
        # generate PULSEAUDIO cookie
        pulseaudio_cookie = self.generate_pulseaudiocookie()
        env[ 'PULSEAUDIO_COOKIE' ] = pulseaudio_cookie    
        # generate BROADCAST cookie
        broadcast_cookie = self.generate_broadcastcookie()
        env[ 'BROADCAST_COOKIE' ] = broadcast_cookie 
        # add user 
        env[ 'USER' ] = userinfo.userid
        env[ 'LOGNAME' ] = userinfo.userid
        self.logger.debug('env created')

        self.logger.debug('labels creating')
        # build label dictionnary
        labels = {  'access_providertype':  authinfo.providertype,
                    'access_provider':  authinfo.provider,
                    'access_userid':    userinfo.userid,
                    'access_username':  self.get_labelvalue(userinfo.name),
                    'domain':           self.endpoint_domain,
                    'netpol/ocuser' :   'true',
                    'xauthkey':          xauth_key, 
                    'pulseaudio_cookie': pulseaudio_cookie,
                    'broadcast_cookie':  broadcast_cookie }

        # add authinfo labels
        for k,v in authinfo.get_labels().items():
            abcdesktopvarenvname = oc.od.settings.ENV_PREFIX_LABEL_NAME + k.lower()
            env[ abcdesktopvarenvname ] = v
            labels[k] = v

        for currentcontainertype in self.nameprefixdict.keys() :
            if self.isenablecontainerinpod( authinfo, currentcontainertype ):
                abcdesktopvarenvname = oc.od.settings.ENV_PREFIX_SERVICE_NAME + currentcontainertype
                env[ abcdesktopvarenvname ] = 'enabled'
    
        # check if we run the desktop in metappli mode or desktop mode
        if type(appname) is str :
            # if appname is set then create a metappli labels
            # this will change and run the app
            labels[ 'type' ]  = self.x11servertype_embeded
            kwargs[ 'type' ]  = self.x11servertype_embeded
            # this is specific to metappli mode
            labels[ 'appname' ] = appname
        else:
            # if appname is None then create a desktop
            # set value as default type x11servertype
            labels[ 'type' ]  = self.x11servertype
            kwargs[ 'type' ]  = self.x11servertype

        self.logger.debug('labels created')

        myuuid = str(uuid.uuid4())
        pod_name = self.get_podname( authinfo, userinfo, myuuid ) 
        self.logger.debug('pod name is %s', pod_name )
        container_graphical_name = self.get_graphicalcontainername( userinfo.userid, myuuid )         
        self.logger.debug('container_graphical_name is %s', container_graphical_name )

        self.logger.debug('envlist creating')
        posixuser = self.alwaysgetPosixAccountUser( userinfo )
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
        self.logger.debug('rules is defined %s', str(rules))
        network_config = ODOrchestrator.applyappinstancerules_network( authinfo, rules )
        fillednetworkconfig = self.filldictcontextvalue(authinfo=authinfo, 
                                                        userinfo=userinfo, 
                                                        desktop=None, 
                                                        network_config=copy.deepcopy(network_config), 
                                                        network_name = None, 
                                                        appinstance_id = None )
        self.logger.debug('rules created')

        self.on_desktoplaunchprogress('b.Building data storage for your desktop')


        self.logger.debug('secrets_requirement creating for graphical')
        currentcontainertype = 'graphical'
        secrets_requirement = None # default value add all secret if no filter 
        # get all secrets
        mysecretdict = self.list_dict_secret_data( authinfo, userinfo )
        # by default give the abcdesktop/kerberos and abcdesktop/cntlm secrets inside the pod, if exist
        secrets_type_requirement = oc.od.settings.desktop_pod[currentcontainertype].get('secrets_requirement',[])
        if isinstance( secrets_type_requirement, list ):
            # list the secret entry by requirement type 
            secrets_requirement = ['abcdesktop/vnc'] # always add the vnc password in the secret list 
            for secretdictkey in mysecretdict.keys():
                if mysecretdict.get(secretdictkey,{}).get('type') in secrets_type_requirement:
                    secrets_requirement.append( secretdictkey )
        else:
            raise ValueError( f"invalid secrets_requirement type={type(secrets_type_requirement)} it must be a list")
        self.logger.debug('secrets_requirement created for graphcial')

        self.logger.debug('volumes creating')
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
            self.logger.debug('pod container creating %s', currentcontainertype )
            securityContext = oc.od.settings.desktop_pod[currentcontainertype].get('securityContext',  { 'runAsUser': 0 } )
            self.logger.debug('pod container %s use securityContext %s ', currentcontainertype, securityContext)
                
            image = self.getimagecontainerfromauthlabels( currentcontainertype, authinfo )  
                
            initContainers.append( {    'name':             self.get_containername( currentcontainertype, userinfo.userid, myuuid ),
                                        'imagePullPolicy':  oc.od.settings.desktop_pod[currentcontainertype].get('pullpolicy'),
                                        'image':            image,       
                                        'command':          oc.od.settings.desktop_pod[currentcontainertype].get('command'),
                                        'volumeMounts':     list_volumeMounts,
                                        'env':              envlist,
                                        'securityContext':  securityContext
            } )
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

        for currentcontainertype in oc.od.settings.desktop_pod.keys() :
            if self.isenablecontainerinpod( authinfo, currentcontainertype ):
                label_servicename = 'service_' + currentcontainertype
                # tcpport is a number, convert it as str for a label value
                label_value = str( oc.od.settings.desktop_pod[currentcontainertype].get('tcpport','enabled') )
                labels.update( { label_servicename: label_value } )



        currentcontainertype = 'graphical'
        self.logger.debug('pod container creating %s', currentcontainertype )
        securityContext = self.updateSecurityContextWithUserInfo( currentcontainertype, userinfo )
        image = self.getimagecontainerfromauthlabels( currentcontainertype, authinfo )
        
        # define pod_manifest
        pod_manifest = {
            'apiVersion': 'v1',
            'kind': 'Pod',
            'metadata': {
                'name': pod_name,
                'namespace': self.namespace,
                'labels': labels,
                'annotations': annotations
            },
            'spec': {
                'dnsPolicy' : dnspolicy,
                'dnsConfig' : dnsconfig,
                'automountServiceAccountToken': False,  # disable service account inside pod
                'subdomain': self.endpoint_domain,
                'shareProcessNamespace': True, # oc.od.settings.desktop_pod[currentcontainertype].get('shareProcessNamespace'),
                'volumes': list_pod_allvolumes,                    
                'nodeSelector': oc.od.settings.desktop.get('nodeselector'), 
                'initContainers': initContainers,
                'containers': [ {   'imagePullPolicy': oc.od.settings.desktop_pod[currentcontainertype].get('imagePullPolicy'),
                                    'image': image,
                                    'name': self.get_containername( currentcontainertype, userinfo.userid, myuuid ),
                                    'command': command,
                                    'args': args,
                                    'env': envlist,
                                    'imagePullSecrets': oc.od.settings.desktop_pod[currentcontainertype].get('imagePullSecrets'),
                                    'volumeMounts': list_volumeMounts,
                                    'securityContext': securityContext,
                                    'resources': oc.od.settings.desktop_pod[currentcontainertype].get('resources')
                                }                                                             
                ]
            }
        }
        self.logger.debug('pod container created %s', currentcontainertype )

        # by default remove Anonymous home directory at stop or if oc.od.settings.desktop['removehomedirectory']
        if oc.od.settings.desktop['removehomedirectory'] is True or userinfo.name == 'Anonymous':
            pod_manifest['spec']['containers'][0]['lifecycle'] = {  
                'preStop': {
                    'exec': { 'command':  [ "/bin/bash", "-c", "rm -rf " + oc.od.settings.getballoon_homedirectory() + "/*" ] }
                }   
        }
          
        # Add printer sound servives 
        for currentcontainertype in [ 'printer' ] :
            if  self.isenablecontainerinpod( authinfo, currentcontainertype ):
                self.logger.debug('pod container creating %s', currentcontainertype )
                image = self.getimagecontainerfromauthlabels( currentcontainertype, authinfo ) 
                securityContext = self.updateSecurityContextWithUserInfo( currentcontainertype, userinfo )
                pod_manifest['spec']['containers'].append( { 
                        'name': self.get_containername( currentcontainertype, userinfo.userid, myuuid ),
                        'imagePullPolicy':  oc.od.settings.desktop_pod[currentcontainertype].get('pullpolicy'),
                        'image':image,                                    
                        'env': envlist,
                        'volumeMounts': [ self.default_volumes_mount['tmp'] ],
                        'securityContext': securityContext,
                        'resources': oc.od.settings.desktop_pod[currentcontainertype].get('resources')                             
                    }   
                )
                self.logger.debug('pod container created %s', currentcontainertype )

              # Add printer sound servives 
        for currentcontainertype in [ 'sound' ] :
            if  self.isenablecontainerinpod( authinfo, currentcontainertype ):
                self.logger.debug('pod container creating %s', currentcontainertype )
                image = self.getimagecontainerfromauthlabels( currentcontainertype, authinfo ) 
                securityContext = self.updateSecurityContextWithUserInfo( currentcontainertype, userinfo  )
                pod_manifest['spec']['containers'].append( { 
                        'name': self.get_containername( currentcontainertype, userinfo.userid, myuuid ),
                        'imagePullPolicy':  oc.od.settings.desktop_pod[currentcontainertype].get('pullpolicy'),
                        'image':image,                                    
                        'env': envlist,
                        'volumeMounts': [ self.default_volumes_mount['tmp'] ],
                        'securityContext': securityContext,
                        'resources': oc.od.settings.desktop_pod[currentcontainertype].get('resources')                             
                    }   
                )
                self.logger.debug('pod container created %s', currentcontainertype )

        # Add ssh service 
        currentcontainertype = 'ssh'
        if  self.isenablecontainerinpod( authinfo, currentcontainertype ):
            self.logger.debug('pod container creating %s', currentcontainertype )
            securityContext = self.updateSecurityContextWithUserInfo( currentcontainertype, userinfo )
            image = self.getimagecontainerfromauthlabels( currentcontainertype, authinfo ) 
            pod_manifest['spec']['containers'].append( { 
                                    'name': self.get_containername( currentcontainertype, userinfo.userid, myuuid ),
                                    'imagePullPolicy':  oc.od.settings.desktop_pod[currentcontainertype].get('pullpolicy'),
                                    'image': image,                                    
                                    'env': envlist,
                                    'securityContext': securityContext,
                                    'volumeMounts': list_volumeMounts,
                                    'resources': oc.od.settings.desktop_pod[currentcontainertype].get('resources')                             
                                }   
            )
            self.logger.debug('pod container created %s', currentcontainertype )

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
            securityContext = self.updateSecurityContextWithUserInfo( currentcontainertype, userinfo )
            image = self.getimagecontainerfromauthlabels( currentcontainertype, authinfo ) 
            pod_manifest['spec']['containers'].append( { 
                                    'name': self.get_containername( currentcontainertype, userinfo.userid, myuuid ),
                                    'imagePullPolicy':  oc.od.settings.desktop_pod[currentcontainertype].get('pullpolicy'),
                                    'image': image,                                  
                                    'env': envlist,
                                    'volumeMounts': list_volumeMounts,
                                    'securityContext': securityContext,
                                    'resources': oc.od.settings.desktop_pod[currentcontainertype].get('resources')                                      
                                }   
            )
            self.logger.debug('pod container created %s', currentcontainertype )

        # Add storage service 
        currentcontainertype = 'storage'
        if  self.isenablecontainerinpod( authinfo, currentcontainertype ):
            self.logger.debug('pod container creating %s', currentcontainertype )
            securityContext = self.updateSecurityContextWithUserInfo( currentcontainertype, userinfo )
            image = self.getimagecontainerfromauthlabels( currentcontainertype, authinfo ) 
            pod_manifest['spec']['containers'].append( { 
                                    'name': self.get_containername( currentcontainertype, userinfo.userid, myuuid ),
                                    'imagePullPolicy': oc.od.settings.desktop_pod[currentcontainertype].get('pullpolicy'),
                                    'image': image,                                 
                                    'env': envlist,
                                    'volumeMounts':  list_pod_allvolumeMounts,
                                    'securityContext': securityContext,
                                    'resources': oc.od.settings.desktop_pod[currentcontainertype].get('resources')                      
                                }   
            )
            self.logger.debug('pod container created %s', currentcontainertype )

        # Add rdp service 
        currentcontainertype = 'rdp'
        if  self.isenablecontainerinpod( authinfo, currentcontainertype ):
            self.logger.debug('pod container creating %s', currentcontainertype )
            securityContext = self.updateSecurityContextWithUserInfo( currentcontainertype, userinfo )
            image = self.getimagecontainerfromauthlabels( currentcontainertype, authinfo ) 
            pod_manifest['spec']['containers'].append( { 
                                    'name': self.get_containername( currentcontainertype, userinfo.userid, myuuid ),
                                    'imagePullPolicy': oc.od.settings.desktop_pod[currentcontainertype].get('pullpolicy'),
                                    'image': image, 
                                    'securityContext': securityContext,                                
                                    'env': envlist,
                                    'volumeMounts':  list_volumeMounts,
                                    'resources': oc.od.settings.desktop_pod[currentcontainertype].get('resources')                      
                                }   
            )
            self.logger.debug('pod container created %s', currentcontainertype )

        # if metapply stop, do not restart the pod 
        if kwargs[ 'type' ] == self.x11servertype_embeded :
            pod_manifest['spec']['restartPolicy'] = 'Never'

        # we are ready to create our Pod 
        myDesktop = None
        self.on_desktoplaunchprogress('b.Creating your desktop')
        self.logger.info( 'dump yaml %s', json.dumps( pod_manifest, indent=2 ) )
        pod = self.kubeapi.create_namespaced_pod(namespace=self.namespace,body=pod_manifest )

        if not isinstance(pod, client.models.v1_pod.V1Pod ):
            self.on_desktoplaunchprogress('e.Create Pod failed.' )
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
                self.logger.error( 'event type is %s, and should be a dict, skipping event', type(event) )
                continue

            event_object = event.get('object')
            if not isinstance(event_object, client.models.core_v1_event.CoreV1Event ):
                self.logger.error( 'event_object type is %s skipping event waiting for kubernetes.client.models.core_v1_event.CoreV1Event', type(event_object))
                continue

            # Valid values for event types (new types could be added in future)
            #    EventTypeNormal  string = "Normal"     // Information only and will not cause any problems
            #    EventTypeWarning string = "Warning"    // These events are to warn that something might go wrong
            object_type = event_object.type
            self.logger.info( f"object_type={object_type} reason={event_object.reason}")

            if isinstance(event_object.message, str) and len(event_object.message)>0:
                message = f"{object_type.lower()} {event_object.reason} {event_object.message}"
            else:
                message = f"b.{event_object.reason}"
                
            self.logger.info(message)
            self.on_desktoplaunchprogress( message )

            if object_type == 'Warning':
                # These events are to warn that something might go wrong
                self.logger.warning( f"something might go wrong object_type={object_type} reason={event_object.reason} message={event_object.message}")
                self.on_desktoplaunchprogress( f"b.something might go wrong {object_type} reason={event_object.reason} message={event_object.message}" )
                w.stop()
                continue

            if object_type == 'Normal' and event_object.reason == 'Started' :
                # add number_of_container_started counter 
                number_of_container_started += 1
                self.on_desktoplaunchprogress( f"b.Waiting for containers {number_of_container_started}/{number_of_container_to_start}" )
                # if the number of container to start is expected, all containers should be started 
                if number_of_container_started >= number_of_container_to_start:
                    w.stop() # do not wait any more
                    continue

                myPod = self.kubeapi.read_namespaced_pod(namespace=self.namespace,name=pod_name)  
                # check if the graphical container is started
                for c in myPod.status.container_statuses:
                    # look only for for the ontainer_graphical_name
                    if c.name == container_graphical_name:
                        if c.started is True :
                            startedmsg =  f"b.{c.name} is started" 
                            self.logger.debug( startedmsg )
                            self.on_desktoplaunchprogress( startedmsg )
                        if c.ready is True :
                            # the graphical container is ready 
                            # do not wait for other containers
                            readymsg = f"b.{c.name} is ready"
                            self.logger.debug( readymsg )
                            self.on_desktoplaunchprogress( readymsg )
                            w.stop()

        self.logger.debug( f"watch list_namespaced_event pod created object_type={object_type}")
        #if object_type == 'Warning':
        #    self.logger.warning( f"object_type is warning {message}")
        #    # can occurs for example
        #    # - failed to sync secret cache: time out waiting for the condition
        #    # try to continue 
           
    
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
            # if podevent type must be a client.models.v1_pod.V1Pod, we use kubeapi.list_namespaced_pod
            if not isinstance( pod_event, client.models.v1_pod.V1Pod ) :  
                # pod_event is not a client.models.v1_pod.V1Pod :
                # something go wrong  
                w.stop()
                continue

            self.on_desktoplaunchprogress( f"b.Your {pod_event.kind} is {event_type.lower()} " )    
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
            if pod_event.status.phase != 'Pending' :
                # pod data object is complete, stop reading event
                # phase can be 'Running' 'Succeeded' 'Failed' 'Unknown'
                self.logger.debug(f"The pod is not in Pending phase, phase={pod_event.status.phase} stop watching" )
                w.stop()
            else:
                self.logger.debug(f"The pod is in phase={pod_event.status.phase} continue for watching events" )
        self.logger.debug('watch list_namespaced_pod created, the pod is no more in Pending phase' )

        # read pod again
        self.logger.debug('watch read_namespaced_pod creating' )
        myPod = self.kubeapi.read_namespaced_pod(namespace=self.namespace,name=pod_name)    
        self.logger.info( f"myPod.metadata.name {myPod.metadata.name} is {myPod.status.phase} with ip {myPod.status.pod_ip}" )
        # The pod is not in Pending
        # read the status.phase, if it's not Running 
        if myPod.status.phase != 'Running':
            # something wrong 
            return f"Your pod does not start, status is {myPod.status.phase} reason is {myPod.status.reason} message {myPod.status.message}" 
        else:
            # At least one container is running,
            self.on_desktoplaunchprogress("b.Your pod is running.")   

        myDesktop = self.pod2desktop( pod=myPod, userinfo=userinfo)
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

  
    
    def findPodByUser(self, authinfo, userinfo ):
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
            V1Pod: kubernetes.client.models.v1_pod.V1Pod or None if not found
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

            if isinstance(myPodList, client.models.v1_pod_list.V1PodList) :
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

    def findPodAppByUser(self, authinfo, userinfo, appname ):
        """findPodAppByUser find an application pod by user
            filter use type=self.x11servertype_embeded only
        Args:
            authinfo (AuthInfo): authentification data
            userinfo (AuthUser): user data 
            appname (str): name of the application

        Returns:
            V1Pod: kubernetes.client.models.v1_pod.V1Pod or None if not found
        """
        self.logger.info('')
        assert isinstance(authinfo, AuthInfo),  f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo, AuthUser),  f"userinfo has invalid type {type(userinfo)}"

        access_userid = userinfo.userid
        access_provider = authinfo.provider

        try: 
            label_selector= 'access_userid='    + access_userid + \
                            ',type='            + self.x11servertype_embeded + \
                            ',appname='         + appname

            if oc.od.settings.desktop['authproviderneverchange'] is True:
                label_selector += f",access_provider={access_provider}"

            myPodList = self.kubeapi.list_namespaced_pod(self.namespace, label_selector=label_selector)

            if isinstance(myPodList, client.models.v1_pod_list.V1PodList) :
                for myPod in myPodList.items:
                    myPhase = myPod.status.phase
                    if myPod.metadata.deletion_timestamp is not None:
                       myPhase = 'Terminating'
                    if myPhase in [ 'Running', 'Pending', 'Succeeded' ] :  # 'Init:0/1'
                        return myPod
                    
        except ApiException as e:
            self.logger.info("Exception when calling CoreV1Api->read_namespaced_pod: %s\n" % e)

        return None

    def is_a_pod( self, pod ):
        return isinstance(pod, client.models.v1_pod.V1Pod )

    def is_a_dekstop( self, desktop ):
        return isinstance(desktop, ODDesktop )


    def isPodBelongToUser( self, authinfo, userinfo, pod_name ):
        self.logger.debug('')
        assert isinstance(authinfo, AuthInfo),  f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo, AuthUser),  f"userinfo has invalid type {type(userinfo)}"
        assert isinstance(pod_name,  str),      f"pod_name has invalid type {type(pod_name)}"

        belong = False
        myPod = self.kubeapi.read_namespaced_pod(namespace=self.namespace,name=pod_name )
        if isinstance( myPod, client.models.v1_pod.V1Pod ):
            (pod_authinfo,pod_userinfo) = self.extract_userinfo_authinfo_from_pod(myPod)

        if  authinfo.provider == pod_authinfo.provider and \
            userinfo.userid   == pod_userinfo.userid :
            belong = True

        return belong


    def findDesktopByUser(self, authinfo, userinfo, **kwargs ):
        ''' find a desktop for authinfo and userinfo '''
        ''' return a desktop object '''
        ''' return None if not found '''
        self.logger.info( '' )
        assert isinstance(authinfo, AuthInfo),  f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo, AuthUser),  f"userinfo has invalid type {type(userinfo)}"
        
        myDesktop = None  # return Desktop Object
        appname=kwargs.get('appname')

        if isinstance(appname,str) and len(appname) > 0  :
            myPod = self.findPodAppByUser( authinfo, userinfo, appname )
        else :
            myPod = self.findPodByUser( authinfo, userinfo )

        if isinstance(myPod, client.models.v1_pod.V1Pod ):
            self.logger.info( 'Pod is found %s ', myPod.metadata.name )
            myDesktop = self.pod2desktop( pod=myPod, userinfo=userinfo )
        return myDesktop

    def getcontainerfromPod( self,  prefix:str, pod:client.models.v1_pod.V1Pod ):
        assert isinstance(pod,      client.models.v1_pod.V1Pod),    f"pod has invalid type {type(pod)}"
        assert isinstance(prefix,   str),                           f"prefix has invalid type {type(prefix)}"

        # get the container id for the desktop object
        for c in pod.status.container_statuses:
            if hasattr( c, 'name') and c.name[0] == prefix:
                return c
        return None


    def build_internalPodFQDN( self, myPod ):
        ''' Describe how to reach a pod '''
        ''' When http request '''

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

    def pod2desktop( self, pod:client.models.v1_pod.V1Pod, userinfo=None ):
        """pod2Desktop convert a Pod to Desktop Object
        Args:
            myPod ([V1Pod): kubernetes.client.models.v1_pod.V1Pod
            userinfo ([]): userinfo set to None by default
                           to obtain vnc_password, defined userinfo context 
        Returns:
            [ODesktop]: oc.od.desktop.ODDesktop Desktop Object
        """
        assert isinstance(pod,      client.models.v1_pod.V1Pod),    f"pod has invalid type {type(pod)}"

        desktop_container_id   = None
        storage_container_id   = None
        desktop_container_name = None
        desktop_interfaces     = None

        # read metadata annotations 'k8s.v1.cni.cncf.io/networks-status'
        network_status = None
        if isinstance(pod.metadata.annotations, dict):
            network_status = pod.metadata.annotations.get( 'k8s.v1.cni.cncf.io/networks-status' )

            if isinstance( network_status, str ):
                # k8s.v1.cni.cncf.io/networks-status is set
                # load json formated string
                network_status_json = json.loads( network_status )
            if isinstance( network_status, list ):
                desktop_interfaces = {}
                for interface in network_status_json :
                    if not isinstance( interface, dict ):
                        continue

                    name = interface.get('interface')
                    ips = interface.get('ips')
                    mac = interface.get('mac')
                    # check if type is valid
                    if  not isinstance( ips, list ) or not isinstance( name, str ) or not isinstance( mac, str ) :
                        # skipping bad data type
                        continue
                    if len(ips) == 1: ips = ips[0]
                    desktop_interfaces.update( { name : { 'mac': mac, 'ips': str(ips) } } )

       
        desktop_container = self.getcontainerfromPod( self.graphicalcontainernameprefix, pod )
        if desktop_container :
            desktop_container_id = desktop_container.container_id
            desktop_container_name = desktop_container.name
        
        internal_pod_fqdn = self.build_internalPodFQDN( pod )

        # read the vnc password from kubernetes secret
        vnc_password = None
        if isinstance( userinfo, AuthUser ):
            vnc_secret = oc.od.secret.ODSecretVNC( self.namespace, self.kubeapi )
            vnc_secret_password = vnc_secret.read( userinfo )  
            if isinstance( vnc_secret_password, client.models.v1_secret.V1Secret ):
                vnc_password = oc.od.secret.ODSecret.read_data( vnc_secret_password, 'password' )

     
        storage_container = self.getcontainerfromPod( self.storagecontainernameprefix, pod )
        if isinstance(storage_container, client.models.v1_container_status.V1ContainerStatus) :
           storage_container_id = storage_container.container_id

        # Build the ODDesktop Object 
        myDesktop = oc.od.desktop.ODDesktop(    nodehostname=pod.spec.node_name, 
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
                                                labels = pod.metadata.labels )
        return myDesktop

    def countdesktop(self):        
        ''' return the number count of pod type 'type=' + self.x11servertype    '''
        ''' return 0 if failed ( not the best return value )                    ''' 
        nCount = 0   
        try: 
            list_label_selector = [ 'type=' + self.x11servertype, 'type=' + self.x11servertype_embeded ]
            for label_selector in list_label_selector:
                myPodList = self.kubeapi.list_namespaced_pod(self.namespace, label_selector=label_selector)
                nCount = nCount + len(myPodList.items)                    
        except ApiException as e:
            self.logger.error(e)
        return nCount

    def list_desktop(self):
        myDesktopList = []   
        try:  
            list_label_selector = 'type=' + self.x11servertype
            myPodList = self.kubeapi.list_namespaced_pod(self.namespace, label_selector=list_label_selector)
            if isinstance( myPodList,  client.models.v1_pod_list.V1PodList):
                for myPod in myPodList.items:
                        mydesktop = self.pod2desktop( myPod )
                        myDesktopList.append( mydesktop.to_dict() )              
        except ApiException as e:
            self.logger.error(e)

        return myDesktopList
            
    def isgarbagable( self, pod:client.models.v1_pod.V1Pod, expirein:int, force=False ):
        """isgarbagable

        Args:
            pod (client.models.v1_pod.V1Pod): pod
            expirein (int): in seconds
            force (bool, optional): check if user is connected or not. Defaults to False.

        Returns:
            boot: True if pod is garbageable
        """

        bReturn = False

        assert isinstance(pod,      client.models.v1_pod.V1Pod),    f"pod has invalid type {type(pod)}"
        assert isinstance(expirein, int),                           f"expirein has invalid type {type(expirein)}"

        myDesktop = self.pod2desktop( pod=pod )
        if not isinstance(myDesktop, ODDesktop):
            return False

        if force is False:
            nCount = self.user_connect_count( myDesktop )
            if nCount < 0: # if something wrong do not garbage this pod
                return bReturn 
            if nCount > 0 : # if a user is connected do not garbage this pod
                return bReturn 

        # read the lastlogin datetime from metadata annotations
        lastlogin_datetime = self.read_pod_annotations_lastlogin_datetime( pod )
        if isinstance( lastlogin_datetime, str):
            # get the current time
            now_datetime = datetime.datetime.now()
            delta_datetime = now_datetime - lastlogin_datetime
            delta_second = delta_datetime.total_seconds()
            # if delta_second is more than expirein in second
            if ( delta_second > expirein  ):
                # this pod is gabagable
                bReturn = True
        return bReturn


    def extract_userinfo_authinfo_from_pod( self, pod:client.models.v1_pod.V1Pod ):
        """extract_userinfo_authinfo_from_pod
            Read labels (authinfo,userinfo) from a pod
        Args:
            myPod (V1Pod): Pod

        Returns:
            (tuple): (authinfo,userinfo) AuthInfo, AuthUser
        """
        assert isinstance(pod,      client.models.v1_pod.V1Pod),    f"pod has invalid type {type(pod)}"

        # fake an authinfo object
        authinfo = AuthInfo( provider=pod.metadata.labels.get('access_provider') )
        # fake an userinfo object
        userinfo = AuthUser( {
            'userid':pod.metadata.labels.get('access_userid'),
            'name':  pod.metadata.labels.get('access_username')
        } )
        return (authinfo,userinfo)


    def find_userinfo_authinfo_by_desktop_name( self, name:str ):
        self.logger.debug('')
        assert isinstance(name, str), f"name has invalid type {type(str)}"
        authinfo = None
        userinfo = None
        myPod = self.kubeapi.read_namespaced_pod(namespace=self.namespace,name=name )
        if isinstance( myPod, client.models.v1_pod.V1Pod ) :  
            (authinfo,userinfo) = self.extract_userinfo_authinfo_from_pod(myPod)
        return (authinfo,userinfo)

    def describe_desktop_byname( self, name:str ):
        """describe_desktop_byname

        Args:
            name (str): name of the desktop (pod)

        Returns:
            dict: dict of the desktop's pod
        """
        self.logger.debug('')
        assert isinstance(name, str), f"name has invalid type {type(str)}"
        myPod = self.kubeapi.read_namespaced_pod(namespace=self.namespace,name=name, _preload_content=False)
        if isinstance( myPod, urllib3.response.HTTPResponse ) :  
            myPod = json.loads( myPod.data )
        return myPod

    def garbagecollector( self, expirein:int, force=False ):
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
            if isinstance( myPodList,  client.models.v1_pod_list.V1PodList):
                for myPod in myPodList.items:
                    try: 
                        myPodisgarbagable = self.isgarbagable( myPod, expirein, force ) 
                        self.logger.debug(  f"pod {myPod.metadata.name} is garbageable {myPodisgarbagable}" )
                        if myPodisgarbagable is True:
                            self.logger.debug( f"{myPod.metadata.name} is garbagable, removing start" )
                            # fake an authinfo object
                            (authinfo,userinfo) = self.extract_userinfo_authinfo_from_pod(myPod)
                            self.removedesktop( authinfo, userinfo, myPod )
                            self.logger.debug( f"{myPod.metadata.name} is garbagable, removing done" )
                            # add the name of the pod to the list of garbaged pod
                            garbaged.append( myPod.metadata.name )
                    except ApiException as e:
                        self.logger.error(e)
        return garbaged


@oc.logging.with_logger()
class ODAppInstanceBase(object):
    def __init__(self,orchestrator):
        self.orchestrator = orchestrator

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

        # read locale language from USER AGENT
        language        = userinfo.get('locale', 'en_US')
        lang            = language + '.UTF-8'

        # make sure env DISPLAY, PULSE_SERVER,CUPS_SERVER exist
        desktop_ip_addr = myDesktop.get_default_ipaddr('eth0')

        env = oc.od.settings.desktop['environmentlocal'].copy()
        env.update( {   'DISPLAY': self.get_DISPLAY(desktop_ip_addr),
                        'CONTAINER_IP_ADDR': desktop_ip_addr,   # CONTAINER_IP_ADDR is used by ocrun node js command
                        'XAUTH_KEY': myDesktop.xauthkey,
                        'BROADCAST_COOKIE': myDesktop.broadcast_cookie,
                        'PULSEAUDIO_COOKIE': myDesktop.pulseaudio_cookie,
                        'PULSE_SERVER':  self.get_PULSE_SERVER(desktop_ip_addr),
                        'CUPS_SERVER':  self.get_CUPS_SERVER(desktop_ip_addr),
                        'UNIQUERUNKEY' : app.get('uniquerunkey')
                    }
        )

        #
        # update env with cuurent http request user LANG values
        env.update ( {  'LANGUAGE'	    : language,
                        'LANG'		    : lang,
                        'LC_ALL'        : lang,
                        'LC_PAPER'	    : lang,
                        'LC_ADDRESS'    : lang,
                        'LC_MONETARY'   : lang,
                        'LC_TIME'	    : lang,
                        'LC_MEASUREMENT': lang,
                        'LC_TELEPHONE'  : lang,
                        'LC_NUMERIC'    : lang,
                        'LC_IDENTIFICATION' : lang,
                        'PARENT_ID' 	    : myDesktop.id,
                        'PARENT_HOSTNAME'   : myDesktop.nodehostname
                    }
        )

        # Add specific vars
        if isinstance( kwargs, dict ):
            timezone = kwargs.get('timezone')
            if isinstance(timezone, str) and len(timezone) > 1:
                env['TZ'] = timezone
        if isinstance(userargs, str) and len(userargs) > 0:
            env['APPARGS'] = userargs
        if hasattr(authinfo, 'data') and isinstance( authinfo.data, dict ):
            env.update(authinfo.data.get('environment', {}))

        self.logger.debug('envlist creating')
        posixuser = self.orchestrator.alwaysgetPosixAccountUser( userinfo )
        # replace  'UID' : '{{ uidNumber }}' by value 
        ODOrchestratorKubernetes.expandchevron_envdict( env, posixuser )

        # convert env dictionnary to env list format for kubernetes
        envlist = ODOrchestratorKubernetes.envdict_to_kuberneteslist( env )
        ODOrchestratorKubernetes.appendkubernetesfieldref( envlist )
        
        return envlist

    def get_securitycontext(self, userinfo ):
        securitycontext = self.orchestrator.updateSecurityContextWithUserInfo( self.type, userinfo )
        return securitycontext

@oc.logging.with_logger()
class ODAppInstanceKubernetesEphemeralContainer(ODAppInstanceBase):

    def __init__(self, orchestrator):
        super().__init__(orchestrator)
        self.type = self.orchestrator.ephemeral_container

    @staticmethod
    def isinstance( ephemeralcontainer ):
        bReturn =   isinstance( ephemeralcontainer, client.models.v1_pod.V1Pod ) or \
                    isinstance( ephemeralcontainer, client.models.v1_container_state.V1ContainerState ) or \
                    isinstance( ephemeralcontainer, client.models.v1_container_status.V1ContainerStatus )
        return bReturn

    def get_DISPLAY(  self, desktop_ip_addr:str='' ):
        return ':0.0'

    def get_PULSE_SERVER(  self, desktop_ip_addr:str='' ):
        return  '/tmp/.pulse.sock'

    def get_CUPS_SERVER(  self, desktop_ip_addr:str='' ):
        return '/tmp/.cups.sock'

    def envContainerApp(self, pod_name, container_name):
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
        assert isinstance(pod_name,  str),  f"pod_name has invalid type  {type(pod_name)}"
        assert isinstance(container_name,  str),  f"container_name has invalid type {type(container_name)}"
        env_result = None
        pod_ephemeralcontainers =  self.orchestrator.kubeapi.read_namespaced_pod_ephemeralcontainers(name=pod_name, namespace=self.orchestrator.namespace )
        if not isinstance(pod_ephemeralcontainers, client.models.v1_pod.V1Pod ):
            raise ValueError( 'Invalid read_namespaced_pod_ephemeralcontainers')

        if isinstance(pod_ephemeralcontainers.spec.ephemeral_containers, list):
            for c in pod_ephemeralcontainers.spec.ephemeral_containers:
                if c.name == container_name :
                    env_result = {}
                    #  convert name= value= to dict
                    for e in c.env:
                        if isinstance( e, client.models.v1_env_var.V1EnvVar ):
                            env_result[ e.name ] =  e.value
                    break
        return env_result

    def get_status( self, pod_ephemeralcontainers:client.models.v1_pod.V1Pod, container_name:str ):
        """get_status

        Args:
            pod_ephemeralcontainers (client.models.v1_pod.V1Pod): pod_ephemeralcontainers
            container_name (str): name of the container to return

        Returns:
            _type_: _description_
        """
        assert isinstance(pod_ephemeralcontainers, client.models.v1_pod.V1Pod), f"pod_ephemeralcontainers has invalid type  {type(pod_ephemeralcontainers)}"
        assert isinstance(container_name,  str),  f"container_name has invalid type  {type(container_name)}"
        pod_ephemeralcontainer = None
        if isinstance(pod_ephemeralcontainers.status.ephemeral_container_statuses, list):
            for c in pod_ephemeralcontainers.status.ephemeral_container_statuses :
                if c.name == container_name:
                    pod_ephemeralcontainer = c
                    break
        return pod_ephemeralcontainer

    def get_phase( self, ephemeralcontainer:client.models.v1_container_status.V1ContainerStatus ):
        """get_phase
            return a Phase like as pod for ephemeral_container
            string 'Terminated' 'Running' 'Waiting' 'Error'
        Args:
            ephemeralcontainer (kubernetes.client.models.v1_container_status.V1ContainerStatus): V1ContainerStatus

        Returns:
            str: str phase of ephemeral_container status can be one of 'Terminated' 'Running' 'Waiting' 'Error'
        """
        text_state = 'Error' # defalut value shoud never be return

        if isinstance( ephemeralcontainer, client.models.v1_container_status.V1ContainerStatus ):
            if  isinstance(ephemeralcontainer.state.terminated, client.models.v1_container_state_terminated.V1ContainerStateTerminated ):
                text_state = 'Terminated'
            elif isinstance(ephemeralcontainer.state.running, client.models.v1_container_state_running.V1ContainerStateRunning ):
                text_state = 'Running'
            elif isinstance(ephemeralcontainer.state.waiting, client.models.v1_container_state_waiting.V1ContainerStateWaiting):
                text_state = 'Waiting'
        return text_state


    def stop(self, pod_name:str, container_name:str):
        self.logger.debug('')
        assert isinstance(pod_name,  str),  f"pod_name has invalid type  {type(pod_name)}"
        assert isinstance(container_name,  str),  f"container_name has invalid type  {type(container_name)}"

        pod_ephemeralcontainers =  self.orchestrator.kubeapi.read_namespaced_pod_ephemeralcontainers(name=pod_name, namespace=self.namespace )
        if not isinstance(pod_ephemeralcontainers, client.models.v1_pod.V1Pod ):
            raise ValueError( 'Invalid read_namespaced_pod_ephemeralcontainers')

        if isinstance(pod_ephemeralcontainers.spec.ephemeral_containers, list):
            for i in range( len(pod_ephemeralcontainers.spec.ephemeral_containers) ):
                if pod_ephemeralcontainers.spec.ephemeral_containers[i].name == container_name :
                    pod_ephemeralcontainers.spec.ephemeral_containers.pop(i)
                    break

        # replace ephemeralcontainers
        pod=self.orchestrator.kubeapi.patch_namespaced_pod_ephemeralcontainers(name=pod_name, namespace=self.namespace, body=pod_ephemeralcontainers )
        if not isinstance(pod, client.models.v1_pod.V1Pod ):
            raise ValueError( 'Invalid patch_namespaced_pod_ephemeralcontainers')

        stop_result = True

        return stop_result


    def list( self, authinfo, userinfo, myDesktop, phase_filter=[ 'Running', 'Waiting'], apps:ODApps=None ):
        self.logger.debug('')
        assert isinstance(myDesktop,  ODDesktop),  f"desktop has invalid type  {type(myDesktop)}"
        assert isinstance(authinfo,   AuthInfo),   f"authinfo has invalid type {type(authinfo)}"
        assert isinstance(userinfo,   AuthUser),   f"userinfo has invalid type {type(userinfo)}"
        assert isinstance(phase_filter, list),     f"phase_filter has invalid type {type(phase_filter)}"

        result = []
        pod_ephemeralcontainers =  self.orchestrator.kubeapi.read_namespaced_pod_ephemeralcontainers(name=myDesktop.id, namespace=self.orchestrator.namespace )
        if not isinstance(pod_ephemeralcontainers, client.models.v1_pod.V1Pod ):
            raise ValueError( 'Invalid read_namespaced_pod_ephemeralcontainers')

        if isinstance(pod_ephemeralcontainers.spec.ephemeral_containers, list):
            for c_spec in pod_ephemeralcontainers.spec.ephemeral_containers:
                c_status = self.get_status( pod_ephemeralcontainers, c_spec.name  )
                if isinstance( c_status, client.models.v1_container_status.V1ContainerStatus ):
                    phase = self.get_phase( c_status )
                    if phase in phase_filter:
                        app = apps.find_app_by_id( c_status.image ) if hasattr( apps, 'find_app_by_id' ) else {}
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
                        mycontainer['oc.displayname']   = c_status.name
                        mycontainer['runtime']          = 'kubernetes'
                        mycontainer['type']             = 'ephemeralcontainer'
                        mycontainer['status']           = phase

                        # add the object to the result array
                        result.append( mycontainer )

        return result


    def create(self, myDesktop, app, authinfo, userinfo={}, userargs=None, **kwargs ):
        self.logger.debug('')
        assert isinstance(myDesktop,  ODDesktop),  f"desktop has invalid type  {type(myDesktop)}"
        assert isinstance(authinfo,   AuthInfo),   f"authinfo has invalid type {type(authinfo)}"

        if kwargs.get('recurvise_counter', 0) > 5:
            self.logger.error( 'too much try to patch_namespaced_pod_ephemeralcontainers ')
            raise ODError( 'too much try to patch_namespaced_pod_ephemeralcontainers ')

        _app_container_name = self.orchestrator.get_normalized_username(userinfo.get('name', 'name')) + '_' + oc.auth.namedlib.normalize_imagename( str(app['name']) + '_' + str(uuid.uuid4().hex) )
        app_container_name =  oc.auth.namedlib.normalize_name_dnsname( _app_container_name )

        rules = app.get('rules' )

        self.logger.debug( f"reading pod desktop desktop={myDesktop.id} app_container_name={app_container_name}")
        envlist = self.get_env_for_appinstance(  myDesktop, app, authinfo, userinfo, userargs, **kwargs )

        (_volumebind, volumeMounts) = self.orchestrator.build_volumes( authinfo,
                                                        userinfo,
                                                        volume_type=self.type,
                                                        secrets_requirement=app.get('secrets_requirement'),
                                                        rules=rules,
                                                        **kwargs)

        list_volumeMounts = list( volumeMounts.values() )
        self.logger.debug( f"list volume pod desktop {list_volumeMounts}")

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
        
        securitycontext = self.get_securitycontext( userinfo=userinfo )

        body = client.models.V1EphemeralContainer(  name=app_container_name,
                                                    env=envlist,
                                                    image=app['id'],
                                                    command=app.get('cmd'),
                                                    target_container_name=myDesktop.container_name,
                                                    image_pull_policy=app.get('image_pull_policy'),
                                                    volume_mounts = list_volumeMounts,
                                                    security_context = securitycontext
        )

        pod_ephemeralcontainers =  self.orchestrator.kubeapi.read_namespaced_pod_ephemeralcontainers(name=myDesktop.id, namespace=self.orchestrator.namespace )
        if not isinstance(pod_ephemeralcontainers, client.models.v1_pod.V1Pod ):
            raise ValueError( 'Invalid read_namespaced_pod_ephemeralcontainers')

        # append body to pod_ephemeralcontainers.spec.ephemeral_containers
        if not isinstance( pod_ephemeralcontainers.spec.ephemeral_containers, list ):
            # create entry for the first time
            pod_ephemeralcontainers.spec.ephemeral_containers = list()
        pod_ephemeralcontainers.spec.ephemeral_containers.append( body )

        try:
            pod=self.orchestrator.kubeapi.patch_namespaced_pod_ephemeralcontainers(name=myDesktop.id, namespace=self.orchestrator.namespace, body=pod_ephemeralcontainers )
        except ApiException as e:
            if e.status == 409:
                # "status":"Failure",
                # "message":"Operation cannot be fulfilled on pods the object has been modified; please apply your changes to the latest version and try again",
                # "reason":"Conflict",
                # "details":{"name":"12896316-ca68ecaf-7315-46f0-8d07-5af4e79ef6fe","kind":"pods"},"code":409}\n'
                wait_time = random.random()
                self.logger.info( f"Operation cannot be fulfilled on pods the object has been modified; waiting for {wait_time}")
                time.sleep( wait_time )
                self.logger.debug( f"end of wait time, retrying to call read_namespaced_pod_ephemeralcontainers pod and patch_namespaced_pod_ephemeralcontainers")
                # recursive call
                kwargs['recurvise_counter'] = kwargs.get('recurvise_counter', 0) + 1
                return self.create( myDesktop, app, authinfo, userinfo, userargs, **kwargs )
            else:
                # forward the exception
                raise e
        if not isinstance(pod, client.models.v1_pod.V1Pod ):
            raise ValueError( 'Invalid patch_namespaced_pod_ephemeralcontainers')

        self.logger.debug( f"patch_namespaced_pod_ephemeralcontainers done")
        #
        # len_pod_status_ephemeral_container_statuses can be None, but
        # len_pod_spec_ephemeral_containers shoud not
        # len_pod_status_ephemeral_container_statuses can take delmay to be updated
        #
        appinstancestatus = None
        #
        for wait_time in [ 0, 0.1, 0.2, 0.4, 0.8, 1.6, 3.2 ]:
            pod =  self.orchestrator.kubeapi.read_namespaced_pod_ephemeralcontainers(name=myDesktop.id, namespace=self.orchestrator.namespace )
            if not isinstance(pod, client.models.v1_pod.V1Pod ):
                raise ValueError( 'Invalid patch_namespaced_pod_ephemeralcontainers')

            if isinstance(pod.status.ephemeral_container_statuses, list):
                for c in pod.status.ephemeral_container_statuses:
                    if isinstance( c, client.models.v1_container_status.V1ContainerStatus ) and \
                       c.name == app_container_name:
                        appinstancestatus = oc.od.appinstancestatus.ODAppInstanceStatus( id=c.name, type=self.type )
                        if isinstance( c.state, client.models.v1_container_state.V1ContainerState ):
                            appinstancestatus.message = self.get_phase( c )
                        break
            if isinstance( appinstancestatus, oc.od.appinstancestatus.ODAppInstanceStatus):
                self.logger.info(f"read_namespaced_pod_ephemeralcontainers status.ephemeral_container_statuses updated in {wait_time}s" )
                break
            else:
                time.sleep( wait_time )
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
        if not isinstance(pod_ephemeralcontainers, client.models.v1_pod.V1Pod ):
            self.logger.error(f"Invalid read_namespaced_pod_ephemeralcontainers {myDesktop.id} not found: pod_ephemeralcontainers is not a client.models.v1_pod.V1Pod")
            raise ValueError("Invalid read_namespaced_pod_ephemeralcontainers {myDesktop.id} not found")

        if isinstance(pod_ephemeralcontainers.spec.ephemeral_containers, list):
            for spec_ephemeralcontainer in pod_ephemeralcontainers.spec.ephemeral_containers:
                for v in spec_ephemeralcontainer.env:
                    if isinstance( v, client.models.v1_env_var.V1EnvVar ):
                        if v.name == 'UNIQUERUNKEY' and v.value == uniquerunkey:
                            # check if the ephemeralcontainer is running
                            ephemeralcontainer = self.get_status( pod_ephemeralcontainers, spec_ephemeralcontainer.name )
                            if isinstance( ephemeralcontainer, client.models.v1_container_status.V1ContainerStatus) and \
                               ephemeralcontainer.state.running:
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
    def isinstance( pod:client.models.v1_pod.V1Pod ):
        bReturn =  isinstance( pod, client.models.v1_pod.V1Pod )
        return bReturn

    def get_DISPLAY( self, desktop_ip_addr:str=None ):
        return desktop_ip_addr + ':0'

    def get_PULSE_SERVER( self, desktop_ip_addr:str=None ):
        return  desktop_ip_addr + ':' + str(DEFAULT_PULSE_TCP_PORT),

    def get_CUPS_SERVER( self, desktop_ip_addr=None ):
        return desktop_ip_addr + ':' + str(DEFAULT_CUPS_TCP_PORT)

    def list( self, authinfo, userinfo, myDesktop, phase_filter=[ 'Running', 'Waiting'], apps=None ):
        self.logger.info('')

        if not isinstance( myDesktop, ODDesktop ):
            raise ValueError( 'invalid desktop parameter')
        if not isinstance( phase_filter, list ):
            raise ValueError( 'invalid phase_filter parameter')

        result = []
        access_userid = userinfo.userid
        access_provider = authinfo.provider
        try:
            field_selector = ''
            label_selector = 'access_userid=' + access_userid + ',type=' + self.type
            label_selector += ',access_provider='  + access_provider

            # use list_namespaced_pod to filter user pod
            myPodList = self.orchestrator.kubeapi.list_namespaced_pod(self.orchestrator.namespace, label_selector=label_selector, field_selector=field_selector)
            if isinstance( myPodList, client.models.v1_pod_list.V1PodList ):
                for myPod in myPodList.items:
                    phase = myPod.status.phase
                    # keep only Running pod
                    if myPod.metadata.deletion_timestamp is not None:
                        myPhase = 'Terminating'
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


    def envContainerApp( self, authinfo, userinfo, pod_name ):
        '''get the environment vars exec for the containerid '''
        env_result = None

        # define filters
        access_userid = userinfo.userid
        access_provider = authinfo.provider
        field_selector = f"metadata.name={pod_name}"
        label_selector = f"access_userid={access_userid},type={self.type},access_provider={access_provider}"

        myPodList = self.orchestrator.kubeapi.list_namespaced_pod(self.orchestrator.namespace, label_selector=label_selector, field_selector=field_selector)
        if isinstance( myPodList, client.models.v1_pod_list.V1PodList ) and len(myPodList.items) > 0 :
            local_env = myPodList.items[0].spec.containers[0].env
            env_result = {}
            #  convert name= value= to dict
            for e in local_env:
                if isinstance( e, client.models.v1_env_var.V1EnvVar ):
                    env_result[ e.name ] =  e.value
        return env_result

    def stop( self, pod_name ):
        '''get the user's containerid stdout and stderr'''
        result = None
        propagation_policy = 'Foreground'
        grace_period_seconds = 0
        # delete_options = client.V1DeleteOptions( propagation_policy = propagation_policy )
        delete_options = client.V1DeleteOptions(propagation_policy = propagation_policy, grace_period_seconds=grace_period_seconds )
        v1status = self.orchestrator.kubeapi.delete_namespaced_pod(  name=pod_name,
                                                        namespace=self.namespace,
                                                        body=delete_options,
                                                        propagation_policy=propagation_policy )

        result = isinstance( v1status, client.models.v1_pod.V1Pod ) or isinstance(v1status,client.models.v1_status.V1Status)

        return result

    def list_and_stop( self, authinfo, userinfo, pod_name ):
        '''get the user's containerid stdout and stderr'''
        result = None
        access_userid = userinfo.userid
        access_provider = authinfo.provider
        field_selector = f"metadata.name={pod_name}"
        label_selector = f"access_userid={access_userid},type={self.type},access_provider={access_provider}"

        myPodList = self.orchestrator.kubeapi.list_namespaced_pod(self.namespace, label_selector=label_selector, field_selector=field_selector)
        if isinstance( myPodList, client.models.v1_pod_list.V1PodList ) and len(myPodList.items) > 0 :
            # propagation_policy = 'Background'
            propagation_policy = 'Foreground'
            grace_period_seconds = 0
            # delete_options = client.V1DeleteOptions( propagation_policy = propagation_policy )
            delete_options = client.V1DeleteOptions(propagation_policy = propagation_policy, grace_period_seconds=grace_period_seconds )
            v1status = self.kubeapi.delete_namespaced_pod(  name=pod_name,
                                                            namespace=self.namespace,
                                                            body=delete_options,
                                                            propagation_policy=propagation_policy )

            result = isinstance( v1status, client.models.v1_pod.V1Pod ) or isinstance(v1status,client.models.v1_status.V1Status)

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

            myPodList = self.orchestrator.kubeapi.list_namespaced_pod(self.orchestrator.namespace, label_selector=label_selector, field_selector=field_selector)

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
        rules = app.get('rules' )
        network_config = self.orchestrator.applyappinstancerules_network( authinfo, rules )

        (volumebind, volumeMounts) = self.orchestrator.build_volumes(   authinfo,
                                                                        userinfo,
                                                                        volume_type='pod_application',
                                                                        secrets_requirement=app.get('secrets_requirement'),
                                                                        rules=rules,
                                                                        **kwargs)
        list_volumes = list( volumebind.values() )
        list_volumeMounts = list( volumeMounts.values() )
        self.logger.info( 'volumes=%s', volumebind.values() )
        self.logger.info( 'volumeMounts=%s', volumeMounts.values() )

        # apply network rules
        # network_config = self.applyappinstancerules_network( authinfo, rules )
        # apply homedir rules
        # homedir_disabled = self.applyappinstancerules_homedir( authinfo, rules )
        envlist = self.get_env_for_appinstance(  myDesktop, app, authinfo, userinfo, userargs, **kwargs )

        command = [ '/composer/appli-docker-entrypoint.sh' ]
        labels = {  'access_providertype':  authinfo.providertype,
                    'access_provider':  authinfo.provider,
                    'access_userid':    userinfo.userid,
                    'access_username':  self.orchestrator.get_labelvalue(userinfo.name),
                    'type':             self.type,
                    'uniquerunkey':     app.get('uniquerunkey'),
                    'launch':           app.get('launch'),
                    'icon':             app.get('icon'),
                    'displayname':      app.get('displayname')
        }

        # container name
        # DO NOT USE TOO LONG NAME for container name
        # filter can failed or retrieve invalid value in case userid + app.name + uuid
        # limit length is not defined but take care
        _app_pod_name = self.orchestrator.get_normalized_username(userinfo.get('name', 'name')) + '_' + oc.auth.namedlib.normalize_imagename( str(app['name']) + '_' + str(uuid.uuid4().hex) )
        app_pod_name =  oc.auth.namedlib.normalize_name_dnsname( _app_pod_name )

        host_config = copy.deepcopy(oc.od.settings.applicationhostconfig)
        self.logger.info('default application hostconfig=%s', host_config )

        # load the specific hostconfig from the app object
        host_config.update( app.get('host_config'))
        self.logger.info('updated app values hostconfig=%s', host_config )

        # default empty dict annotations
        annotations = {}
        # Check if a network annotations exists
        network_annotations = network_config.get( 'annotations' )
        if isinstance( network_annotations, dict):
            annotations.update( network_annotations )

        securitycontext = self.get_securitycontext( userinfo=userinfo )

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
                'restartPolicy' : 'Never',
                'affinity': {
                    'nodeAffinity': {
                        'preferredDuringSchedulingIgnoredDuringExecution': [
                            {   'weight': 1,
                                'preference': {
                                    'matchExpressions': [
                                        {   'key': 'kubernetes.io/hostname',
                                            'operator': 'In',
                                            'values': [ myDesktop.hostname ]
                                        }
                                    ]
                                }
                            }
                        ]
                    }
                },
                'automountServiceAccountToken': False,  # disable service account inside pod
                'volumes': list_volumes,
                'nodeSelector': oc.od.settings.desktop.get('nodeselector'),
                'containers': [ {
                                    'imagePullPolicy': 'IfNotPresent',
                                    'image': app['id'],
                                    'name': app_pod_name,
                                    'command': command,
                                    'env': envlist,
                                    'volumeMounts': list_volumeMounts,
                                    'securityContext': securitycontext,
                                    'resources': oc.od.settings.desktopkubernetesresourcelimits
                                }
                ],
            }
        }

        if oc.od.settings.desktop['imagepullsecret']:
            pod_manifest['spec']['imagePullSecrets'] = [ { 'name': oc.od.settings.desktop['imagepullsecret'] } ]

        self.logger.info( 'dump yaml %s', json.dumps( pod_manifest, indent=2 ) )
        pod = self.orchestrator.kubeapi.create_namespaced_pod(namespace=self.orchestrator.namespace,body=pod_manifest )

        if not isinstance(pod, client.models.v1_pod.V1Pod ):
            raise ValueError( 'Invalid create_namespaced_pod type')
        # set desktop web hook
        # webhook is None if network_config.get('context_network_webhook') is None
        fillednetworkconfig = self.orchestrator.filldictcontextvalue(   authinfo=authinfo,
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