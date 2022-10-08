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
from unicodedata import lookup
from oc.od.apps import ODApps
import oc.logging
import oc.od.settings
import docker
import oc.lib 
import oc.auth.namedlib
import os
import time
import binascii
import urllib3

import time
import datetime
import iso8601

import yaml
import json
import uuid
import chevron
import requests
import copy
import threading

from kubernetes import client, config, watch
from kubernetes.stream import stream
from kubernetes.stream.ws_client import ERROR_CHANNEL
from kubernetes.client.rest import ApiException

import oc.lib
import oc.od.infra
import oc.od.acl
import oc.od.volume         # manage volume for desktop
import oc.od.secret         # manage secret for kubernetes
import oc.od.configmap
from   oc.od.desktop        import ODDesktop
from   oc.auth.authservice  import AuthInfo, AuthUser # to read AuthInfo and AuthUser
from   oc.od.vnc_password   import ODVncPassword

logger = logging.getLogger(__name__)


DEFAULT_PULSE_TCP_PORT = 4713
DEFAULT_CUPS_TCP_PORT  = 631

@oc.logging.with_logger()
class ODOrchestratorBase(object):
    @property
    def nodehostname(self):
        return self._nodehostname

    @nodehostname.setter
    def nodehostname(self, val ):
        if val is not None and type(val) is not str: 
            raise ValueError('Invalid nodehostname, must be a string or None: nodehostname = %s ' % str(val))
        if self._nodehostname != val:
            self.close()
            self._nodehostname = val

    def on_desktoplaunchprogress(self, key, *args):
        if callable(self.desktoplaunchprogress): 
            self.desktoplaunchprogress(self, key, *args)

    def __init__(self, nodehostname=None):

        if nodehostname is not None and type(nodehostname) is not str: 
            raise ValueError('Invalid nodehostname, must be a string or None: type nodehostname = %s ' % str(type(nodehostname)))

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
 

        self._nodehostname = nodehostname
        self.desktoplaunchprogress  = oc.pyutils.Event()        
        self.x11servertype          = 'x11server'        
        self.x11servertype_embeded  = 'x11serverembeded' 
        self.applicationtype        = 'application'     
        self.printerservertype      = 'cupsserver'
        self.soundservertype        = 'pulseserver'
        self.endpoint_domain        = 'desktop'
        self._myinfra = None
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

        # must be no more than 63 characters [0:62]
        name = oc.auth.namedlib.normalize_name( containernameprefix         + \
                                                self.containernameseparator + \
                                                user_container_name         + \
                                                container_name )[0:62]
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

    def __del__(self):
        self.close()
        
    def close(self):
       if self._myinfra is not None:
            self._myinfra.close()
            self._myinfra = None
   
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
        raise NotImplementedError('%s.garbargecollector' % type(self))

    def execwaitincontainer( self, desktop, command, timeout):
        raise NotImplementedError('%s.execwaitincontainer' % type(self))

    def createInfra(self, nodehostname=None): 
        if self._myinfra is None:
           self._myinfra = oc.od.infra.selectInfra( nodehostname )
        return self._myinfra

    def describe_container( self, container ):
        myinfra = self.createInfra( self.nodehostname )
        return myinfra.describe_container( container  )

    def listContainerApps( self, authinfo, userinfo ):
        ''' list containers application for user '''
        result = None
        try:
            myinfra = self.createInfra( self.nodehostname )
            # get list of app 
            listContainersApps = myinfra.listContainersApps( userinfo.userid )        
            myinfra.close()
            result = []
            for container in listContainersApps:
                mycontainer = {}
                try:
                    #
                    # convert a docker container to json by filter entries
                    mycontainer['id']       = container.id
                    mycontainer['short_id'] = container.short_id
                    mycontainer['status']   = container.status
                    mycontainer['image']    = container.attrs.get('Config',{}).get('Image')
                    mycontainer['oc.path']  = container.labels.get('oc.path')
                    mycontainer['oc.args']  = container.labels.get('oc.args')
                    mycontainer['oc.icon']  = container.labels.get('oc.icon')
                    mycontainer['oc.icondata'] = container.labels.get('oc.icondata')
                    mycontainer['oc.launch']        = container.labels.get('oc.launch')
                    mycontainer['oc.displayname']   = container.labels.get('oc.displayname')
                    mycontainer['nodehostname']     = self.nodehostname 
                    # add the object to the result array
                    result.append( mycontainer )
                except Exception as e:
                    self.logger.error( 'listContainerApps:add entry %s', str(e))
        except Exception as e:
            self.logger.error( '%s', str(e) ) 

        return result

    def countRunningContainerforUser( self, authinfo, userinfo):  
        counter = -1  
        myinfra = self.createInfra( self.nodehostname )
        # get list of app 
        listContainersApps = myinfra.listContainersApps( userinfo.userid )        
        myinfra.close()
        if type(listContainersApps) is list:
            counter = len(listContainersApps)
        return counter


    def envContainerApp( self, authinfo, userinfo, containerid):
        '''get the environment vars exec for the containerid '''
        env_result = {}
        myinfra = self.createInfra( self.nodehostname )

        # get list of app 
        listContainersApps = myinfra.listContainersApps( userinfo.userid )        
        for container in listContainersApps:                         
            # find the right container to kill
            if container.id == containerid :
                env_result = myinfra.env_container( container.id )  
                break
        myinfra.close()
        return env_result

    
    def removeContainerApp( self, authinfo, userinfo, containerid):
        '''get the user's containerid stdout and stderr'''
        result = None
        myinfra = self.createInfra( self.nodehostname )

        # get list of app 
        # make shure the app belongs to the user 
        # this is a security check
        listContainersApps = myinfra.listContainersApps( userinfo.userid )        
        for container in listContainersApps:                         
            # find the right container to kill
            if container.id == containerid :
                result = myinfra.remove_container( container.id )  
                break
        myinfra.close()
        return result

    def logContainerApp( self, authinfo, userinfo, containerid):
        '''get the user's containerid stdout and stderr'''
        log_result = None
        myinfra = self.createInfra( self.nodehostname )

        # get list of app 
        listContainersApps = myinfra.listContainersApps( userinfo.userid )        
        for container in listContainersApps:                         
            # find the right container to kill
            if container.id == containerid :
                log_result = myinfra.log_container( container.name )  
                break
        myinfra.close()
        return log_result


    def stopContainerApp( self, authinfo, userinfo, containerid, timeout=5 ):
        """Stop the user's containerid

        Args:
            authinfo (AuthInfo): authentification data
            userinfo (AuthUser): user data 
            containerid (str): container id
            timeout (int, optional): time out in ms. Defaults to 5.

        Returns:
            bool: True if sucess, False is failed or not found
        """
        myinfra = self.createInfra( self.nodehostname )
        stop_result = False
        # get list of app 
        listContainersApps = myinfra.listContainersApps( userinfo.userid )        
        for container in listContainersApps:                         
            # find the right container to kill
            if container.id == containerid :
                stop_result = myinfra.stop_container( container.name, timeout=timeout )  
                break
        return stop_result

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
            return nReturn

        self.logger.info( 'command %s , exitcode %s output %s', command, str(result.get('ExitCode')), result.get('stdout') )
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

    def waitForDesktopProcessReady(self, desktop, callback_notify, nTimeout=42):
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
                messageinfo = 'c.Starting desktop graphical service %ds / %d' % (nCount,nCountMax) 
                callback_notify(messageinfo)
                bListen['x11server'] = self.waitForServiceListening( desktop, service='graphical' )
                self.logger.info('service:x11server return %s', str(bListen['x11server']))
                nCount += 1

            # check if spawner is ready 
            if bListen['spawner'] is False:
                messageinfo = 'c.Starting desktop spawner service %ds / %d' % (nCount,nCountMax) 
                callback_notify(messageinfo)
                bListen['spawner']  = self.waitForServiceListening( desktop, service='spawner' )
                self.logger.info('service:spawner return %s', str(bListen['spawner']))  
                nCount += 1
            
            if bListen['x11server'] is True and bListen['spawner'] is True:     
                self.logger.debug( "desktop services are ready" )                  
                callback_notify('c.Desktop services are ready after %d s' % (nCount) )              
                return True

            # wait 0.1    
            self.logger.debug( 'sleeping for 0.5')
            time.sleep(0.5)
        
        # Can not chack process status     
        self.logger.warning('waitForDesktopProcessReady not ready services status: %s', bListen )

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
    
    def __init__(self, nodehostname=None):
        super().__init__(nodehostname)
        self.name = 'docker'
          
    def is_configured( self):        
        '''Returns boolean is dockerd is up.'''
        return oc.od.infra.ODInfra().is_configured()        
   
    def findDesktopByUser( self, authinfo, userinfo, **kwargs ):
        """ Return a full completed ODDesktop object .

        Parameters:            
            authinfo (): user authentification data
            userinfo (): user informations 

        Returns:
            findDesktopByUser(authinfo, userinfo, **kwargs ): full completed ODDesktop object

        """
        self.logger.info( '' )
        myDesktop = None  # return Desktop Object
        
        appname=kwargs.get('appname')

        access_userid   = userinfo.userid
        access_provider = authinfo.provider

        if  type(appname) is str and len(appname) > 0  :
            myFilter = {    'type': self.x11servertype_embeded, 
                            'access_userid': access_userid,
                            'appname': appname }
        else :
            myFilter = {    'type': self.x11servertype, 
                            'access_userid': access_userid }

        if oc.od.settings.desktop['authproviderneverchange'] is True:
            myFilter['access_provider'] = access_provider

        myInfra = self.createInfra( self.nodehostname )

        assert access_userid, "userid is undefined"
        list_containers= myInfra.listContainersFilter( access_userid, myFilter )
      
        if type(list_containers) is list:
            len_list_containers = len( list_containers )
            if len_list_containers > 1 :
                self.logger.error( 'query too much desktop found with filter %s, attended 1 , get %d', myFilter, len_list_containers )                
                self.logger.error( 'dump result %s', list_containers )   

            # This loop read the fisrt one containers and break
            for c in list_containers:                                
                ipAddr = myInfra.getDesktopIpAddr( c.id, kwargs.get('defaultnetworknetuserid') )
                clear_vnc_password = c.labels['vnc_password']     
                myDesktop = oc.od.desktop.ODDesktop( nodehostname=self.nodehostname, ipAddr=ipAddr, status=c.status, desktop_id=c.id, container_id=c.id, vncPassword=clear_vnc_password, websocketrouting=oc.od.settings.websocketrouting )
                break   
        
        return myDesktop


   
    def createvolume(self, prefix:str, authinfo:AuthInfo, userinfo:AuthUser, removeifexist: bool=False ):
        '''
        docker volume create --driver local \
            --opt type=tmpfs \
            --opt device=tmpfs \
            --opt o=size=100m,uid=1000 \
            foo
        '''
        volume = None
        name = self.get_volumename(prefix, userinfo )        
        auth_dict = {   'access_provider':  authinfo.provider,
                        'access_userid':    userinfo.userid,                        
                        'type':             self.x11servertype}
        
        myinfra = self.createInfra( self.nodehostname )
        volume = myinfra.createvolume( name=name, prefix=prefix, driver='local', labels=auth_dict, removeifexist=removeifexist )
        myinfra.close()
        return volume
    
    def mountallProfilPath(self, nodehostname, profilePath, arguments):
        if nodehostname is None or profilePath is None:
            return
        
    def get_volumename(self, prefix, userinfo):
        if type(prefix) is not str:
             raise ValueError('invalid prefix value %s' % type(prefix)) 
        
        if type(userinfo) is not oc.auth.authservice.AuthUser:
             raise ValueError('invalid userinfo value %s' % type(userinfo)) 

        userinfo_id = userinfo.get('userid')
        if type(userinfo_id) is not str:
             raise ValueError('invalid userinfo.id value %s' % type(userinfo_id)) 

        name = prefix + '-' + userinfo_id
        normalize_name = oc.auth.namedlib.normalize_name( name )
        self.logger.info( 'volume name %s', normalize_name)
        return normalize_name

    def prepareressources(self, authinfo:AuthInfo, userinfo:AuthUser):
        self.logger.info('externals ressources are not supported in docker mode')  

    def getsecretuserinfo(self, authinfo:AuthInfo, userinfo:AuthUser):  
        ''' cached userinfo are not supported in docker mode '''    
        ''' return an empty dict '''
        self.logger.info('get cached userinfo are not supported in docker mode')
        return {} 

    def build_volumes( self, authinfo:AuthInfo, userinfo:AuthUser, volume_type, secrets_requirement, rules, **kwargs):
        """[build_volumes]

        Args:
            authinfo (AuthInfo): authentification data
            userinfo (AuthUser): user data 
            volume_type ([str]): 'container_desktop' 'pod_desktop', 'container_app', 'pod_application'
            rules (dict, optional): [description]. Defaults to {}.

        Returns:
            [type]: [description]
        """
        self.logger.debug('')
        volumes = []
        volumesbind = []

        if userinfo.userid is None or authinfo.provider is None:
            # return empty objects
            return (volumes, volumesbind)

        # create a volume for tmp
        # tmp is always a volume        
        myvol = self.createvolume('tmp', userinfo, authinfo, removeifexist=True)
        if myvol is not None:
            volumes.append('/tmp')
            volumesbind.append(myvol.name + ':/tmp')

        # Check if share memory is enable if config file 
        # add the volume mappping for /dev/shm device
        # if oc.od.settings.desktophostconfig.get('ipc_mode') == 'shareable':
        #    # if ipc_mode = 'shareable' then
        #    # application does not use own shm memory but the pod share memory 
        #    volumes.append('/dev/shm')
        #    volumesbind.append('/dev/shm:/dev/shm')

        # if home is volume, create a volume or reuse the volume
        if kwargs.get('homedirectory_type') == 'volume':        
            # Map the home directory
            myvol = self.createvolume('home', userinfo, authinfo, removeifexist=False)        
            if myvol is not None:
                volumes.append( kwargs.get('balloon_homedirectory') )
                volumesbind.append(myvol.name + ':' + kwargs.get('balloon_homedirectory') )                
        
        self.logger.debug('end')
        return (volumes, volumesbind)
  

    def countdesktop(self):
        return  oc.od.infra.ODInfra().countdesktop()

    def removedesktop(self, authinfo, userinfo, args={}):
        status = None
        remove_volume_home = args.get( 'remove_volume_home', False ) 

        if userinfo.name == 'Anonymous':
            # by default remove Anonymous home directory
            remove_volume_home = True

        myDesktop = self.findDesktopByUser(authinfo, userinfo)
        if isinstance(myDesktop, ODDesktop):
            status = self.removecontainer( myDesktop.id, remove_volume_home )
        return status

    def removecontainer( self, desktopid, remove_volume_home=False ):
        self.logger.info( 'name=%s nodehostname=%s', desktopid, self.nodehostname)
        myinfra = self.createInfra( self.nodehostname )
        
        # Stop and remove running applications
        # self.stopContainerApps( myinfra, userinfo )

        # Before removing the container 
        # List all volume bind, 
        # the volumes will be deleted when the container has been stopped
        volume_binds = myinfra.list_volume_bind( desktopid )
        
        # Remove the container
        bRemove = myinfra.remove_container( desktopid )

        # if the conainer has been removed successully
        # remove the tmp volume 

        if bRemove and isinstance(volume_binds, dict) :
            # Remove volume if desktop home directory type is volume 
            if oc.od.settings.desktop['homedirectorytype'] == 'volume':
                for k, v in volume_binds.items(): 
                    self.logger.debug('volume %s map to %s', v, k )

                    # always remove tmp volume
                    if v == '/tmp':
                        myinfra.remove_volume( k )
                        continue

                    # remove all volumes only if user is anonymous                    
                    # for authenticated user keep home volume 
                    if remove_volume_home is True:
                        myinfra.remove_volume( k )
                        continue
        return bRemove

    def isinstance_app( self, appinstance ):
        return  isinstance( appinstance, docker.models.containers.Container )

    def execincontainer_metappli( self, containerid, command):
        myinfra = self.createInfra( self.nodehostname )
        return myinfra.execincontainer( containerid, command, detach=True)

    def execwaitincontainer( self, desktop, command, timeout=1000):
        myinfra = self.createInfra( self.nodehostname )
        return myinfra.execincontainer( desktop.id, command)

    def execininstance( self, container_id, command):
        """exec command in container

        Args:
            containerid (str): container id
            command (str): command to execute
            
        Returns:
            (dict): Dictionary of values returned by the endpoint, 
                    stdout entry
        """
        myinfra = self.createInfra( self.nodehostname )
        return myinfra.execincontainer( container_id, command)

    def getappinstance( self, authinfo, userinfo, app ):        
        userid = userinfo.userid
        self.logger.debug( "app=%s, userid=%s", app['name'], userid )
        myinfra = self.createInfra( self.nodehostname )
        container = myinfra.findRunningContainerforUserandImage( userid, app['uniquerunkey'])
        if isinstance( container, docker.models.containers.Container ):
            container.app = app
        return container

    def get_auth_env_dict( self, authinfo, userinfo  ):
        return {}

    def applyappinstancerules_homedir( self, authinfo, rules ):
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

    def applyappinstancerules_network( self, authinfo, rules ):
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
    
    def getvolumebindforapplication( self, volume_bind, volume_filter ):
        new_volumebind  = []
        new_volume      = []
        for v in volume_bind:
            arv = v.split(':')
            if len(arv) > 1:
                for vf in volume_filter:
                    if arv[1].startswith( vf ):
                        new_volumebind.append( v )
                        new_volume.append( arv[1] )
        return (new_volumebind, new_volume)

    def createappinstance(self, myDesktop, app, authinfo, userinfo={}, userargs=None, **kwargs ):                    

        assert type(app)       is dict,      "app       invalid type %r" % type(app)
        assert type(myDesktop) is ODDesktop, "myDesktop invalid type %r" % type(myDesktop)
        

        rules = app.get('rules') 
        network_config = self.applyappinstancerules_network( authinfo, rules )  # apply network rules 
        homedir_enabled = self.applyappinstancerules_homedir( authinfo, rules ) # apply volumes rules
       

        # connnect to the dockerd 
        infra = self.createInfra( myDesktop.nodehostname )
        # get desktop 
        desktop = infra.getcontainer( myDesktop.container_id )

        # get volunebind from the storage container if exist else 
        # use volume from the running x11 container
        storage_container_id = myDesktop.storage_container_id
        storage_container = infra.getcontainer( storage_container_id ) if storage_container_id else desktop

        volume_filter = [ '/tmp' ]
        if homedir_enabled:
            volume_filter.append( oc.od.settings.balloon_homedirectory )

        if isinstance( app.get('secrets_requirement'), list ):
            for secret in app.get('secrets_requirement'):
                volume_filter.append( oc.od.settings.desktop['secretsrootdirectory'] + secret )
    
        (volumesbind, volumes) = self.getvolumebindforapplication( storage_container.attrs["HostConfig"]["Binds"], volume_filter )

        network_name    = None
        # read locale language from USER AGENT
        language        = userinfo.get('locale', 'en_US')
        lang            = language + '.UTF-8'  

        # load env dict from configuration file
        env = oc.od.settings.desktop['environmentlocal'].copy()
        # overwrite 'HOME' if app set a specific value 
        if isinstance( app.get('home'), str ):
            env['HOME'] = app.get('home')

        # update env with 
        #     * user's lang value 
        #     * XAUTH_KEY
        #     * PARENT_ID
        #     * PARENT_HOSTNAME
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
                        'PARENT_ID' 	    : desktop.id, 
                        'PARENT_HOSTNAME'   : self.nodehostname,
                        'XAUTH_KEY'         : myDesktop.xauthkey,
                        'BROADCAST_COOKIE'  : myDesktop.broadcast_cookie,
                        'PULSEAUDIO_COOKIE' : myDesktop.pulseaudio_cookie
        } )

        # Add specific vars      
        timezone = kwargs.get('timezone')
        if isinstance(timezone,str) and len(timezone) > 0:     env['TZ'] = timezone
        if isinstance(userargs,str) and len(userargs) > 0:     env['APPARGS'] = userargs
        # if hasattr(authinfo, 'data'):                       env.update(authinfo.data.get('environment', {}))
        
        # container name
        # DO NOT USE TOO LONG NAME for container name  
        # filter can failed or retrieve invalid value in case userid + app.name + uuid
        # limit length is not defined but take care 
        _containername = self.get_normalized_username(userinfo.get('name', 'name')) + '_' + oc.auth.namedlib.normalize_imagename( app['name'] + '_' + str(uuid.uuid4().hex) )
        containername =  oc.auth.namedlib.normalize_name( _containername )

        # build the host config
        # first load the default hostconfig from od.config for all containers
        # create a new host_config dict
        # 
        # host_config = applicationhostconfig from configuration file
        # host_config.update( application hostconfig entry )
        # host_config.update( user rules entry )
        # host_config.update( volume )
        #
        # read the default applicationhostconfig from configuration file
        host_config = copy.deepcopy(oc.od.settings.applicationhostconfig)
        self.logger.info('default application hostconfig=%s', host_config )

        # load the specific hostconfig from the app object
        host_config.update( app.get('host_config'))
        # fixe bad value 
        # Conflicting options: Nano CPUs and CPU Quota cannot both be set 
        if host_config.get('cpu_quota') and host_config.get('nano_cpus'):
            host_config['cpu_quota'] = None

        self.logger.info('updated app values hostconfig=%s', host_config )

        # container: <_name-or-ID_>
        # Join another ("shareable") container's IPC namespace.
        ipc_mode = None
        if host_config.get('ipc_mode') == 'shareable' and oc.od.settings.desktophostconfig.get('ipc_mode') == 'shareable':  
           ipc_mode = 'container:' + desktop.id

        # share pid name space
        pid_mode = None
        if host_config.get('pid_mode') is True :     
            pid_mode = 'container:' + desktop.id


        # set network config default value 
        network_mode = 'none'
        network_name = None
        network_disabled = network_config.get('network_disabled')
        network_dns      = network_config.get('dns')
        # if network mode use conainer network 
        # bind the desktop container network to the application container
        if host_config.get('network_mode') == 'container':
            network_mode = 'container:' + desktop.id

        # if specific network exists
        # bind the specific network to the application container
        if isinstance( network_config.get('name'), str)  :
            network_name = network_config.get('name')
            network_mode = network_config.get('name')

        # if network_disabled is Tue 
        # bind the specific network to None
        if network_disabled is True :
            network_mode = 'none'
            network_name = None
      

        # set abcdesktop requirements and specific context running 
        # 'binds'    : volumesbind
        # 'ipc_mode' : ipc_mode
        # 'pid_mode' : pid_mode
        host_config.update( {
                'binds'         : volumesbind,
                'ipc_mode'      : ipc_mode,
                'network_mode'  : network_mode,
                'dns'           : network_dns,
                'pid_mode'      : pid_mode
        } )


         # dump host config berfore create   
        self.logger.info('application hostconfig=%s', host_config )


        appinfo = infra.createcontainer(
            image = app['id'],
            name  =  containername,
            working_dir = app['workingdir'],
            command = app['cmd'],
            environment = env,
            user = app['user'],
            network_disabled = network_disabled,
            labels = {                
                'access_type'           : authinfo.provider,
                'access_username'       : self.get_normalized_username( userinfo.get('name') ),
                'access_userid'         : userinfo.userid,
                'access_parent_id'      : desktop.id,
                'access_parent_hostname': self.nodehostname
            },
            volumes = volumes,
            host_config = host_config,
            network_name = network_name,
        )

        if not isinstance( appinfo, dict) :
            return None

        appinstance_id = appinfo.get('Id')
        if appinstance_id is None:
            return None

        appinstance = infra.getcontainer(appinstance_id)
        if appinstance is None:
            return None
        
        infra.startcontainer(appinstance.id)
        appinstance.message = 'starting'
        # webhook is None if network_config.get('context_network_webhook') is None

        appinstance.webhook = self.buildwebhookinstance(authinfo=authinfo, 
                                                        userinfo=userinfo, 
                                                        app=app,
                                                        network_config=network_config, 
                                                        network_name = network_name, 
                                                        appinstance_id = appinstance_id  )

        return appinstance

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
            myinfra = self.createInfra( self.nodehostname )
            network = myinfra.getnetworkbyname( network_name )
            if network:
                container_ip = myinfra.getDesktopIpAddr( containerid, network.id )
                sourcedict.update( { 'container_ip': container_ip } )
            myinfra.close()

        elif isinstance(app, ODDesktop ):
            self.logger.debug( f"app is ODDesktop" )
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
        ''' update the lastconnectdatetime labels '''
        self.logger.info('')
        myDesktop = None
        # Look for the destkop 
        myDesktop = self.findDesktopByUser(authinfo, userinfo)

        '''
        if myDesktop is None:
            return myDesktop

        try:
            myinfra = self.createInfra( self.nodehostname )
            c = myinfra.getcontainer( myDesktop.id )

        except docker.errors.APIError as e:
            self.logger.error('failed: %s', e)
        '''
        
        return myDesktop
    
    def createdesktop(self, authinfo, userinfo, **kwargs):
        self.logger.info( '')
        args     = kwargs.get('args')
        image    = kwargs.get('image')
        command  = kwargs.get('command')
        env      = kwargs.get('env', {} )
        appname  = kwargs.get('appname')
        container_name = None
        
        # add a new VNC Password to env var
        vnc_password = ODVncPassword()
        env['VNC_PASSWORD'] = vnc_password.getplain()

        # # compile a env list with the auth list  
        ## translate auth environment to env 
        ## env exist only in docker mode
        #environment = authinfo.data.get('environment')
        #if type(environment) is dict:
        #    for auth_env_built in environment.values():
        #        # each entry in authinfo.data.environment is a dict 
        #        env.update( auth_env_built )

        # convert the dict env to a list of string key=value
        envlist = ['%s=%s' % kv for kv in env.items()]

        # if appname is None then create a desktop with x11servertype
        # if appname id not None then create a desktop with self.x11servertype_embeded
        labels = {  'access_provider':  authinfo.provider,
                    'access_userid':    userinfo.userid,
                    'access_username':  userinfo.name,
                    'type':             self.x11servertype,
                    'vnc_password':     vnc_password.getplain()
        }

        # if appname is set then create a metappli labels
        # this will change and run the app
        if type(appname) is str:
            labels.update( { 'type': self.x11servertype_embeded, 'appname':  appname } )
            container_name  = self.get_graphicalcontainername( userinfo.userid, appname )
        else:
            container_name  = self.get_graphicalcontainername( userinfo.userid, self.x11servertype )

        # build storage volume or directory binding
        # callback_notify( 'Build volumes' )
        volumes, volumesbind = self.build_volumes(authinfo, userinfo, volume_type='container_desktop', secrets_requirement=None, rules={}, **kwargs)
        myDesktop = None
        
        try:
            myinfra = self.createInfra( self.nodehostname )
            c = myinfra.getdockerClientAPI()
            # callback_notify( 'Create your network' )
            networking_config = c.create_networking_config({oc.od.settings.defaultnetworknetuser: c.create_endpoint_config()})

            # if oc.od.settings.desktophostconfig.get('network_mode') :  
            #    del oc.od.settings.desktophostconfig['container']
            # remove bad/nosence value if exists
            if oc.od.settings.desktophostconfig.get('pid_mode'):      
               del oc.od.settings.desktophostconfig['pid_mode']

            desktophostconfig = copy.deepcopy( oc.od.settings.desktophostconfig )
            desktophostconfig['binds'] = volumesbind

            # dump host config berfore create
            # self.logger.info('oc.od.settings.desktophostconfig=%s', oc.od.settings.desktophostconfig )
            self.logger.info( f"desktophostconfig= {desktophostconfig}" )

            host_config  = c.create_host_config( **desktophostconfig )
            
            # callback_notify( 'Create your desktop' )
            mydesktopcreate_container = c.create_container( name=container_name,
                                                            image=image,
                                                            command=command,
                                                            environment=envlist,                                        
                                                            networking_config=networking_config,
                                                            labels=labels,
                                                            volumes=volumes,
                                                            host_config=host_config,
                                                            detach=True,
                                                            runtime=host_config.get('runtime')
            )

            # get the containerid as mydesktopid
            mydesktopid = mydesktopcreate_container.get('Id', None)
            if mydesktopid is not None:
                # Start the containerid
                # callback_notify( 'Let\'s start your desktop' )
                c.start(container=mydesktopid)
                # get the container IpAddr
                # callback_notify( 'Getting desktop status' )
                ipAddr = myinfra.getDesktopIpAddr( mydesktopid, oc.od.settings.defaultnetworknetuserid  )
                # get the container Status
                status  = myinfra.getDesktopStatus( mydesktopid )                 
                myDesktop = ODDesktop(  nodehostname=self.nodehostname,
                                        container_id=mydesktopid,
                                        desktop_id = mydesktopid,
                                        status=status,
                                        ipAddr=ipAddr,
                                        vncPassword=vnc_password.getplain(),
                                        websocketrouting=oc.od.settings.websocketrouting )      
            myinfra.close()

        except docker.errors.APIError as e:
            self.logger.error('failed: %s', e)
        return myDesktop
    
    def logs( self, authinfo, userinfo ):
        strlogs = ''

        # Look for the destkop 
        myDesktop = self.findDesktopByUser(authinfo, userinfo)
        if type(myDesktop) is not ODDesktop:
            return strlogs

        # connnect to the dockerd 
        infra = self.createInfra()
        strlogs = infra.log_container( myDesktop.container_id )
        infra.close()
        return strlogs

    def container2desktop( self, container ):
        # get the container IpAddr
        # callback_notify( 'Getting desktop status' )
        myinfra = self.createInfra( self.nodehostname )
        ipAddr = myinfra.getDesktopIpAddr( container.id, oc.od.settings.defaultnetworknetuserid )           
        myDesktop = ODDesktop(  nodehostname=self.nodehostname,
                                container_id=container.id,
                                desktop_id = container.id,
                                status=container.status,
                                ipAddr=ipAddr,
                                vncPassword=container.labels['vnc_password'],
                                websocketrouting=oc.od.settings.websocketrouting
                    )
        return myDesktop

    def isgarbagable( self, container, expirein, force=False ):
        bReturn = False
        myDesktop = self.container2desktop( container )
        if force is False:
            nCount = self.user_connect_count( myDesktop )
            if nCount == -1 : 
                return bReturn 
            if nCount > 0:
                return False
        try:
            creation_date = container.attrs['Created']
            # times are delivered in ISO8601
            # creation_datetime = datetime.datetime.strptime(creation_date, '%Y-%m-%dT%H:%M:%S.%fZ')
            creation_datetime =  iso8601.parse_date( creation_date )
            now_datetime =  datetime.datetime.now( datetime.timezone.utc )
            delta_datetime = now_datetime - creation_datetime
            delta_second = delta_datetime.total_seconds()
            if delta_second > expirein:
                bReturn = True
        except Exception as e:
            self.logger.error(str(e))

        return bReturn

    def garbagecollector( self, expirein, force=False ):
        garbaged = []
        myInfra = self.createInfra( self.nodehostname )
        try:
            list_label_selector = [ {'type': self.x11servertype} , {'type': self.x11servertype_embeded }]
            for label_selector in list_label_selector:
                myList = myInfra.listContainersFilter( None, label_selector )
                for myContainer in myList:
                    myContainergarbagable = self.isgarbagable( myContainer, expirein, force ) 
                    if myContainergarbagable is True:
                        self.logger.info( '%s is garbagable, removing ', myContainer.name  )
                        status = self.removecontainer( myContainer.id )
                        if status :
                            garbaged.append( myContainer.name )
                    else:
                        self.logger.info( '%s is not garbagable ', myContainer.name  )
        except ApiException as e:
            self.logger.error(str(e))
        return garbaged

@oc.logging.with_logger()
class ODOrchestratorKubernetes(ODOrchestrator):

    def __init__(self, arguments=None):
        super().__init__(arguments)

        self.DEFAULT_K8S_TIMEOUT_SECONDS = 15
        self.DEFAULT_K8S_CREATE_TIMEOUT_SECONDS = 30
        
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
                self.logger.debug( 'config.load_kube_config docker mode done')
            
            # 
            # previous line is 
            #   from kubernetes.client import configuration 
            #   SSL hostname verification failure with websocket-client #138
            #   https://github.com/kubernetes-client/python/issues/138#
            # 
            #   you're using minikube for development purpose. It is not able to recognise your hostname. 
            #   https://stackoverflow.com/questions/54050504/running-connect-get-namespaced-pod-exec-using-kubernetes-client-corev1api-give
            client.configuration.assert_hostname = False
            self.kubeapi = client.CoreV1Api()
            self.namespace = oc.od.settings.namespace
            self.bConfigure = True
            self.name = 'kubernetes'
            self.createpod_timeout=30   # createpod_timeout timeout - time before disconnecting stream for watch

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

            self.default_volumes['run']       = { 'name': 'run',  'emptyDir': { 'medium': 'Memory', 'sizeLimit': '16M' } }
            self.default_volumes_mount['run'] = { 'name': 'run',  'mountPath': '/var/run/desktop' }

            self.default_volumes['log']       = { 'name': 'log',  'emptyDir': { 'medium': 'Memory', 'sizeLimit': '8M' } }
            self.default_volumes_mount['log'] = { 'name': 'log',  'mountPath': '/var/log/desktop' }

            self.default_volumes['x11unix'] = { 'name': 'x11unix',  'emptyDir': { 'medium': 'Memory' } }
            self.default_volumes_mount['x11unix'] = { 'name': 'x11unix',  'mountPath': '/tmp/.X11-unix' }

        except Exception as e:
            self.bConfigure = False
            self.logger.info( '%s', str(e) ) # this is not an error in docker configuration mode, do not log as an error but as info

        self.logger.debug( 'ODOrchestratorKubernetes __init__ done configure=%s', str(self.bConfigure) )

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
                self.kubeapi.list_node()
                bReturn = True
        except Exception as e:
            self.logger.error( str(e) )
        return bReturn

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

    def safeget_localaccount_confimap( self, userinfo, configmap_type ):
        """safeget_localaccount_confimap
            This section code should be removed if the kubernetes cluster use a stable etc cluster
            Fix issues if etcd clusters are unstable

        Args:
            userinfo (AuthUser): user data
            configmap_type (str): 'localaccount' define in oc.od.configmap.selectConfigMap

        Returns:
            tuple: (ODConfigMapLocalAccount, client.models.v1_config_map.V1ConfigMap)
        """
       
        configmap_localaccount = None
        configmap_localaccount_data = None

        nCounterReadConfigMap = 0
        maxCounterReadEtcdRetry = 5

        #
        # this section code is to debug some issues 
        # when a node create a configmap, another node can find or read it 
        # the call on the another node may failed in production

        #
        # this section code tries to fix and get the configmap data
        # the read call and the nCounterReadConfigMap up to maxCounterReadEtcdRetry 
        # issues occurs if etcd clusters are unstable or do not run on dedicated machines or isolated environments
        #
        while nCounterReadConfigMap < maxCounterReadEtcdRetry:
            nCounterReadConfigMap = nCounterReadConfigMap + 1
            configmap_localaccount = oc.od.configmap.selectConfigMap( self.namespace, self.kubeapi, prefix=None, configmap_type=configmap_type )
            # the read call is dummy only to read safe test
            configmap_localaccount_data = configmap_localaccount.read( userinfo=userinfo) 
            configmap_localaccount_name = configmap_localaccount.get_name( userinfo=userinfo )
            if isinstance( configmap_localaccount_data, client.models.v1_config_map.V1ConfigMap):
                self.logger.info(f"Configmap {configmap_localaccount_name} has been read successfully try={nCounterReadConfigMap}" )
                break
            if nCounterReadConfigMap > maxCounterReadEtcdRetry:
                # do not map passwd, group and shaddow files
                # use default emdedded in the container image
                self.logger.error( 'ETCD fatal error') 
                self.logger.error( f"Configmap {configmap_localaccount_name} is unreadable but it has been created successfully")
                self.logger.error( 'do not map custom passwd, group and shaddow')
                self.logger.error( 'rollback uses default emdedded passwd, group and shaddow in the container image')
            else:
                # the config map localaccount MUST exist, be it seems not 
                # i down know what to do except sleeping
                # the configmap is unreadable but it has been created succefully on another node
                # may be waiting for an etc sync 
                # counter [ 1, 2, 3, 4, 5 ] -> sleep time [ 0.5, 1, 1.5, 2, 2.5 ]
                sleeptime = nCounterReadConfigMap/2 #  sleeptime in float
                self.logger.error(f"Configmap {configmap_localaccount_name} is unreadable but it has been created successfully previously")
                self.logger.error(f"Configmap localaccount {configmap_localaccount_name} can not be read, waiting for etcd {nCounterReadConfigMap}/{maxCounterReadEtcdRetry}")
                self.on_desktoplaunchprogress( f"b.Configmap localaccount {configmap_localaccount_name} can not be read, waiting for {sleeptime}s on etcd {nCounterReadConfigMap}/{maxCounterReadEtcdRetry}")
                time.sleep(nCounterReadConfigMap/2)

        return (configmap_localaccount, configmap_localaccount_data)


    def build_volumes( self, authinfo, userinfo, volume_type, secrets_requirement, rules={}, **kwargs):
        """[build_volumes]

        Args:
            authinfo ([type]): [description]
            userinfo (AuthUser): user data
            volume_type ([str]): 'container_desktop' 'pod_desktop', 'container_app', 'pod_application'
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
        if volume_type in [ 'pod_desktop', 'container_desktop', 'container_app' ] :
            self.logger.debug( f"adding volume ['tmp', 'x11unix', 'run', 'log'] to {volume_type}" )
            # set tmp volume
            volumes['tmp']       = self.default_volumes['tmp']
            volumes_mount['tmp'] = self.default_volumes_mount['tmp'] 
            volumes['x11unix']   = self.default_volumes['x11unix']
            volumes_mount['x11unix'] = self.default_volumes_mount['x11unix']
            # set run volume
            # run volume is used to write run files
            volumes['run']       = self.default_volumes['run']
            volumes_mount['run'] = self.default_volumes_mount['run']
            # set log volume
            # log volume is used to write log files
            volumes['log']       = self.default_volumes['log']
            volumes_mount['log'] = self.default_volumes_mount['log']
            self.logger.debug( f"added volume ['tmp', 'x11unix', 'run', 'log'] to {volume_type}" )

        #
        # shm volume is shared between all container inside the desktop pod
        # 
        if volume_type in [ 'pod_desktop', 'container_desktop' ] \
            and oc.od.settings.desktophostconfig.get('shm_size'):
                # set shm memory volume
                self.logger.debug( f"adding volume ['shm'] to {volume_type}" )
                volumes['shm']       = self.default_volumes['shm']
                volumes_mount['shm'] = self.default_volumes_mount['shm'] 
                self.logger.debug( f"added volume ['shm'] to {volume_type}" )

       
        # if a config map localaccount exist
        self.logger.debug( "looking for selectConfigMap configmap_type='localaccount'" )
        configmap_localaccount = oc.od.configmap.selectConfigMap( self.namespace, self.kubeapi, prefix=None, configmap_type='localaccount'  )
        configmap_localaccount_data = configmap_localaccount.read( userinfo=userinfo ) 
        if isinstance( configmap_localaccount_data, client.models.v1_config_map.V1ConfigMap):
            self.logger.debug(f"Configmap {configmap_localaccount_data.metadata.name} has been read successfully" )
            # Note: configmaps are mounted read-only so that you can't touch the files
            # Note: a config map is always mounted as 'readOnly': True
            config_map_auth_name = configmap_localaccount.get_name( userinfo=userinfo )
            # add passwd
            volumes['passwd']       = { 'name': 'config-passwd', 'configMap': { 'name': config_map_auth_name } }
            volumes_mount['passwd'] = { 'name': 'config-passwd', 'mountPath': '/etc/passwd', 'subPath': 'passwd' }
            # add shadow
            volumes['shadow']       = { 'name': 'config-shadow', 'configMap': { 'name': config_map_auth_name } }
            volumes_mount['shadow'] = { 'name': 'config-shadow', 'mountPath': '/etc/shadow', 'subPath': 'shadow' }
            # add group
            volumes['group']       = { 'name': 'config-group', 'configMap': { 'name': config_map_auth_name } }
            volumes_mount['group'] = { 'name': 'config-group', 'mountPath': '/etc/group', 'subPath': 'group' }
        else:
            self.logger.debug(f"Configmap localaccount is not defined" )
        self.logger.debug( "look done for selectConfigMap configmap_type='localaccount'" )

        #
        # mount secret in /var/secrets/abcdesktop
        # always add vnc secret for 'pod_desktop'
        self.logger.debug( f"checking volume_type={volume_type} in [ 'pod_desktop' ]" )
        if volume_type in [ 'pod_desktop' ] :
            # Add VNC password as volume secret
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
        self.logger.debug( f"checked volume_type={volume_type} in [ 'pod_desktop' ]" )
        
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
            self.logger.debug( 'added secret type %s to volume pod', mysecretdict[secret_auth_name]['type'] )
        self.logger.debug( f"listed list_dict_secret_data access_type='auth'" )

        #
        # if type is self.x11servertype then keep user home dir data
        # else do not use the default home dir to metapplimode
        homedir_enabled = True

        self.logger.debug( 'adding applyappinstancerules_homedir' )
        # if the pod or container is not an x11servertype
        if kwargs.get('type') != self.x11servertype:
            homedir_enabled = self.applyappinstancerules_homedir( authinfo, rules )
        self.logger.debug( f"added applyappinstancerules_homedir homedir_enabled={homedir_enabled}" )
        
        if  homedir_enabled and kwargs.get('homedirectory_type') == 'persistentVolumeClaim':
            self.logger.debug( "adding homedir volume" )
            self.on_desktoplaunchprogress('b.Building home dir data storage')
            volume_home_name = self.get_volumename( 'home', userinfo )
            # Map the home directory
            volumes['home'] = { 'name': volume_home_name } # home + userid 
            if authinfo.provider == 'anonymous':
                volumes['home'].update( {'emptyDir': {} } )            
            else:
                volumes['home'].update( { 'persistentVolumeClaim': { 'claimName': oc.od.settings.desktop['persistentvolumeclaim'] } } )

            subpath_name = oc.auth.namedlib.normalize_name( userinfo.name )
            volumes_mount['home'] = {   'name'      : volume_home_name,                          # home + userid
                                        'mountPath' : oc.od.settings.getballoon_homedirectory(), # /home/balloon
                                        'subPath'   : subpath_name                               # userid
            }
            self.logger.debug( 'volume mount : %s %s', 'home', volumes_mount['home'] )
            self.logger.debug( 'volumes      : %s %s', 'home', volumes['home'] )
            self.logger.debug( "added homedir volume" )

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
                volumes[mountvol.name] = {  'name': volume_name,
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
            self.logger.info( 'desktop.id=%s command=%s return code %s', desktop.id, command, str(err))
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
            self.logger.error( 'command exec failed %s', str(e)) 

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
            self.logger.info( 'pod_name %s', pod_name)              
            self.nodehostname = myPod.spec.node_name

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
            if isinstance(v1status,client.models.v1_pod.V1Pod) :
                removedesktopStatus['pod'] = v1status
            else:
                removedesktopStatus['pod'] = False

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
            
    def prepareressources(self, authinfo:AuthInfo, userinfo:AuthUser, allow_exception=False):
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
        if type(authinfo.protocol) is dict :
            # if ldif is enabled
            if authinfo.protocol.get('ldif') is True:
                # create a ldif secret
                self.logger.debug('oc.od.secret.ODSecretLDIF creating')
                secret = oc.od.secret.ODSecretLDIF( self.namespace, self.kubeapi )
                secret.create( authinfo, userinfo, data=userinfo )
                self.logger.debug('create oc.od.secret.ODSecretLDIF created')

        localaccount_data = authinfo.get_localaccount()
        if isinstance( localaccount_data, dict ) :
            # create /etc/passwd, /etc/group and /etc/shadow configmap entries
            self.logger.debug('localaccount_configmap.create creating')
            localaccount_configmap= oc.od.configmap.selectConfigMap( self.namespace, self.kubeapi, prefix=None, configmap_type='localaccount' )
            localaccount_configmap_name = localaccount_configmap.get_name(userinfo=userinfo)
            createdconfigmap = localaccount_configmap.create( authinfo, userinfo, data=localaccount_data )
            if not isinstance( createdconfigmap, client.models.v1_config_map.V1ConfigMap):
                self.logger.error((f"cannot create configmap localaccount {localaccount_configmap_name}"))
                if allow_exception is True: 
                    raise Exception(f"cannot create configmap localaccount {localaccount_configmap_name}")
            self.logger.debug('localaccount_configmap.create created')
        else:
            self.logger.debug( 'no localaccount_data is defined, no localaccount_configmap')

        # for each auth protocol enabled
        self.logger.debug('secret.create creating')
        local_secrets = authinfo.get_secrets()
        for auth_env_built_key in local_secrets.keys(): 
            self.logger.debug( f"oc.od.secret.selectSecret type={auth_env_built_key}")
            secret = oc.od.secret.selectSecret( self.namespace, self.kubeapi, prefix=None, secret_type=auth_env_built_key )
            # build a kubernetes secret with the auth values 
            # values can be empty to be updated later
            self.logger.debug( f"creating secret.create type={auth_env_built_key}")
            createdsecret = secret.create( authinfo, userinfo, data=local_secrets.get(auth_env_built_key) )
            if not isinstance( createdsecret, client.models.v1_secret.V1Secret):
                mysecretname = self.get_name( userinfo )
                self.logger.error(f"cannot create secret {mysecretname}")
                if allow_exception is True: 
                    raise Exception(f"cannot create secret {auth_env_built_key}")
            else:
                self.logger.debug( f"created secret.create type={auth_env_built_key}")
        self.logger.debug('secret.create created')
    
        # Create flexvolume secrets
        self.logger.debug('flexvolume secrets creating')
        rules = oc.od.settings.desktop['policies'].get('rules')
        if isinstance(rules, dict):
            mountvols = oc.od.volume.selectODVolumebyRules( authinfo, userinfo,  rules.get('volumes') )
            for mountvol in mountvols:
                # use as a volume defined and the volume is mountable
                fstype = mountvol.fstype # Get the fstype: for example 'cifs' or 'cifskerberos' or 'webdav'
                # Flex volume use kubernetes secret, add mouting path
                arguments = { 'mountPath': mountvol.containertarget, 'networkPath': mountvol.networkPath, 'mountOptions': mountvol.mountOptions }
                # Build the kubernetes secret
                secret = oc.od.secret.selectSecret( self.namespace, self.kubeapi, prefix=mountvol.name, secret_type=fstype)
                auth_secret = secret.create( authinfo, userinfo, arguments )
                if auth_secret is None:
                    self.logger.error( f"Failed to build auth secret fstype={fstype}" )
        self.logger.debug('flexvolume secrets created')

    def get_annotations_lastlogin_datetime(self):
        """get a new lastlogin datetime dict 

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
            datetime: a datetime from pod.metadata.annotations.get('lastlogin_datetime')
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
            label_selector =    'access_userid=' + access_userid 

            if oc.od.settings.desktop['authproviderneverchange'] is True:
                label_selector += ',' + 'access_provider='  + access_provider   
   
            if type(access_type) is str :
                label_selector += ',access_type=' + access_type 
           
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
            label_selector =    'access_userid=' + access_userid 

            if oc.od.settings.desktop['authproviderneverchange'] is True:
                label_selector += ',' + 'access_provider='  + access_provider   
   
            if type(access_type) is str :
                label_selector += ',access_type=' + access_type 
           
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

    def findRunningPodforUserandImage( self, authinfo, userinfo, app):
        self.logger.info('')

        myrunningPodList = []
        access_userid = userinfo.userid
        access_provider = authinfo.provider
        try: 
            field_selector = ''
            label_selector = 'access_userid=' + access_userid + ',type=' + self.applicationtype
                             
            uniquerunkey = app.get('uniquerunkey')
            if uniquerunkey:
                label_selector += ',uniquerunkey=' + uniquerunkey

            if oc.od.settings.desktop['authproviderneverchange'] is True:
                label_selector += ',access_provider='  + access_provider

            myPodList = self.kubeapi.list_namespaced_pod(self.namespace, label_selector=label_selector, field_selector=field_selector)

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
            self.logger.info("Exception when calling list_namespaced_pod: %s", str(e))
        
        return myrunningPodList

        def isinstance_app( self, appinstance ):
            bReturn = super().isinstance_app( appinstance) or isinstance( appinstance, client.models.v1_pod.V1Pod )
            return bReturn


    def getappinstance( self, authinfo, userinfo, app ):    
        self.logger.debug('')
        # check if the application instance exixts and
        # is running as a container
        appinstance = super().getappinstance( authinfo, userinfo, app )
        if super().isinstance_app( appinstance ):
            return appinstance

        # the application instance does not exist as a container
        # looking for a pod instance
        pod = None 
        podlist = self.findRunningPodforUserandImage( authinfo, userinfo, app)
        if len(podlist) > 0:
            pod = podlist[0]
            pod.id = pod.metadata.name # add an id for container compatibility
        return pod


    def execininstance( self, desktop, command):
        self.logger.info('')

        # if the desktop object is a container instance object
        if isinstance( desktop, docker.models.containers.Container ):
            return super().execininstance( desktop.id, command)

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
        bReturn =   isinstance(  oc.od.settings.desktop_pod.get(currentcontainertype), dict ) and \
                    oc.od.acl.ODAcl().isAllowed( authinfo, oc.od.settings.desktop_pod[currentcontainertype].get('acl') ) and \
                    oc.od.settings.desktop_pod[currentcontainertype].get('enable') == True
        return bReturn

    def getimagecontainerfromauthlabels( self, currentcontainertype, authinfo ):
        imageforcurrentcontainertype = None
        image = oc.od.settings.desktop_pod[currentcontainertype].get('image')
        if isinstance( image, str):
            imageforcurrentcontainertype = image
        elif isinstance( image, dict ):
            imageforcurrentcontainertype = image.get('default')
            labels = authinfo.get_labels()
            if isinstance( labels, dict ):
                for k in labels.keys():
                    if image.get(k):
                        imageforcurrentcontainertype=image.get(k)
                        break
        return imageforcurrentcontainertype

    
    def createappinstance(self, myDesktop, app, authinfo, userinfo={}, userargs=None, **kwargs ):                    

        assert type(myDesktop) is ODDesktop, "myDesktop invalid type %r" % type(myDesktop)
        assert type(app)       is dict,      "app       invalid type %r" % type(app)
        

        if app.get('run_inside_pod') is False:
            # create app as a docker container 
            return super().createappinstance( myDesktop, app, authinfo, userinfo, userargs, **kwargs )

        rules = app.get('rules' )
        network_config = self.applyappinstancerules_network( authinfo, rules )

        (volumebind, volumeMounts) = self.build_volumes( authinfo, userinfo, volume_type='pod_application', secrets_requirement=app.get('secrets_requirement'), rules=rules, **kwargs)
        list_volumes = list( volumebind.values() )
        list_volumeMounts = list( volumeMounts.values() )
        self.logger.info( 'volumes=%s', volumebind.values() )
        self.logger.info( 'volumeMounts=%s', volumeMounts.values() )

        # apply network rules 
        # network_config = self.applyappinstancerules_network( authinfo, rules )
        # apply homedir rules
        # homedir_disabled = self.applyappinstancerules_homedir( authinfo, rules )
       
      
        network_name    = None
        # read locale language from USER AGENT
        language        = userinfo.get('locale', 'en_US')
        lang            = language + '.UTF-8'  

        # make sure env DISPLAY, PULSE_SERVER,CUPS_SERVER exist  
        desktop_ip_addr = myDesktop.desktop_interfaces.get('eth0').get('ips')
        env = oc.od.settings.desktop['environmentlocal'].copy()
        env.update( {   'DISPLAY': desktop_ip_addr + ':0',
                        'CONTAINER_IP_ADDR': desktop_ip_addr,   # CONTAINER_IP_ADDR is used by ocrun node js command 
                        'XAUTH_KEY': myDesktop.xauthkey,
                        'BROADCAST_COOKIE': myDesktop.broadcast_cookie,
                        'PULSEAUDIO_COOKIE': myDesktop.pulseaudio_cookie,
                        'PULSE_SERVER': desktop_ip_addr + ':' + str(DEFAULT_PULSE_TCP_PORT),
                        'CUPS_SERVER':  desktop_ip_addr + ':' + str(DEFAULT_CUPS_TCP_PORT)
                        # 'NO_AT_BRIDGE': 1
                    } 
        )
        
        # update env with user's lang value 
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
                        'PARENT_HOSTNAME'   : self.nodehostname
                    } 
        )

        # Add specific vars      
        timezone = kwargs.get('timezone')
        if type(timezone) is str and len(timezone) > 1:     env['TZ'] = timezone
        if type(userargs) is str and len(userargs) > 0:     env['APPARGS'] = userargs
        if hasattr(authinfo, 'data'):                       env.update(authinfo.data.get('environment', {}))


        # envdict to envlist
        envlist = []
        for k, v in env.items():
            # need to convert v as str : kubernetes supports ONLY string type to env value
            envlist.append( { 'name': k, 'value': str(v) } )

        envlist.append( { 'name': 'NODE_NAME',      'valueFrom': { 'fieldRef': { 'fieldPath':'spec.nodeName' } } } )
        envlist.append( { 'name': 'POD_NAME',       'valueFrom': { 'fieldRef': { 'fieldPath':'metadata.name' } } } )
        envlist.append( { 'name': 'POD_NAMESPACE',  'valueFrom': { 'fieldRef': { 'fieldPath':'metadata.namespace' } } } )
        envlist.append( { 'name': 'POD_IP',         'valueFrom': { 'fieldRef': { 'fieldPath':'status.podIP' } } } )

        command = [ '/composer/appli-docker-entrypoint.sh' ]
        

        labels = {  'access_provider':  authinfo.provider,
                    'access_userid':    userinfo.userid,
                    'access_username':  self.get_labelvalue(userinfo.name),
                    'type':             self.applicationtype,
                    'uniquerunkey':     app['uniquerunkey']
        }

        # container name
        # DO NOT USE TOO LONG NAME for container name  
        # filter can failed or retrieve invalid value in case userid + app.name + uuid
        # limit length is not defined but take care 
        _app_pod_name = self.get_normalized_username(userinfo.get('name', 'name')) + '_' + oc.auth.namedlib.normalize_imagename( app['name'] + '_' + str(uuid.uuid4().hex) )
        app_pod_name =  oc.auth.namedlib.normalize_name( _app_pod_name )

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

        pod_manifest = {
            'apiVersion': 'v1',
            'kind': 'Pod',
            'metadata': {
                'name': app_pod_name,
                'namespace': self.namespace,
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
                'subdomain': self.endpoint_domain,
                'volumes': list_volumes,                    
                'nodeSelector': oc.od.settings.desktop.get('nodeselector'), 
                'containers': [ { 
                                    'imagePullPolicy': 'IfNotPresent',
                                    'image': app['id'],
                                    'name': app_pod_name,
                                    'command': command,
                                    'env': envlist,
                                    'volumeMounts': list_volumeMounts,
                                    'securityContext': { 
                                             # permit sudo command inside the container False by default 
                                            'allowPrivilegeEscalation': oc.od.settings.desktop.get('allowPrivilegeEscalation'),
                                            # to permit strace call 'capabilities':  { 'add': ["SYS_ADMIN", "SYS_PTRACE"]  
                                            'capabilities': { 'add':  oc.od.settings.desktophostconfig.get('cap_add'),
                                                              'drop': oc.od.settings.desktophostconfig.get('cap_drop') }
                                    },
                                    'resources': oc.od.settings.desktopkubernetesresourcelimits
                                }                                                             
                ],
            }
        }

        if oc.od.settings.desktop['imagepullsecret']:
            pod_manifest['spec']['imagePullSecrets'] = [ { 'name': oc.od.settings.desktop['imagepullsecret'] } ]

        self.logger.info( 'dump yaml %s', json.dumps( pod_manifest, indent=2 ) )
        pod = self.kubeapi.create_namespaced_pod(namespace=self.namespace,body=pod_manifest )

        if not isinstance(pod, client.models.v1_pod.V1Pod ):
            raise ValueError( 'Invalid create_namespaced_pod type')

        appinstance = pod
        # add compatible attribute for docker container
        appinstance.message = pod.status.phase   
        appinstance.id = pod.metadata.name    


         # set desktop web hook
        # webhook is None if network_config.get('context_network_webhook') is None
        fillednetworkconfig = self.filldictcontextvalue(authinfo=authinfo, 
                                                        userinfo=userinfo, 
                                                        desktop=myDesktop, 
                                                        network_config=network_config, 
                                                        network_name = None, 
                                                        appinstance_id = None )

        appinstance.webhook = fillednetworkconfig.get('webhook')
        return appinstance

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
        self.logger.debug('createdesktop end' )
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
        labels = {  'access_provider':  authinfo.provider,
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
        # envdict to envlist
        envlist = []
        for k, v in env.items():
            # need to convert v as str : kubernetes supports ONLY string type to env value
            envlist.append( { 'name': k, 'value': str(v) } )

      
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
        self.logger.debug('envlist created')

        # look for desktop rules
        # apply network rules 
        self.logger.debug('rules creating')   
        rules = oc.od.settings.desktop['policies'].get('rules')
        self.logger.debug('rules is defined %s', str(rules))
        network_config = self.applyappinstancerules_network( authinfo, rules )
        fillednetworkconfig = self.filldictcontextvalue(authinfo=authinfo, 
                                                        userinfo=userinfo, 
                                                        desktop=None, 
                                                        network_config=copy.deepcopy(network_config), 
                                                        network_name = None, 
                                                        appinstance_id = None )
        self.logger.debug('rules created')

        self.on_desktoplaunchprogress('b.Building data storage for your desktop')


        self.logger.debug('secrets_requirement creating')
        secrets_requirement = None # default value add all secret if no filter 
        # get all secrets
        mysecretdict = self.list_dict_secret_data( authinfo, userinfo )
        # by default give the abcdesktop/kerberos and abcdesktop/cntlm secrets inside the pod, if exist
        secrets_type_requirement = oc.od.settings.desktophostconfig.get('secrets_requirement')
        if isinstance( secrets_type_requirement, list ):
            # list the secret entry by requirement type 
            secrets_requirement = ['abcdesktop/vnc'] # always add the vnc passwork in the secret list 
            for secretdictkey in mysecretdict.keys():
                if mysecretdict.get(secretdictkey,{}).get('type') in secrets_type_requirement:
                    secrets_requirement.append( secretdictkey )
        self.logger.debug('secrets_requirement created')

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
            image = self.getimagecontainerfromauthlabels( currentcontainertype, authinfo )  
            self.logger.debug('pod container creating %s', currentcontainertype )
            securityContext = oc.od.settings.desktop_pod[currentcontainertype].get('securityContext',  { 'runAsUser': 0 } )
            self.logger.debug('pod container %s use securityContext %s ', currentcontainertype, securityContext)
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

        currentcontainertype = 'graphical'
        self.logger.debug('pod container creating %s', currentcontainertype )
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
                'shareProcessNamespace': oc.od.settings.desktop_pod[currentcontainertype].get('shareProcessNamespace'),
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
                                    'securityContext': oc.od.settings.desktop_pod[currentcontainertype].get('securityContext'),
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
        for currentcontainertype in [ 'printer', 'sound' ] :
            if  self.isenablecontainerinpod( authinfo, currentcontainertype ):
                self.logger.debug('pod container creating %s', currentcontainertype )
                image = self.getimagecontainerfromauthlabels( currentcontainertype, authinfo )
                pod_manifest['spec']['containers'].append( { 
                        'name': self.get_containername( currentcontainertype, userinfo.userid, myuuid ),
                        'imagePullPolicy':  oc.od.settings.desktop_pod[currentcontainertype].get('pullpolicy'),
                        'image': image,                                    
                        'env': envlist,
                        'volumeMounts': [ self.default_volumes_mount['tmp'] ],
                        'securityContext': oc.od.settings.desktop_pod[currentcontainertype].get('securityContext'),
                        'resources': oc.od.settings.desktop_pod[currentcontainertype].get('resources')                             
                    }   
                )
                self.logger.debug('pod container created %s', currentcontainertype )

        # Add ssh service 
        currentcontainertype = 'ssh'
        if  self.isenablecontainerinpod( authinfo, currentcontainertype ):
            self.logger.debug('pod container creating %s', currentcontainertype )
            image = self.getimagecontainerfromauthlabels( currentcontainertype, authinfo )
            pod_manifest['spec']['containers'].append( { 
                                    'name': self.get_containername( currentcontainertype, userinfo.userid, myuuid ),
                                    'imagePullPolicy':  oc.od.settings.desktop_pod[currentcontainertype].get('pullpolicy'),
                                    'image': image,                                    
                                    'env': envlist,
                                    'securityContext': oc.od.settings.desktop_pod[currentcontainertype].get('securityContext'),
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
            image = self.getimagecontainerfromauthlabels( currentcontainertype, authinfo )
            pod_manifest['spec']['containers'].append( { 
                                    'name': self.get_containername( currentcontainertype, userinfo.userid, myuuid ),
                                    'imagePullPolicy':  oc.od.settings.desktop_pod[currentcontainertype].get('pullpolicy'),
                                    'image': image,                                  
                                    'env': envlist,
                                    'volumeMounts': list_volumeMounts,
                                    'resources': oc.od.settings.desktop_pod[currentcontainertype].get('resources')                                      
                                }   
            )
            self.logger.debug('pod container created %s', currentcontainertype )

        # Add storage service 
        currentcontainertype = 'storage'
        if  self.isenablecontainerinpod( authinfo, currentcontainertype ):
            self.logger.debug('pod container creating %s', currentcontainertype )
            image = self.getimagecontainerfromauthlabels( currentcontainertype, authinfo )
            pod_manifest['spec']['containers'].append( { 
                                    'name': self.get_containername( currentcontainertype, userinfo.userid, myuuid ),
                                    'imagePullPolicy': oc.od.settings.desktop_pod[currentcontainertype].get('pullpolicy'),
                                    'image': image,                                 
                                    'env': envlist,
                                    'volumeMounts':  list_pod_allvolumeMounts,
                                    'resources': oc.od.settings.desktop_pod[currentcontainertype].get('resources')                      
                                }   
            )
            self.logger.debug('pod container created %s', currentcontainertype )

        # Add rdp service 
        currentcontainertype = 'rdp'
        if  self.isenablecontainerinpod( authinfo, currentcontainertype ):
            self.logger.debug('pod container creating %s', currentcontainertype )
            image = self.getimagecontainerfromauthlabels( currentcontainertype, authinfo )
            pod_manifest['spec']['containers'].append( { 
                                    'name': self.get_containername( currentcontainertype, userinfo.userid, myuuid ),
                                    'imagePullPolicy': oc.od.settings.desktop_pod[currentcontainertype].get('pullpolicy'),
                                    'image': image, 
                                    'securityContext': oc.od.settings.desktop_pod[currentcontainertype].get('securityContext'),                                
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
                # message = f"b. {object_type.lower()} {event_object.message}" 
                message = f"b.{event_object.message}"      
            else:
                message = f"b.{event_object.reason}"
                
            self.logger.info(message)
            self.on_desktoplaunchprogress( message )

            if object_type == 'Warning':
                # These events are to warn that something might go wrong
                self.logger.warning( f"something might go wrong object_type={object_type} reason={event_object.reason} message={event_object.message}")
                self.on_desktoplaunchprogress( f"b. something might go wrong {object_type} reason={event_object.reason} message={event_object.message}" )
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
        if myPod.status.phase != 'Running':
            # something wrong 
            return f"Your pod does not start, status {myPod.status.phase}" 
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
        access_userid = userinfo.userid
        access_provider = authinfo.provider

        try: 
            label_selector= 'access_userid='    + access_userid + \
                            ',type='            + self.x11servertype_embeded + \
                            ',appname='         + appname

            if oc.od.settings.desktop['authproviderneverchange'] is True:
                label_selector += ',access_provider='  + access_provider

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

    def findDesktopByUser(self, authinfo, userinfo, **kwargs ):
        ''' find a desktop for authinfo and userinfo '''
        ''' return a desktop object '''
        ''' return None if not found '''
        self.logger.info( '' )
        
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

    def getcontainerfromPod( self,  prefix, pod ):
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

    def pod2desktop( self, pod, userinfo=None ):
        """pod2Desktop convert a Pod to Desktop Object
        Args:
            myPod ([V1Pod): kubernetes.client.models.v1_pod.V1Pod
            userinfo ([]): userinfo set to None by default
                           to obtain vnc_password, defined userinfo context 
        Returns:
            [ODesktop]: oc.od.desktop.ODDesktop Desktop Object
        """
        desktop_container_id   = None
        storage_container_id   = None
        desktop_container_name = None
        desktop_interfaces     = None

        # read metadata annotations 'k8s.v1.cni.cncf.io/networks-status'
        network_status = pod.metadata.annotations.get( 'k8s.v1.cni.cncf.io/networks-status' )
        self.logger.debug( f"pod.metadata.annotations.get('k8s.v1.cni.cncf.io/networks-status') is {network_status}" )
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

                name = interface.get('interface')
                ips = interface.get('ips')
                mac = interface.get('mac')
                
                # check if type is valid
                if  not isinstance( ips, list ) or \
                    not isinstance( name, str ) or \
                    not isinstance( mac, str ) :
                    # skipping bad data type
                    continue

                if len(ips) == 1:
                    ips = ips[0]
           
                desktop_interfaces.update( { name : { 'mac': mac, 'ips': str(ips) } } )

       
        desktop_container = self.getcontainerfromPod( self.graphicalcontainernameprefix, pod )
        if desktop_container :
            desktop_container_id = desktop_container.container_id
            desktop_container_name = desktop_container.name
        
        internal_pod_fqdn = self.build_internalPodFQDN( pod )

        # read the vnc password from kubernetes secret
        vnc_password = None
        if userinfo :     
            vnc_secret = oc.od.secret.ODSecretVNC( self.namespace, self.kubeapi )
            vnc_secret_password = vnc_secret.read( userinfo )  
            if isinstance( vnc_secret_password, client.models.v1_secret.V1Secret ):
                vnc_password = oc.od.secret.ODSecret.read_data( vnc_secret_password, 'password' )

     
        storage_container = self.getcontainerfromPod( self.storagecontainernameprefix, pod )
        if storage_container :
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


    def extract_userinfo_authinfo_from_pod( self, myPod:client.models.v1_pod.V1Pod ):
        """extract_userinfo_authinfo_from_pod
            Read labels (authinfo,userinfo) from a pod
        Args:
            myPod (V1Pod): Pod

        Returns:
            (tuple): (authinfo,userinfo) AuthInfo, AuthUser
        """
        # fake an authinfo object
        authinfo = AuthInfo( provider=myPod.metadata.labels.get('access_provider') )
        # fake an userinfo object
        userinfo = AuthUser( { 'userid':myPod.metadata.labels.get('access_userid'), 'name':  myPod.metadata.labels.get('access_username') } )
        return (authinfo,userinfo)


    def find_userinfo_authinfo_by_desktop_name( self, name:str ):
        self.logger.debug('')
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
