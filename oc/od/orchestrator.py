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
import oc.od.settings
import docker
import oc.lib 
import oc.auth.namedlib
import os

import time
import datetime
import iso8601

import yaml
import json
import distutils.util
import uuid


from kubernetes import client, config, watch
from kubernetes.stream import stream
from kubernetes.stream.ws_client import ERROR_CHANNEL
from kubernetes.client.rest import ApiException

import oc.lib

from oc.od.desktop import ODDesktop
import oc.od.volume         # manage volume for desktop
import oc.od.secret         # manage secret for kubernetes
from   oc.auth.authservice  import AuthInfo, AuthUser # to read AuthInfo and  


logger = logging.getLogger(__name__)

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
        if len(self.desktoplaunchprogress): 
            self.desktoplaunchprogress(self, key, *args)

    def __init__(self, nodehostname=None):
        if nodehostname is not None and type(nodehostname) is not str: 
            raise ValueError('Invalid nodehostname, must be a string or None: type nodehostname = %s ' % str(type(nodehostname)))

        # container name is g-UUID
        self.graphicalcontainernameprefix   = 'g'   # graphical container letter prefix 
        # printer name is p-UUID
        self.printercontainernameprefix     = 'p'   # printer container letter prefix 
        # sound name is p-UUID
        self.soundcontainernameprefix       = 's'   # sound container letter prefix
        # name separtor only for human read 
        self.containernameseparator         = '-'   # separator

        self._nodehostname = nodehostname
        self.desktoplaunchprogress = oc.pyutils.Event()        
        self.x11servertype          = 'x11server'        
        self.x11servertype_embeded  = 'x11serverembeded' 
        self.printerservertype      = 'cupsserver'
        self.soundservertype        = 'pulseserver'
        self.endpoint_domain        = 'desktop'
        self._myinfra = None
        self.name = 'base'
  
    def get_graphicalcontainername( self, container_name ):
        return  self.graphicalcontainernameprefix   + \
                self.containernameseparator         + \
                oc.auth.namedlib.normalize_name( container_name )

    def get_printercontainername( self, container_name ):
        return  self.printercontainernameprefix     + \
                self.containernameseparator         + \
                oc.auth.namedlib.normalize_name( container_name )

    def get_soundcontainername( self, container_name ):
        return  self.soundcontainernameprefix       + \
                self.containernameseparator         + \
                oc.auth.namedlib.normalize_name( container_name )

    def __del__(self):
        self.close()
        
    def close(self):
       if self._myinfra is not None:
            self._myinfra.close()
            self._myinfra = None

    def mkvnc_password(self):
        return oc.lib.randomStringwithDigitsAndSymbols(10)
   
    def resumedesktop(self, authinfo, userinfo, **kwargs):
        raise NotImplementedError('%s.desktop' % type(self))

    def createdesktop(self, authinfo, userinfo, **kwargs):
        raise NotImplementedError('%s.createdesktop' % type(self))

    def build_desktopvolumes( self, authinfo, userinfo, **kwargs):
        raise NotImplementedError('%s.build_desktopvolumes' % type(self))

    def findDesktopByUser( self, authinfo, userinfo, **kwargs ):
        raise NotImplementedError('%s.findDesktopByUser' % type(self))

    def removedesktop(self, authinfo, userinfo, args={}):
        raise NotImplementedError('%s.removedesktop' % type(self))

    def get_auth_env_dict( self, authinfo, userinfo ):
        raise NotImplementedError('%s.get_auth_env_dict' % type(self))

    def getapplist(self, authinfo, userinfo, **kwargs):
        raise NotImplementedError('%s.getapplist' % type(self))

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
                    mycontainer['oc.launch']        = container.labels.get('oc.launch')
                    mycontainer['oc.displayname']   = container.labels.get('oc.displayname')
                    # add the object to the result array
                    result.append( mycontainer )
                except Exception as e:
                    logger.error( 'listContainerApps:add entry %s', str(e))
        except Exception as e:
            logger.error( '%s', str(e) ) 

        return result
        
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

    def userconnectcount(self, desktop, timeout=2000):
        ''' return  /composer/connectcount.sh value '''
        ''' return  -1 if failed '''
        self.logger.info('')
        nReturn = -1
        if type(desktop) is not ODDesktop:
            raise ValueError('invalid desktop object type' )

        # call bash script in oc.user 
        # bash script 
        # !/bin/bash
        # COUNT=$(netstat -t | grep 'ESTABLISHED' | grep 6081 | wc -l)
        # echo $COUNT
        command = [ '/composer/connectcount.sh' ]      
        result = self.execwaitincontainer( desktop, command, timeout)
        if type(result) is not dict:
            return nReturn

        self.logger.info( 'command %s , exitcode %s output %s', command, str(result.get('ExitCode')), result.get('stdout') )
        if result.get('ExitCode') == 0 and result.get('stdout'):
            try:
                nReturn = int(result.get('stdout'))
            except ApiException as e:
                self.logger.error(str(e))
        return nReturn

    def waitForDesktopProcessReady(self, desktop, callback_notify, nTimeout=42):
        self.logger.info('')

        nCountMax = nTimeout
        # check if supervisor has stated all processs
        nCount = 1
        bListen = { 'x11server': False, 'spawner': False }
        while nCount < 42:
           time.sleep( 1 )
           # check if WebSockifyListening id listening on tcp port 6081
           if bListen['x11server'] is False:
                messageinfo = 'Starting desktop graphical service %ds / %d' % (nCount,nCountMax) 
                callback_notify(messageinfo)
                bListen['x11server'] = self.waitForServiceListening( desktop, port=oc.od.settings.desktopservicestcpport['x11server'] )
                self.logger.info('service:x11server return %s', str(bListen['x11server']))
                nCount += 1

           # check if spawner is ready 
           if bListen['x11server'] is True:
                messageinfo = 'Starting desktop spawner service %ds / %d' % (nCount,nCountMax) 
                callback_notify(messageinfo)
                bListen['spawner']  = self.waitForServiceListening( desktop, port=oc.od.settings.desktopservicestcpport['spawner'] )
                self.logger.info('service:spawner return %s', str(bListen['spawner']))  
                if bListen['spawner'] is True:                          
                    callback_notify('Desktop services are ready after %d s' % (nCount) )              
                    return True
                nCount += 1
        
        self.logger.warning('waitForDesktopProcessReady not ready services status: %s', bListen )
        return False

      
    def waitForServiceListening(self, desktop, port, timeout=1000):     
        '''    waitForServiceListening tcp port '''
        self.logger.info('')
        # Note the same timeout value is used twice
        # for the wait_port command and for the exec command         
        
        if type(desktop) is not ODDesktop:
            raise ValueError('invalid desktop object type' )
        
        binding = '{}:{}'.format(desktop.ipAddr, str(port))
        command = [ '/usr/local/bin/wait-port', '-t', str(timeout), binding ]       
        result = self.execwaitincontainer( desktop, command, timeout)
        self.logger.info( 'command %s , return %s output %s', command, str(result.get('exit_code')), result.get('stdout') )
     
        if isinstance(result, dict):      
            return result.get('ExitCode') == 0
        else:
            return False


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
            userinfo (): user informat                            ions 

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
                            'access_provider': access_provider, 
                            'access_userid': access_userid,
                            'appname': appname }
        else :
            myFilter = {    'type': self.x11servertype, 
                            'access_provider': access_provider, 
                            'access_userid': access_userid }

        myInfra = self.createInfra( self.nodehostname )

        assert access_userid, "userid is undefined"
        list_containers= myInfra.listContainersFilter( access_userid, myFilter )
      
        if type(list_containers) is list:
            len_list_containers = len( list_containers )
            if len_list_containers > 1 :
                self.logger.error( 'query too much desktop found with filter %s, attended 1 , get %d', myFilter, len_list_containers )                
                self.logger.error( 'dump result %s', list_containers )                
            # This loop read the fisrt one and break
            for c in list_containers:                                
                ipAddr = myInfra.getDesktopIpAddr( c.id, kwargs.get('defaultnetworknetuserid') )
                myDesktop = oc.od.desktop.ODDesktop( nodehostname=self.nodehostname, ipAddr=ipAddr, status=c.status, desktop_id=c.id, container_id=c.id, vncPassword=c.labels['vnc_password'] )
                break   
        
        return myDesktop


   
    def createvolume(self, prefix, userinfo, authinfo, removeifexist=False, **kwargs ):
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

    def prepareressources(self, authinfo, userinfo, **kwargs):
        self.logger.info('externals ressources are not supported in docker mode')  

    def getsecretuserinfo(self, authinfo, userinfo):  
        ''' cached userinfo are not supported in docker mode '''    
        ''' return an empty dict '''
        self.logger.info('get cached userinfo are not supported in docker mode')
        return {} 

    def build_desktopvolumes( self, authinfo, userinfo, **kwargs):
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
        if kwargs.get( 'desktopuserusehostsharememory' ) :
            # add -v /dev/shm:/dev/shm        
            volumes.append('/dev/shm')
            volumesbind.append('/dev/shm:/dev/shm')

        # if home is volume, create a volume or reuse the volume
        if kwargs.get('desktophomedirectorytype') == 'volume':        
            # Map the home directory
            myvol = self.createvolume('home', userinfo, authinfo, removeifexist=False)        
            if myvol is not None:
                volumes.append( kwargs.get('balloon_defaulthomedirectory') )
                volumesbind.append(myvol.name + ':' + kwargs.get('balloon_defaulthomedirectory') )                
        
        self.logger.debug('end')
        return (volumes, volumesbind)
  

    def countdesktop(self):
        return  oc.od.infra.ODInfra().countdesktop()

    def removedesktop(self, authinfo, userinfo, args={}):
        status = None
        remove_volume_home = False
        if userinfo.name == 'Anonymous':
           remove_volume_home = True

        myDesktop = self.findDesktopByUser(authinfo, userinfo, **args)
        if type(myDesktop) is ODDesktop:
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

        if bRemove and isinstance( volume_binds, dict) :
            # Remove volume if desktop home directory type is volume 
            if oc.od.settings.getdesktop_homedirectory_type() == 'volume':
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

    def execincontainer_metappli( self, containerid, command):
        myinfra = self.createInfra( self.nodehostname )
        return myinfra.execincontainer( containerid, command, detach=True)

    def execwaitincontainer( self, desktop, command, timeout=1000):
        myinfra = self.createInfra( self.nodehostname )
        return myinfra.execincontainer( desktop.id, command)

    def execincontainer( self, containerid, command):
        """exec command in container

        Args:
            containerid (str): container id
            command (str): command to execute
            
        Returns:
            (dict): Dictionary of values returned by the endpoint, 
                    stdout entry
        """
        myinfra = self.createInfra( self.nodehostname )
        return myinfra.execincontainer( containerid, command)

    def getappinstance( self, app, userid):        
        self.logger.debug( "app=%s, userid=%s", app['name'], userid )
        myinfra = self.createInfra( self.nodehostname )
        container = myinfra.findRunningContainerforUserandImage( userid, app['uniquerunkey'])
        if container:
            container.app = app        
        self.logger.debug( 'return container=%s', str(container) )
        return container

    def get_auth_env_dict( self, authinfo, userinfo  ):
        return {}

    def build_volumefromvolumebind(self,volumebind):
        # the entry /home/balloon from the volume bind list
        # "Binds" : [
        # '/mnt/desktop/home/4e27356a-3207-4644-8aa7-9e6eb3e29d32:/home/balloon',
        #             'tmp4e27356a-3207-4644-8aa7-9e6eb3e29d32:/tmp'
        #           ]
        volume = []
        if not isinstance(volumebind, list):
            return volume

        for v in volumebind:
            arv = v.split(':')
            if len(arv) > 1:
                volume.append(arv[1])
        return volume

    def applyappinstancerules_homedir( self, authinfo, app ):
        homedir_disabled        = False      # by default all application share the user homedir

        # Check if there is a specify rules to start this application
        rules = app.get('rules')
        if rules is dict  :
            # Check if there is a homedir rule
            rule_homedir =  rules.get('homedir')
            if type(rule_homedir) is dict:
                # read the default rule first 
                rule_homedir_default = rule_homedir.get('default', True )
                if rule_homedir_default is False:
                        homedir_disabled = True
                # list user context tag 
                # check if user auth tag context exist
                if authinfo.data and type( authinfo.data.get('labels') ) is dict :
                    for kn in rule_homedir.keys():
                        for ka in authinfo.data.get('labels') :
                            if kn == ka :
                                if type(rule_homedir.get(kn)) is bool:
                                    homedir_disabled = not rule_homedir.get(kn)
                                break
                        if kn == ka :
                                break
        return homedir_disabled        

    def applyappinstancerules_network( self, authinfo, app ):

        # set default context value 
        network_disabled        = False      # network is enabled by default
        context_network_name    = None       # acl network is not set by default
        context_network_dns     = None       # to change the DNSServer used by a container

        # Check if there is a specify rules to start this application
        rules = app.get('rules')
        if type(rules) is dict  :
            # Check if there is a network rule
            rule_network =  rules.get('network')
            if type(rule_network) is dict:
                # read the default context first 
                rule_network_default = rule_network.get('default', True)
                if rule_network_default is False:
                    network_disabled = True
              
                if type(rule_network_default) is dict:
                    context_network_name = rule_network_default.get('name')
                    context_network_dns  = rule_network_default.get('dns')
                    network_disabled = False    

                # list user context tag 
                # check if user auth tag context exist
                if authinfo.data and type( authinfo.data.get('labels') ) is dict :
                    for kn in rule_network.keys():
                        for ka in authinfo.data.get('labels') :
                            if kn == ka :
                                context_network_name = rule_network.get(kn).get('name')
                                context_network_dns  = rule_network.get(kn).get('dns')
                                network_disabled = False
                                break
                        if kn == ka :
                                break

                # context_network_dns must be an array for docker api
                if type( context_network_dns ) is str:
                    # convert context_network_dns as list if need
                    context_network_dns = [ context_network_dns ]

        return (network_disabled, context_network_name, context_network_dns)

    
    def createappinstance(self, myDesktop, app, authinfo, userinfo={}, userargs=None, **kwargs ):                    

        assert type(myDesktop) is ODDesktop, "myDesktop invalid type %r" % type(myDesktop)
        
        # connnect to the dockerd 
        infra = self.createInfra( myDesktop.nodehostname )
       
        desktop = infra.getcontainer( myDesktop.container_id )

        # get volunebind from the running x11 container
        volumebind = desktop.attrs["HostConfig"]["Binds"]

        # apply network rules 
        (network_disabled, context_network_name, context_network_dns) = self.applyappinstancerules_network( authinfo, app )
        # apply homedir rules
        homedir_disabled = self.applyappinstancerules_homedir( authinfo, app )
       
      
        network_name    = None
        # make sure env DISPLAY exists
        display         = oc.od.settings.desktopenvironmentlocal.get('DISPLAY', ':0.0')
        # make sure env PULSE_SERVER exists
        pulse_server    = oc.od.settings.desktopenvironmentlocal.get('PULSE_SERVER', '/tmp/.pulse.sock')
        # make sure env CUPS_SERVER exists
        cups_server     = oc.od.settings.desktopenvironmentlocal.get('CUPS_SERVER', '/tmp/.cups.sock')
        # read locale language from USER AGENT
        language        = userinfo.get('locale', 'en_US')
        lang            = language + '.UTF-8'    

        # copy a env dict from configuration file
        env = oc.od.settings.desktopenvironmentlocal.copy()
        
        # update env with user's lang value 
        env.update ( {  'DISPLAY'       : display,
                        'PULSE_SERVER'  : pulse_server,
                        'CUPS_SERVER'   : cups_server,
                        'LANGUAGE'	    : language,
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
                        'PARENT_ID' 	: desktop.id, 
                        'PARENT_HOSTNAME'   : self.nodehostname
        } )

        # Add specific vars      
        timezone = kwargs.get('timezone')
        if type(timezone) is str and len(timezone) > 1:     env['TZ'] = timezone
        if type(userargs) is str and len(userargs) > 0:     env['APPARGS'] = userargs
        if app.get('uniquerunkey'):                         env['APPUNIQUERUNKEY'] = app.get('uniquerunkey') 
        if oc.od.settings.desktopusedbussession :           env['OD_DBUS_SESSION_BUS'] = oc.od.settings.desktopusedbussession
        if oc.od.settings.desktopusedbussystem :            env['OD_DBUS_SYSTEM_BUS'] = oc.od.settings.desktopusedbussystem
        if hasattr(authinfo, 'data'):                       env.update(authinfo.data.get('environment', {}))

        if homedir_disabled is True:
            # remove home dir set by image context metadata
            for v in volumebind:
                arv = v.split(':')
                if len(arv) > 1:
                    if arv[1].startswith(oc.od.settings.balloon_defaulthomedirectory):
                        volumebind.remove(v)
                        break # only one balloon_defaulthomedirectory in volumebind

        volumes = self.build_volumefromvolumebind(volumebind)
        command = '/composer/appli-docker-entrypoint.sh'
        
        # network_mode (str) – One of:
        #   bridge Create a new network stack for the container on on the
        #   bridge network.
        #   none No networking for this container.
        #   container:<name|id> Reuse another container’s network stack.
        #   host Use the host network stack.
        # Warning: if desktopusex11unixsocket is set then aclnetworkname is not
        # used
        if oc.od.settings.desktopsharednetworkstack:
            network_mode = 'container:' + desktop.id    # by default
        if context_network_name :
            network_name = context_network_name
            network_mode = context_network_name
        if network_disabled :
            network_mode = 'none'
            network_name = None
        
        extra_hosts = {}
        try:
            host_imagelabel = app.get('oc.extra_hosts')
            if host_imagelabel is not None:
                extra_hosts = json.loads(host_imagelabel)
        except Exception as e:
            self.logger.warning('Failed to parse extra_hosts: %s', e)

        # “container: <_name-or-ID_>"
        # Join another (“shareable”) container’s IPC namespace.
        if oc.od.settings.desktopusershareipcnamespace == 'shareable':
            ipc_mode = 'container:' + desktop.id
        else:
            ipc_mode = None

        # share process name space
        pid_mode = 'container:' + desktop.id if oc.od.settings.desktopusershareprocessnamespace else None

        # container name
        # DO NOT USE TOO LONG NAME for container name  
        # filter can failed or retrieve invalid value in case userid + app.name + uuid
        # limit length is not defined but take care 
        _containername = userinfo.get('name','name') + '_' + oc.auth.namedlib.normalize_imagename( app['name'] + '_' + str(uuid.uuid4().hex) )
        containername =  oc.auth.namedlib.normalize_name( _containername )

        host_config = {
                'auto_remove'   : oc.od.settings.desktopcontainer_autoremove,
                'binds'         : volumebind,
                'extra_hosts'   : extra_hosts,
                'ipc_mode'      : ipc_mode,
                'network_mode'  : network_mode,
                'pid_mode'      : pid_mode,
                'dns'           : context_network_dns,
                'security_opt'  : oc.od.settings.desktopsecurityopt,
                'privileged'    : oc.od.settings.desktopdockerprivileged,
                'cap_add'       : oc.od.settings.desktopcapabilities.get('add'),
                'cap_drop'      : oc.od.settings.desktopcapabilities.get('drop')
        }

        # set shm_size if image require
        if app.get('shm_size') :   host_config.update(  { 'shm_size' : app.get('shm_size') } )
        # set mem_limit if image require
        if app.get('memory') :     host_config.update(  { 'mem_limit' : app.get('memory') } )

        appinfo = infra.createcontainer(
            image = app['id'],
            name  =  containername,
            command = command,
            environment = env,
            user = oc.od.settings.getballoon_name(),
            network_disabled = network_disabled,
            labels = {                
                'access_type'           : authinfo.provider,
                'access_username'       : userinfo.get('name'),
                'access_userid'         : userinfo.userid,
                'access_parent_id'      : desktop.id,
                'access_parent_hostname': self.nodehostname
            },
            volumes = volumes,
            host_config = host_config,
            network_name = network_name
        )

        if type(appinfo) is not dict :
            return None

        appinstance_id = appinfo.get('Id')
        if appinstance_id is None:
            return None

        appinstance = infra.getcontainer(appinstance_id)
        if appinstance is None:
            return None
        
        infra.startcontainer(appinstance.id)
        return appinstance
        

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
        ipc_mode = oc.od.settings.desktopusershareipcnamespace
        env      = kwargs.get('env', {} )
        appname  = kwargs.get('appname')
        container_name = None
        
        # add a new VNC Password to the command line
        vncPassword = self.mkvnc_password()
        command.extend('--vncpassword {}'.format(vncPassword).split(' '))

        # compile a env list with the auth list  
        # translate auth environment to env 
        # env exist only in docker mode
        environment = authinfo.data.get('environment')
        if type(environment) is dict:
            for auth_env_built in environment.values():
                # each entry in authinfo.data.environment is a dict 
                env.update( auth_env_built )

        # convert the dict env to a list of string key=value
        envlist = ['%s=%s' % kv for kv in env.items()]

        # if appname is None then create a desktop
        # set value as default type x11servertype
        # update labels values next
        # x11desktoptype can be :
        #   self.x11servertype 
        #       or
        #   self.x11servertype_embeded
        x11desktoptype = self.x11servertype

        labels = {  'access_provider':  authinfo.provider,
                    'access_userid':    userinfo.userid,
                    'access_username':  userinfo.name,
                    'type':             x11desktoptype,
                    'vnc_password':     vncPassword }

        # if appname is set then create a metappli labels
        # this will change and run the app
        if type(appname) is str:
            labels.update( {    'type':     self.x11servertype_embeded,
                                'appname':  appname } )
            container_name  = self.get_graphicalcontainername( userinfo.userid + '-' + appname )
        else:
            container_name  = self.get_graphicalcontainername( userinfo.userid )

        # build storage volume or directory binding
        # callback_notify( 'Build volumes' )
        volumes, volumebind = self.build_desktopvolumes(authinfo, userinfo, **kwargs)
        myDesktop = None
        
        try:
            myinfra = self.createInfra( self.nodehostname )
            c = myinfra.getdockerClientAPI()
            # callback_notify( 'Create your network' )
            networking_config = c.create_networking_config({oc.od.settings.defaultnetworknetuser: c.create_endpoint_config()})
            host_config       = c.create_host_config(   auto_remove=True, 
                                                        binds=volumebind, 
                                                        privileged=oc.od.settings.desktopdockerprivileged, 
                                                        ipc_mode=ipc_mode,
                                                        cap_add=oc.od.settings.desktopcapabilities.get('add'),
                                                        cap_drop=oc.od.settings.desktopcapabilities.get('drop') )
            # callback_notify( 'Create your desktop' )
            mydesktopcreate_container = c.create_container( name=container_name,
                                                            image=image,
                                                            command=command,
                                                            environment=envlist,                                        
                                                            networking_config=networking_config,
                                                            labels=labels,
                                                            volumes=volumes,
                                                            host_config=host_config,
                                                            detach=True
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
                                        vncPassword=vncPassword
                                        )                
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
        ipAddr = myinfra.getDesktopIpAddr( container.id, oc.od.settings.defaultnetworknetuserid  )                
        myDesktop = ODDesktop(  nodehostname=self.nodehostname,
                                container_id=container.id,
                                desktop_id = container.id,
                                status=container.status,
                                ipAddr=ipAddr,
                                vncPassword=container.labels['vnc_password']
                    )
        return myDesktop

    def isgarbagable( self, container, expirein, force=False ):
        bReturn = False
        myDesktop = self.container2desktop( container )
        if force is False:
            nCount = self.userconnectcount( myDesktop )
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
                self.logger.debug( 'env has detected $KUBERNETES_SERVICE_HOST and $KUBERNETES_SERVICE_PORT' )
                self.logger.debug( 'config.load_incluster_config start')
                config.load_incluster_config() # set up the client from within a k8s pod
                self.logger.debug( 'config.load_incluster_config done')
            else:
                self.logger.debug( 'config.load_kube_config not in cluster mode')
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
            client.configuration.assert_hostname = False
            self.kubeapi = client.CoreV1Api()
            self.namespace = oc.od.settings.namespace
            self.bConfigure = True
            self.name = 'kubernetes'

        except Exception as e:
            self.bConfigure = False
            self.logger.warning( '%s', str(e) ) # this is not an error in docker configuration mode, do not log as an error but as warning

        self.logger.debug( 'ODOrchestratorKubernetes __init__ done configure=%s', str(self.bConfigure) )

    def close(self):
        #self.kupeapi.close()
        pass

    def is_configured(self): 
        bReturn = False
        try:
            if self.bConfigure :
                # run a dummy node list to check if kube is working
                self.kubeapi.list_node()
                bReturn = True
        except Exception as e:
            self.logger.error( str(e) )
        return bReturn

    def findSecretByUser( self,  authinfo, userinfo, secret_type ):
        secret = oc.od.secret.selectSecret( self.namespace, self.kubeapi, secret_type )
        return secret.read_credentials(userinfo)

    def get_podname( self, pod_name ):
        return oc.auth.namedlib.normalize_name(pod_name)        
 
    def get_name( self, container_name ):
        return oc.auth.namedlib.normalize_name( container_name ) 

    def get_labelvalue( self, label_value):
        return oc.auth.namedlib.normalize_label( label_value )

    def logs( self, authinfo, userinfo ):
        strlogs = ''
        myPod =  self.findPodByUser(authinfo, userinfo)

        if myPod is None :            
            self.logger.info( 'No pod found for user %s ',  userinfo.userid )
            return strlogs

        try:
            myDesktop = self.pod2desktop( myPod )
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

    def build_desktopvolumes( self, authinfo, userinfo, **kwargs):
        
        volumes = {}        # set empty volume dict by default
        volumes_mount = {}  # set empty volume_mount dict by default
    
        if oc.od.settings.desktopuselocaltime is True:
            volumes['localtime']       = { 'name': 'localtime', 'hostPath': { 'path': '/etc/localtime' } }
            volumes_mount['localtime'] = { 'name': 'localtime', 'mountPath' : '/etc/localtime' }

        if oc.od.settings.desktopuserusehostsharememory is True:
            volumes['shm']       = { 'name': 'shm', 'emptyDir': { 'medium': 'Memory', 'sizeLimit': '2Gi' } }
            volumes_mount['shm'] = { 'name': 'shm', 'mountPath' : '/dev/shm' }
        
        #
        # add dedicated tmp volume for /tmp/ X11 unix socket support
        # volumes['tmp']       = { 'name': 'tmp',  'hostPath': { 'path': '/var/abcdesktop/pods' } }
        # volumes_mount['tmp'] = { 'name': 'tmp',  'mountPath': '/tmp', 'subPathExpr': '$(POD_NAME)' }
        volumes['tmp']       = { 'name': 'tmp',  'emptyDir': { 'sizeLimit': '8Gi' } }
        volumes_mount['tmp'] = { 'name': 'tmp',  'mountPath': '/tmp' }

        mysecretdict = self.list_dict_secret_data( authinfo, userinfo, access_type='auth' )
        for secret_auth_name in mysecretdict.keys():
            # https://kubernetes.io/docs/concepts/configuration/secret
            # create an entry eq: 
            # /var/secrets/abcdesktop/ntlm
            # /var/secrets/abcdesktop/cntlm
            # /var/secrets/abcdesktop/kerberos
            secretmountPath = oc.od.settings.desktopsecretsrootdirectory + mysecretdict[secret_auth_name]['type'] 
            # mode is 644 -> rw-r--r--
            # Owing to JSON limitations, you must specify the mode in decimal notation.
            # 644 in decimal equal to 420
            volumes[secret_auth_name]       = { 'name': secret_auth_name, 'secret': { 'secretName': secret_auth_name, 'defaultMode': 420  } }
            volumes_mount[secret_auth_name] = { 'name': secret_auth_name, 'mountPath':  secretmountPath }

        #
        # if type is self.x11servertype then keep user home dir data
        # else do not use the default home dir to metapplimode
        if  kwargs[ 'type' ]  == self.x11servertype and \
            oc.od.settings.getdesktop_homedirectory_type() == 'persistentVolumeClaim':
            
            self.on_desktoplaunchprogress('Building home dir data storage')
            volume_home_name = self.get_volumename( 'home', userinfo )
            # Map the home directory
            volumes['home'] = { 'name': volume_home_name } # home + userid 
            if authinfo.provider == 'anonymous':
                volumes['home'].update( {'emptyDir': {} } )            
            else:
                volumes['home'].update( { 'persistentVolumeClaim': { 'claimName': oc.od.settings.desktoppersistentvolumeclaim } } )

            subpath_name = oc.auth.namedlib.normalize_name( userinfo.name )
            volumes_mount['home'] = {   'name'      : volume_home_name,                                 # home + userid
                                        'mountPath' : oc.od.settings.getballoon_defaulthomedirectory(), # /home/balloon
                                        'subPath'   : subpath_name                                      # userid
            }
            self.logger.debug( 'volume mount : %s %s', 'home', volumes_mount['home'] )
            self.logger.debug( 'volumes      : %s %s', 'home', volumes['home'] )

       
        rules = oc.od.settings.desktoppolicies.get('rules', {} )
        mountvols = oc.od.volume.selectODVolumebyRules( authinfo, userinfo,  rules.get('volumes') )
        for mountvol in mountvols:                        
        
            fstype = mountvol.fstype
            volume_name = self.get_volumename( mountvol.name, userinfo )
            # mount the remote home dir as a flexvol
            # WARNING ! if the flexvol mount failed, pod will starts 
            # abcdesktop/cifs always respond a success
            # in case of failure access right is denied                
            # the flexvolume driver abcdesktop/cifs MUST be deploy on each node

            # Flex volume use kubernetes secret                    
            # Kubernetes secret as already been created by prepareressource function 
            # Read the secret and use it

            driver_type =  self.namespace + '/' + fstype

            self.on_desktoplaunchprogress('Building flexVolume storage data for driver ' + driver_type )

            secret = oc.od.secret.selectSecret( self.namespace, self.kubeapi, prefix=mountvol.name, secret_type=fstype )
            
            # read the container mount point from the secret
            # for example /home/balloon/U             
            # Read data from secret    
            secret_name         = secret.get_name( userinfo )
            secret_dict_data    = secret.read_data( userinfo )
            mountPath           = secret_dict_data.get( 'mountPath')
            networkPath         = secret_dict_data.get( 'networkPath' )
            
            # Check if the secret contains valid datas 
            if mountPath is None :
                self.logger.error( 'Invalid value for mountPath read from secret' )
                continue

            if networkPath is None:
                self.logger.error( 'Invalid value for networkPath read from secret' )
                continue

            volumes_mount[mountvol.name] = {'name': volume_name, 'mountPath': mountPath }                        

            # Default mount options
            mountOptions =  'uid=' + str( oc.od.settings.getballoon_uid() ) + ',' + \
                            'gid=' + str( oc.od.settings.getballoon_gid() )
                            
            # if a volume mountOptions exists, concat the mountvol.mountOptions
            if type(mountvol.mountOptions) is str and len(mountvol.mountOptions) > 0:
                mountOptions = mountOptions +  ',' + mountvol.mountOptions
            self.logger.info( 'flexvolume: read secret %s to mount %s', secret_name, networkPath )

            volumes[mountvol.name] = { 'name': volume_name,
                                        'flexVolume' : {
                                            'driver': driver_type,
                                            'fsType': fstype,
                                            'secretRef' : { 'name': secret_name },
                                            'options'   : { 'networkPath':  networkPath, 
                                                            'mountOptions': mountOptions }
                                        }
            }

            self.logger.debug( 'volume mount : %s %s', mountvol.name, volumes_mount[mountvol.name] )
            self.logger.debug( 'volumes      : %s %s', mountvol.name, volumes[mountvol.name] )
        
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
          
            resp = stream( self.kubeapi.connect_get_namespaced_pod_exec, 
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
                if respdict.get('status') == 'Success':
                    result['ExitCode'] = 0
                exit_code = respdict.get('ExitCode')
                if exit_code is not None:
                    result['ExitCode'] = exit_code

        except Exception as e:
            self.logger.error( 'command exec failed %s', str(e)) 

        return result


    def removePod( self, myPod, remove_volume_home=False ):
        ''' remove kubernetes pod '''
        v1status = None
        try:
            #   The Kubernetes propagation_policy to apply
            #   to the delete. Default 'Foreground' means that child Pods to the Job will be deleted
            #   before the Job is marked as deleted.
            
            pod_name = myPod.metadata.name                
            self.logger.info( 'pod_name %s', pod_name)              
            self.nodehostname = myPod.spec.node_name

            # myinfra = self.createInfra()
            # self.stopContainerApps( myinfra, userinfo )

            # read the volume entry
            # podvolumes = None
            # try:
            #     podvolumes = myPod.spec.volumes
            # except Exception:
            #     pass
                
            # propagation_policy='Background'
            propagation_policy = 'Foreground'
            #grace_period_seconds = 0
            delete_options = client.V1DeleteOptions( propagation_policy = propagation_policy )
            # delete_options = client.V1DeleteOptions(propagation_policy = propagation_policy, grace_period_seconds=grace_period_seconds )
            
            
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
        dict_secret = self.list_dict_secret_data( authinfo, userinfo, access_type=None)
        for secret_name in dict_secret.keys():
            try:            
                v1status = self.kubeapi.delete_namespaced_secret( name=secret_name, namespace=self.namespace )
            except ApiException as e:
                self.logger.error('secret name %s can not be deleted: error %s', secret_name, e ) 

    def removedesktop(self, authinfo, userinfo, args={} ):
        ''' remove kubernetes pod for a give user '''
        ''' remove kubernetes secrets too '''
        statusPod = None
        self.logger.debug('')
        # by default do not remove user home directory
        remove_volume_home = args.get( 'remove_volume_home', False ) 
        if userinfo.name == 'Anonymous':
            # by default remove Anonymous home directory
            remove_volume_home = True
        myPod =  self.findPodByUser(authinfo, userinfo, args)
        if myPod :
            statusPod    = self.removePod( myPod, remove_volume_home )
            self.removesecrets( authinfo, userinfo )
        return statusPod
            
    def prepareressources(self, authinfo, userinfo, **kwargs):
        

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
        self.on_desktoplaunchprogress('Building auth secrets')

        #
        # Create ODSecretLDIF, build userinfo object secret ldif cache
        # This section is necessary to get user photo in user_controller.py
        # dump the ldif in kubernetes secret 
        if type(authinfo.protocol) is dict and authinfo.protocol.get('ldif') is True:
            secret = oc.od.secret.ODSecretLDIF( self.namespace, self.kubeapi )
            secret.create( authinfo, userinfo, data=userinfo )

        # Create environments secrets
        auth_environment = authinfo.data.get('environment')
        if type( auth_environment ) is dict :
            # for each auth protocol enabled
            for auth_env_built_key in auth_environment.keys():
                # each entry in authinfo.data.environment is a dict 
                # build a kubernetes secret with the auth values
                secret = oc.od.secret.selectSecret( self.namespace, self.kubeapi, prefix=None, secret_type=auth_env_built_key )
                secret.create( authinfo, userinfo, data=auth_environment.get(auth_env_built_key) )
    
        # Create flexvolume secrets
        rules = oc.od.settings.desktoppolicies.get('rules')
        if rules is not None:
          mountvols = oc.od.volume.selectODVolumebyRules( authinfo, userinfo,  rules.get('volumes') )
          for mountvol in mountvols:  
              # use as a volume defined and the volume is mountable
              fstype = mountvol.fstype # Get the fstype: for example 'cifs' or 'webdav'          
              # Flex volume use kubernetes secret, add mouting path
              arguments = { 'mountPath': mountvol.containertarget, 'networkPath': mountvol.networkPath }
              # Build the kubernetes secret 
              secret = oc.od.secret.selectSecret( self.namespace, self.kubeapi, prefix=mountvol.name, secret_type=fstype)
              auth_secret = secret.create( authinfo, userinfo, arguments )
              if auth_secret is None:
                 self.logger.error( 'Failed to build auth secret fstype=%s', fstype )


    def get_annotations_lastlogin_datetime(self):
        """get a new lastlogin datetime dict 

        Returns:
            dict: a dict with annotations lastlogindatetime.now()
                    format is {'annotations':{'lastlogin_datetime': datetime.datetime.now() } }
        """
        lastlogin_datetime = datetime.datetime.now()
        str_lastlogin_datetime = lastlogin_datetime.strftime("%Y-%m-%dT%H:%M:%S")
        annotations = {'annotations':{'lastlogin_datetime': str_lastlogin_datetime } }
        return annotations

    def read_pod_annotations_lastlogin_datetime(self, pod ):
        """read pod annotations data lastlogin_datetime value

        Args:
            pod (pod): kubernetes pod

        Returns:
            datetime: a datetime from pod.metadata.annotations.get('lastlogin_datetime')
        """
        str_lastlogin_datetime = pod.metadata.annotations.get('lastlogin_datetime')
        if type(str_lastlogin_datetime) is str:
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
        self.logger.info('')
        myDesktop = None
        myPod =  self.findPodByUser(authinfo, userinfo)

        if myPod is None :            
            self.logger.info( 'Pod name not found for user %s ',  userinfo.userid )
        else:
            newlabel = {"metadata":  self.get_annotations_lastlogin_datetime() }
            v1newPod = self.kubeapi.patch_namespaced_pod(   name=myPod.metadata.name, 
                                                            namespace=self.namespace, 
                                                            body=newlabel )
            myDesktop = self.pod2desktop( v1newPod )
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
        dict_secret = self.list_dict_secret_data( authinfo, userinfo, access_type='ldif' )
        raw_secrets = {}
        for key in dict_secret.keys():
            raw_secrets.update( dict_secret[key] )
        return raw_secrets

    def list_dict_secret_data( self, authinfo, userinfo, access_type=None ):
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
            label_selector =    'access_userid=' + access_userid + ',' + \
                                'access_provider='  + access_provider 
            if type(access_type) is str :
                label_selector += ',access_type=' + access_type 
           
            ksecret_list = self.kubeapi.list_namespaced_secret(self.namespace, label_selector=label_selector)
          
            for mysecret in ksecret_list.items:
                secret_dict[mysecret.metadata.name] = { 'type': mysecret.type, 'data': {} }
                for mysecretkey in mysecret.data:
                    b64data = mysecret.data[mysecretkey]
                    data = oc.od.secret.ODSecret.b64todata( b64data )
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

    '''
    def createappinstance(self, myDesktop, app, authinfo, userinfo={}, userargs=None, **kwargs ):                    

        assert type(myDesktop) is ODDesktop, "myDesktop invalid type %r" % type(myDesktop)
        
        # connnect to the dockerd 
        myPod = self.findPodByUser( authinfo, userinfo )

        # get the container id for the desktop object
        for c in myPod.spec.containers:
            if c.name[0] == self.graphicalcontainernameprefix: # this is the graphical container
                break

        # desktop = infra.getcontainer( myDesktop.container_id )

        # get volunebind from the running x11 container
        volumebind = c.volume_mounts

        # apply network rules 
        (network_disabled, context_network_name, context_network_dns) = self.applyappinstancerules_network( authinfo, app )
        # apply homedir rules
        homedir_disabled = self.applyappinstancerules_homedir( authinfo, app )
       
      
        network_name    = None
        display         = oc.od.settings.desktopenvironmentlocal.get('DISPLAY', ':0.0')
        pulse_server    = oc.od.settings.desktopenvironmentlocal.get('PULSE_SERVER', '/tmp/.pulse.sock')
        cups_server     = oc.od.settings.desktopenvironmentlocal.get('CUPS_SERVER', '/tmp/.cups.sock')
        language        = userinfo.get('locale', 'en_US')
        lang            = language + '.UTF-8'    

        # copy a env dict from configuration file
        env = oc.od.settings.desktopenvironmentlocal.copy()

        env.update ( {  'DISPLAY'       : display,
                        'PULSE_SERVER'  : pulse_server,
                        'CUPS_SERVER'   : cups_server,
                        'LANGUAGE'	    : language,
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
                        'PARENT_ID' 	: desktop.id, 
                        'PARENT_HOSTNAME'   : self.nodehostname
        } )

      
        timezone = kwargs.get('timezone')
        if type(timezone) is str and len(timezone) > 1:     env['TZ'] = timezone
        if type(userargs) is str and len(userargs) > 0:     env['APPARGS'] = userargs
        if app.get('uniquerunkey'):                         env['APPUNIQUERUNKEY'] = app.get('uniquerunkey') 
        if oc.od.settings.desktopusedbussession :           env['OD_DBUS_SESSION_BUS'] = oc.od.settings.desktopusedbussession
        if oc.od.settings.desktopusedbussystem :            env['OD_DBUS_SYSTEM_BUS'] = oc.od.settings.desktopusedbussystem
        if hasattr(authinfo, 'data'):                       env.update(authinfo.data.get('environment', {}))

        if homedir_disabled is True:
            # remove home dir set by image context metadata
            for v in volumebind:
                arv = v.split(':')
                if len(arv) > 1:
                    if arv[1].startswith(oc.od.settings.balloon_defaulthomedirectory):
                        volumebind.remove(v)
                        break # only one balloon_defaulthomedirectory in volumebind

        volumes = self.build_volumefromvolumebind(volumebind)
        command = '/composer/appli-docker-entrypoint.sh'
        
        # network_mode (str) – One of:
        #   bridge Create a new network stack for the container on on the
        #   bridge network.
        #   none No networking for this container.
        #   container:<name|id> Reuse another container’s network stack.
        #   host Use the host network stack.
        # Warning: if desktopusex11unixsocket is set then aclnetworkname is not
        # used
        if oc.od.settings.desktopsharednetworkstack:
            network_mode = 'container:' + desktop.id    # by default
        if context_network_name :
            network_name = context_network_name
            network_mode = context_network_name
        if network_disabled :
            network_mode = 'none'
            network_name = None
        
        extra_hosts = {}
        try:
            host_imagelabel = app.get('oc.extra_hosts')
            if host_imagelabel is not None:
                extra_hosts = json.loads(host_imagelabel)
        except Exception as e:
            self.logger.warning('Failed to parse extra_hosts: %s', e)

        # “container: <_name-or-ID_>"
        # Join another (“shareable”) container’s IPC namespace.
        if oc.od.settings.desktopusershareipcnamespace == 'shareable':
            ipc_mode = 'container:' + desktop.id
        else:
            ipc_mode = None

        # share process name space
        pid_mode = 'container:' + desktop.id if oc.od.settings.desktopusershareprocessnamespace else None

        # container name
        # DO NOT USE TOO LONG NAME for container name  
        # filter can failed or retrieve invalid value in case userid + app.name + uuid
        # limit length is not defined but take care 
        _containername = userinfo.get('name','name') + '_' + oc.auth.namedlib.normalize_imagename( app['name'] + '_' + str(uuid.uuid4().hex) )
        containername =  oc.auth.namedlib.normalize_name( _containername )

        host_config = {
                'auto_remove'   : oc.od.settings.desktopcontainer_autoremove,
                'binds'         : volumebind,
                'extra_hosts'   : extra_hosts,
                'ipc_mode'      : ipc_mode,
                'network_mode'  : network_mode,
                'pid_mode'      : pid_mode,
                'dns'           : context_network_dns,
                'security_opt'  : oc.od.settings.desktopsecurityopt,
                'privileged'    : oc.od.settings.desktopdockerprivileged,
                'cap_add'       : oc.od.settings.desktopcapabilities.get('add'),
                'cap_drop'      : oc.od.settings.desktopcapabilities.get('drop')
        }

        # set shm_size if image require
        if app.get('shm_size') :   host_config.update(  { 'shm_size' : app.get('shm_size') } )
        # set mem_limit if image require
        if app.get('memory') :     host_config.update(  { 'mem_limit' : app.get('memory') } )

        appinfo = infra.createcontainer(
            image = app['id'],
            name  =  containername,
            command = command,
            environment = env,
            user = oc.od.settings.getballoon_name(),
            network_disabled = network_disabled,
            labels = {                
                'access_type'           : authinfo.provider,
                'access_username'       : userinfo.get('name'),
                'access_userid'         : userinfo.userid,
                'access_parent_id'      : desktop.id,
                'access_parent_hostname': self.nodehostname
            },
            volumes = volumes,
            host_config = host_config,
            network_name = network_name
        )

        if type(appinfo) is not dict :
            return None

        appinstance_id = appinfo.get('Id')
        if appinstance_id is None:
            return None

        appinstance = infra.getcontainer(appinstance_id)
        if appinstance is None:
            return None
        
        infra.startcontainer(appinstance.id)
        return appinstance
    '''
    
    def createdesktop(self, authinfo, userinfo, **kwargs):
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

        myDesktop       = None # default return object           

        args     = kwargs.get('args')
        image    = kwargs.get('image')
        command  = kwargs.get('command')
        env      = kwargs.get('env', {} )
        appname  = kwargs.get('appname')
        preferednodehostname = kwargs.get('preferednodehostname', None )

        vncPassword = self.mkvnc_password()
        args.extend('--vncpassword {}'.format(vncPassword).split(' '))
    
        labels = {  'access_provider':  authinfo.provider,
                    'access_userid':    userinfo.userid,
                    'access_username':  self.get_labelvalue(userinfo.name),
                    'domain':           self.endpoint_domain,
                    'vnc_password':     vncPassword }

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

        myuuid = str(uuid.uuid4())
        pod_name = self.get_podname( str(uuid.uuid4() ) ) 
        container_name = self.get_graphicalcontainername( myuuid )         

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


        self.on_desktoplaunchprogress('Building data storage for your desktop')
        (volumes, volumeMounts) = self.build_desktopvolumes( authinfo, userinfo, **kwargs)
        list_volumes = list( volumes.values() )
        list_volumeMounts = list( volumeMounts.values() )
        self.logger.info( 'volumes=%s', volumes.values() )
        self.logger.info( 'volumeMounts=%s', volumeMounts.values() )

        initContainers = []

        if  oc.od.settings.desktopuseinitcontainer              is True and \
            type(oc.od.settings.desktopuseinitcontainercommand) is list and \
            type(oc.od.settings.desktopinitcontainerimage)      is str  :
            # init container chown to change the owner of the home directory
            init_name = 'init' + pod_name
            initContainers.append( {    'imagePullPolicy': 'IfNotPresent',
                                        'name':             init_name,
                                        'image':            oc.od.settings.desktopinitcontainerimage,
                                        'command':          oc.od.settings.desktopuseinitcontainercommand,
                                        'volumeMounts':     list_volumeMounts
            } )
            self.logger.debug( 'initContainers is %s', initContainers)


        nodeselector = {}
        if type(preferednodehostname) is str :
            nodeselector.update( { 'kubernetes.io/hostname': preferednodehostname } )
        if type(oc.od.settings.desktopnodeselector) is dict:
            nodeselector.update( oc.od.settings.desktopnodeselector )

        pod_manifest = {
            'apiVersion': 'v1',
            'kind': 'Pod',
            'metadata': {
                'name': pod_name,
                'namespace': self.namespace,
                'labels': labels,
                **self.get_annotations_lastlogin_datetime()
            },
            'spec': {
                'subdomain': self.endpoint_domain,
                'shareProcessNamespace': oc.od.settings.desktopusershareprocessnamespace,
                'volumes': list_volumes,                    
                'nodeSelector': oc.od.settings.desktopnodeselector, 
                'initContainers': initContainers,
                'containers': [ { 
                                    'imagePullPolicy': 'IfNotPresent',
                                    'image': image,
                                    'name': container_name,
                                    'command': command,
                                    'args': args,
                                    'env': envlist,
                                    'volumeMounts': list_volumeMounts,
                                    'securityContext': 
                                        { 
                                             # permit sudo command inside the container False by default 
                                            'allowPrivilegeEscalation': oc.od.settings.desktopallowPrivilegeEscalation,
                                            # to permit strace call 'capabilities':  { 'add': ["SYS_ADMIN", "SYS_PTRACE"]  
                                            'capabilities':  oc.od.settings.desktopcapabilities
                                        } 
                                }                                                             
                ],
            }
        }

        if oc.od.settings.desktopimagepullsecret:
            pod_manifest['spec']['imagePullSecrets'] = [ { 'name': oc.od.settings.desktopimagepullsecret } ]

        if oc.od.settings.desktopuseprintercontainer is True and type(oc.od.settings.desktopprinterimage) is str :
            # get the container sound name prefix with 'p' like sound
            container_printer_name = self.get_printercontainername( myuuid )
            pod_manifest['spec']['containers'].append( { 
                                    'name': container_printer_name,
                                    'imagePullPolicy': 'IfNotPresent',
                                    'image': oc.od.settings.desktopprinterimage,                                    
                                    'env': envlist,
                                    'volumeMounts': list_volumeMounts                                    
                                }   
            )
        
        if oc.od.settings.desktopusesoundcontainer is True and type(oc.od.settings.desktopsoundimage) is str :
            # get the container sound name prefix with 's' like sound
            container_sound_name = self.get_soundcontainername( myuuid )
            # pulseaudio need only shared volume 
            # /tmp for the unix socket 
            # /dev/shm for the share memory
            # this is a filter to reduce surface attack
            soundcontainerlist_volumeMounts = [ {'mountPath': '/dev/shm',   'name': 'shm'}, 
                                                {'mountPath': '/tmp',       'name': 'tmp'} ]
            pod_manifest['spec']['containers'].append( { 
                                    'name': container_sound_name,
                                    'imagePullPolicy': 'IfNotPresent',
                                    'image': oc.od.settings.desktopsoundimage,                                    
                                    'env': envlist,
                                    'volumeMounts': soundcontainerlist_volumeMounts                                    
                                }   
            )

        # if metapply stop, do not restart the pod 
        if kwargs[ 'type' ] == self.x11servertype_embeded :
            pod_manifest['spec']['restartPolicy'] = 'Never'

        self.logger.info( pod_manifest )

        # we are ready to create our Pod 
        myDesktop = None
        try:
            nMaxEvent = 64
            nEventCount = 0
            
            self.on_desktoplaunchprogress('Creating your desktop')
            pod = self.kubeapi.create_namespaced_pod(namespace=self.namespace,body=pod_manifest )

            if type(pod) is not client.models.v1_pod.V1Pod:
                self.on_desktoplaunchprogress('Create Pod failed.' )
                raise ValueError( 'Invalid create_namespaced_pod type')

            try:                    
                self.logger.info( 'Start watching events' )
                self.on_desktoplaunchprogress('Watching for events from services')
                w = watch.Watch()                 
                for event in w.stream(  self.kubeapi.list_namespaced_pod, 
                                        namespace=self.namespace, 
                                        field_selector='metadata.name=' + pod_name ):                        
                    event_type = event.get('type')
                    if event_type is None:
                        # nothing to do 
                        continue

                    self.logger.info('count=%d event_type=%s ', nEventCount, event['type'] )
                    self.on_desktoplaunchprogress('{} event received', event_type.lower() )

                    nEventCount +=1
                    if nEventCount > nMaxEvent:                            
                        w.stop()  
                    
                    if event_type == 'ADDED':
                        self.logger.info('event type ADDED received')
                        # the pod has been added
                        # wait for next MODIFIED event type
                        
                    if event_type == 'MODIFIED':
                        self.logger.info('event type MODIFIED received')
                        # pod_event = w.unmarshal_event( data=event['object'], return_type=type(pod) )

                    pod_event = event.get('object')
                    
                    if type(pod_event) == type(pod) :                            
                        self.on_desktoplaunchprogress('Install process can take up to 10 s. Status is {}:{}', pod_event.status.phase, event_type.lower() )
                        if pod_event.status.phase != 'Pending' :
                            self.logger.info('Stop event')
                            w.stop()                          
                                            
            except ApiException as e:
                self.logger.debug("Exception when calling CoreV1Api->list_namespaced_pod: %s\n", str(e) )


            self.logger.debug( "%d/%d", nEventCount, nMaxEvent )
            
            myPod = self.kubeapi.read_namespaced_pod(namespace=self.namespace,name=pod_name)            
            self.on_desktoplaunchprogress('Your desktop phase is {}.', myPod.status.phase.lower() )
          
            self.logger.info( 'myPod %s', myPod)
            self.logger.info( 'myPod.metadata.name is %s, ipAddr is %s', myPod.metadata.name, myPod.status.pod_ip)

            myDesktop = self.pod2desktop( myPod )

        except ApiException as e:
            self.logger.error( str(e) )

        
        return myDesktop

  
    
    def findPodByUser(self, authinfo, userinfo, args=None ):
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
        logger.info('')
        access_userid = userinfo.userid
        access_provider = authinfo.provider
        pod_name = None
        if type(args) is dict:
            pod_name = args.get( 'pod_name' )
        try: 
            field_selector = ''
            label_selector = 'access_userid='    + access_userid     + ',' + \
                             'access_provider='  + access_provider   
            # if pod_name is set, don't care about the type
            # type can be type=self.x11servertype or type=self.x11embededservertype
            if type( pod_name ) is str :
                field_selector =  'metadata.name=' + pod_name
            else :    
                label_selector += ',type=' + self.x11servertype

            myPodList = self.kubeapi.list_namespaced_pod(self.namespace, label_selector=label_selector, field_selector=field_selector)

            if len(myPodList.items)> 0:
                for myPod in myPodList.items:
                    myPhase = myPod.status.phase
                    if myPod.metadata.deletion_timestamp is not None:
                       myPhase = 'Terminating'
                    if myPhase != 'Running':                        
                       continue # This pod is Terminating or not Running, skip it   
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
            label_selector= 'access_userid='    + access_userid     + ',' + \
                            'access_provider='  + access_provider   + ',' + \
                            'type='             + self.x11servertype_embeded + ',' + \
                            'appname='          + appname
            myPodList = self.kubeapi.list_namespaced_pod(self.namespace, label_selector=label_selector)

            if len(myPodList.items)> 0:
                for myPod in myPodList.items:
                    myPhase = myPod.status.phase
                    if myPod.metadata.deletion_timestamp is not None:
                       myPhase = 'Terminating'
                    if myPhase != 'Running':                        
                       continue # This pod is Terminating or not Running, by pass
                    return myPod
                    
        except ApiException as e:
            self.logger.info("Exception when calling CoreV1Api->read_namespaced_pod: %s\n" % e)

        return None

    def findDesktopByUser(self, authinfo, userinfo, **kwargs ):
        ''' find a desktop for authinfo and userinfo '''
        ''' return a desktop object '''
        ''' return None if not found '''
        self.logger.info( '' )
        
        myDesktop = None  # return Desktop Object
        appname=kwargs.get('appname')

        if type(appname) is str and len(appname) > 0  :
            myPod = self.findPodAppByUser( authinfo, userinfo, appname )
        else :
            myPod = self.findPodByUser( authinfo, userinfo, kwargs)

        if myPod is not None :
            self.logger.info( 'Pod is found %s ', myPod.metadata.name )
            myDesktop = self.pod2desktop( myPod )
        return myDesktop

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
        if oc.od.settings.desktopuseinternalfqdn and type(oc.od.settings.kubernetes_default_domain) is str:
            defaultFQDN = myPod.metadata.name + '.' + myPod.spec.subdomain + '.' + oc.od.settings.kubernetes_default_domain
        return defaultFQDN

    def pod2desktop( self, myPod ):
        """pod2Desktop convert a Pod to Desktop Object
        Args:
            myPod ([V1Pod): kubernetes.client.models.v1_pod.V1Pod
        Returns:
            [ODesktop]: oc.od.desktop.ODDesktop Desktop Object
        """
        desktop_container_id   = None
        desktop_container_name = None
        
        # get the container id for the desktop object
        for c in myPod.status.container_statuses:
            if c.name[0] == self.graphicalcontainernameprefix: # this is the graphical container
                desktop_container_id = c.container_id
                desktop_container_name = c.name
                break

        internal_pod_fqdn = self.build_internalPodFQDN( myPod )

        # Build the ODDesktop Object 
        myDesktop = oc.od.desktop.ODDesktop(    nodehostname=myPod.spec.node_name, 
                                                name=myPod.metadata.name,
                                                hostname=myPod.spec.hostname,
                                                ipAddr=myPod.status.pod_ip, 
                                                status=myPod.status.phase, 
                                                desktop_id=myPod.metadata.name, 
                                                container_id=desktop_container_id,                                                   
                                                container_name=desktop_container_name,
                                                vncPassword=myPod.metadata.labels['vnc_password'],
                                                fqdn = internal_pod_fqdn )
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
            
    def isgarbagable( self, pod, expirein, force=False ):
        bReturn = False
        myDesktop = self.pod2desktop( pod )
        if force is False:
            nCount = self.userconnectcount( myDesktop )
            if nCount < 0: # if something wrong do not garbage this pod
                return bReturn 
            if nCount > 0 : # if a user is connected do not garbage this pod
                return bReturn 
        # now nCount be equal to zero : no error and nouser connected
        try:
            # read the lastlogin datetime fomr metadata annotations
            lastlogin_datetime = self.read_pod_annotations_lastlogin_datetime( pod )
            # get the cuurent time
            now_datetime = datetime.datetime.now()
            # now_datetime.tzinfo = creation_datetime.tzinfo
            delta_datetime = now_datetime - lastlogin_datetime
            delta_second = delta_datetime.total_seconds()
            if ( delta_second > expirein  ):
                bReturn = True
        except Exception as e:
            self.logger.error(str(e))

        return bReturn

    def garbagecollector( self, expirein, force=False ):
        garbaged = []
        try: 
            list_label_selector = [ 'type=' + self.x11servertype, 'type=' + self.x11servertype_embeded ]
            for label_selector in list_label_selector:
                myPodList = self.kubeapi.list_namespaced_pod(self.namespace, label_selector=label_selector)
                for myPod in myPodList.items:
                    myPodisgarbagable = self.isgarbagable( myPod, expirein, force ) 
                    self.logger.debug(  "%s is garbageable %s", myPod.metadata.name, str(myPodisgarbagable) )
                    if myPodisgarbagable is True:
                        self.logger.info( '%s is garbagable, removing...', myPod.metadata.name  )
                        # fake an authinfo object
                        authinfo = AuthInfo( provider=myPod.metadata.labels.get('access_provider') )
                        # fake an userinfo object
                        userinfo = AuthUser( { 'userid':myPod.metadata.labels.get('access_userid'),
                                               'name':  myPod.metadata.labels.get('access_username') } )
                        status = self.removedesktop( authinfo, userinfo )
                        if type(status) is client.models.v1_status.V1Status :
                            garbaged.append( myPod.metadata.name )
        except ApiException as e:
            self.logger.error(str(e))
        return garbaged
