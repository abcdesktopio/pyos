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
import requests
from   requests.packages.urllib3.exceptions import InsecureRequestWarning
import docker
import oc.lib 
import oc.auth.namedlib
import oc.od.resolvdns
import oc.od.settings as settings

bStopBugingWarningTLSmesssage = False

logger = logging.getLogger(__name__)

class ODError(Exception):
    def __init__(self,message):
        super().__init__(message)

class ODResourceNotFound(ODError):
    def __init__(self,message):
        super().__init__(message)

class ODAPIError(ODError):
    def __init__(self,message):
        super().__init__(message)

#
# return the infra object from the settings configuration file
# raise NotImplementedError if not found
def selectInfra( arguments=None ):
    myinfra = None
    stack_mode = settings.stack_mode
    logger.info( 'infra mode is %s', stack_mode)
    if stack_mode == 'standalone' :     
        # standalone means a docker just installed        
        myinfra = ODInfra(arguments)    
    elif stack_mode == 'kubernetes' :
        # kubernetes means a docker and kubernetes installed        
        myinfra = ODInfraKubernetes(arguments)
    else:
        raise NotImplementedError('ODInfra:infra  %s is not implemented', stack_mode )  
        
    return myinfra


 
@oc.logging.with_logger()
class ODInfra(object):

    bStopBugingWarningTLSmesssage = False
    nodehostname = None

    def __init__(self, nodehostname=None):
        self.logger.info( 'nodehostname=%s', nodehostname )
        self.urllib3_disable_warnings()

        if nodehostname is None:
            # Use local unix docker socket file
            self.base_url = 'unix://var/run/docker.sock'
        else:
            # Use a docker daemon TCP socket 
            self.base_url = settings.getbase_url(nodehostname) 

        self.nodehostname = nodehostname
        self.client = None
        self.clientAPI = None
        self.tls_config = None
        self.bClientTLS = False

        if nodehostname is not None:
            # Set TLS config 
            if settings.tlscacert and settings.clienttlscert and settings.clienttlskey:
                self.tls_config = docker.tls.TLSConfig(ca_cert=settings.tlscacert, assert_hostname=settings.tls_assert_hostname, client_cert=(settings.clienttlscert, settings.clienttlskey))

            elif settings.tlscacert:
                self.tls_config = docker.tls.TLSConfig(ca_cert=settings.tlscacert, assert_hostname=settings.tls_assert_hostname)

            elif settings.clienttlscert and settings.clienttlskey:
                self.tls_config = docker.tls.TLSConfig(client_cert=(settings.clienttlscert, settings.clienttlskey))
        
    
    def __del__(self): 
        # self.logger.debug('deleting %s' % type(self).__name__)
        self.close()
        

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        try:
            self.close()
        except Exception:
            pass

    def isClientTLS( self):
        bReturn = False
        if self.tls_config :
            self.getdockerClient()
            if self.bClientTLS :
                bReturn = True
        return bReturn

    def isLocal(self):
        return True if self.nodehostname is None else False

    # Cache the current client
    def getdockerClient(self):            
        if self.client is None:          
            try:                    
                self.logger.info("Creating client: base_url = '%s'", self.base_url)
                self.client = docker.DockerClient(base_url=self.base_url, tls=self.tls_config, version='auto')
                if self.tls_config :
                    self.bClientTLS = True
            except (docker.errors.APIError, Exception) as e:                                    
                self.logger.error("Client connect failed %s, falling back to local unix://var/run/docker.sock: error = %s", self.base_url, e)
                self.base_url='unix://var/run/docker.sock'
                self.client = docker.DockerClient(base_url=self.base_url, version='auto')
                self.bClientTLS = False                
        return self.client

    # Cache the current clientAPI
    def getdockerClientAPI(self):        
        if self.clientAPI is None:
            try:                
                self.logger.debug("Creating client API: base_url = '%s'", self.base_url)
                self.clientAPI = docker.APIClient(base_url=self.base_url, tls=self.tls_config, version='auto')
                if self.tls_config :
                    self.bClientTLS = True
            except (docker.errors.APIError, Exception) as e:
                self.logger.error('base_url=%s: %s', self.base_url, e)
                self.logger.error('Falling back to local unix://var/run/docker.sock for client API')
                self.base_url='unix://var/run/docker.sock'
                self.clientAPI = docker.APIClient(self.base_url, version='auto')
                self.bClientTLS = False
        return self.clientAPI

    def close(self):        
        # Close client
        if self.client is not None:
            # self.logger.debug('infra.client is not None: closing infra client ')
            self.client.close()
        self.client = None

        # Close ClientAPI
        if self.clientAPI:
            # self.logger.debug('infra.clientAPI is not None: closing infra clientAPI ')
            self.clientAPI.close()
        self.clientAPI = None

    def version( self ):
        version = None
        try:
            c = self.getdockerClient()
            version = c.version()
        except docker.errors.APIError as e:
            self.logger.error('docker.errors.APIError: %s', e)
        except Exception as e:
            self.logger.error('ping failed: %s', e)
        return version


    def urllib3_disable_warnings(self):
        # remove insecure message warning
        # THIS IS BAD !!!!
        # Only for test
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    # return True if ping 
    # False if failed
    def ping(self):
        bReturn = False
        try:
            c = self.getdockerClient()
            c.ping()
            bReturn = True
        except docker.errors.APIError as e:
            self.logger.error('docker.errors.APIError: %s', e)
        except Exception as e:
            self.logger.error('ping failed: %s', e)
        return bReturn

    def is_configured( self ):
        # get version
        bReturn = False
        if self.version() is not None:
            bReturn = True
        # self.logger.debug('return %s', bReturn )
        return bReturn


    def countdesktop(self):
        ''' return the counter of desktop type type=x11server '''
        ''' return 0 if failed '''
        ncount = 0
        try:            
            c = self.getdockerClient()
            myfilter = {'label': 'type=x11server'}
            mylist = c.containers.list(filters=myfilter)
            ncount = len(mylist)
        except docker.errors.NotFound as e:
            self.logger.info('docker.errors.NotFound %s',e)
        except docker.errors.APIError as e:
            self.logger.error('docker.errors.APIError: %s', e)
        except Exception as e:
            self.logger.error('countdesktop failed: %s', e)
        return ncount

    
    def listContainers( self, labelfilterdict={} ):
        """list containers unsing the labelfilterdict key value 

        Args:
            labelfilterdict (dict): labelfilterdict key value 

        Returns:
            [list]: list of container
        """
        desktoplist = []        
        listlabelfilter = []
        for k,v in labelfilterdict.items():
            listlabelfilter.append( str(k) + '=' + str(v) )
        labelfilter = {'label': listlabelfilter }        
        self.logger.info('label filter: %s base_url: %s', labelfilter, self.base_url)
        
        try:
            c = self.getdockerClient()
            desktoplist = c.containers.list( all=True, filters=labelfilter )
        except docker.errors.NotFound as e:
            self.logger.info('docker.errors.NotFound: %s', e)
            self.lastErrorMessage = 'docker.errors.NotFound' + str(e)
        except Exception as e:
            self.logger.error('docker.errors.NotFound: %s', e)
            self.lastErrorMessage = 'docker.errors.NotFound' + str(e)
        
        return desktoplist

   
    def listContainersFilter( self, userid, myFilter={} ):
        """listContainersFilter

        Args:
            userid (str): user id 
            myFilter (dict, optional): dict of labels value  Defaults to {}.
                    for example { 'oc.type': 'app', 'access_userid': '12345' }
        Returns:
            [list]: list of filtered app
        """
        if userid:          
            myFilter['access_userid'] = userid
        self.logger.info('listContainersFilter:filter=%s', myFilter)

        myContainersList = self.listContainers( myFilter )                
        return myContainersList

    def listContainersApps( self, userid ):
        """return a list of container oc.type:app for user=userid

        Args:
            userid (str): user id 

        Returns:
            [list]: list of running app
        """
        assert userid, "userid is undefined"
        return self.listContainersFilter( userid, { 'oc.type' : 'app' } )


    def getDesktopContainer( self, containerid ):
        """return a container object from container id 

        Args:
            containerid (str): container id

        Returns:
            [container]: container object, None if not found
        """
        container = None
        try:
            c = self.getdockerClient()
            container = c.containers.get( containerid )            
        except (docker.errors.NotFound, Exception) as e:
            self.logger.warning('Error: %s', e)
        except (docker.errors.APIError, Exception) as e:
            self.logger.warning('Error: %s', e)
        except (KeyError, Exception) as e:
            self.logger.warning('Error: %s', e)
        return container


    def getDesktopIpAddr( self, containerid, lookfornetworkid=None ):
        """return the ip address on the container network id

        Args:
            containerid (str): container id
            lookfornetworkid (str, optional): network id. Defaults to None.

        Returns:
            str: ip address
        """
        ip_addr = None
        try:
            if lookfornetworkid is None:
                lookfornetworkid = settings.defaultnetworknetuserid            
            container = self.getDesktopContainer( containerid )
            networksettings = container.attrs.get('NetworkSettings')
            if networksettings is not None:
                networks = networksettings.get('Networks', {} )
                for n, vn in networks.items():
                    networkid = vn.get('NetworkID')
                    if networkid == lookfornetworkid:
                        ip_addr = vn.get('IPAddress')
                        break
        except (KeyError, Exception) as e:
                self.logger.warning('Error - ip_addr not found: %s', e)
        return ip_addr
    
    def getDesktopStatus( self, containerid ):
        """ 
            return the status from a container id
            None if not found or exception
        """
        status = None
        try:
            container = self.getDesktopContainer( containerid )
            status = container.status
        except (docker.errors.NotFound, Exception) as e:
            self.logger.warning('Error: %s', e)
        except (docker.errors.APIError, Exception) as e:
            self.logger.warning('Error: %s', e)
        except (KeyError, Exception) as e:
            self.logger.warning('Error: %s', e)
        return status


    def getInfo(self):
        info = None
        try:
            c = self.getdockerClientAPI()
            info = c.info()
        except (docker.errors.APIError, Exception) as e:
            self.logger.error('docker getinfo failed base_url=%s: %s', self.base_url, e)
        return info 


    def findRunningContainerforUserandImage(self, current_userid, uniquerunkey):                        
        myfilters = {   'status': 'running',
                        'label' : [ 'access_userid=' + current_userid,  'oc.uniquerunkey=' + uniquerunkey] }
        self.logger.debug( 'filters %s', myfilters )
        try:
            c = self.getdockerClient()
            cl = c.containers.list(filters=myfilters)
            self.logger.debug( 'container list len is %d ', len(cl) )
            if len(cl) > 0:        
                return cl[0]
        except docker.errors.NotFound:
            pass
        except KeyError:
            pass
        except docker.errors.APIError as e:
            self.logger.error('Error: %s', e)            
        except Exception as e:
            self.logger.error('Error: %s', e)

        return None
         

    def findDesktopbyContainerId( self, containerid ):
        res = None
        try:
            c = self.getdockerClient()
            res = c.containers.get(containerid)
        except docker.errors.NotFound as e:
            self.logger.error('Error - %s is not found: %s', str(containerid), e)
        except docker.errors.APIError as e:
            self.logger.error('docker.errors.APIError - name = %s: %s', str(containerid), e)
        except Exception as e:
            self.logger.error('failed: %s', e)        
        return res

    def findDesktopbyName(self, name):
        self.logger.info('')
        myDesktop = None
        try:
            c = self.getdockerClient()
            myfilter = {'name': name}
            res = c.containers.list(filters=myfilter)
            len_res = len(res)
            if len_res == 0:
                self.logger.debug('desktop name=%s does not exist', name)
            if len_res == 1:  # only one per user everything else is error
                myDesktop = res[0]
                myDesktop.nodehostname = self.nodehostname
            if len_res > 1:
                self.logger.error('More than one desktop found filter by name: %s', name)

        except docker.errors.NotFound as e:
            self.logger.error('Error - %s is not found: %s', name, e)
        except docker.errors.APIError as e:
            self.logger.error('docker.errors.APIError - name = %s: %s', name, e)
        except Exception as e:
            self.logger.error('failed: %s', e)

        return myDesktop

    
    def resumeorcreatenewnetwork(self, name, labels=None):
        net = None
        networkname = oc.auth.namedlib.normalize_networkname(name)
        if networkname is None:
            # Can not create the overlay network named None
            # invalid access_userid
            self.logger.error('Can not create network overlay named None')
            return None

        try:
            c = self.getdockerClientAPI()
            dict_net = c.create_network(name,
                                        driver='overlay',
                                        options=None,
                                        ipam=None,
                                        check_duplicate=True,
                                        internal=False,
                                        labels=labels,
                                        enable_ipv6=False,
                                        attachable=True,
                                        scope=None)
            netid = dict_net.get('Id')
            if netid is not None:
                c = self.getdockerClient()
                net = c.networks.get(netid)
            else:
                self.logger.error('Can not create network overlay named %s', name)

            # the driver must be overlay
            # Only networks scoped to the swarm can be used, such as those
            # created with the overlay driver.
            # net = c.networks.create( name=networkname,
            #                               driver='overlay',
            #                               options=options,
            #                               ipam=ipam_config,
            #                               labels=labels)
        except docker.errors.APIError as e:
            self.logger.error(str(e))
            net = self.getnetworkbyname(networkname)
        return net
    
    def getlabelfromcontainer(self, containerid, label):
        objLabel = None
        try:
            c = self.getdockerClientAPI()
            ci = c.inspect_container(containerid)
            objLabel = ci['Config']['Labels'][label]

        except Exception as e:
            self.logger.error('failed: %s', e)
            pass  # nothin to do
        return objLabel


    # stop and remove a desktop 
    # timeout :  time to wait in seconds for removing the desktop
    def stop_container( self, containerid, timeout=5 ):
        """[summary]

        Args:
            containerid (str): container id
            timeout (int, optional): timeout in ms, Defaults to 5.

        Returns:
            bool: True if the container if stopped, else False
        """
        bReturn = False
        myContainer = None
        logger.info('stop_container containerid=%s', containerid )
        
        try:
            c = self.getdockerClient()
            myContainer = c.containers.get(containerid)            
            myContainer.stop(timeout=timeout)            
            bReturn = True
        except docker.errors.APIError as e:
            logger.error('Error: %s', str(e) )
        except docker.errors.NotFound as e:
            logger.error('failed: %s', str(e) )
        except Exception as e:
            logger.error('log_container:Exception %s', str(e) )
    
        return bReturn

    # stop and remove a desktop 
    # timeout :  time to wait in seconds for removing the desktop
    def log_container( self, containerid ):
        myresult = None
        mycontainer = None        
        try:
            c = self.getdockerClient()
            mycontainer = c.containers.get(containerid)
            myresult = mycontainer.logs()
            myresult = myresult.decode('utf-8')                
        except docker.errors.APIError as e:
            logger.error('log_container:docker.errors.APIError: %s', str(e) )
        except docker.errors.NotFound as e:
            logger.error('log_container:docker.errors.NotFound failed: %s', str(e) )
        except Exception as e:
            logger.error('log_container:Exception %s', str(e) )
    
        return myresult

    def remove_container( self, containerid, force=True ):
        """
            Remove a container 
            if force is True, Force the removal of a running container (uses SIGKILL)
        """
        result = False
        mycontainer = None        
        try:
            c = self.getdockerClient()
            mycontainer = c.containers.get(containerid)
            mycontainer.remove( force=force )            
            result = True
        except docker.errors.APIError as e:
            logger.error('remove_container:docker.errors.APIError: %s', str(e) )
        except docker.errors.NotFound as e:
            logger.error('remove_container:docker.errors.NotFound failed: %s', str(e) )
        except Exception as e:
            logger.error('remove_container:Exception %s', str(e) )
    
        return result

   
    def env_container( self, containerid ):
        ''' return a dict of enviroment var string utf-8 decoded '''
        myresult = {}
        mycontainer = None        
        try:
            c = self.getdockerClient()
            mycontainer = c.containers.get(containerid)
            envarray = mycontainer.attrs.get('Config',{}).get('Env')     
            for e in envarray:
                # must be formated as VAR=VALUE
                a = e.split('=')
                # must be two enties in the a array
                if len(a) == 2:
                    # set data to dict
                    myresult[ a[0] ] = a[1]                    
        except docker.errors.APIError as e:
            logger.error('env_container:docker.errors.APIError: %s', e )
        except docker.errors.NotFound as e:
            logger.error('env_container:docker.errors.NotFound failed: %s', e )
        except Exception as e:
            logger.error('env_container:Exception %s', e )
    
        return myresult

 
    @staticmethod
    def volumebind_to_dict(volumebind):
        # the entry /home/balloon from the volume bind list
        # "Binds" : [
        # '/mnt/desktop/home/4e27356a-3207-4644-8aa7-9e6eb3e29d32:/home/balloon',
        #             'tmp4e27356a-3207-4644-8aa7-9e6eb3e29d32:/tmp'
        #           ]
        volume_dict = {}

        if not isinstance(volumebind, list):
            return volume_dict

        for v in volumebind:
            arv = v.split(':')
            if len(arv) == 2:
                volume_dict[ arv[0] ] = arv[1]
        return volume_dict

    def list_volume_bind( self, containerid ):
        volume_bind = []
        try:
            container = self.getDesktopContainer( containerid )
            volume_bind = container.attrs["HostConfig"]["Binds"]
        except Exception as e:            
            logger.error('Error: %s', str(e) )
        return ODInfra.volumebind_to_dict(volume_bind)

    def remove_volume( self, name ):
        self.logger.info( 'name=%s', name)
        bReturn = False
        try:
            c = self.getdockerClient()
            v = c.volumes.get(name)
            if v is not None:
                v.remove()
            bReturn = True
        except docker.errors.APIError as e:
            logger.error('Error: %s', str(e) )
        except docker.errors.NotFound as e:
            logger.error('failed: %s', str(e) )
        return bReturn

    def getnetworkbyname(self, networkname):
        if not networkname:
            return None

        try:
            netquery = self.getdockerClient().networks.list()
            if type(netquery) is not list :
               self.logger.info('Does not return not a type list')
               return None

            for n in netquery:
               if networkname == n.name:
                    return n

        except docker.errors.APIError as e:
            self.logger.error('docker.errors.APIError - %s: ', networkname, e)
        except Exception as e:
            self.logger.error('Error - %s: ', networkname, e)
        return None        


        
    def findimages(self, name=None, filters={'dangling': False, 'label': 'oc.type=app'} ):
        return  self.getdockerClientAPI().images(name=name, filters=filters)

    
    def resumeorcreatenewnetwork(self, name, labels=None):
        net = None
        networkname = ODInfra.normalize_networkname(name)
        if networkname is None:
            # Can not create the overlay network named None
            # invalid access_userid
            self.logger.error('Can not create network overlay named None')
            return None

        try:
            dict_net = self.getdockerClientAPI().create_network(
                name, 
                driver='overlay',
                options=None,ipam=None,
                check_duplicate=True,
                internal=False,
                labels=labels, 
                enable_ipv6=False,
                attachable=True,
                scope=None)

            netid = dict_net.get('Id')
            if netid is not None:
                net = self.getdockerClient().networks.get(netid)
            else:
                self.logger.error('Can not create network overlay named %s', name)

            # the driver must be overlay
            # Only networks scoped to the swarm can be used, such as those
            # created with the overlay driver.
            # net = c.networks.create( name=networkname,
            #                               driver='overlay',
            #                               options=options,
            #                               ipam=ipam_config,
            #                               labels=labels)
        except docker.errors.APIError as e:
            self.logger.error(str(e))
            net = self.getnetworkbyname(networkname)
        return net


    def getlabelfromcontainer(self, containerid, label):
        try:
            return self.getdockerClientAPI().inspect_container(containerid)['Config']['Labels'][label]
        except Exception as e:
            self.logger.error('failed: %s', e)
        return None

    def execincontainer(self, containerid, command, user='balloon', detach=False):
        myresult = None

        assert type(containerid) is str, "type(containerid) is not str"
        
        try:
            c = self.getdockerClientAPI()
            self.logger.debug('running in container=%s  command=%s as user=%s', containerid, command, user)
            execid = c.exec_create(container=containerid, cmd=command, user=user)
            stdout = c.exec_start(execid['Id'], detach=detach)
            myresult = c.exec_inspect(execid['Id'])
            myresult['stdout'] = str( stdout ) # convert to str to make sure json data ca be encoded
        except docker.errors.APIError as e:
            self.logger.error('docker.errors.APIError: %s', e)
            if e.status_code == 409:                
                self.logger.error('docker.errors.APIError is 409')  
                # Container is not running                
        except Exception as e:
            self.logger.error('failed: %s', e)

        return myresult


    def findcontainers(self, filters={}):
        ''' look for container              '''
        ''' return a list of containers     '''
        return self.getdockerClient().containers.list(filters=filters)

    def getcontainer(self, id):
        ''' return a container object from container id '''
        return self.getdockerClient().containers.get(id)

    def createcontainer(self,image,network_name=None,host_config=None,**args):
        client = self.getdockerClientAPI()
        
        if network_name:
            args['networking_config'] = client.create_networking_config({ network_name: client.create_endpoint_config()})
        
        if host_config:
            args['host_config'] = client.create_host_config(**host_config)

        return client.create_container(image,**args)

    def startcontainer(self,id):
        ''' start a container from container id '''
        self.getdockerClientAPI().start(container=id)

    def stopcontainer(self,id):
        ''' start a container from container id     '''
        ''' return True if stopped                  '''
        ''' return False if API Error or Not Found  '''
        bReturn = False
        try:
            container = self.getcontainer(id)
            container.stop(timeout=0)
            container.wait(timeout=10, condition='removed')
            bReturn =True
        except docker.errors.APIError as e:
            logger.error('Error: %s - %s', id, e)
        except docker.errors.NotFound:
            logger.warning('Container already removed: %s', id)
            bReturn = False
        return bReturn

    def getvolume(self, name):
        try:
            return self.getdockerClient().volumes.get(name)
        except docker.errors.NotFound:
            return None

    def removevolume(self, volume):
        if isinstance(volume, str): 
            volume = self.getvolume(volume)
        if volume:
            volume.remove()
            return True
        return False


    def createvolume( self, name, prefix=None, driver='local', labels={}, removeifexist=False ):

        driver_opts = {}
        if prefix == 'tmp':
            driver_opts = {'type': 'tmpfs', 'device': 'tmpfs'}            
        elif prefix == 'home':
            pass
            # driver_opts={'type': 'tmpfs', 'device': 'tmpfs'}
        elif prefix == 'remotehome':
            driver_opts = {'type': 'tmpfs', 'device': 'tmpfs'}
        
        volume = None
        try:        
            c = self.getdockerClient()            
            volume = c.volumes.get(name)
            if removeifexist:
                try:
                    volume.remove()
                    volume = c.volumes.create(name=name, driver=driver, labels=labels, driver_opts=driver_opts)
                except docker.errors.APIError as e:
                    logger.error('Failed, api error: %s', e)                    
                except Exception as e:
                    logger.error('Failed: %s', e)            
        except docker.errors.NotFound:            
            try:
                volume = c.volumes.create(name=name, driver=driver, labels=labels, driver_opts=driver_opts)
            except docker.errors.APIError as e:
                logger.error('Failed, API error: %s', e)
            except Exception as e:
                logger.error('Failed: %s', e)
        return volume

    def findDesktopById(self, id, nodehostname=None):        
        try:
            return self.getcontainer(id)
        except docker.errors.NotFound:
            self.logger.warning('Desktop %s is not found', id)
        except Exception as e:
            self.logger.error('Failed to retreive desktop %s: %s', id , e)

        return None

    
@oc.logging.with_logger()
class ODInfraKubernetes(ODInfra):
    
    def __init__(self, arguments):
        self.logger.info(arguments)
        super().__init__(arguments)
        
        self.labelfilterpodname = 'io.kubernetes.pod.name=%s'
        self.labelfiltercontainername = 'io.kubernetes.container.name=%s' # use to query dockerd and find the desktop inside the pod

        self.namespace = settings.namespace
        self.container_type  = "container"
        self.podsandbox_type = "podsandbox" 

    def urllib3_disable_warnings(self):
        pass
    
    # list all container inside a pod
    def listContainersPod( self, pod_name ):
        self.logger.info('pod_name=%s', pod_name)
        desktoplist = None
        labelfilter = self.labelfilterpodname % pod_name
        logger.info('label filter: %s base_url: %s', labelfilter, self.base_url)
        
        try:
            c = self.getdockerClient()
            desktoplist = c.containers.list( filters = { 'label': labelfilter } )
        except docker.errors.NotFound as e:
            self.logger.info('docker.errors.NotFound: %s', e)
            self.lastErrorMessage = 'docker.errors.NotFound' + str(e)
        except Exception as e:
            self.logger.error('docker.errors.NotFound: %s', e)
            self.lastErrorMessage = 'docker.errors.NotFound' + str(e)
        
        return desktoplist

    # filter is a dict
    # { 'oc.type': 'app', 'access_userid': '12345' }
    def listContainersPodFilter( self, pod_name, filters ):
        self.logger.info('pod_name=%s filter=%s', pod_name, filters)
        list_containerfilter = []
        myContainersList = self.listContainersPod( pod_name )                
        for c in myContainersList:
            bFind = None
            for k, v in filters.items():
                if c.labels.get(k, None ) == v:
                    if bFind is None:
                        bFind = True
                else:
                    bFind = False
            if bFind :
               list_containerfilter.append( c )
        return list_containerfilter

    def find_sidecar_container( self, pod_name ):        
        sidecar_container = None
        container_list = self.listContainersPodFilter( pod_name, { 'io.kubernetes.docker.type': 'podsandbox' } )
        if len( container_list ) > 0:
            sidecar_container = container_list[0]
        return sidecar_container


    # kubernetesdockertype is "podsandbox" or "container"
    def _findContainer( self, name, kubernetesdockertype ):
        self.logger.info('name=%s', name)
        myDesktop = None
        labelfilter = self.labelfiltercontainername % name
        logger.info('label filter: %s base_url: %s', labelfilter, self.base_url)
        
        try:
            c = self.getdockerClient()
            desktoplist = c.containers.list(    sparse=False,   # sparse: Do not inspect containers. Returns partial information, but guaranteed not to block. 
                                                filters = { 'label': labelfilter } )
            for d in desktoplist:
                    if d.labels['io.kubernetes.docker.type'] == kubernetesdockertype:
                        myDesktop = d
                        break

        except docker.errors.NotFound as e:
            self.logger.info('docker.errors.NotFound: %s', e)
            self.lastErrorMessage = 'docker.errors.NotFound' + str(e)
        except Exception as e:
            self.logger.error('docker.errors.NotFound: %s', e)
            self.lastErrorMessage = 'docker.errors.NotFound' + str(e)
        
        return myDesktop

    def getDesktopbyId( self, desktopid ):
        pass

    def findDesktopbyName( self, name ):
        self.logger.info('name=%s', name)
        myDesktop = self._findContainer( name=name, kubernetesdockertype = self.container_type )
        self.logger.info( 'return value %s', str(myDesktop) )        
        return myDesktop