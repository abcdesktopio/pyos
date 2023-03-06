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
import oc.auth.namedlib

from kubernetes import client
from kubernetes.client.rest import ApiException

logger = logging.getLogger(__name__)

'''

from :
https://www.jeffgeerling.com/blog/2019/mounting-kubernetes-secret-single-file-inside-pod

One thing that is not supported, unfortunately, is mounting a single secret to a single file 
in a directory which already exists inside the container. 
This means secrets can't be mounted as files in the same way you'd do a file-as-volume-mount 
in Docker or mount a ConfigMap item into an existing directory. 
When you mount a secret to a directory (like /var/my-app in the above example), 
Kubernetes will mount the entire directory /var/my-app with only the contents of your secret / secretName items.

=> we replace the secret by a configmap to mount a single configmap key to a single file

'''


def selectConfigMap( namespace, kubeapi, prefix, configmap_type):
    """[selectConfigMap]
        return a configmap class object from a configmap_type
    Args:
        namespace ([str]): [kubernetes namespace where configmap should be created]
        kubeapi ([api]): [kubernets api object]
        prefix ([str]): [prefix for configmap name]
        configmap_type ([str]): [type of configmap] must be in the list [ 'localaccount' ]

    Returns:
        [configmap class]: [configmap class instance for the configmap_type]
    """
    configmap = None
    configmap_cls = None
    
    # configmap_cls_dict is a dict of class 
    # key   : is the class name equal to the configmap_type
    # value : is the class object 
    configmap_cls_dict = { 'localaccount': ODConfigMapLocalAccount }
                        
    # get the class from the configmap_type
    configmap_cls = configmap_cls_dict.get( configmap_type, ODConfigMap )
    # instance the class
    configmap = configmap_cls( namespace, kubeapi, prefix, configmap_type )
    # return the configmap object
    return configmap

def list_configmaptype():
    """[list_configmapype]
        list all supported configmap type
    Returns:
        [list]: [list of supported configmap type]
    """
    return [ 'localaccount' ]

@oc.logging.with_logger()
class ODConfigMap():

    def __init__( self, namespace, kubeapi, prefix, configmap_type ):
        self.namespace  = namespace
        self.kubeapi    = kubeapi
        self.configmapnameheader = 'auth' 
        self.access_type='auth'
        self.configmap_type = namespace + '/' + configmap_type
        self.normalize_name_configmap_type = configmap_type.replace( '/', '-')
        if type(prefix) is str:
            self.prefix = '-' + prefix
        else:
           self.prefix = ''
        
    def get_name( self, userinfo ):   
        configmap_name = f"{self.configmapnameheader}-{self.normalize_name_configmap_type}-{userinfo.userid}{self.prefix}"
        configmap_name = oc.auth.namedlib.normalize_name_dnsname(configmap_name)        
        return configmap_name

    @staticmethod
    def read_data( configmap, key):
        return configmap.data.get(key)

    def _create_dict(self, authinfo, userinfo,  arguments):       
        # Default configmap dict
        mydict_configmap = arguments
        return mydict_configmap

    def patch(self, authinfo, userinfo, arguments ): 

        myauth_dict_configmap = self._create_dict( authinfo, userinfo, arguments ) 
        # we suppose that the configmap has changed 
        # labels_dict = { 'access_provider':  authinfo.provider, 'access_userid': userinfo.userid, 'access_type': self.access_type }
        # metadata = client.V1ObjectMeta( name=myconfigmapname, labels=labels_dict, namespace=self.namespace )        
        myconfigmapname = self.get_name( userinfo )        
        body = { 'data' : myauth_dict_configmap }
        created_configmap = self.kubeapi.patch_namespaced_config_map( name=myconfigmapname, namespace=self.namespace, body=body)
        return  created_configmap

    def _create(self, authinfo, userinfo, arguments ): 
        myauth_dict_configmap = self._create_dict( authinfo, userinfo, arguments )  
        myconfigmapname = self.get_name( userinfo )
        labels_dict = { 'access_provider':  authinfo.provider, 'access_userid': userinfo.userid, 'access_type': self.access_type }
        metadata = client.V1ObjectMeta( name=myconfigmapname, labels=labels_dict, namespace=self.namespace )  
        myconfigmap = client.V1ConfigMap( data=myauth_dict_configmap, metadata=metadata )         
        created_configmap = self.kubeapi.create_namespaced_config_map( namespace=self.namespace, body=myconfigmap)
        self.logger.info( 'new configmap name %s created', myconfigmapname )
        return  created_configmap

    def read( self, userinfo ):
        myconfigmap = None
        try:            
            configmap_name = self.get_name( userinfo )
            myconfigmap = self.kubeapi.read_namespaced_config_map( name=configmap_name, namespace=self.namespace )
        except ApiException as e:
            if e.status != 404:
                self.logger.error('configmap name %s can not be read: %s', str(configmap_name), e ) 
        return myconfigmap
      
    def delete( self, userinfo ):
        ''' delete a configmap '''
        self.logger.debug('')
        v1status = None
        try:            
            configmap_name = self.get_name( userinfo )
            v1status = self.kubeapi.delete_namespaced_config_map( name=configmap_name, namespace=self.namespace )
        except ApiException as e:
            self.logger.error('configmap name %s can not be deleted %s', str(configmap_name), e ) 
        return v1status

    def create(self, authinfo, userinfo, data ):
        """[create configmap]

        Args:
            authinfo (AuthInfo): authentification data
            userinfo (AuthUser): user data 
            data ([dict]): [dictionnary key value]

        Returns:
            [client.models.v1_config_map.V1ConfigMap ]: [kubernetes V1ConfigMap]
        """
        self.logger.debug('')
        myconfigmap = None

        # sanity check 
        readconfigmap = self.read(userinfo)
        try:
            # if the configmap already exists, delete it 
            if isinstance( readconfigmap, client.models.v1_config_map.V1ConfigMap) :
                # a configmap already exists, patch it with new data 
                # it may contains obsolete value, for example if the password has changed
                myconfigmap = self.delete(  userinfo )

            myconfigmap = self._create( authinfo, userinfo, data )
            if not isinstance( myconfigmap, client.models.v1_config_map.V1ConfigMap):
                # an error occurs
                self.logger.error( 'Failed to create configmap return type=%s', type(myconfigmap) )
            else: 
                # This section is to debug an config map create issue
                # try to read the configmap created
                # there should be an error in sync etc database
                self.logger.debug( 'create configmap return type=%s', type(myconfigmap) )
                readconfigmap = self.read(userinfo)
                if not isinstance( readconfigmap, client.models.v1_config_map.V1ConfigMap):
                    # an error occurs
                    self.logger.error( 'Failed to read a created configmap' )
                self.logger.debug( 'reread configmap return %s', type(readconfigmap) )

        except Exception as e:
            self.logger.error( 'Failed to create configmap type=%s %s', str(self.configmap_type), str(e) )

        return myconfigmap

class ODConfigMapLocalAccount( ODConfigMap ):
    ''' Create a configmap used for /etc/password and /etc/shadow'''
    def __init__( self, namespace, kubeapi, prefix=None, configmap_type='localaccount' ):
        super().__init__( namespace, kubeapi, prefix, configmap_type)
        self.access_type='localaccount'

    def _create_dict(self, authinfo, userinfo,  arguments):   
        
        # Default configmap dict
        uid = arguments.get('uid' )
        sha512 = arguments.get('sha512')
        uidNumber =  arguments.get('uidNumber' )
        gidNumber =  arguments.get('gidNumber' )
        passwd_line = f"{uid}:x:{uidNumber}:{gidNumber}::{oc.od.settings.balloon_homedirectory}:{oc.od.settings.balloon_shell}"
        group_line  = f"{uid}:x:{gidNumber}" + "\n" + "sudo:x:27:{uid}"
        shadow_line = f"{uid}:{sha512}:19080:0:99999:7:::"

        passwd_file = oc.od.settings.DEFAULT_PASSWD_FILE + '\n' + passwd_line
        group_file  = oc.od.settings.DEFAULT_GROUP_FILE  + '\n' + group_line
        shadow_file = oc.od.settings.DEFAULT_SHADOW_FILE + '\n' + shadow_line
        
        mydict_configmap = { 'passwd' : passwd_file, 'shadow' : shadow_file, 'group': group_file }
        return mydict_configmap
