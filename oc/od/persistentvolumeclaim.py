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
import time
from oc.auth.authservice import AuthInfo, AuthUser
from typing_extensions import assert_type

from kubernetes.client.api.core_v1_api import CoreV1Api
from kubernetes.client.rest import ApiException
from kubernetes.client.models.v1_persistent_volume import V1PersistentVolume
from kubernetes.client.models.v1_persistent_volume_list import V1PersistentVolumeList
from kubernetes.client.models.v1_persistent_volume_spec import V1PersistentVolumeSpec
from kubernetes.client.models.v1_persistent_volume_status import V1PersistentVolumeStatus
from kubernetes.client.models.v1_persistent_volume_claim import V1PersistentVolumeClaim
from kubernetes.client.models.v1_persistent_volume_claim_list import V1PersistentVolumeClaimList
from kubernetes.client.models.v1_persistent_volume_claim_spec import V1PersistentVolumeClaimSpec
from kubernetes.client.models.v1_persistent_volume_claim_status import V1PersistentVolumeClaimStatus
from kubernetes.client.models.v1_resource_requirements import V1ResourceRequirements
from kubernetes.client.models.v1_object_meta import V1ObjectMeta
from kubernetes.client.models.v1_status import V1Status

logger = logging.getLogger(__name__)

@oc.logging.with_logger()
class ODPersistentVolumeClaim():

    def __init__( self, namespace:str, kubeapi:CoreV1Api, prefix:str=None ):
        self.namespace  = namespace
        self.kubeapi    = kubeapi
        self.prefix = ''
        self.separator = '-'
        if type(prefix) is str:
            self.prefix +=  prefix

    def get_pv_name( self, authinfo:AuthInfo, userinfo:AuthUser, suffix:str )->str:
        return self.get_name(authinfo=authinfo, userinfo=userinfo, suffix=suffix)

    def get_pvc_name( self, authinfo:AuthInfo, userinfo:AuthUser, suffix:str )->str: 
        return self.get_name(authinfo=authinfo, userinfo=userinfo, suffix=suffix)  

    def get_name( self, authinfo:AuthInfo, userinfo:AuthUser, suffix:str='' )->str:   
        assert_type( authinfo, AuthInfo)
        assert_type( userinfo, AuthUser)
        name = self.prefix + authinfo.provider + self.separator + userinfo.userid + self.separator + suffix
        name = name.lower()
        name = oc.auth.namedlib.normalize_name_dnsname(name)     
        return name

    def get_labels( self, authinfo:AuthInfo, userinfo:AuthUser )->dict:
        assert_type( authinfo, AuthInfo)
        assert_type( userinfo, AuthUser)
        labels = {  'access_provider':      authinfo.provider,
                    'access_providertype':  authinfo.providertype,
                    'access_userid':        userinfo.userid }
        return labels

    def get_label_selector( self, labels:dict )->str:
        # label_selector = ''
        # for k in labels.key():
        #     if labels.get(k):
        #        if len(label_selector) > 0;
        #            label_selector += ','
        #        label_selector += k + '=' labels[k]

        label_selector = f"access_provider={labels['access_provider']},\
            access_providertype={labels['access_providertype']},\
            access_userid={labels['access_userid']}"
        
        return label_selector


    def create( self, authinfo:AuthInfo, userinfo:AuthUser, persistentvolumespec:dict, persistentvolumeclaimspec:dict )->V1PersistentVolumeClaim:
        self.logger.debug('')
        assert_type( authinfo, AuthInfo)
        assert_type( userinfo, AuthUser)

        # look for pvc
        pvc = self.find_pvc( authinfo=authinfo, userinfo=userinfo )
        if isinstance( pvc, V1PersistentVolumeClaim ):
            return pvc

        self.logger.debug( 'pvc does not exist, create a new one' )

        # assert_type( persistentvolumespec, dict ) can be None if 
        # Dynamically provisioned PVC:
        # A bucket or path inside bucket will be created automatically
        # for the PV and removed when the PV will be removed
        assert_type( persistentvolumeclaimspec, dict )

        # unique suffix to get the same name between pvc and pv
        suffix = oc.lib.uuid_digits()

        # create a V1PersistentVolume if need
        persistentvolume = None
        if isinstance( persistentvolumespec, dict ): 
            self.logger.debug( f"create a persistentvolume suffix={suffix}" )
            persistentvolume  = self.create_pv( authinfo=authinfo, userinfo=userinfo, persistentvolumespec=persistentvolumespec, suffix=suffix )
        
        # a PersistentVolume is optional but recommanded
        if not isinstance( persistentvolume, V1PersistentVolume ):
            self.logger.debug( f"V1PersistentVolume is not created, continue to create a V1PersistentVolumeClaim without name mapping" )

        # create a V1PersistentVolumeClaim
        self.logger.debug( f"create a persistentvolumeclaim suffix={suffix}" )
        pvc = self.create_pvc( authinfo=authinfo, userinfo=userinfo, persistentvolume=persistentvolume, persistentvolumeclaimspec=persistentvolumeclaimspec,  suffix=suffix  )
        return pvc


    def waitforBoundPVC( self, name:str, callback_notify, timeout:int=42 )->tuple:
        self.logger.debug('')
        assert_type( name, str)
        pvc = None
        c = 0
        while( c<timeout):
            c = c + 1
            pvc = self.kubeapi.read_namespaced_persistent_volume_claim(name=name, namespace=self.namespace)
            if isinstance(pvc, V1PersistentVolumeClaim) :
                if isinstance( pvc.status, V1PersistentVolumeClaimStatus):
                    # A volume will be in one of the following phases:
                    #   Available -- a free resource that is not yet bound to a claim
                    #   Bound -- the volume is bound to a claim
                    #   Released -- the claim has been deleted, but the resource is not yet reclaimed by the cluster
                    #   Failed -- the volume has failed its automatic reclamation
                    if callable(callback_notify):
                        callback_notify( f"b.Reading your volume {name}, status is {pvc.status.phase}" )
                    if pvc.status.phase == 'Bound':
                        return (True, f"b.Volume {name} is bound to claim {name}")
                    if pvc.status.phase == 'Failed':
                        return (False, f"e.Volume {name} has failed its automatic reclamation, claim={name}")
                    if pvc.status.phase in [ 'Pending', 'Available' ]:
                        time.sleep(1)
            else:
                time.sleep(1)
        return (False, f"e.Volume {name} has failed its automatic reclamation")


    def find_pv( self, authinfo:AuthInfo, userinfo:AuthUser )->V1PersistentVolume:
        self.logger.debug('')
        pv = None
        label_selector= self.get_label_selector(  self.get_labels(authinfo, userinfo) ) 
        pv_list = self.kubeapi.list_persistent_volume( label_selector=label_selector )
        if isinstance( pv_list, V1PersistentVolumeList):
            for pv_item in pv_list.items:
                if isinstance( pv_item, V1PersistentVolume ):
                    if isinstance( pv_item, V1PersistentVolumeStatus):
                        self.logger.debug( f"{pv_item.metadata.name} phase is {pv_item.status.phase}")
                        if pv_item.status.phase in [ 'Bound', 'Pending', 'Available' ] :
                            pv = pv_item
                            break
        return pv


    def find_pvc( self, authinfo:AuthInfo, userinfo:AuthUser )->V1PersistentVolumeClaim:
        self.logger.debug('')
        pvc = None
        label_selector= self.get_label_selector( self.get_labels(authinfo, userinfo) ) 
        self.logger.debug( f"look for pvc {label_selector}" )
        pvc_list = self.kubeapi.list_namespaced_persistent_volume_claim( namespace=self.namespace, label_selector=label_selector )
        if isinstance( pvc_list, V1PersistentVolumeClaimList):
            for pvc_item in pvc_list.items:
                if isinstance( pvc_item, V1PersistentVolumeClaim ):
                    if isinstance( pvc_item.status, V1PersistentVolumeClaimStatus ):
                        self.logger.debug( f"{pvc_item.metadata.name} phase is {pvc_item.status.phase}")
                        if pvc_item.status.phase == 'Terminating'  :
                            continue
                        pvc = pvc_item
        if isinstance( pvc, V1PersistentVolumeClaim):
            self.logger.debug( f"pvc found name={pvc.metadata.name}" )
        else:
            self.logger.debug( "pvc not found" )
        return pvc


    def create_pv( self, authinfo:AuthInfo, userinfo:AuthUser, persistentvolumespec:dict, suffix:str )->V1PersistentVolume:
        self.logger.debug('')
        pv = self.find_pv( authinfo, userinfo )
        if isinstance( pv, V1PersistentVolume ):
            self.logger.debug( f"pv has been found name={pv.metadata.name}" )
            return pv 

        self.logger.debug( "pv not found, create a new one" )
        pv_name = self.get_pv_name( authinfo, userinfo, suffix )
        pv_labels = self.get_labels( authinfo, userinfo )
        # spec:
        # storageClassName: manual
        # capacity:
        #  storage: 10Gi
        # accessModes:
        #  - ReadWriteOnce
        # hostPath:
        #  path: "/mnt/data"
        

        #volumeSpec = {
        #    'storageClassName': storage_class_name,
        #    'capacity': { 
        #        'storage': '10Gi' 
        #    },
        #    'accessModes': [ 'ReadWriteOnce' ], 
        #    'hostPath': {
        #        'path': '/mnt/data' 
        #    }
        #}
        metadata    = V1ObjectMeta( name=pv_name, labels=pv_labels )
        body        = V1PersistentVolume( metadata=metadata, spec=persistentvolumespec )
        pv = self.kubeapi.create_persistent_volume( body=body )
        if isinstance( pv, V1PersistentVolume):
            self.logger.debug( f"pv created name={pv.metadata.name}" )
        else:
            self.logger.debug( "pv create failed" )
        return pv



    def create_pvc( self, authinfo:AuthInfo, userinfo:AuthUser, persistentvolume:V1PersistentVolume, persistentvolumeclaimspec:dict, suffix:str )->V1PersistentVolumeClaim:

        assert_type(authinfo, AuthInfo)
        assert_type(userinfo, AuthUser)
        assert_type(persistentvolumeclaimspec,dict)

        pvc = self.find_pvc( authinfo, userinfo )
        if isinstance( pvc, V1PersistentVolumeClaim ):
            self.logger.debug( f"pvc has been found name={pvc.metadata.name}" )
            return pvc 

        #
        # read https://kubernetes.io/docs/concepts/storage/persistent-volumes/
        #

        # apiVersion: v1
        # kind: PersistentVolumeClaim
        # metadata:
        #   name: foo-pvc
        #   namespace: foo
        # spec:
        # storageClassName: "" # Empty string must be explicitly set otherwise default StorageClass will be set
        # volumeName: foo-pv
        # ...

        # spec=V1PersistentVolumeClaimSpec(
        #            access_modes=["ReadWriteOnce"],
        #            storage_class_name='',
        #            resources=V1ResourceRequirements( requests={ 'storage': '1Gi'} ),
        #            volume_name = pv_name )
        pvc_name = self.get_pvc_name(  authinfo, userinfo, suffix )
        if isinstance( persistentvolume, V1PersistentVolume):
            persistentvolumeclaimspec['volumeName'] = persistentvolume.metadata.name

        # pvc does not exist create a new one        
        pvc_labels = self.get_labels( authinfo, userinfo )
        # add https://kubernetes.io/docs/concepts/storage/persistent-volumes/
        body = V1PersistentVolumeClaim( 
                metadata=V1ObjectMeta(name=pvc_name, labels=pvc_labels ),
                spec=persistentvolumeclaimspec
        )
        pvc = self.kubeapi.create_namespaced_persistent_volume_claim( namespace=self.namespace, body=body )
        return pvc

    def get_persistent_volume_claim( self, claim_name:str=None, storage_class_name:str=None )->str:
        pvc = None
        try:
            pvc = self.kubeapi.read_namespaced_persistent_volume_claim( namespace=self.namespace, name=claim_name )
        except ApiException as e:
            pass
        return pvc



