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

from kubernetes import watch
from kubernetes.client.models.core_v1_event import CoreV1Event
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
        self.namespace = namespace
        self.kubeapi = kubeapi
        self.separator = '-'
        self.prefix = prefix if isinstance(prefix,str) else ''

    def get_pv_name( self, authinfo:AuthInfo, userinfo:AuthUser, suffix:str=None )->str:  
        return self.get_name(authinfo=authinfo, userinfo=userinfo, suffix=suffix)

    def get_pvc_name( self, authinfo:AuthInfo, userinfo:AuthUser, suffix:str=None )->str: 
        return self.get_name(authinfo=authinfo, userinfo=userinfo, suffix=suffix)  

    def get_name( self, authinfo:AuthInfo, userinfo:AuthUser, suffix:str=None )->str:   
        assert_type( authinfo, AuthInfo)
        assert_type( userinfo, AuthUser)
        name = self.prefix + authinfo.provider + self.separator + userinfo.userid
        if isinstance(suffix, str):
             name = name + self.separator + suffix
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
    
    def delete_pv( self, name:str):
        """delete_pv
            delete persistent volume in async 
        Args:
            name (str): name of the persistent volume
        """
        self.logger.debug('')        
        assert_type( name, str)
        try:
            # todo should better use the uid of the pvc than the name (volume_name)
            self.kubeapi.delete_persistent_volume( name=name, async_req=True )
        except ApiException as e:
            self.logger.error( e )
        

    def delete_pvc( self, authinfo:AuthInfo, userinfo:AuthUser )->V1PersistentVolumeClaim:
        self.logger.debug('')
        assert_type( authinfo, AuthInfo)
        assert_type( userinfo, AuthUser)

        deleted_pvc = None

        if oc.od.settings.desktop['removepersistentvolumeclaim'] is True: 
            # look for pvc
            pvc = self.find_pvc( authinfo=authinfo, userinfo=userinfo )
            if not isinstance( pvc, V1PersistentVolumeClaim ):
                self.logger.debug(f"delete_pvc can not found pvc for user authinfo={authinfo} userinfo={userinfo}")
                return None
            try:
                volume_name = None
                if isinstance( pvc.spec, V1PersistentVolumeClaimSpec ):
                    volume_name = pvc.spec.volume_name
                self.logger.debug(f"deleting pvc {pvc.metadata.name}")
                deleted_pvc = self.kubeapi.delete_namespaced_persistent_volume_claim( 
                    namespace=self.namespace, 
                    name=pvc.metadata.name, 
                    grace_period_seconds=0,
                    propagation_policy='Foreground'
                )
                if isinstance( deleted_pvc , V1PersistentVolumeClaim):
                    self.logger.debug(f"pvc {deleted_pvc.metadata.name} has beed deleted")
                    if isinstance( volume_name, str ):
                        if oc.od.settings.desktop['removepersistentvolume'] is True:
                            # delete the pc in async mod
                            self.logger.debug(f"deleting pv {volume_name} in async")
                            self.delete_pv( volume_name )
            except ApiException as e:
                self.logger.error( e )
        
        return deleted_pvc

    def create( self, authinfo:AuthInfo, userinfo:AuthUser, persistentvolume_request:dict, persistentvolumeclaim_request:dict )->V1PersistentVolumeClaim:
        self.logger.debug('')
        assert_type( authinfo, AuthInfo)
        assert_type( userinfo, AuthUser)

        # look for pvc
        pvc = self.find_pvc( authinfo=authinfo, userinfo=userinfo, persistentvolumeclaim=persistentvolumeclaim_request )
        if isinstance( pvc, V1PersistentVolumeClaim ):
            return pvc

        self.logger.debug( 'pvc does not exist, create a new one' )

        # assert_type( persistentvolume, dict ) can be None if 
        # Dynamically provisioned PVC:
        # A bucket or path inside bucket will be created automatically
        # for the PV and removed when the PV will be removed
        assert_type( persistentvolumeclaim_request, dict )

        # unique suffix to get the same name between pvc and pv
        # suffix = oc.lib.uuid_digits()
        suffix = None

        # create a V1PersistentVolume if need
        persistentvolume = None
        if isinstance( persistentvolume_request, dict ): 
            self.logger.debug( f"create a persistentvolume suffix={suffix}" )
            persistentvolume  = self.create_pv( authinfo=authinfo, userinfo=userinfo, persistentvolume_request=persistentvolume_request, suffix=suffix )
        
        # a PersistentVolume is optional but recommanded
        if not isinstance( persistentvolume, V1PersistentVolume ):
            self.logger.debug( f"V1PersistentVolume is not created, continue to create a V1PersistentVolumeClaim without name mapping" )

        # create a V1PersistentVolumeClaim
        self.logger.debug( f"create a persistentvolumeclaim suffix={suffix}" )
        pvc = self.create_pvc( 
            authinfo=authinfo, 
            userinfo=userinfo, 
            persistentvolume=persistentvolume,
            persistentvolumeclaim=persistentvolumeclaim_request,
            suffix=suffix  )
        return pvc

    
    def waitforBoundPVC( self, name:str, callback_notify, timeout:int=42 )->tuple:
        self.logger.debug('')
        assert_type( name, str )
        w = watch.Watch()                 
        event_counter = 0
        for event in w.stream(  self.kubeapi.list_namespaced_persistent_volume_claim, 
                                namespace=self.namespace, 
                                timeout_seconds=oc.od.settings.desktop['K8S_BOUND_PVC_TIMEOUT_SECONDS'],
                                field_selector=f'metadata.name={name}' ):  
            if event_counter > oc.od.settings.desktop['K8S_BOUND_PVC_MAX_EVENT']:
                return (False, f"e.Volume {name} has failed {event_counter}/{oc.od.settings.desktop['K8S_BOUND_PVC_MAX_EVENT']}")
            
            self.logger.debug( f"read event {event_counter} {event}")
            # safe type test event is a dict
            if not isinstance(event, dict ): continue
            pvc = event.get('object')
            if not isinstance(pvc, V1PersistentVolumeClaim ): continue
            
            # volume_mode = 'unknowfilesystem'
            volume_name = 'unknowvolumename'
            storage_class_name = 'unknowstorageclassname'
            if isinstance( pvc.spec, V1PersistentVolumeClaimSpec ):
                # volume_mode = pvc.spec.volume_mode
                volume_name = pvc.spec.volume_name
                storage_class_name = pvc.spec.storage_class_name
            if isinstance( pvc.status, V1PersistentVolumeClaimStatus):
                    # A volume will be in one of the following phases:
                    #   Available -- a free resource that is not yet bound to a claim
                    #   Bound -- the volume is bound to a claim
                    #   Released -- the claim has been deleted, but the resource is not yet reclaimed by the cluster
                    #   Failed -- the volume has failed its automatic reclamation
                    if callable(callback_notify):
                        callback_notify( f"b.Reading your persistent volume claim {name}, status is {pvc.status.phase}, using storage class {storage_class_name} " )
                    if pvc.status.phase == 'Bound':
                        return (True, f"b. Your persistent volume claim {name} is {pvc.status.phase} using storage class {storage_class_name} ")
                    if pvc.status.phase == 'Failed':
                        return (False, f"e.PersistentVolumeClaim {name} has failed its automatic reclamation, claim={name}, volume {volume_name}, storage class {storage_class_name}")
                    if pvc.status.phase in [ 'Pending', 'Available' ]:
                        event_counter += 1

        return (False, f"e.Volume {name} has failed its automatic reclamation")

    '''
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
    '''

    def unrelease_pv( self, persistentvolume:V1PersistentVolume )->V1PersistentVolume:
        # kubectl patch pv pv-for-rabbitmq -p '{"spec":{"claimRef": null}}'
        # when a pvc/pv binding happens, it updates the .spec.claimRef section of the pv. 
        # You can check this using k get pv pv-name -o jsonpath="{.spec.claimRef}". 
        # By patching this to null means erasing this binding and making it available
        assert_type( persistentvolume, V1PersistentVolume )
        pv_patch = { 'spec': { 'claimRef': None } }
        newpv = None
        try: 
            newpv = self.kubeapi.patch_persistent_volume( name=persistentvolume.metadata.name, body=pv_patch )
            self.logger.debug( f"{persistentvolume.metadata.name}.spec.claimRef has been set to None"  )
        except ApiException as e:
            self.logger.error( f"{persistentvolume.metadata.name}.spec.claimRef has NOT been set to None"  )
            self.logger.error( e )
        return newpv


    def find_pv( self, authinfo:AuthInfo, userinfo:AuthUser, persistentvolume:V1PersistentVolume )->V1PersistentVolume:
        self.logger.debug('')

        pv = None # default return value

        # check if the persistentvolume has a meta and name
        pv_name = None
        if isinstance( persistentvolume, dict ):
            if isinstance( persistentvolume.get('metadata'), dict ):
                pv_name = persistentvolume.get('metadata').get('name')

        if isinstance( persistentvolume, V1PersistentVolume ):
            pv_name = persistentvolume.metadata.name
        
        if isinstance( pv_name, str ):
            # look for this pv
            self.logger.debug( f"look for pv name={pv_name}" )
            pv = self.get_persistent_volume( name=pv_name )
            if isinstance( pv, V1PersistentVolume):
                return pv

        # pv is not found using metadate.name
        # look for using label selector
        self.logger.debug('pv is not found using metadate.name')        
        label_selector= self.get_label_selector( self.get_labels(authinfo, userinfo) ) 
        self.logger.debug( f"try to find one using label_selector={label_selector}")
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


    def find_pvc( self, authinfo:AuthInfo, userinfo:AuthUser, persistentvolumeclaim:dict=None )->V1PersistentVolumeClaim:
        self.logger.debug('')
 
        pvc = None # return default value  
        # check if the persistentvolumeclaim has a metadata and name
        pvc_name = None
        if isinstance( persistentvolumeclaim, dict ):
            if isinstance( persistentvolumeclaim.get('metadata'), dict ):
                pvc_name = persistentvolumeclaim.get('metadata').get('name')
    
        if isinstance( persistentvolumeclaim, V1PersistentVolumeClaim ):
            pvc_name = persistentvolumeclaim.metadata.name

        if isinstance( pvc_name, str ):
            # look for this pvc 
            self.logger.debug( f"look for pvc name={pvc_name}" )
            pvc = self.get_persistent_volume_claim( name=pvc_name )
            if isinstance( pvc, V1PersistentVolumeClaim):
                return pvc

        label_selector= self.get_label_selector( self.get_labels(authinfo, userinfo) ) 
        self.logger.debug( f"look for pvc label_selector={label_selector}" )
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


    def create_pv( self, authinfo:AuthInfo, userinfo:AuthUser, persistentvolume_request:dict, suffix:str=None )->V1PersistentVolume:
        self.logger.debug('')
        assert_type(authinfo, AuthInfo)
        assert_type(userinfo, AuthUser)
        assert_type(persistentvolume_request,dict)

        pv_spec = persistentvolume_request.get('spec')
        assert_type( pv_spec, dict)

        pv_metadata = persistentvolume_request.get('metadata')
        assert_type( pv_metadata, dict)

        # if no name has been defined
        if not isinstance(pv_metadata.get('name'), str):
            pv_metadata['name'] = self.get_pv_name(  authinfo, userinfo, suffix )

        if not isinstance(pv_metadata.get('labels'), dict):
            pv_metadata['labels'] = {}

        # add always user labes to the pvc
        # for example
        # Labels:        
        #   - access_provider=planet
        #   - access_providertype=ldap
        #   - access_userid=fry
        # read user labels
        # put user labels into pv_labels
        pv_metadata['labels'].update( self.get_labels( authinfo, userinfo ) )

        metadata    = V1ObjectMeta( **pv_metadata )
        body        = V1PersistentVolume( metadata=metadata, spec=pv_spec )

        pv = self.find_pv( authinfo, userinfo, persistentvolume=body )
        if isinstance( pv, V1PersistentVolume ):
            self.logger.debug( f"pv has been found name={pv.metadata.name}" )
            # check if pv status phase is released
            # if it is remove claimref
            # else the pvc bound will fail
            if isinstance( pv.status, V1PersistentVolumeStatus):
                if pv.status.phase == 'Released':
                    # try to remove claimref
                    unreleased_pv = self.unrelease_pv( pv )
                    if isinstance( unreleased_pv, V1PersistentVolume):
                        pv = unreleased_pv
            return pv 
        
        pv = self.kubeapi.create_persistent_volume( body=body )

        if isinstance( pv, V1PersistentVolume):
            assert_type( pv.metadata, V1ObjectMeta )
            self.logger.debug( f"pv created name={pv.metadata.name}" )
        else:
            self.logger.debug( "pv create failed" )
        return pv



    def create_pvc( self, authinfo:AuthInfo, userinfo:AuthUser, persistentvolume:V1PersistentVolume, persistentvolumeclaim:dict, suffix:str=None )->V1PersistentVolumeClaim:
        self.logger.debug('')
        assert_type(authinfo, AuthInfo)
        assert_type(userinfo, AuthUser)
        assert_type(persistentvolumeclaim,dict)

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

        pvc_spec = persistentvolumeclaim.get('spec')
        assert_type( pvc_spec, dict)

        pvc_metadata = persistentvolumeclaim.get('metadata')
        assert_type( pvc_metadata, dict)
        
        # if no name has been defined
        if not isinstance(pvc_metadata.get('name'), str):
            pvc_metadata['name'] = self.get_pvc_name(  authinfo, userinfo, suffix )

        if not isinstance(pvc_metadata.get('labels'), dict):
            pvc_metadata['labels'] = {}
        # add always user labes to the pvc
        # for example
        # Labels:        
        #   - access_provider=planet
        #   - access_providertype=ldap
        #   - access_userid=fry
        # read user labels
        # put user labels into pvc_labels
        pvc_metadata['labels'].update( self.get_labels( authinfo, userinfo ) )
            
        # after a create and delete pvc
        # a new pvc can not bound 
        # volume "planet-fry" already bound to a different claim.
        # 
        if isinstance( persistentvolume, V1PersistentVolume) and pvc_spec.get('volumeName') is None:
            pvc_metadata.get('spec')['volumeName'] = persistentvolume.metadata.name
        # add https://kubernetes.io/docs/concepts/storage/persistent-volumes/
        metadata=V1ObjectMeta( **pvc_metadata )
        body = V1PersistentVolumeClaim( metadata=metadata, spec=pvc_spec)
        pvc = self.find_pvc( authinfo, userinfo, persistentvolumeclaim=body )
        if isinstance( pvc, V1PersistentVolumeClaim ):
            assert_type( pvc.metadata, V1ObjectMeta )
            self.logger.debug( f"pvc has been found name={pvc.metadata.name}" )
            return pvc
        self.logger.debug ( f"create {body}")
        pvc = self.kubeapi.create_namespaced_persistent_volume_claim( namespace=self.namespace, body=body )
        return pvc

    def get_persistent_volume_claim( self, name:str )->V1PersistentVolumeClaim:
        pvc = None
        assert_type( name, str)
        try:
            pvc = self.kubeapi.read_namespaced_persistent_volume_claim( namespace=self.namespace, name=name )
        except ApiException as e:
            pass
        return pvc
    
    def get_persistent_volume( self, name:str )->V1PersistentVolume:
        pv = None
        assert_type( name, str)
        try:
            pv = self.kubeapi.read_persistent_volume( name=name )
        except ApiException as e:
            pass
        return pv



