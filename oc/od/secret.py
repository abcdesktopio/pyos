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

import oc.logging
import oc.od.settings
import oc.auth.namedlib
import oc.od.volume   # manage volume

from kubernetes import client
from kubernetes.client.rest import ApiException

import base64
import json


def selectSecret( namespace, kubeapi, prefix, secret_type):
        secret = None
        secret_cls = None
     
        if secret_type == 'cifs': 
            secret_cls = ODSecretCIFS
        elif secret_type == 'webdav':
            secret_cls = ODSecretWEBDAV
        elif secret_type == 'ldif':
            secret_cls = ODSecretLDIF
        elif secret_type == 'citrix':
            secret_cls = ODSecretCitrix
        else:
            secret_cls = ODSecret

        secret = secret_cls( namespace, kubeapi, prefix, secret_type )
        if secret is None:
            raise NotImplementedError('Secret type=%s can not be instanciated', secret_type) 
       
        return secret

def list_secretype():
    return [ 'cifs', 'webdav', 'ldif', 'citrix' ]


@oc.logging.with_logger()
class ODSecret():

    def __init__( self, namespace, kubeapi, prefix, secret_type ):
        self.namespace  = namespace
        self.kubeapi    = kubeapi
        self.secretnameheader = 'auth' 
        self.access_type='auth'
        self.secret_type = namespace + '/' + secret_type
        self.normalize_name_secret_type = secret_type.replace( '/', '-')
        if type(prefix) is str:
            self.prefix = '-' + prefix
        else:
           self.prefix = ''
        
    def get_name( self, userinfo ):   
        secret_name = self.secretnameheader + '-' + self.normalize_name_secret_type + '-' + userinfo.userid + self.prefix
        secret_name = oc.auth.namedlib.normalize_name(secret_name)        
        return secret_name

    @staticmethod
    def b64tostr( s ):    
        b = base64.b64decode( s.encode('ascii') ).decode('utf-8')
        return b

    @staticmethod
    def b64tobytes( s ):    
        b = base64.b64decode( s.encode('ascii') )
        return b

    @staticmethod
    def b64todata( s ):    
        b = base64.b64decode( s )
        try:
            b = b.decode('utf-8')
        except Exception:
            pass
        return b

    @staticmethod
    def strtob64( s ):        
        b = base64.b64encode( s.encode('utf-8') ).decode('ascii')
        return b

    @staticmethod
    def bytestob64( s ):        
        b = base64.b64encode( s ).decode('ascii')
        return b

    def _create_dict(self, authinfo, userinfo,  arguments):       
       
        # Default secret dict
        mydict_secret = {}

        # convert each argument key to base64
        for key in arguments.keys():
            argument_type = type(arguments[key])
            if argument_type is str:
                mydict_secret.update( { key:  ODSecret.strtob64(arguments[key]) } )
            if argument_type is bytes:
                mydict_secret.update( { key:  ODSecret.bytestob64(arguments[key]) } )

        return mydict_secret

    def patch(self, authinfo, userinfo, old_secret, arguments ): 

        myauth_dict_secret = self._create_dict( authinfo, userinfo, arguments ) 
        # we suppose that the secret has changed 
        # labels_dict = { 'access_provider':  authinfo.provider, 'access_userid': userinfo.userid, 'access_type': self.access_type }
        # metadata = client.V1ObjectMeta( name=mysecretname, labels=labels_dict, namespace=self.namespace )        
        mysecretname = self.get_name( userinfo )        
        body = { 'data' : myauth_dict_secret }
        created_secret = self.kubeapi.patch_namespaced_secret( name=mysecretname, namespace=self.namespace, body=body)

        return  created_secret

    def _create(self, authinfo, userinfo, arguments ): 
        myauth_dict_secret = self._create_dict( authinfo, userinfo, arguments )  
        mysecretname = self.get_name( userinfo )
        labels_dict = { 'access_provider':  authinfo.provider, 'access_userid': userinfo.userid, 'access_type': self.access_type }
        metadata = client.V1ObjectMeta( name=mysecretname, labels=labels_dict, namespace=self.namespace )        
        mysecret = client.V1Secret( data=myauth_dict_secret, metadata=metadata, type=self.secret_type )         
        created_secret = self.kubeapi.create_namespaced_secret( namespace=self.namespace, body=mysecret)
        self.logger.info( 'new secret name %s type %s created', mysecretname, self.secret_type )
        return  created_secret

    def read( self, userinfo ):
        mysecret = None
        try:            
            secret_name = self.get_name( userinfo )
            mysecret = self.kubeapi.read_namespaced_secret( name=secret_name, namespace=self.namespace )
        except ApiException as e:
            self.logger.debug('secret name %s can not be read: error %s', secret_name, e ) 
        return mysecret
      
    def delete( self, userinfo ):
        ''' delete a secret '''
        self.logger.debug('')
        v1status = None
        try:            
            secret_name = self.get_name( userinfo )
            v1status = self.kubeapi.delete_namespaced_secret( name=secret_name, namespace=self.namespace )
        except ApiException as e:
            self.logger.debug('secret name %s can not be deleted: error %s', secret_name, e ) 
        return v1status

    def create(self, authinfo, userinfo, data ):
        self.logger.debug('')
        mysecret = None
        op = None

        # sanity check 
        readsecret = self.read(userinfo)
        try:
            if type( readsecret ) is client.models.v1_secret.V1Secret :
                # a secret already exists, patch it with new data 
                # it may contains obsolete value, for example if the password has changed
                op = 'patch' # operation is used for log message
                mysecret = self.patch( authinfo, userinfo, old_secret=readsecret, arguments=data )
            else:
                # the secret does not exist, create a new one
                op = 'create'  # operation is used for log message
                mysecret = self._create( authinfo, userinfo, data )
        except Exception as e:
            self.logger.error( 'Failed to %s secret type=%s %s', str(op), str(self.secret_type), str(e) )
        
        if type( mysecret ) is client.models.v1_secret.V1Secret :
            self.logger.info( '%s secret type=%s name=%s done', str(op), self.secret_type, mysecret.metadata.name )

        return mysecret

class ODSecretLDIF( ODSecret ):
    ''' Create a secret used for userinfo ldif '''
    def __init__( self, namespace, kubeapi, prefix=None, secret_type='ldif' ):
        super().__init__( namespace, kubeapi, prefix, secret_type)
        self.access_type='ldif'


class ODSecretCitrix( ODSecret ):
    ''' Create a secret used for userinfo ldif '''
    def __init__( self, namespace, kubeapi, prefix=None, secret_type='citrix' ):
        super().__init__( namespace, kubeapi, prefix, secret_type)
        self.access_type='auth'

class ODSecretRemoteFileSystemDriver( ODSecret ):
    ''' Create a secret used by for Remote File System driver ''' 

    def __init__( self, namespace, kubeapi, prefix, secret_type ):
        super().__init__( namespace, kubeapi, prefix, secret_type)
        self.access_type='driver'

    def read_credentials( self, userinfo ):
        self.logger.info('')
        credentials = {}
        mysecret = self.read( userinfo )
        if mysecret is None:
            self.logger.error('read secret return None, credentials failed')
            return credentials
        keyArray = [ 'username', 'password', 'domain' ]
        for k in keyArray:
            credentials[k] = ODSecret.b64tostr( mysecret.data.get(k) )
        return credentials
    
    def read_data( self, arguments ):
        mysecret = self.read( arguments )
        if mysecret is None:
            self.logger.error('read secret return None, data failed')
            return {}
        data = mysecret.data
        data = data.get('data')
        if data :
             return json.loads( ODSecret.b64tostr( data ) )
        return {} 

    def _create_dict(self, authinfo, userinfo, arguments):       
        # Value must exists
        userid      = authinfo.claims['userid']     # Exception if not set
        password    = authinfo.claims['password']   # Exception if not set
        str_dict_data   = json.dumps( arguments )
        
        ## Driver use values
        ## cifsUsernameBase64="$(jq --raw-output -e '.["kubernetes.io/secret/username"]' <<< "$json" 2>/dev/null)"
	    ## cifsPasswordBase64="$(jq --raw-output -e '.["kubernetes.io/secret/password"]' <<< "$json" 2>/dev/null)"
	    ## cifsDomainBase64="$(jq --raw-output -e '.["kubernetes.io/secret/domain"]' <<< "$json" 2>/dev/null)"
        ## Mount values are set to data dict 

        # Default secret 
        mydict_secret = {   'username'  :  ODSecret.strtob64( userid ),
                            'password'  :  ODSecret.strtob64( password ),
                            'data'      :  ODSecret.strtob64( str_dict_data)                      
        }

        # append domain only if set 
        domain          = authinfo.claims.get('domain', None )    # None if not set
        if domain :
            mydict_secret.update( { 'domain':  ODSecret.strtob64(domain) } )
        return mydict_secret


class ODSecretCIFS( ODSecretRemoteFileSystemDriver ):
    ''' Create a secret used for CIFS driver ''' 
    def __init__( self, namespace, kubeapi, prefix, secret_type='cifs' ):
        super().__init__( namespace, kubeapi, prefix, secret_type )



class ODSecretWEBDAV( ODSecretRemoteFileSystemDriver ):
    ''' Create a secret used for WEBDAV driver ''' 
    def __init__( self, namespace, kubeapi, prefix, secret_type='webdav' ):
        super().__init__( namespace, kubeapi, prefix, secret_type)