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
import oc.od.volume   # manage volume
from   oc.auth.authservice import AuthInfo, AuthUser

from kubernetes.client.rest import ApiException
from kubernetes.client.models.v1_secret import V1Secret
from kubernetes.client.models.v1_object_meta import V1ObjectMeta
from kubernetes.client.models.v1_status import V1Status

import base64
import json

logger = logging.getLogger(__name__)

def selectSecret( namespace, kubeapi, prefix, secret_type):
    """[selectSecret]
        return a secret class object from a secret_type
    Args:
        namespace ([str]): [kubernetes namespace where secret should be created]
        kubeapi ([api]): [kubernets api object]
        prefix ([str]): [prefix for secret name]
        secret_type ([str]): [type of secret] must be in the list [ 'cifs', 'webdav', 'ldif', 'citrix' ]

    Returns:
        [secret class]: [secret class instance for the secret_type]
    """
    secret = None
    secret_cls = None
    
    # secret_cls_dict is a dict of class 
    # key   : is the class name equal to the secret_type
    # value : is the class object 
    secret_cls_dict = { 'cifs':             ODSecretCIFS,                # use NTLM auth for compatibility cifs use by default cifs_ntlm
                        'cifs_ntlm':        ODSecretCIFS,                # use NTLM auth 
                        'cifs_kerberos' :   ODSecretCIFSKerberos,        # use KERBEROS auth
                        'webdav':           ODSecretWEBDAV,              # 
                        'ldif':             ODSecretLDIF,
                        'kerberos':         ODSecret,
                        'vnc':              ODSecretVNC,
                        'ntlm':             ODSecret,
                        'citrix':           ODSecretCitrix,
                        'localaccount':     ODSecretLocalAccount,
                        'posixaccount':     ODSecretPosixAccount  }
                        
    # get the class from the secret_type
    secret_cls = secret_cls_dict.get( secret_type )
    # instance the class
    if  secret_cls :
        secret = secret_cls( namespace, kubeapi, prefix, secret_type )
    # return the secret object
    return secret

@oc.logging.with_logger()
class ODSecret():

    def __init__( self, namespace:str, kubeapi, prefix:str, secret_type:str ):
        self.namespace  = namespace
        self.kubeapi    = kubeapi
        self.secretnameheader = 'auth' 
        self.access_type='auth'
        self.secret_type = namespace + '/' + secret_type
        self.normalize_name_secret_type = secret_type.replace( '/', '-')
        self.typeConverterValues = {}
        if type(prefix) is str:
            self.prefix = '-' + prefix
        else:
           self.prefix = ''
        
    def get_name( self, authinfo:AuthInfo,  userinfo:AuthUser )->str:   
        secret_name = self.secretnameheader + '-' + self.normalize_name_secret_type + '-' + userinfo.userid + self.prefix
        secret_name = oc.auth.namedlib.normalize_name_dnsname(secret_name)        
        return secret_name

    @staticmethod
    def b64tostr( s:str )->str:
        """[b64tostr]
            convert b64 to str
        Args:
            s ([b64]): [b64 'ascii' encoded str]

        Returns:
            [str]: [str utf-8 ]
        """
        b = base64.b64decode( s.encode('ascii') ).decode('utf-8')
        return b

    @staticmethod
    def b64tobytes( s:str )->bytes:    
        b = base64.b64decode( s.encode('ascii') )
        return b

    @staticmethod
    def b64todata( s:str )->str:    
        b = base64.b64decode( s )
        try:
            # try to decode as utf8
            b = b.decode('utf-8')
        except Exception:
            # self.logger.error( 'failed to decode b64 str %s', str(e))
            # don't care if decode as utf8 has failed, it should not be a utf8
            pass
        return b

    @staticmethod
    def strtob64( s:str )->str:        
        b = base64.b64encode( s.encode('utf-8') ).decode('ascii')
        return b

    @staticmethod
    def bytestob64( s:bytes )->str:        
        b = base64.b64encode( s ).decode('ascii')
        return b

    @staticmethod
    def read_data( secret:V1Secret, key:str)->str:
        data = None
        if isinstance( secret, V1Secret ):
            try:
                b64data = secret.data.get(key)
                data = oc.od.secret.ODSecret.b64todata( b64data )
            except Exception as e:
                logger.error( f"failed to read secret key {key} {e}")
        return data 


    def read_alldata(self, authinfo:AuthInfo, userinfo:AuthUser)->dict:
        readdata = None
        secret = self.read( authinfo, userinfo )
        if isinstance( secret, V1Secret ):
            readdata = {}
            for key in secret.data.keys():
                try:
                    b64data = secret.data.get(key)
                    readdata[key] = oc.od.secret.ODSecret.b64todata( b64data )
                    if self.typeConverterValues.get(key):
                        try:
                            readdata[key] = self.typeConverterValues.get(key)(readdata[key] )
                        except Exception as e:
                            self.logger.error( f"failed to decode typeConverterValues secret key {key} {e}")
                except Exception as e:
                    self.logger.error( f"failed to read secret key {key} {e}")
        return readdata 
        
    def _create_dict(self, authinfo:AuthInfo, userinfo:AuthUser, arguments:dict)->dict:       
        assert isinstance(arguments, dict),  f"arguments has invalid type {type(arguments)}"
        # Default secret dict
        mydict_secret = {}
        # convert each argument key to base64
        for key in arguments.keys():
            argument_type = type(arguments[key])
            if argument_type is str:
                mydict_secret.update( { key:  ODSecret.strtob64(arguments[key]) } )
            elif argument_type is int:
                mydict_secret.update( { key:  ODSecret.strtob64(str(arguments[key])) } )
            elif argument_type is bytes:
                mydict_secret.update( { key:  ODSecret.bytestob64(arguments[key]) } )
            elif argument_type is dict :
                serialized = json.dumps(arguments[key])
                mydict_secret.update( { key:  ODSecret.strtob64(serialized) } )
            elif argument_type is list:
                serialized = json.dumps(arguments[key])
                mydict_secret.update( { key:  ODSecret.strtob64(serialized) } )
        return mydict_secret

    def patch(self, authinfo:AuthInfo, userinfo:AuthUser, arguments )->V1Secret: 
        assert isinstance(arguments, dict),  f"arguments has invalid type {type(arguments)}"
        myauth_dict_secret = self._create_dict( authinfo, userinfo, arguments ) 
        # we suppose that the secret has changed 
        # labels_dict = { 'access_provider':  authinfo.provider, 'access_userid': userinfo.userid, 'access_type': self.access_type }
        # metadata = client.V1ObjectMeta( name=mysecretname, labels=labels_dict, namespace=self.namespace )        
        mysecretname = self.get_name( authinfo, userinfo )        
        body = { 'data' : myauth_dict_secret }
        created_secret = self.kubeapi.patch_namespaced_secret( name=mysecretname, namespace=self.namespace, body=body)
        return  created_secret

    def _create(self, authinfo:AuthInfo, userinfo:AuthUser, arguments:dict )->V1Secret: 
        assert isinstance(arguments, dict),  f"arguments has invalid type {type(arguments)}"
        created_secret = None
        myauth_dict_secret = self._create_dict( authinfo, userinfo, arguments )  
        mysecretname = self.get_name( authinfo, userinfo )
        labels_dict = { 'access_provider':  authinfo.provider, 'access_userid': userinfo.userid, 'access_type': self.access_type }
        metadata = V1ObjectMeta( name=mysecretname, labels=labels_dict, namespace=self.namespace )        
        mysecret = V1Secret( data=myauth_dict_secret, metadata=metadata, type=self.secret_type ) 
        if isinstance( mysecret, V1Secret) :      
            created_secret = self.kubeapi.create_namespaced_secret( namespace=self.namespace, body=mysecret )
            self.logger.info( 'new secret name %s type %s created', mysecretname, self.secret_type )
        return created_secret

    def read( self, authinfo:AuthInfo, userinfo:AuthUser )->V1Secret:
        mysecret = None
        try:            
            secret_name = self.get_name( authinfo, userinfo )
            mysecret = self.kubeapi.read_namespaced_secret( name=secret_name, namespace=self.namespace )
        except ApiException as e:
            if e.status != 404:
                self.logger.error('secret name %s can not be read: error %s', str(secret_name), e ) 
        return mysecret
      
    def delete( self, authinfo:AuthInfo, userinfo:AuthUser )->V1Status:
        ''' delete a secret '''
        self.logger.debug('')
        v1status = None
        try:            
            secret_name = self.get_name( authinfo, userinfo )
            v1status = self.kubeapi.delete_namespaced_secret( name=secret_name, namespace=self.namespace, grace_period_seconds=0 )
        except ApiException as e:
            self.logger.error('secret name %s can not be deleted %s', str(secret_name), e ) 
        return v1status

    def create(self, authinfo:AuthInfo, userinfo:AuthUser, data:dict )->V1Secret:
        """[create secret]

        Args:
            authinfo (AuthInfo): authentification data
            userinfo (AuthUser): user data 
            data ([dict]): [dictionnary key value]

        Returns:
            [V1Secret]: [kubernetes V1Secrets]
        """
        self.logger.debug('')
        mysecret = None
        op = None

        # sanity check 
        readsecret = self.read(authinfo, userinfo)
        try:
            # if the secret already exists, patch it with new data
            if isinstance( readsecret, V1Secret) :
                # a secret already exists, patch it with new data 
                # it may contains obsolete value, for example if the password has changed
                op = 'patch' # operation is used for log message
                mysecret = self.patch( authinfo, userinfo, arguments=data )
            else:
                # the secret does not exist, create a new one
                op = 'create'  # operation is used for log message
                mysecret = self._create( authinfo, userinfo, data )
        except Exception as e:
            self.logger.error( 'Failed to %s secret type=%s %s', str(op), str(self.secret_type), str(e) )
        
        if isinstance( mysecret, V1Secret) :
            self.logger.info( '%s secret type=%s name=%s done', str(op), self.secret_type, mysecret.metadata.name )

        return mysecret

class ODSecretLDIF( ODSecret ):
    ''' Create a secret used for userinfo ldif '''
    def __init__( self, namespace, kubeapi, prefix=None, secret_type='ldif' ):
        super().__init__( namespace, kubeapi, prefix, secret_type)
        self.access_type='ldif'
        self.typeConverterValues = { 'jpegPhoto':ODSecret.b64tobytes, 'thumbnailPhoto':ODSecret.b64tobytes }

class ODSecretLocalAccount( ODSecret ):
    ''' Create a secret used for userinfo ldif '''
    def __init__( self, namespace, kubeapi, prefix=None, secret_type='localaccount' ):
        super().__init__( namespace, kubeapi, prefix, secret_type)
        self.access_type='localaccount'
class ODSecretPosixAccount( ODSecret ):
    ''' Create a secret used for userinfo ldif '''
    def __init__( self, namespace, kubeapi, prefix=None, secret_type='posixaccount' ):
        super().__init__( namespace, kubeapi, prefix, secret_type)
        self.access_type='posixaccount'
        self.typeConverterValues = { 'uidNumber':int, 'gidNumber':int, 'groups': json.loads }

class ODSecretVNC( ODSecret ):
    ''' Create a secret used for vnc password '''
    def __init__( self, namespace, kubeapi, prefix=None, secret_type='vnc' ):
        super().__init__( namespace, kubeapi, prefix, secret_type)
        self.access_type='vnc'

class ODSecretCitrix( ODSecret ):
    ''' Create a secret used for userinfo ldif '''
    def __init__( self, namespace, kubeapi, prefix=None, secret_type='citrix' ):
        super().__init__( namespace, kubeapi, prefix, secret_type)
        self.access_type='auth'
class ODSecretRemoteFileSystemDriver( ODSecret ):
    """[class ODSecretRemoteFileSystemDriver]
        Create a secret used by for Remote File System driver 
    Args:
        ODSecret ([ODSecret]): [ODSecret class]

    """

    def __init__( self, namespace, kubeapi, prefix, secret_type ):
        super().__init__( namespace, kubeapi, prefix, secret_type)
        self.access_type='driver'
        self.authprotocol='ntlm'

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
        mydict_secret = {   'username'      :   ODSecret.strtob64( userid ),
                            'password'      :   ODSecret.strtob64( password ),
                            'data'          :   ODSecret.strtob64( str_dict_data),
                            'authprotocol'  :   ODSecret.strtob64( self.authprotocol)                       
        }

        # append domain only if set 
        domain          = authinfo.claims.get('domain' )    # None if not set
        if isinstance(domain,str) :
            mydict_secret.update( { 'domain':  ODSecret.strtob64(domain) } )
        return mydict_secret


class ODSecretRemoteFileSystemDriverUsingKerberosAuth( ODSecret ):
    """[class ODSecretRemoteFileSystemDriver]
        Create a secret used by for Remote File System driver 
    Args:
        ODSecret ([ODSecret]): [ODSecret class]

    """

    def __init__( self, namespace, kubeapi, prefix, secret_type ):
        super().__init__( namespace, kubeapi, prefix, secret_type)
        self.access_type='driver'
        self.authprotocol='kerberos'

    def read_credentials( self, userinfo ):
        self.logger.info('')
        credentials = {}
        mysecret = self.read( userinfo )
        if mysecret is None:
            self.logger.error('read secret return None, credentials failed')
            return credentials

        credentials['principal'] = ODSecret.b64tostr( mysecret.data.get('principal') )
        credentials['realm']     = ODSecret.b64tostr( mysecret.data.get('realm') )
        credentials['krb5_conf'] = ODSecret.b64tostr( mysecret.data.get('krb5_conf') )
        credentials['keytab']    = ODSecret.b64tobytes( mysecret.data.get('keytab') )

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
        principal   = authinfo.get_identity()['kerberos']['PRINCIPAL']    # Exception if not set
        realm       = authinfo.get_identity()['kerberos']['REALM']
        keytab      = authinfo.get_identity()['kerberos']['keytab'] 
        krb5_conf   = authinfo.get_identity()['kerberos']['krb5_conf'] 

        str_dict_data   = json.dumps( arguments )
        
        ## Driver use values
        ## cifsPrincipalBase64="$(jq --raw-output -e '.["kubernetes.io/secret/principal"]' <<< "$json" 2>/dev/null)"
	    ## cifsKeytabBase64="$(jq --raw-output -e '.["kubernetes.io/secret/keytab"]' <<< "$json" 2>/dev/null)"
	    ## cifsRealmBase64="$(jq --raw-output -e '.["kubernetes.io/secret/realm"]' <<< "$json" 2>/dev/null)"
        ## Mount values are set to data dict 

        # Default secret 
        mydict_secret = {   'principal' :   ODSecret.strtob64( principal ),
                            'realm'     :   ODSecret.strtob64( realm ),
                            'keytab'    :   ODSecret.bytestob64( keytab ),
                            'krb5_conf' :   ODSecret.strtob64( krb5_conf ),
                            'data'      :   ODSecret.strtob64( str_dict_data),
                            'authprotocol': ODSecret.strtob64( self.authprotocol)                        
        }

        return mydict_secret

class ODSecretCIFS( ODSecretRemoteFileSystemDriver ):
    ''' Create a secret used for CIFS driver ''' 
    def __init__( self, namespace, kubeapi, prefix, secret_type='cifs' ):
        super().__init__( namespace, kubeapi, prefix, secret_type )

class ODSecretCIFSKerberos( ODSecretRemoteFileSystemDriverUsingKerberosAuth ):
    ''' Create a secret used for CIFS driver ''' 
    def __init__( self, namespace, kubeapi, prefix, secret_type='cifs' ):
        super().__init__( namespace, kubeapi, prefix, secret_type )

class ODSecretWEBDAV( ODSecretRemoteFileSystemDriver ):
    ''' Create a secret used for WEBDAV driver ''' 
    def __init__( self, namespace, kubeapi, prefix, secret_type='webdav' ):
        super().__init__( namespace, kubeapi, prefix, secret_type)