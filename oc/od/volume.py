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

logger = logging.getLogger(__name__)


def selectODVolume( authinfo, userinfo ):

    volumes = []
    volumeclassnamelist = []

    if authinfo.providertype == 'activedirectory':
        volumeclassnamelist = [ ODVolumeActiveDirectoryCIFS, ODVolumeActiveDirectoryWebDav ]        

    for vclass in volumeclassnamelist:         
        volumes.append( vclass(authinfo, userinfo ) )

    return volumes


def selectODVolumebyRules( authinfo, userinfo, rules ):
    volumes = []
    if isinstance(rules,dict) :
        for k in authinfo.get_labels() :
            rule =  rules.get(k)
            
            if not isinstance(rule,dict):
                continue

            vol = None
            if rule.get('type') == 'cifs' :
                name          = rule.get('volumename')
                mountOptions  = rule.get('mountOptions')
                if rule.get('name') == 'homedirectory' :
                    homeDrive     = userinfo.get('homeDrive', 'homeDrive')
                    networkPath   = userinfo.get('homeDirectory')
                    vol = ODVolumeActiveDirectoryCIFS( authinfo, userinfo, name, homeDrive, networkPath, mountOptions )
                else:
                    entry       = rule.get('name')
                    unc         = rule.get('unc')
                    vol         = ODVolumeActiveDirectoryCIFS( authinfo, userinfo, name, entry, unc, mountOptions )

            if rule.get('type') == 'webdav' :
                entry       = userinfo.get('name')
                url         = rule.get('url')
                vol         = ODVolumeActiveDirectoryWebDav( authinfo, userinfo, entry, url )

            if rule.get('type') == 'nfs' :
                name          = rule.get('name')
                server        = rule.get('server')
                path          = rule.get('path')
                readOnly      = rule.get('readOnly')
                mountPath     = rule.get('mountPath')
                vol           = ODVolumeNFS( name, server=server, path=path, mountPath=mountPath, readOnly=readOnly)

            if rule.get('type') == 'pvc'  :
                name          = rule.get('name')
                claimName     = rule.get('claimName')
                mountPath     = rule.get('mountPath')
                vol           = ODVolumePersistentVolumeClaim( name=name, mountPath=mountPath, claimName=claimName)

            if vol :        
                volumes.append( vol ) 

    return volumes


@oc.logging.with_logger()
class ODVolumeBase(object):    
    def __init__(self):                 
        self._type          = 'base'    
        self._name          = 'volbase'                 
        self._fstype        = None

    @property
    def type(self):
        return self._type
    
    @property
    def name(self):
        return self._name
    
    @property
    def fstype(self):
        return self._fstype

    def has_options(self):
        b_has_options = False
        if  hasattr(self, 'mountOptions')       and \
            isinstance(self.mountOptions,str)   and \
            len(self.mountOptions) > 0:
                b_has_options = True
        return b_has_options


@oc.logging.with_logger()
class ODVolumeHostPath(ODVolumeBase):    
    def __init__(self ):        
        super().__init__()                       
        self._type          = 'HostPath'    
        self._name          = 'hostpath'    
          
    def is_mountable(self):
        raise NotImplementedError('%s.is_mountable' % type(self))


@oc.logging.with_logger()
class ODVolumePersistentVolumeClaim(ODVolumeBase):    
    def __init__(self, name:str, mountPath:str, claimName:str ):        
        super().__init__()      
        self._fstype = 'pvc'                 
        self._type = 'pvc'    
        self._name = 'pvc-' + name
        self.mountPath = mountPath 
        self.claimName = claimName

    def is_mountable(self):
         return all( [self.claimName, self.mountPath] )


@oc.logging.with_logger()
class ODVolumeNFS(ODVolumeBase):    
    def __init__(self, name, server, path, mountPath, readOnly=True ):        
        super().__init__()      
        self._fstype        = 'nfs'                 
        self._type          = 'nfs'    
        self._name          = 'nfs-' + name
        self.server= server
        self.path    = path
        self.mountPath   = mountPath 
        self.readOnly   = readOnly
          
    def is_mountable(self):
         return all( [self.server, self.path, self.mountPath ] )

@oc.logging.with_logger()
class ODVolumeActiveDirectory(ODVolumeHostPath):    
    def __init__(self, authinfo, userinfo, name):    
        super().__init__()
        ''' authinfo.claims:
                {'domain': 'AD', 'password': 'xxxx', 'userid': 'alex'}
            userinfo 
            'cn':'alex'
            'distinguishedName':'CN=alex,CN=Users,DC=ad,DC=domain,DC=local'
            'dn':'CN=alex,CN=Users,DC=ad,DC=domain,DC=local'
            'homeDirectory':'//NAS/alex'
            'homeDrive':'U:'
            'name':'alex'
            'sAMAccountName':'alex'
            'userPrincipalName':'alex@ad.domain.local'
            'userid':'alex'
        '''
        # add homedir for Active Directory                
        self._name                  = 'activedirectory-' + name    
        self.sAMAccountName         = userinfo.get('sAMAccountName')
        self.domainlogin            = self.sAMAccountName
        self.domainpassword         = None
        self.domain                 = authinfo.data.get('domain')
        
        # if claim is defined
        if type(authinfo.get('claims')) is dict:
            self.domainpassword         = authinfo.claims.get('password')
        
        self.mountOptions           = None
        self._containertarget       = None
        

    @property
    def containertarget(self):
        return self._containertarget
    
    def is_mountable(self):
        return all( [ self.sAMAccountName, self.domainlogin, self.domainpassword, self._containertarget ] )
    

@oc.logging.with_logger()
class ODVolumeActiveDirectoryCIFS(ODVolumeActiveDirectory):
    def __init__(self, authinfo, userinfo, name, homeDrive, networkPath, mountOptions=None ):
        self.logger.info(locals())
        super().__init__(authinfo, userinfo, name)
        self._fstype       = 'cifs'
        self._type         = 'flexvol'
        self._name         = 'flexvol-cifs-' + name   
        self.homeDrive     = homeDrive
        self.networkPath   = networkPath
        self.mountOptions  = mountOptions

        if isinstance( self.homeDrive, str ):
            # remove the last char if it is ':'
            if self.homeDrive[-1] == ':':
                self._containertarget  = '/home/balloon/' + self.homeDrive[0:-1] 
            else:
                self._containertarget  = '/home/balloon/' + self.homeDrive 

    def is_mountable( self ):
        return all( [ super().is_mountable(), self.homeDrive, self.networkPath, self._containertarget ] )



@oc.logging.with_logger()
class ODVolumeActiveDirectoryWebDav(ODVolumeActiveDirectory):

    def __init__(self, authinfo, userinfo, name, entry, url, mountOptions=None ):
        super().__init__(authinfo, userinfo)
        self._fstype            = 'webdav'
        self._type              = 'flexvol'
        self._name              = 'flexvol-webdav-' + name
        self.networkPath        = url
        self._containertarget   = '/home/balloon/' + entry
        self.mountOptions       = mountOptions

       

    def is_mountable( self ):
        ''' OLD CODE WAS 
            memberOf = arguments.get('memberOf', [])
            hasuserWebdavOption = oc.auth.ad.adconfig.isMemberOf(memberOf, oc.od.settings.webdavgroup)
            sAMAccountName = arguments.get('sAMAccountName', None)

            if all([hasuserWebdavOption, sAMAccountName, oc.od.settings.webdavurl, oc.od.settings.webdaventryname]):
                self.logger.info('hasuserWebdavOption: True')
                setmessageinfo('Mounting ' + str(oc.od.settings.webdavurl))
                mountwebdavpoint = oc.od.settings.getmount_remotewebdav_point(sAMAccountName)
                mountwebdavdirname = '/home/balloon/' + oc.od.settings.webdaventryname
        '''
        return all( [ super().is_mountable(), self.networkPath, self._containertarget ] )

    '''
    def mount_command(self):

        username=oc.auth.namedlib.normalize_shell_variable(self.domainlogin),
        password=oc.auth.namedlib.normalize_shell_variable(self.domainpassword)

        command = ['echo', password, '|',
                    'mount', 
                    '-t', 'davfs',
                    '-o', 'uid=' + str(oc.od.settings.getballoon_uid()),
                    '-o', 'gid=' + str(oc.od.settings.getballoon_gid()),          
                    '-o', 'username=' + username,
                    self.remotewebdav_url,
                    self._mountpoint]
        return command
    '''