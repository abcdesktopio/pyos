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
import base64
import os
import json
import oc.od.acl
import threading
import copy
import oc.od.settings

from oc.od.infra import ODInfra

logger = logging.getLogger(__name__)


@oc.logging.with_logger()
class ODApps:
    """ ODApps
        manage application list 
    """
    def __init__(self):
        self.lock = threading.Lock()
        self.myglobal_list = {}
        self.build_image_counter = 0
        self.cached_image_counter = 0
        self.public_attr_list   = [ 
            'id',           'launch',       'name',         
            'icon',         'icondata',       
            'keyword',      'uniquerunkey',     
            'cat',          'args',         'execmode',     'showinview',           'displayname',  
            'mimetype',     'path',         'desktopfile',  'executablefilename',   'secrets_requirement' ]

        self.private_attr_list  = [ 
            'sha_id', 'acl',  'rules', 'privileged', 'security_opt', 'host_config' ]

 

    def makeicon_url(self, filename ):
        self.img_path = '/img/app/'
        icon_url = oc.od.settings.default_host_url + self.img_path + filename
        return icon_url


    def makeicon_file(self, filename, b64data):
        bReturn = False
        self.img_path = '/img/app/'
        if filename is None or b64data is None:
            return bReturn

        # normalise trust no one
        # hard code image path
        currentPath = os.getcwd() # '/var/pyos' or os.getcwd()
        filepath = os.path.normpath( currentPath + self.img_path + filename )
        try:
            f = None
            strdecode = base64.b64decode(b64data)
            try:
                data = strdecode.decode("utf-8")
                f = open(filepath, 'w')
            except Exception:
                data = strdecode
                f = open(filepath, 'wb')

            try:
                f.write(data)
                bReturn = True
            except Exception as e:
                self.logger.error('Can not makeicon_file %s: %s', filename, e)
            f.close()

        except Exception as e:
            self.logger.error('Can not makeicon_file %s: %s', filename, e)
        return bReturn

    def countApps(self):
        return len(self.myglobal_list)

    def getCached_image_counter(self):
        return self.cached_image_counter

    def getBuild_image_counter(self):
        return self.build_image_counter

    def cached_applist(self, bRefresh=False):
        self.logger.debug('')

        # if force refresh or myglobal_list is empty 
        if bRefresh or len(self.myglobal_list) == 0:
            # Build the AppList
            mybuild_applist = self.build_applist()
            self.lock.acquire()
            try:
                self.myglobal_list = mybuild_applist
            finally:
                self.lock.release()

            #
            # Note: this section code has been remove for user dedicated userapplist
            # 
            # Mimemap and Extension section
            # Sort the applist using MimeType as index
            # ODApps.buildmap(ODApps.myglobal_list, 'mimetype', ODApps.Mimemap)
            # Sort the applist using FileExtension as index
            # ODApps.buildmap(ODApps.myglobal_list, 'fileextension', ODApps.FileExtensionsmap)
            # Sort the applist using LegacyFileExtension as index
            # ODApps.buildmap(ODApps.myglobal_list, 'legacyfileextensions', ODApps.LegacyFileExtensionsmap)
            #
            # End of Note: user dedicated userapplist
            #

            self.build_image_counter = self.build_image_counter + 1 
        else:
            self.cached_image_counter = self.cached_image_counter + 1 

        return mybuild_applist

    
    def updatemap(self, mymap, app, attr):
        mylist = app.get(attr)
        image = app.get('id')
        if image is None or not isinstance(mylist, list):
            return

        for e in mylist:
            oldapp = mymap.get(e)
            if oldapp is not None:
                if app.get('usedefaultapplication'):
                    mymap[e] = image
            else:
                mymap[e] = image

    #
    # Query image list
    # label label image
    # mymap is map the update
    def buildmap(self, applist, attr ):
        mymap = {}
        for app in applist.keys():
            self.updatemap(mymap, applist[app], attr)
        return mymap

    def labeltoList(self, mimetype, separator=';'):
        return [m for m in mimetype.split(separator) if m and not m.isspace()] if mimetype is not None else []
    
    def is_app_allowed( self, auth, app ):
        return oc.od.acl.ODAcl().isAllowed( auth, app.get('acl'))
   
    def acl_permission_appdict( self, auth, applist ):
        appdict = {}
        # for earch app, add only allowed app
        for app in applist.keys():
            myapp = applist[app]
            # add application if allowed
            if self.is_app_allowed( auth, myapp ) is True :
                appdict[ app ] = myapp
        return appdict

    def user_applist( self, auth, filter ):
        """[user_applist] return a list of user application list
        make a copy to remove security entries 
        keep only public_attr_list data
        self.public_attr_list   = [ 'launch', 'name', 'icon',       'keyword',      'uniquerunkey',
                                    'cat',    'args',  'execmode',  'showinview', 'displayname', 
                                    'mimetype', 'path', 'desktopfile', 'executablefilename' ]
        Args:
            auth ([type]): [description]

        Returns:
            [list]: [list of application]
        """
        self.logger.info('')
        userapplist = []
        
        # Lock here 
        # run a quick deep copy of self.myglobal_list 
        self.lock.acquire()
        try:
            applist = copy.deepcopy( self.myglobal_list )
        finally:
            self.lock.release()

        # for each app in docker images
        for myapp in applist.values():
            if self.is_app_allowed( auth, myapp ) is True :
                newapp = {}

                # filter only public attr 
                # do not push system informations
                # to web user
                for a in self.public_attr_list:
                        newapp[a] = myapp[a]
                userapplist.append( newapp )
        return userapplist

    def default_appdict( self, auth, default_app, filtered_public_attr_list=False ):    
        """default_appdict
            return the default dock application list
        Args:
            auth (_type_): _description_
            default_app (_type_): _description_
            filtered_public_attr_list (bool, optional): _description_. Defaults to False.

        Returns:
            _type_: _description_
        """
        self.logger.info('')
        default_app = self.acl_permission_appdict( auth, default_app ) 
        if filtered_public_attr_list is True:
            default_app = self.filter_public_attr_list( default_app )
        return default_app

    def user_appdict( self, auth, filtered_public_attr_list=False ):     
        """return a dict of user application list

        Args:
            auth ([type]): [description]

        Returns:
            [dict]: [user application list]
        """
        userappdict = {}

        # Lock here
        self.lock.acquire()
        try:
            # make a quick copy to release lock
            appdict = copy.deepcopy(self.myglobal_list)
        finally:
            self.lock.release()

        # reduce acl apps
        appdict = self.acl_permission_appdict( auth, appdict )

        userappdict = appdict
        # reduce entries in each app if need
        if filtered_public_attr_list is True :
            userappdict = self.filter_public_attr_list( appdict )
        
        return userappdict

    def filter_public_attr_list( self, appdict ):
        self.logger.info('')
        filtered_app_dict = {}
        for key in appdict.keys():
            currentapp = appdict[key]
            newapp = {}
            # filter only public attr 
            # do not push system informations
            # to web user
            for a in self.public_attr_list:
                newapp[a] = currentapp.get(a)
            filtered_app_dict[key] = newapp
        return filtered_app_dict


    def imagetoapp( self, image ):
        """[imagetoapp]
            return an abcdesktop image object from a docker image
            return None if failed
        Args:
            image ([docker image]): [docker image]
        """

        def safe_load_label_json( name, labels, label, default_value=None ): 
            load_json = default_value # default return value
            data = labels.get(label)
            if isinstance(data, str) :     
                try:
                    load_json = json.loads(data)
                except Exception as e:
                    self.logger.error( 'image:%s invalid label=%s, json format %s, skipping label', name, label, e)
                    self.logger.error( 'image:%s label=%s data=%s', name, label, data )
            return load_json 

        def safe_secrets_requirement_prefix( secrets_requirement, namespace ):
            mylist = []
            muststartwith = namespace + '/' 
            for secret in secrets_requirement:
                if isinstance(secret, str ):
                    if not secret.startswith( muststartwith ):
                       secret =  muststartwith + secret
                    mylist.append( secret )
                else:
                    self.logger.error( 'skipping bad data in secrets_requirement')
            return mylist

        myapp = None
        labels = image.get('Labels')
        if type(labels) is not dict: # skip image if no labels
            return None

        repoTags = image.get('RepoTags')
        if type(repoTags) is not list: # skip image if no repoTags 
            return None

        sha_id = image.get('Id')    

        # Read all data came from Labels images value
        imageid = repoTags[0]
      
        # inspect the docker image
        inspect_dict = ODInfra().inspectimage( imageid )
        # read the CMD with fallback for compatibiliy with old version release
        cmd = inspect_dict.get('Config').get('Cmd', '/composer/appli-dockerentrypoint.sh' )
        if isinstance( cmd, list ):
            # fix error in deprecated image format in release 2.0
            if cmd[0] == 'bash' and len(cmd) == 1:
                cmd.append('/composer/appli-docker-entrypoint.sh')
                self.logger.warning( f"fixing cmd entry for image {imageid} update to {cmd}")

        # read WORKING with fallback for compatibiliy with old version release
        workingdir = inspect_dict.get('Config').get('WorkingDir', oc.od.settings.getballoon_homedirectory() ) 
        # read USER with fallback for compatibiliy with old version release
        user = inspect_dict.get('Config').get('User', oc.od.settings.getballoon_name() ) 
        # read oc specific value
        desktopfile = labels.get('oc.desktopfile')
        icon = labels.get('oc.icon')
        icondata = labels.get('oc.icondata')
        keyword = labels.get('oc.keyword')
        cat = labels.get('oc.cat')
        launch = labels.get('oc.launch')
        home = labels.get('oc.home')
        name = labels.get('oc.name')
        args = labels.get('oc.args')
        uniquerunkey = labels.get('oc.uniquerunkey')
        showinview = labels.get('oc.showinview')
        displayname = labels.get('oc.displayname')
        mimetype = labels.get('oc.mimetype')
        path = labels.get('oc.path')
        fileextensions = labels.get('oc.fileextensions')
        legacyfileextensions = labels.get('oc.legacyfileextensions')
        usedefaultapplication = labels.get('oc.usedefaultapplication')
        execmode = labels.get('oc.execmode')
        run_inside_pod = labels.get('oc.run_inside_pod', False)

        if usedefaultapplication is not None:
            usedefaultapplication = json.loads(usedefaultapplication)

        # safe load convert json data json
        rules = safe_load_label_json( imageid, labels, 'oc.rules' )
        if rules:
            self.logger.debug( '%s has rules %s', name, rules )
        acl   = safe_load_label_json( imageid, labels, 'oc.acl', default_value={ "permit": [ "all" ] } )
        secrets_requirement = safe_load_label_json( imageid, labels, 'oc.secrets_requirement' )
       

        if secrets_requirement is not None: 
            # type of secrets_requirement must be list
            if isinstance( secrets_requirement, str ):
                secrets_requirement = [ secrets_requirement ]
            secrets_requirement = safe_secrets_requirement_prefix( secrets_requirement, oc.od.settings.namespace)

        security_opt = safe_load_label_json(imageid, labels, 'oc.security_opt' )
        host_config  = safe_load_label_json(imageid, labels, 'oc.host_config', default_value={})
        host_config  = oc.od.settings.filter_hostconfig( host_config )
        
        executablefilename = None
        if path is not None:
            executablefilename = os.path.basename(path)

        mimelist = self.labeltoList(mimetype)
        fileextensionslist = self.labeltoList(fileextensions)
        legacyfileextensionslist = self.labeltoList(legacyfileextensions)

        # icon_url = None
        # check if icon file name exists and icon data is str
        if isinstance(icon, str) and isinstance(icondata, str):
            if self.makeicon_file(icon, icondata):
                # create the file icon with icondata
                self.makeicon_url(icon)

        if all([sha_id, launch, name, icon, imageid]):
            myapp = {
                'home': home,
                'cmd': cmd,
                'workingdir': workingdir,
                'user': user,
                'sha_id': sha_id,
                'id': imageid,
                'rules' : rules,
                'acl': acl,
                'launch': launch,
                'name': name,
                'icon': icon,
                'icondata' : icondata,
                'keyword': keyword,
                'uniquerunkey': uniquerunkey,
                'cat': cat,
                'args': args,
                'execmode': execmode,
                'security_opt' : security_opt,
                'showinview': showinview,
                'displayname': displayname,
                'mimetype': mimelist,
                'path': path,
                'desktopfile': desktopfile,
                'executablefilename': executablefilename,
                'usedefaultapplication': usedefaultapplication,
                'fileextensions': fileextensionslist,
                'legacyfileextensions': legacyfileextensionslist,
                'host_config' : host_config,
                'secrets_requirement' : secrets_requirement,
                'run_inside_pod' : run_inside_pod
            }

        return myapp
 
    def build_applist(self):
        self.logger.debug('')
        mydict = {}
        localimage_list = ODInfra().findimages( filters={'dangling': False, 'label': 'oc.type=app'} )
        for image in localimage_list:
            try:
                myapp = self.imagetoapp(image)
                if type(myapp) is dict:
                    # self.logger.debug (f"adding new image {myapp['id']}")
                    # self.logger.debug( f"cmd {myapp['cmd']}" )
                    mydict[ myapp['id'] ] = myapp
            except Exception as e:
                self.logger.error('Image id:%s failed invalid value: %s', image, e)
        return mydict

    def add_image( self, image_name ):
        myapp = None

        if image_name is None:
            return myapp

        # query dockerd to get all properties of the new image
        image_list_lookfor = ODInfra().findimages( name=image_name )
        # there is only one image
        for image in image_list_lookfor:
            myapp = self.imagetoapp( image )
            if type(myapp) is dict :
                # Lock here
                self.lock.acquire()
                try:
                    # add new application to myglobal_list dict
                    self.myglobal_list[ myapp['id'] ] = myapp
                finally:
                    self.lock.release()
                self.logger.debug( 'updated global applist %s', myapp['id'])
        return myapp


    def del_image( self, image_sha_id ):
        # Lock here
        bDeleted = False
        self.lock.acquire()
        try:
            # remove application to myglobal_list dict
            for k in self.myglobal_list.keys():
                if self.myglobal_list[k].get('sha_id') == image_sha_id:
                    del self.myglobal_list[ k ]
                    self.logger.debug( 'image %s %s DELETED', k, image_sha_id )
                    bDeleted = True
                    break
        except Exception as e:
            self.logger.error( e )
        finally:
            self.lock.release()
        if not bDeleted :
            self.logger.debug( 'image %s NOT DELETED', image_sha_id )

    def findappbyname(self, authinfo, keyname):
        """find application by kyname

        Args:
            authinfo ([type]): [description]
            keyname (str): name of application can be 
                'dockerimagename', 
                'name',
                'launch',
                'path',
                'executablefilename',
                'mimetype'

        Returns:
            [ODApps]: ODApps object, None if not found
        """

        userappdict = self.user_appdict( authinfo )

        # quick look up inside the applist
        # keyname should be the key of the userappdict most case
        app = userappdict.get(keyname)
        if app is not None: 
            return app

        # look for in deep
        # look if name is the id or launch or executablefilename or path again
        for keyapp in userappdict.keys():
            app = userappdict[ keyapp ]
            for n in ['name','launch','path','executablefilename']:
                if app.get(n) == keyname :
                    return app

        app = None
        # image is not found try to find the app using the mimetype tagged as default 
        mimemap = self.buildmap(userappdict, 'mimetype' ) # build  mimemap
        # if image is mimetype get the associated imageid from the mimetype
        appid = mimemap.get(keyname)
        if appid:
            app = userappdict.get( appid )

        return app # can be None if not found
