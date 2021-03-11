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

from oc.od.infra import ODInfra

logger = logging.getLogger(__name__)


@oc.logging.with_logger()
class ODApps:

    def __init__(self):
        self.lock = threading.Lock()
        self.myglobal_list = {}
        self.build_image_counter = 0
        self.cached_image_counter = 0

    def makeiconfile(self, filename, b64data):
        bReturn = False
        if filename is None or b64data is None:
            return bReturn

        # normalise trust no one
        # hard code image path
        currentPath = '/var/pyos' # or os.getcwd()
        filepath = os.path.normpath( currentPath + '/img/app/' + filename)
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
            except Exception as e:
              self.logger.error('Can not makeiconfile %s: %s', filename, e)
            f.close()

            bReturn = True
        except Exception as e:
           self.logger.error('Can not makeiconfile %s: %s', filename, e)
        return bReturn

    def countApps(self):
        mylen = 0
        if isinstance(self.myglobal_list, dict):
            mylen = len(self.myglobal_list)
        return mylen

    def getCached_image_counter(self):
        return self.cached_image_counter

    def getBuild_image_counter(self):
        return self.build_image_counter

    def cached_applist(self, bRefresh=False):
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
   
    def user_applist( self, auth ):
        userapplist = []
        #
        # make a copy to remove security entries 
        # like 'acl', 'rules', 'shm_size', 'oom_kill_disable', 'mem_limit', 'privileged', 'security_opt'
        #

        # Lock here
        self.lock.acquire()
        try:
            applist = self.myglobal_list.copy()
        finally:
            self.lock.release()

        # for each app in docker images
        for app in applist.keys():
            myapp = applist[app].copy()
            if self.is_app_allowed( auth, myapp ) is True :
                for m in [ 'sha_id', 'acl', 'rules', 'shm_size', 'oom_kill_disable', 'mem_limit', 'privileged', 'security_opt'] :
                    # hidden internal dict entry to frontweb json
                    del myapp[m]
                userapplist.append( myapp )
        return userapplist

    
    def user_appdict( self, auth ):
        
        userappdict = {}

        # Lock here
        self.lock.acquire()
        try:
            # make a quick copy to release lock
            applist = self.myglobal_list.copy()
        finally:
            self.lock.release()

        # make a copy to remove security entries 
        for app in applist.keys():
            myapp = applist[app]
            if self.is_app_allowed( auth, myapp ) is True :
                # add application if allowed
                userappdict[app] = myapp

        return userappdict

    def imagetoapp( self, image ):
        """[imagetoapp]
            return an abcdesktop image object from a docker image
            return None if failed
        Args:
            image ([docker image]): [docker image]
        """

        def safe_load_label_json( labels, label, default_value=None ): 
            load_json = default_value # default return value
            data = labels.get(label)
            if data is not None:     
                try:
                    load_json = json.loads(data)
                except Exception as e:
                    logger.error( 'invalid label %s json format %s, skipping label', label, e)
            return load_json 

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
        desktopfile = labels.get('oc.desktopfile')
        icon = labels.get('oc.icon')
        icondata = labels.get('oc.icondata')
        keyword = labels.get('oc.keyword')
        cat = labels.get('oc.cat')
        launch = labels.get('oc.launch')
        name = labels.get('oc.name')
        args = labels.get('oc.args')
        uniquerunkey = labels.get('oc.uniquerunkey')
        shm_size = labels.get('oc.shm_size')
        mem_limit  = labels.get('oc.mem_limit')
        execmode = labels.get('oc.execmode')
        showinview = labels.get('oc.showinview')
        displayname = labels.get('oc.displayname')
        mimetype = labels.get('oc.mimetype')
        path = labels.get('oc.path')
        fileextensions = labels.get('oc.fileextensions')
        legacyfileextensions = labels.get('oc.legacyfileextensions')
        usedefaultapplication = labels.get('oc.usedefaultapplication')

        if usedefaultapplication is not None:
            usedefaultapplication = json.loads(usedefaultapplication)

        # safe load convert json data json
        acl = safe_load_label_json( labels, 'oc.acl' )
        rules = safe_load_label_json( labels, 'oc.rules' )
        security_opt = safe_load_label_json(labels, 'oc.security_opt' )
        oomkilldisable = safe_load_label_json(labels, 'oc.oomkilldisable', False)
        privileged = safe_load_label_json(labels, 'oc.privileged', False )

        executablefilename = None
        if path is not None:
            executablefilename = os.path.basename(path)

        mimelist = self.labeltoList(mimetype)
        fileextensionslist = self.labeltoList(fileextensions)
        legacyfileextensionslist = self.labeltoList(legacyfileextensions)

        if icon is not None and icondata is not None:
            self.makeiconfile(icon, icondata)

        if all([sha_id, launch, name, icon, imageid]):
            myapp = {
                'sha_id': sha_id,
                'id': imageid,
                'rules' : rules,
                'acl': acl,
                'launch': launch,
                'name': name,
                'icon': icon,
                'keyword': keyword,
                'uniquerunkey': uniquerunkey,
                'cat': cat,
                'args': args,
                'execmode': execmode,
                'mem_limit': mem_limit,
                'shm_size': shm_size,
                'security_opt' : security_opt,
                'oom_kill_disable': oomkilldisable,
                'showinview': showinview,
                'displayname': displayname,
                'mimetype': mimelist,
                'path': path,
                'privileged': privileged,
                'desktopfile': desktopfile,
                'executablefilename': executablefilename,
                'usedefaultapplication': usedefaultapplication,
                'fileextensions': fileextensionslist,
                'legacyfileextensions': legacyfileextensionslist
            }

        return myapp
 
    def build_applist(self):
        logger.debug('')
        mydict = {}
        localimage_list = ODInfra().findimages( filters={'dangling': False, 'label': 'oc.type=app'} )
        for image in localimage_list:
            try:
                myapp = self.imagetoapp(image)
                if type(myapp) is dict:
                    mydict[ myapp['id'] ] = myapp
            except Exception as e:
                logger.error('Image id:%s failed invalid value: %s', image, e)
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
                logger.debug( 'updated global applist %s', myapp['id'])
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
            logger.error( e )
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

        # image is not found try to find the app using the mimetype tagged as default 
        mimemap = self.buildmap(userappdict, 'mimetype' ) # build  mimemap

        # if image is mimetype get the associated imageid from the mimetype
        appid = mimemap.get(keyname)
        if appid:
            app = userappdict.get( appid )

        return app # can be None if not found