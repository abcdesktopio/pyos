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
import base64
import os
import json
import oc.od.acl

from oc.od.infra import ODInfra

logger = logging.getLogger(__name__)

class ODDektopApp(object):
    def __init__(self,template):
        self.template = template

class ODDektopAppImage(object):
    def __init__(self,template):
        pass

    def run(self):
        pass


class ODApps:
    # static properties
    Mimemap = {}
    FileExtensionsmap = {}
    LegacyFileExtensionsmap = {}
    myglobal_list = None          # Cached app list
    build_image_counter = 0
    cached_image_counter = 0

    def __init__(self):
        pass

    @staticmethod
    def makeiconfile(filename, b64data):
        bReturn = False
        if filename is None or b64data is None:
            return bReturn

        # normalise trust no one
        # hard code image path
        currentPath = os.getcwd()
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
              logger.error('Can not makeiconfile %s: %s', filename, e)
            f.close()

            bReturn = True
        except Exception as e:
           logger.error('Can not makeiconfile %s: %s', filename, e)
        return bReturn

    @staticmethod
    def countApps():
        mylen = 0
        if isinstance(ODApps.myglobal_list, dict):
            mylen = len(ODApps.myglobal_list)
        return mylen

    @staticmethod
    def getCached_image_counter():
        return ODApps.cached_image_counter

    @staticmethod
    def getBuild_image_counter():
        return ODApps.build_image_counter

    @staticmethod
    def cached_applist(bRefresh=False):
        if bRefresh or ODApps.myglobal_list is None:

            # Build the AppList
            ODApps.myglobal_list = ODApps.build_applist()

            # Mimemap and Extension section
            # Sort the applist using MimeType as index
            ODApps.buildmap(ODApps.myglobal_list, 'mimetype', ODApps.Mimemap)

            # Sort the applist using FileExtension as index
            ODApps.buildmap(ODApps.myglobal_list, 'fileextension', ODApps.FileExtensionsmap)

            # Sort the applist using LegacyFileExtension as index
            ODApps.buildmap(ODApps.myglobal_list, 'legacyfileextensions', ODApps.LegacyFileExtensionsmap)
            ODApps.build_image_counter = ODApps.build_image_counter + 1 
        else:
            ODApps.cached_image_counter = ODApps.cached_image_counter + 1 

        return ODApps.myglobal_list

    @staticmethod
    def updatemap(mymap, app, attr):
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

    @staticmethod
    def buildmap(applist, attr, mymap):
        for app in applist.keys():
            ODApps.updatemap(mymap, applist[app], attr)

    
    @staticmethod
    def labeltoList(mimetype, separator=';'):
        return [m for m in mimetype.split(separator) if m and not m.isspace()] if mimetype is not None else []

    @staticmethod
    def is_app_allowed( auth, app ):
        return oc.od.acl.ODAcl().isAllowed( auth, app.get('acl'))
   
                
    @staticmethod
    def user_applist( auth ):
        userapplist = []
        # make a copy to remove security entries 
        for app in ODApps.myglobal_list.keys():
            myapp = ODApps.myglobal_list[app].copy()
            if ODApps.is_app_allowed( auth, myapp ) is True :
                for m in [ 'acl', 'rules', 'shm_size', 'oom_kill_disable', 'mem_limit', 'privileged', 'security_opt'] :
                    # hidden internal dict entry to frontweb json
                    del myapp[m]
                userapplist.append( myapp )
        return userapplist

    @staticmethod
    def user_appdict( auth ):
        userappdict = {}
        # make a copy to remove security entries 
        for app in ODApps.myglobal_list.keys():
            myapp = ODApps.myglobal_list[app]
            if ODApps.is_app_allowed( auth, myapp ) is True :
                userappdict[app] = myapp
        return userappdict

    @staticmethod
    def build_applist():
        logger.debug('')

        def safe_load_label_json( labels, label, default_value=None ): 
            load_json = default_value # default return value
            data = labels.get(label)
            if data is not None:     
                try:
                    load_json = json.loads(data)
                except Exception as e:
                    logger.error( 'invalid label %s json format %s, skipping label', label, e)
            return load_json 

        mydict = {}
        for image in ODInfra().findimages({'dangling': False, 'label': 'oc.type=app'}):
            try:
                labels = image.get('Labels')
                if type(labels) is not dict: # skip image if no labels
                    continue # Nothing to do

                repoTags = image.get('RepoTags')
                if type(repoTags) is not list: # skip image if no repoTags 
                    continue # Nothing to do
                    
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

                mimelist = ODApps.labeltoList(mimetype)
                fileextensionslist = ODApps.labeltoList(fileextensions)
                legacyfileextensionslist = ODApps.labeltoList(legacyfileextensions)

                if icon is not None and icondata is not None:
                    ODApps.makeiconfile(icon, icondata)

                if all([launch, name, icon, imageid]):
                    myapp = {
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
                    mydict[ imageid ] = myapp
            except Exception as e:
                logger.error('Image id:%s failed invalid value: %s', image, e)
                pass
        return mydict

    @staticmethod
    def findappbyname(authinfo, keyname):
        """find application by name

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

        userappdict = ODApps.user_appdict( authinfo )

        # quick look up inside the applist
        app = userappdict.get(keyname)
        if app is not None: 
            return app

        # look for in deep
        # look if name is the id or launch or executablefilename or path
        for keyapp in userappdict.keys():
            app = userappdict[ keyapp ]
            for n in ['name','launch','path','executablefilename']:
                if app.get(n) == keyname :
                    return app

        # image is not found try to find the app using the mimetype tagged as default 
        mimemap = {}
        ODApps.buildmap(userappdict, 'mimetype', mimemap ) # build  mimemap
        # if image is mimetype get the associated imageid from the Mimetype
        appid = mimemap.get(keyname)
        if appid:
            app = userappdict.get( appid )
        return app # can be None if not found