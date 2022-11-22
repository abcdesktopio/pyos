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
import pymongo
from bson import json_util, ObjectId
import time

logger = logging.getLogger(__name__)


@oc.logging.with_logger()
class ODApps:

    """ ODApps
        manage application list 
    """
    def __init__(self, mongoconfig=None ):
        self.lock = threading.Lock()
        self.myglobal_list = {}
        self.build_image_counter = 0
        self.cached_image_counter = 0
        # define public attributs forwarded to webbrowser
        self.public_attr_list   = [ 
            'id',           'launch',           'name',         'icon',         'icondata',
            'keyword',      'uniquerunkey',     'cat',          'args',         'execmode',
            'showinview',   'displayname',      'mimetype',     'path',         'desktopfile',
            'executablefilename',   'secrets_requirement' ]
        # define private attributs keep
        self.private_attr_list  = [ 'sha_id',  'acl',  'rules', 'privileged', 'security_opt', 'host_config' ]
        self.thread_sleep_insert = 5
        self.thead_event = None
        # mongo db defines
        if mongoconfig :
            self.datastore = oc.datastore.ODMongoDatastoreClient(mongoconfig)
            self.databasename = 'applications'
            self.index_name = 'id' # id is the name of the image repoTags[0]
            self.image_collection_name = 'image'
            self.init_collection( collection_name=self.image_collection_name)

    def init_collection( self, collection_name ):
        mongo_client = oc.datastore.ODMongoDatastoreClient.createclient(self.datastore)
        db = mongo_client[self.databasename]
        col = db[collection_name]
        try:
            col.create_index( [ (self.index_name, pymongo.ASCENDING) ], unique=True )
        except Exception as e:
            self.logger.info( e )
        mongo_client.close()

    def get_collection(self, collection_name ):
        mongo_client = oc.datastore.ODMongoDatastoreClient.createclient(self.datastore)
        db = mongo_client[self.databasename]
        return db[collection_name]

    def append_app_to_collection( self, app ):
        if not isinstance( app, dict):
            return False
        myapp = app.copy() # copy
        collection = self.get_collection( self.image_collection_name )
        bfind = collection.find_one({ self.index_name: app.get('id')})
        append_app = self.updateorinsert( collection=collection, bUpdate=bfind, app=myapp  )
        if isinstance(append_app, pymongo.results.InsertOneResult ) or isinstance(append_app, pymongo.results.UpdateResult) :
           return append_app.acknowledged
        return False

    def remove_app_to_collection( self, app ):
        if not isinstance( app, dict):
            return False
        collection = self.get_collection( self.image_collection_name )
        bdelete = collection.delete_one({ self.index_name: app.get('id')})
        if isinstance(bdelete, pymongo.results.DeleteResult ) :
           return bdelete.acknowledged
        return False

    def updateorinsert( self, collection, bUpdate, app  ):
        if bUpdate:
            q = collection.replace_one( { self.index_name: app.get('id')}, app)
        else:
            q = collection.insert_one(app)
        return q

    def list_app_images( self ):
        collection = self.get_collection( self.image_collection_name )
        return list( collection.find() )


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

        return self.myglobal_list

    
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

    def safe_load_label_json( self, name, labels, label, default_value=None ):
        load_json = default_value # default return value
        data = labels.get(label)
        if data is None:
            pass
        elif isinstance(data, dict):
            load_json = data
        elif isinstance(data, str) :
            try:
                load_json = json.loads(data)
            except Exception as e:
                self.logger.error( 'image:%s invalid label=%s, json format %s, skipping label', name, label, e)
                self.logger.error( 'image:%s label=%s data=%s', name, label, data )
        else:
            self.logger.debug( f"image:{name} label:{label} type is not detected:{type(data)}" )
        return load_json

    def safe_secrets_requirement_prefix( self, secrets_requirement, namespace ):
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

    def build_applist(self):
        self.logger.debug('')
        mydict = {}
        apps = self.list_app_images()
        if isinstance( apps, list):
            for myapp in apps:
                self.logger.debug( f"build_applist add {myapp['id']}")
                mydict[ myapp['id'] ] = myapp
        return mydict

    def get_json_applist(self, filter=True):
        #
        # a = json_util.dumps(self.myglobal_list)
        # json_sanitized = json.loads(a)
        #
        myapplist = copy.deepcopy( self.myglobal_list )
        for k in myapplist.keys():
            app = myapplist[k]
            if isinstance(app, dict) and app.get('_id'):
                if filter is True:
                    del app['_id']
        return myapplist

    def get_json_app( self, image_id, filter=True):
        myapp = None
        app=self.find_app_by_id( image_id )
        if isinstance(app, dict):
            myapp = app.copy()
            if filter is True:
                if myapp.get('_id'):
                    del myapp['_id']
        return myapp

    def json_imagetoapp( self, json_image):
        """[json_imagetoapp]
            return an abcdesktop image object from a json image format
            to get json image format run command

            $ crictl  inspecti abcdesktopio/2048.d:dev > cri_2048.json
            $ curl -X PUT -H 'Content-Type: text/javascript' http://ABCDESKTOP/API/manager/image -d @cri_2048.json

            $ docker inspect abcdesktopio/2048.d:dev > docker_2048.json
            $ curl -X PUT -H 'Content-Type: text/javascript' http://ABCDESKTOP/API/manager/image -d @docker_2048.json

            return None if failed
        Args:
            json_image ([json OCI image]): [docker image or OCI image]
        """
        myapp = None
        if not isinstance( json_image, dict ):
            return None

        # repoTags is a list of repoTag
        repoTags = json_image.get('RepoTags') or json_image.get('status',{}).get('repoTags')
        if not isinstance(repoTags,list): # skip image if no repoTags
            return None
        # take the first one
        imageid = repoTags[0]
        # read the image Id
        # docker output format use Id
        #
        # crictl  inspecti abcdesktopio/2048.d:dev > cri_2048.json
        # docker inspect abcdesktopio/2048.d:dev > docker_2048.json
        #
        sha_id = json_image.get('Id') or json_image.get('status',{}).get('id')
        if not isinstance(sha_id,str): # skip image if no Id or id
            return None

        # read the config
        inspect_dict = None
        if isinstance( json_image.get('Config'), dict ):
            # this is a docker image format
            inspect_dict = json_image.get('Config')
        else:
            inspect_dict = json_image

        # read the CMD with fallback for compatibiliy with old version release
        cmd = inspect_dict.get('Cmd', '/composer/appli-dockerentrypoint.sh' )
        if isinstance( cmd, list ):
            # fix error in deprecated image format in release 2.0
            if cmd[0] == 'bash' and len(cmd) == 1:
                cmd.append('/composer/appli-docker-entrypoint.sh')
                self.logger.warning( f"fixing cmd entry for image {imageid} update to {cmd}")

        # read WORKING with fallback for compatibiliy with old version release
        workingdir = inspect_dict.get('WorkingDir', oc.od.settings.getballoon_homedirectory() )

        # read USER with fallback for compatibiliy with old version release
        user = inspect_dict.get('User') or json_image.get('status',{}).get('username') or oc.od.settings.getballoon_name()

        # read the labels dict
        if isinstance( inspect_dict.get('Labels'), dict ):
            # this is a docker image format
            labels = inspect_dict.get('Labels')
        else:
            labels = json_image

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
        image_pull_policy = labels.get('image_pull_policy', 'IfNotPresent' )
        image_pull_secrets = labels.get('image_pull_secrets')

        try:
            if isinstance(usedefaultapplication, str ):
                usedefaultapplication = json.loads(usedefaultapplication)
        except Exception as e:
            pass

        # safe load convert json data json
        rules = self.safe_load_label_json( imageid, labels, 'oc.rules' )
        if rules:
            self.logger.debug( '%s has rules %s', name, rules )
        acl   = self.safe_load_label_json( imageid, labels, 'oc.acl', default_value={ "permit": [ "all" ] } )
        secrets_requirement = self.safe_load_label_json( imageid, labels, 'oc.secrets_requirement' )
       
        if secrets_requirement is not None: 
            # type of secrets_requirement must be list
            if isinstance( secrets_requirement, str ):
                secrets_requirement = [ secrets_requirement ]
            secrets_requirement = self.safe_secrets_requirement_prefix( secrets_requirement, oc.od.settings.namespace)

        security_opt = self.safe_load_label_json(imageid, labels, 'oc.security_opt' )
        host_config  = self.safe_load_label_json(imageid, labels, 'oc.host_config', default_value={})
        host_config  = oc.od.settings.filter_hostconfig( host_config )
        
        executablefilename = None
        if isinstance(path,str):
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
                'run_inside_pod' : run_inside_pod,
                'image_pull_policy' : image_pull_policy,
                'image_pull_secrets': image_pull_secrets
            }

        return myapp
 
    def add_json_image_to_collection( self, json_image:str ):
        applist = None
        # if json image is a list add each image in list
        if isinstance( json_image, list ):
            applist = []
            for image in json_image:
                myapp = self.json_imagetoapp( image )
                if isinstance( myapp, dict ):
                    if self.append_app_to_collection( myapp ):
                        applist.append( myapp )

        if isinstance( json_image, dict ):
            myapp = self.json_imagetoapp( json_image )
            if isinstance( myapp, dict ):
                if self.append_app_to_collection( myapp ):
                    applist = myapp
        return applist

    def remove_app( self, documentKey ):
        return self.cached_applist(bRefresh=True)

    def add_app( self, myapp):
        self.logger.debug('')
        bReturn = False
        if isinstance(myapp,dict) :
            # Lock here
            self.lock.acquire()
            try:
                # add new application to myglobal_list dict
                self.myglobal_list[ myapp['id'] ] = myapp
                bReturn = True
            finally:
                self.lock.release()
            self.logger.debug( 'updated global applist %s', myapp['id'])
        return bReturn

    @staticmethod
    def get_id_from_sha_id( sha_id ):
        _sha_id = sha_id
        # "sha_id": "sha256:390745577d89afad703253423624187bdb31f33008320946c335c20a87f0f5f6"
        # get 390745577d89afad703253423624187bdb31f33008320946c335c20a87f0f5f6
        if isinstance(sha_id, str):
            ar_sha_id = sha_id.split(':')
            if isinstance( ar_sha_id, list ) and len(ar_sha_id) > 1:
                _sha_id = ar_sha_id[1]
        return _sha_id

    def find_app_by_id(self, image_id):
        app = None
        for k in self.myglobal_list.keys():
            sha_id = self.myglobal_list[k].get('sha_id')
            id_from_sha_id = ODApps.get_id_from_sha_id( sha_id )
            if  id_from_sha_id == image_id or \
                self.myglobal_list[k].get('sha_id') == image_id or \
                self.myglobal_list[k].get('id') == image_id :
                app = self.myglobal_list[k]
                break
        return app

    def del_image( self, image_id ):
        # Lock here
        bDeleted = None
        app = self.find_app_by_id( image_id )
        if isinstance( app , dict ):
            bDeleted = self.remove_app_to_collection(app)
        return bDeleted

    def del_all_images(self):
        images = []
        for key in self.myglobal_list.keys():
            bDeleted = self.remove_app_to_collection(self.myglobal_list[key])
            if bDeleted is True:
                app_id = self.myglobal_list.get(key,{}).get('id')
                if isinstance(app_id, str) :
                    images.append( app_id )
        return images

    def findappbyname(self, authinfo, keyname:str):
        """find application by keyname

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
