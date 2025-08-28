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
import os
import json
import oc.od.acl
import threading
import copy
import oc.od.settings
import pymongo
import oc.lib

logger = logging.getLogger(__name__)


@oc.logging.with_logger()
class ODApps:

    """ ODApps
        manage application list 
    """
    def __init__(self, mongodburl=None ):
        self.lock = threading.Lock()
        self.myglobal_list = {}
        self.build_image_counter = 0
        self.cached_image_counter = 0
        # define public attributs forwarded to webbrowser
        self.public_attr_list   = [ 
            'id',           'launch',           'name',         'icon',         'icondata',
            'keyword',      'uniquerunkey',     'cat',          'args',         'execmode',
            'showinview',   'displayname',      'mimetype',     'path',         'desktopfile',
            'sha_id',       'created',          'executablefilename',           'os',     
            'secrets_requirement', 'architecture', 'wm_class',   'fileextensions', 'legacyfileextensions']
        
        # define private attributs keep
        self.private_attr_list  = [ 'acl',  'rules', 'securityContext' ]
        self.thead_event = None

        # img path
        self.img_path = '/img/app/'

        # mongo db defines
        self.databasename = 'applications'
        self.index_name = 'id' # id is the name of the image repoTags[0]
        self.image_collection_name = 'image'
        if isinstance( mongodburl, str) :
            self.datastore = oc.datastore.ODMongoDatastoreClient(mongodburl, self.databasename)
            self.init_collection( collection_name=self.image_collection_name )

    def init_collection( self, collection_name ):
        mongo_client = oc.datastore.ODMongoDatastoreClient.createclient(self.datastore,self.databasename)
        db = mongo_client[self.databasename]
        col = db[collection_name]
        try:
            col.create_index( [ (self.index_name, pymongo.ASCENDING) ], unique=True )
        except Exception as e:
            self.logger.error( e )
        mongo_client.close()

    def get_collection(self, collection_name ):
        mongo_client = oc.datastore.ODMongoDatastoreClient.createclient(self.datastore,self.databasename)
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

    def list_app_images( self )->list:
        # get the collection
        collection = self.get_collection( self.image_collection_name ) 
        app_images_collecion = []
        try:
            # get all the collection
            app_images_collecion = list( collection.find() )
        except Exception as e:
            # log error
            self.logger.error( e )
        # return the list of app images
        return app_images_collecion

    def countApps(self):
        return len(self.myglobal_list)

    def getCached_image_counter(self):
        return self.cached_image_counter

    def getBuild_image_counter(self):
        return self.build_image_counter

    def cached_applist(self, bRefresh=False):
        self.logger.debug(f"cached_applist bRefresh={bRefresh}")
        # if bRefresh is True or myglobal_list is empty
        if bRefresh is True or len(self.myglobal_list) == 0:
            # Build the AppList
            mybuild_applist = self.build_applist()
            self.logger.debug(f"cached_applist mybuild_applist lock.acquiring")
            self.lock.acquire()
            self.logger.debug(f"cached_applist mybuild_applist locked")
            try:
                self.myglobal_list = mybuild_applist
            except Exception as e:
                self.logger.error( e )
            finally:
                self.lock.release()
                self.logger.debug(f"cached_applist mybuild_applist released")

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

    
    def updatemap(self, mymap, app:dict, attr):
        assert isinstance( app, dict), f"bad app type dict is expected {type(app)}"
        mylist = app.get(attr)
        image = app.get('id')
        # safe test
        if not image or not isinstance(mylist, list):
            return

        for e in mylist:
            oldapp = mymap.get(e)
            if oldapp is not None:
                if app.get('usedefaultapplication') is True:
                    mymap[e] = image
            else:
                mymap[e] = image

    #
    # Query image list
    # label label image
    # mymap is map the update
    def buildmap(self, applist, attr )->dict:
        mymap = {}
        for app in applist.values():
            self.updatemap(mymap, app, attr)
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
                self.logger.error( f"json.loads failed image:{name} invalid label={label}, err={e}, skipping label type data={type(data)}")
        else:
            self.logger.debug( f"image:{name} label:{label} type is unknow:{type(data)}" )
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
                if isinstance( myapp, dict ):
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

    def get_command_container_str( self, command_container:any )->str:
        p='unknow'
        if isinstance(command_container, str ):
            p = command_container
        if isinstance(command_container, list ):
            p = command_container[0]
        name = os.path.basename(p)
        return name

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
            self.loggger.warning( f"skip image {json_image.get('Id')} no repoTags")
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
            image_architecture = json_image.get('Architecture') # Read Architecture
            image_os = json_image.get('Os') # Read OS
            created = json_image.get('Created') # created date
        else:
            # this is a crictl inspecti
            imageSpec = json_image.get('info',{}).get('imageSpec',{}) 
            inspect_dict = imageSpec.get('config')
            image_architecture = imageSpec.get('architecture') # Read architecture
            image_os = imageSpec.get('os') # Read os
            created = imageSpec.get('created') # created date

        # read the labels dict
        # read the labels dict
        if isinstance( inspect_dict.get('Labels'), dict ):
            # this is a docker image format
            labels = inspect_dict.get('Labels')
        else:
            labels = json_image


        command_container = None
        command_container_args = None
        entrypoint = inspect_dict.get('Entrypoint')
        cmd = inspect_dict.get('Cmd')

        if isinstance( entrypoint, list ):
            command_container = entrypoint
            if isinstance( cmd, list ):
                command_container_args = cmd
            else:
                command_container_args = labels.get('oc.args')
        else:
            # entrypoint is not defined in the image
            # look for cmd in the image 
            if isinstance( cmd, list ):
                command_container = cmd
                command_container_args = labels.get('oc.args')
   
        # if command_container_args is a string convert it to a list
        if isinstance( command_container_args, str):
            command_container_args = [ command_container_args ]

        # read USER with fallback for compatibiliy with old version release
        # user = inspect_dict.get('User') or json_image.get('status',{}).get('username') or oc.od.settings.getballoon_loginname()


        # read the labels 'oc.name' as name 
        name = labels.get('oc.name')
        # check label value, name and path must be string
        if not isinstance(name,str) :
            name = self.get_command_container_str( command_container )
        
        # read the labels 'oc.launch' or 'oc.wm_class' as launch
        launch = labels.get('oc.launch')
        wm_class = labels.get('oc.wm_class')

        # read the labels 'oc.path' as path
        path = labels.get('oc.path')

        self.logger.debug( f"image {name} path={path} cmd={cmd} args={command_container_args}")

        # read oc specific value
        # use name as icon if icon is not defined
        icon = labels.get('oc.icon', name )
        # use create a simple svg file as icondata if icondata is not defined
        icondata = labels.get('oc.icondata', oc.lib.create_svg_base64_content( name=name, width=64, height=64) )

        # safe load convert json data json
        usedefaultapplication = self.safe_load_label_json( imageid, labels, 'oc.usedefaultapplication',  default_value=False )
        rules = self.safe_load_label_json( imageid, labels, 'oc.rules', default_value={} ) 
        acl   = self.safe_load_label_json( imageid, labels, 'oc.acl',   default_value={ "permit": [ "all" ] } )
        self.logger.debug( f"{name} has rules {rules}" )
        secrets_requirement = self.safe_load_label_json( imageid, labels, 'oc.secrets_requirement' )
       
        if secrets_requirement is not None: 
            # type of secrets_requirement must be list
            if isinstance( secrets_requirement, str ):
                secrets_requirement = [ secrets_requirement ]  
            secrets_requirement = self.safe_secrets_requirement_prefix( secrets_requirement, oc.od.settings.namespace)

        securitycontext = self.safe_load_label_json(imageid, labels, 'oc.securitycontext', default_value={} )
        
        # executablefilename is only used to query applist 
        executablefilename = None
        if isinstance(path,str):
            executablefilename = os.path.basename(path)
        else:
            executablefilename = self.get_command_container_str( command_container )

        if all([sha_id, launch, name, icon, imageid]):
            myapp = {
                'cmd':          command_container,
                'path':         path,
                'sha_id':       sha_id,
                'id':           imageid,
                'architecture': image_architecture,
                'os':           image_os,
                'rules':        rules,
                'acl':          acl,
                'launch':       launch,
                'wm_class':     wm_class,
                'name':         name,
                'icon':         icon,
                'icondata' :    icondata,
                'keyword':      labels.get('oc.keyword'),
                'uniquerunkey': labels.get('oc.uniquerunkey'),
                'cat':          labels.get('oc.cat'),
                'args':         command_container_args,
                'execmode':     labels.get('oc.execmode'),
                'showinview':   labels.get('oc.showinview'),
                'displayname':  labels.get('oc.displayname', name),
                'desktopfile':  labels.get('oc.desktopfile'),
                'executeclassname':     labels.get('oc.executeclassname'),
                'executablefilename':   executablefilename,
                'usedefaultapplication': usedefaultapplication,
                'mimetype':             self.labeltoList( labels.get('oc.mimetype') ),
                'fileextensions':       self.labeltoList( labels.get('oc.fileextensions') ),
                'legacyfileextensions': self.labeltoList( labels.get('oc.legacyfileextensions') ),
                'secrets_requirement' : secrets_requirement,
                'image_pull_policy' :   labels.get('image_pull_policy', 'IfNotPresent' ),
                'image_pull_secrets':   labels.get('image_pull_secrets'),
                'containerengine':      labels.get('oc.containerengine', 'ephemeral_container'),
                'securitycontext':      securitycontext,
                'created':              created
            }
        else:
            self.logger.warning(f"skip application missing data sha_id={sha_id} launch={launch} name={name} icon={icon} imageid={imageid}")

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

    def find_app_by_id(self, image_id:str)->dict:
        """find_app_by_id
            return None if app is not found

        Args:
            image_id (str): image id

        Returns:
            dict: app dict
        """
        self.logger.debug(locals())
        app = None
        assert isinstance(image_id, str),f"image has invalid type {type(image_id)}"

        app = self.myglobal_list.get(image_id) 
        if isinstance(app, dict):
            return app

        # apps [DEBUG  ] 'image_id': 'docker.io/abcdesktopio/2048-alpine.d:3.0' 
        # convert 'image_id': 'docker.io/abcdesktopio/2048-alpine.d:3.0' -> 'abcdesktopio/2048-alpine.d:3.0' 
        array_image_id = image_id.split('/')
        if len(array_image_id)>2:
            image_id=f"{array_image_id[-2]}/{array_image_id[-1]}"
        self.logger.debug(f"filtered image_id={image_id}")
        # try to find by key
        app = self.myglobal_list.get(image_id) 
        if isinstance(app, dict):
            return app
        
        # not found use sha 
        for k in self.myglobal_list.keys():
            sha_id = self.myglobal_list[k].get('sha_id')
            id_from_sha_id = ODApps.get_id_from_sha_id( sha_id )
            id = self.myglobal_list[k].get('id')
            # self.logger.debug( f"compare image_id={image_id} with id_from_sha_id={id_from_sha_id} sha_id={sha_id} id={id}" )
            if image_id in [ id_from_sha_id, sha_id, id ]:
                app = self.myglobal_list[k]
                break
        return app

    def find_app_by_key(self, key_value:str, key='name')->dict:
        app=None
        assert isinstance(key, str),f"key has invalid type {type(key)}"
        for app in self.myglobal_list.items():
            if isinstance( app, dict ):
                if key_value == app.get(key) :
                    break
        return app

    def del_image( self, image:str )->bool:
        """del_image
            remove application image form application collection
        Args:
            image (str): image id or image name

        Returns:
            bool: True if image is deleted
        """
        bDeleted = False
        assert isinstance(image, str),f"image has invalid type {type(image)}"
        app = self.find_app_by_id( image )
        if not isinstance( app , dict ):
            # try to find app by name
            app = self.find_app_by_key( image, key='name' )

        if isinstance( app , dict ):
            bDeleted = self.remove_app_to_collection(app)

        return bDeleted

    def del_all_images(self):
        """del_all_images
            remove all application images form application collection

        Returns:
            list: list of deleted image
        """
        images = []
        for key in self.myglobal_list.keys():
            bDeleted = self.remove_app_to_collection(self.myglobal_list[key])
            if bDeleted is True:
                app_id = self.myglobal_list.get(key,{}).get('id')
                if isinstance(app_id, str) :
                    images.append( app_id )
        return images

    def find_app_by_authinfo_and_name(self, authinfo, keyname:str):
        """ find_app_by_authinfo_and_name
            find application by keyname

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
        # for example keyname = 'abcdesktopio/2048-alpine.d:3.0'
        app = userappdict.get(keyname)
        if isinstance(app, dict): 
            return app

        # app is not found
        # look for in deep
        # look if name is the id or launch or executablefilename or path again
        for app in userappdict.values():
            if isinstance( app, dict):
                for n in ['name','launch','path','executablefilename']:
                    if app.get(n) == keyname :
                        return app

        app = None
        # image is not found try to find the app using the mimetype tagged as default 
        mimemap = self.buildmap(userappdict, 'mimetype' ) # build  mimemap
        # if keyname is mimetype get the associated imageid from the mimetype
        application_key = mimemap.get(keyname)
        if application_key:
            app = userappdict.get( application_key )

        return app # can be None if not found