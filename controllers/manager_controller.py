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
# 

import logging
import cherrypy

from oc.od.base_controller import BaseController
import oc.od.composer
import oc.od.services
import oc.cherrypy
import oc.logging
import distutils.util
from oc.od.services import services


logger = logging.getLogger(__name__)

@cherrypy.tools.allow(methods=['GET','PUT','POST','DELETE','PATCH'])
@cherrypy.config(**{ 'tools.auth.on': False })
class ManagerController(BaseController):

    '''
        Description: Manager Controller 
    '''
    def __init__(self, config_controller=None):
        super().__init__(config_controller)

    # buildapplist request is protected by is_permit_request()
    @cherrypy.expose
    @cherrypy.tools.json_out()
    def buildapplist(self):
        """[buildapplist]
            build application list 
            protected by is_permit_request()
        Returns:
            [json]: [list of all images]
        """
        # check if request is allowed, raise an exception if deny
        self.is_permit_request()
        # disable trace log 
        cherrypy.response.notrace = True
        # True to force an application list refresh
        oc.od.services.services.apps.cached_applist(True)
        return oc.od.services.services.apps.get_json_applist(filter=True)

    # updateactivedirectorysite request is protected by is_permit_request()
    @cherrypy.expose
    @cherrypy.tools.json_out()
    def updateactivedirectorysite(self):
        ''' update activedirectory cached site and subnet cached data '''
        self.is_permit_request() 
        cherrypy.response.notrace = True
        return oc.od.services.services.update_locator()
        

    # garbagecollector request is protected by is_permit_request()
    @cherrypy.expose
    @cherrypy.tools.json_out()
    def garbagecollector(self, expirein, force=False):
        self.logger.debug('')
        ''' garbage collector remove all user container not connected created since more than expirein time
            expirein:   value in second
            force:      boolean False by default, garbage even if user is connected
            to remove all user container run garbagecollector(expirein=0, force=True)
        '''
        self.is_permit_request()
        cherrypy.response.notrace = True

        if expirein is None :
            # 400 - Invalid parameters Bad Request
            raise cherrypy.HTTPError(status=400)

        nexpirein = None
        try:
            nexpirein = int( expirein )
            if type(force) is str:
                # convert str parameter to bool type
                force = bool( distutils.util.strtobool( force ) )
            else:
                self.logger.error( 'bad force value str is expected : %s, using default value force to False', type(force))
                force = False
        except Exception:
            raise cherrypy.HTTPError(status=400)        
        
        # remove all disconnected container
        garbaged = oc.od.composer.garbagecollector( expirein=nexpirein, force=force )

        return garbaged


    @cherrypy.expose
    @cherrypy.tools.json_out()
    def desktop( self, *args ):
        self.is_permit_request()
        if cherrypy.request.method == 'GET':
            return self.handle_desktop_GET( args )
        elif cherrypy.request.method == 'DELETE':
            return self.handle_desktop_DELETE( args )


    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def images( self ):
        self.is_permit_request()
        if   cherrypy.request.method == 'GET':
            return self.handle_images_GET( )
        elif cherrypy.request.method == 'DELETE':
            return self.handle_images_DELETE()
        else:
            raise cherrypy.HTTPError(status=400)        

    def handle_images_DELETE( self ):
        self.logger.debug('')
        images_deleted = oc.od.composer.del_application_all_images()
        cherrypy.response.status = 200
        return images_deleted

    def handle_images_GET( self ):
        self.logger.debug('')
        # this is a list request
        return oc.od.services.services.apps.get_json_applist()

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def image( self, image:str=None, node:str=None ):
        self.is_permit_request()
        if   cherrypy.request.method == 'GET':
            return self.handle_image_GET( image=image )
        elif cherrypy.request.method == 'PUT':
            return self.handle_image_PUT( json_images=cherrypy.request.json, node=node )
        elif cherrypy.request.method == 'POST':
            return self.handle_image_POST( json_images=cherrypy.request.json )
        elif cherrypy.request.method == 'DELETE':
            return self.handle_image_DELETE( image=image )
        elif cherrypy.request.method == 'PATCH':
            return self.handle_image_PATCH( image=image, json_images=cherrypy.request.json )


    

    def handle_image_GET( self, image ):
        self.logger.debug('')
        if image is None:
            # this is a list request
            return oc.od.services.services.apps.get_json_applist()
        elif isinstance( image, str):
            app = oc.od.services.services.apps.get_json_app( image_id=image )
            if isinstance( app, dict):
                return app
            else:
                cherrypy.response.status = 404
                return "Not found"
        else:
            # 400 - Invalid parameters Bad Request
            raise cherrypy.HTTPError(status=400, message='Invalid parameters Bad Request')


    def handle_image_PUT( self, json_images, node:str=None ):
        self.logger.debug('')
        json_put = None
        # node can be None or str
        if isinstance( node, str ) or node is  None : 
            # json_images can be list or dict
            if isinstance( json_images, list ) or isinstance( json_images, dict ) :
                json_put = oc.od.composer.pull_application_image( json_images, node=node )
            else:
                raise cherrypy.HTTPError(status=400, message='Invalid parameters Bad Request')
        else:
            raise cherrypy.HTTPError(status=400, message='Invalid parameters Bad Request')
        return json_put

    def handle_image_POST( self, json_images ):
        self.logger.debug('')
        json_put = None
        # json_images can be list or dict
        if isinstance( json_images, list ) or isinstance( json_images, dict ) :
            json_put = oc.od.composer.add_application_image( json_images )
        else:
            raise cherrypy.HTTPError(status=400, message='Invalid parameters Bad Request')
        return json_put

    def handle_image_DELETE( self, image ):
        self.logger.debug('')

        # image can be an sha_id or an repotag
        # it is always a str type
        if not isinstance( image, str):
            raise cherrypy.HTTPError(status=400, message='Invalid parameters Bad Request')

        if image == '*':
            images_deleted = oc.od.composer.del_application_all_images()
            cherrypy.response.status = 200
            return images_deleted

        del_images = oc.od.composer.del_application_image( image )
        if isinstance(del_images, list):
            if len( del_images ) > 0:
                return del_images
        
        cherrypy.response.status = 404
        return "Not found"
        

    def handle_image_PATCH( self, image=None, json_images=None ):
        self.logger.debug('')
        # image can be an sha_id or an repotag
        # it is always a str type
        if image is None:
            # flush applist cache bRefresh=True
            oc.od.services.services.apps.cached_applist( bRefresh=True )
            # return the updated list
            return oc.od.services.services.apps.get_json_applist()

        if isinstance( json_images, list):
            # PATCH only the firest entry
            json_images = json_images[0]

        if isinstance( image, str ) and isinstance( json_images, dict) :
            app = oc.od.services.services.apps.find_app_by_id( image_id=image )
            if isinstance(app, dict):
                app_patch = None
                app_add = oc.od.services.services.apps.add_json_image_to_collection( json_images )
                if isinstance( app_add, dict) :
                    app_patch = oc.od.services.services.apps.get_json_app( app_add.get('id') )
                return app_patch
            else:
                cherrypy.response.status = 404
                return "Not found"
        else:
            raise cherrypy.HTTPError(status=400, message='Invalid parameters Bad Request')


    @cherrypy.expose
    @cherrypy.tools.json_out()
    def ban( self, collection, *args ):
        self.is_permit_request()
        if cherrypy.request.method == 'GET':
            return self.handle_ban_GET( collection, args )
        elif cherrypy.request.method == 'PUT':
            return self.handle_ban_PUT( collection, args )  
        elif cherrypy.request.method == 'DELETE':
            return self.handle_ban_DELETE( collection, args )              

    def handle_desktop_GET( self, args ):
        self.logger.debug('')

        if not isinstance( args, tuple):
            raise cherrypy.HTTPError( status=400, message='invalid request')

        if len(args)==0:
            # /API/manager/desktop/
            # list all desktops
            listdesktop = oc.od.composer.list_desktop()
            return listdesktop

        desktop_name = args[0]
        if not isinstance( desktop_name, str):
            raise cherrypy.HTTPError(status=400, message='Invalid parameters Bad Request')

        if len(args)==1:
            # get information for a desktop
            # /API/manager/desktop/hermes-8a49ca1a-fcc6-4b7b-960f-5a27debd4773
            describedesktop = oc.od.composer.describe_desktop_byname(desktop_name)
            return describedesktop

        # use a specify desktop
        if len(args)==2 and args[1]=="container":
            # list container for a desktop
            # /API/manager/desktop/hermes-8a49ca1a-fcc6-4b7b-960f-5a27debd4773/container
            container = oc.od.composer.list_container_byname(desktop_name)
            return container

        container_id = args[2]
        if not isinstance( container_id, str):
            raise cherrypy.HTTPError(status=400, message='Invalid parameters Bad Request')

        # use a specify desktop
        if len(args)==3 and args[1]=="container":
            # list container for a desktop
            # /API/manager/desktop/hermes-8a49ca1a-fcc6-4b7b-960f-5a27debd4773/container/
            container = oc.od.composer.describe_container( desktop_name, container=container_id )
            return container

        raise cherrypy.HTTPError(status=400, message='Invalid parameters Bad Request')

    def handle_desktop_DELETE( self, args ):
        self.logger.debug('')

        if not isinstance( args, tuple):
            raise cherrypy.HTTPError(status=400, message='Invalid type parameters Bad Request')
        if len(args) == 0:
            raise cherrypy.HTTPError(status=400, message='Invalid parameters empty Bad Request')
        desktop_name = args[0]
        if not isinstance( desktop_name, str):
            raise cherrypy.HTTPError(status=400, message='Invalid parameters Bad Request')
        if len(args)==1:
            # delete a desktop
            # DELETE /API/manager/desktops/hermes-8a49ca1a-fcc6-4b7b-960f-5a27debd4773
            delete_desktop = oc.od.composer.remove_desktop_byname(desktop_name)
            return delete_desktop

        # use a specify desktop
        if len(args)==3 and args[1]=="container":
            # delete a container for a desktop
            # /API/manager/desktops/hermes-8a49ca1a-fcc6-4b7b-960f-5a27debd4773/container/7f77381f778b1214c780762185a2a345ed00cfd1022f18cbd37902af041aff40
            container_id = args[2]
            oc.od.composer.stop_container_byname( desktop_name, container=container_id )
            oc.od.composer.remove_container_byname( desktop_name, container=container_id )
            return container_id
        raise cherrypy.HTTPError(status=400, message='Invalid parameters Bad Request') 

 

    def handle_ban_GET( self, collection, args ):
        self.logger.debug('')

        # handle GET request to ban 
        if not services.fail2ban.iscollection( collection ):
           raise cherrypy.HTTPError(status=400, message='Invalid type parameters Bad Request')
        if not isinstance( args, tuple):
           raise cherrypy.HTTPError(status=400, message='Invalid type parameters Bad Request')
        if len(args)!=0:
           raise cherrypy.HTTPError(status=400, message='Invalid type parameters Bad Request')
        # /API/ban/ipaddr 
        # /API/ban/login 
        # list all desktops
        listban = services.fail2ban.listban( collection_name=collection )
        return listban

    def handle_ban_PUT( self, collection, args ):
        self.logger.debug('')
        # handle GET request to ban 
        if not services.fail2ban.iscollection( collection ):
           raise cherrypy.HTTPError(status=400, message='Invalid type parameters Bad Request')
        if not isinstance( args, tuple):
           raise cherrypy.HTTPError(status=400, message='Invalid type parameters Bad Request')
        if len(args)!=1:
           raise cherrypy.HTTPError(status=400, message='Invalid type parameters Bad Request')
        ban = services.fail2ban.ban( args[0], collection_name=collection)
        return ban


    def handle_ban_DELETE( self, collection, args ):
        self.logger.debug('')
        # handle GET request to ban 
        if not services.fail2ban.iscollection( collection ):
           raise cherrypy.HTTPError(status=400, message='Invalid type parameters Bad Request')
        if not isinstance( args, tuple):
           raise cherrypy.HTTPError(status=400, message='Invalid type parameters Bad Request')
        if len(args)==0:
           drop = services.fail2ban.drop(collection_name=collection)
           return drop
        if len(args)==1:
           ban = services.fail2ban.unban( args[0], collection_name=collection)
           return ban
        raise cherrypy.HTTPError(status=400, message='Invalid type parameters Bad Request')


    @cherrypy.expose
    @cherrypy.tools.json_out()
    def dry_run_desktop(self):
        self.logger.debug('validate_env')
        (auth, user ) = self.validate_env()
        result = oc.od.composer.sampledesktop(auth, user)
        return result