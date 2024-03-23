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
import cherrypy
from oc.od.services import services
from oc.cherrypy import Results
from oc.od.base_controller import BaseController

logger = logging.getLogger(__name__)

@cherrypy.config(**{ 'tools.auth.on': True })
@oc.logging.with_logger()
class StoreController(BaseController):

    def __init__(self, config_controller=None):
        super().__init__(config_controller)
        self.wrapped_key = config_controller.get('wrapped_key', {} )
        self.databasename = 'profiles'

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def set(self):
        # Check auth 
        (auth, user ) = self.validate_env()
        arguments = cherrypy.request.json
        if not isinstance(arguments,dict) :
            return Results.error( message='invalid parameters' )
        userid  =  user.userid
        key     = arguments.get('key')
        value   = arguments.get('value')

        if all([userid, key]):
            if services.datastore.set_document_value_in_collection( self.databasename, userid, key, value) is True:
                return Results.success()
            else:
                raise cherrypy.HTTPError( status=400, message='set_document_value_in_collection failed') 
        else:
            raise cherrypy.HTTPError( status=400, message='invalid params') 

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def get(self):

        # Check auth 
        (auth, user ) = self.validate_env()
        arguments = cherrypy.request.json

        if not isinstance(arguments,dict) :
            raise cherrypy.HTTPError( status=400, message='invalid parameters' )
        userid = user.userid
        value = None
        key = arguments.get('key')

        if all([userid, key]):
            value = self.wrapped_get(userid, key)
        if value is None:
            raise cherrypy.HTTPError( status=404, message=f"value not found: userid={userid} key={key}")
        cherrypy.response.headers[ 'Cache-Control'] = 'no-cache, private'
        # disable content or MIME sniffing which is used to override response Content-Type headers 
        # to guess and process the data using an implicit content type
        # is this case the content-type is json 
        cherrypy.response.headers[ 'X-Content-Type-Options'] = 'nosniff'
        return Results.success(result=value)

    def wrapped_get( self, userid, key ):
        self.logger.debug('')
        value = services.datastore.get_document_value_in_collection( self.databasename, userid, key)
        if value is None:
            # return default wrapped value
            # for {"status": 200, "result": "img", "message": "ok"}
            value = self.wrapped_key.get( key )
            self.logger.debug('wrapped_get result %s:%s->%s', userid, key, value )
        return value

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    @cherrypy.tools.allow(methods=['POST'])
    def getcollection(self):
        (auth, user ) = self.validate_env()
        userid = user.userid
        arguments = cherrypy.request.json
        if not isinstance(arguments,dict) :
            raise cherrypy.HTTPError( status=400, message='bad request invalid parameters')
        key = arguments.get('key')

        # only key 'loginHistory' or 'callHistory' is allowed
        if key not in ['loginHistory', 'callHistory']:
            raise cherrypy.HTTPError( status=400, message='denied key value')
        return self._getcollection( databasename=key, collectionname=userid )
    
    def _getcollection(self, databasename, collectionname):        
        assert isinstance( databasename, str), f"invalid databasename {type(databasename)}"
        assert isinstance( collectionname, str), f"invalid databasename {type(collectionname)}"
        value = services.datastore.getcollection(databasename=databasename, collectionname=collectionname)
        if value is None:
            raise cherrypy.HTTPError( status=400, message=f"{collectionname} not found")
        return Results.success(result=value)