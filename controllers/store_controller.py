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

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def set(self):

        # Check auth 
        try:
            (auth, user ) = self.validate_env()
        except Exception as e:
            self.logger.error( e )
            return Results.error( message=str(e) )
        
        arguments = cherrypy.request.json
        if type(arguments) is not dict :
            return Results.error( message='invalid parameters' )
        userid  =  user.userid
        key     = arguments.get('key')
        value   = arguments.get('value')

        logger.debug('setstoredvalue userid:%s key:%s value:%s', str(userid), str(key), str(value) )
        if all([userid, key]):
            if services.datastore.setstoredvalue(userid, key , value) is True:
                return Results.success()
            else:
                Results.error('setstoredvalue failed') 
        else:
            Results.error('invalid params') 

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def get(self):

        # Check auth 
        try:
            (auth, user ) = self.validate_env()
        except Exception as e:
            self.logger.error( e )
            return Results.error( message=str(e) )
                
        arguments = cherrypy.request.json

        if type(arguments) is not dict :
            return Results.error( message='invalid parameters' )

        userid = user.userid
        value = None
        key = arguments.get('key')

        if all([userid, key]):
            self.logger.debug('getstoredvalue userid:%s key:%s', str(userid), str(key) )
            value = self.wrapped_get(userid, key)
        
        if value is None:
            return Results.error('value not found: userid = %s, key = %s' % (userid,key), 404)
        
        return Results.success(result=value)



    def wrapped_get( self, userid, key ):
        self.logger.debug('')
        value = services.datastore.getstoredvalue(userid, key)
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

         # Check auth 
        try:
            (auth, user ) = self.validate_env()
        except Exception as e:
            self.logger.error( e )
            return Results.error( message=str(e) )
        
        
        userid = user.userid
        arguments = cherrypy.request.json
        if type(arguments) is not dict:
            return Results.error('bad request invalid parameters')

        key = arguments.get('key')
        # only 'loginHistory' or 'callHistory' is allowed
        if key not in ['loginHistory', 'callHistory']:
            return Results.error('denied key value')

        return self._getcollection(userid, key)
    

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    @cherrypy.tools.allow(methods=['GET'])
    def collection(self, key):
        # Check auth 
        try:
            (auth, user ) = self.validate_env()
        except Exception as e:
            self.logger.error( e )
            return Results.error( message=str(e) )

        userid = user.userid
        if type(key) is not str:
            return Results.error('bad request invalid parameters')

        # only 'loginHistory' or 'callHistory' is allowed
        if key not in ['loginHistory', 'callHistory']:
            return Results.error('denied key value')

        return self._getcollection(userid, key)
    



    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def setcollection(self):
        # Check auth 
        try:
            (auth, user ) = self.validate_env()
        except Exception as e:
            self.logger.error( e )
            return Results.error( message=str(e) )


        userid = user.userid
        arguments = cherrypy.request.json
        
        if type(arguments) is not dict:
            return Results.error('bad request invalid parameters')

        key = arguments.get('key')
        value = arguments.get('value')

        if key not in ['callHistory']:
            return Results.error('collection name denied')
            
        return self._addtocollection(userid, key, value)        


    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def getlog(self):
        # Check auth 
        try:
            (auth, user ) = self.validate_env()
        except Exception as e:
            self.logger.error( e )
            return Results.error( message=str(e) )

        return self._getcollection('log', cherrypy.request.json.get('key'))


    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()    
    def getacl(self):
        # Check auth 
        try:
            (auth, user ) = self.validate_env()
        except Exception as e:
            self.logger.error( e )
            return Results.error( message=str(e) )

        return self._getcollection('acl', cherrypy.request.json.get('key'))


    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def setacl(self):
        # Check auth 
        try:
            (auth, user ) = self.validate_env()
        except Exception as e:
            self.logger.error( e )
            return Results.error( message=str(e) )

        arguments = cherrypy.request.json

        if type(arguments) is not dict:
            return Results.error('bad request invalid parameters')

        return self._addtocollection('acl', arguments.get('key', None), arguments.get('value', None))


    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def updateacl(self):
        
        # Check auth 
        try:
            (auth, user ) = self.validate_env()
        except Exception as e:
            self.logger.error( e )
            return Results.error( message=str(e) )

        arguments = cherrypy.request.json

        if type(arguments) is not dict:
            return Results.error('bad request invalid parameters')

        dbname = 'acl'
        key = arguments.get('key')
        value = arguments.get('value')
        req = arguments.get('req')

        if all([dbname, key, req]) and services.datastore.updatestoredvalue(dbname, key, req, value) is True:
            return Results.success()

        return Results.error('set data error')


    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def deleteacl(self):
        # Check auth 
        try:
            (auth, user ) = self.validate_env()
        except Exception as e:
            self.logger.error( e )
            return Results.error( message=str(e) )

        arguments = cherrypy.request.json

        if type(arguments) is not dict:
            return Results.error('bad request invalid parameters')

        dbname = 'acl'

        key = arguments.get('key')
        value = arguments.get('value')

        if all([dbname, key]) and services.datastore.deletestoredvalue(dbname, key, value) is True:
            return Results.success()

        return Results.error('set data error')


    def _getcollection(self, dbname, key):        
        value = None
        if all([dbname, key]):
            value = services.datastore.getcollection(dbname, key)
        if value is None:
            return Results.error('key:%s not found' % key, 404)
        return Results.success(result=value)
    

    def _addtocollection(self, dbname, key, value):        
        if all([dbname, key]) and services.datastore.addtocollection(dbname, key, value) is True:
            return Results.success()           
        else:
            return Results.error( message='addtocollection failed') 