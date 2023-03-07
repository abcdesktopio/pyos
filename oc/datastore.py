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
import pymongo
import pymongo.errors
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
# from bson.objectid import ObjectId

logger = logging.getLogger(__name__)


class ODDatastoreClient(object):

    def getcollection(self, databasename, collectionname, myfilter=None, limit=0):
        raise NotImplementedError("Class %s doesn't implement method %s" %(self.__class__.__name__, 'getcollection'))

    def addtocollection(self, databasename, collectionname, datadict):
        raise NotImplementedError("Class %s doesn't implement method %s" %(self.__class__.__name__, 'addtocollection'))

@oc.logging.with_logger()
class ODMongoDatastoreClient(ODDatastoreClient):

    def __init__(self, mongodburl, databasename=None):
        self.authenticationDatabase = 'admin'
        self.databasename = databasename
        self.mongodburl = mongodburl
         # Defaults to 20000 (20 seconds). 
        # set to 5000 (5 seconds). 
        # self.connectTimeoutMS = 3000  
        # Controls how long (in milliseconds) the driver will wait for a response after sending an ordinary (non-monitoring) database operation 
        # before concluding that a network error has occurred. 
        # Defaults to None (no timeout).
        # set to 5000 (5 seconds). 
        # self.socketTimeoutMS  = 5000  
        # self.serverSelectionTimeoutMS = 5000
        self.index_name = 'kind'

    def createhosturl( self, databasename ):
        return f"{self.mongodburl}/{databasename}?authSource={databasename}"

    def createclient(self, databasename):
        self.logger.debug( f"databasename={databasename}")
        # hosturl = self.createhosturl( databasename )
        # self.logger.debug( f"hosturl={hosturl}")
        hosturl = self.createhosturl( databasename )
        self.logger.debug( f"createclient MongoClient {hosturl}")
        mongo_client = MongoClient(host=hosturl)
        # connectTimeoutMS=self.connectTimeoutMS, 
        # socketTimeoutMS=self.socketTimeoutMS, 
        # serverSelectionTimeoutMS=self.serverSelectionTimeoutMS )
        # server_info = mongo_client.server_info()
        # self.logger.debug( f"server_info={server_info}")
        return mongo_client

    def get_document_value_in_collection(self, databasename, collectionname, key):
        obj = None
        self.logger.debug( f"database={databasename} collectionname={collectionname} key={key}" )
        try:            
            client = self.createclient(databasename)        
            collection = client[databasename][collectionname]            
            if collection is not None:
                obj = collection.find_one( { self.index_name:key })
                if obj is not None:
                    data = obj.get(key, None)                 
                    client.close()
                    return data          
            client.close()  
        except pymongo.errors.ConnectionFailure as e:
            self.logger.error( f"get_document_value_in_collection: {e}" )       
        except Exception as e :            
            self.logger.error( f"get_document_value_in_collection: {e}" )       
        return obj

    def getcollection(self, databasename, collectionname, myfilter=None, limit=0):
        self.logger.debug( f"database={databasename} collectionname={collectionname}" )
        mycollection = []
        try:            
            client = self.createclient(databasename)        
            collection = client[databasename][collectionname]                        
            if collection is not None:
                findcollection = collection.find() if myfilter is None else collection.find(filter=myfilter, limit=limit)
                for obj in findcollection:
                    id = obj.get('_id', None)  # should never be None
                    if id is not None: 
                        id = str(id) # translate type to string
                    obj['_id'] = id
                    mycollection.append(obj)
            client.close()
        except pymongo.errors.ConnectionFailure  as e  :
            self.logger.error( 'getcollection ' + str(e) ) 
        except Exception  as e  :            
            self.logger.error( 'getcollection ' + str(e) ) 

        return mycollection


    def set_document_value_in_collection(self, databasename, collectionname, key, value):
        self.logger.debug( f"database={databasename} collectionname={collectionname} key={key} value={value}")
        datadict = value if isinstance(value, dict) else {key: value}
        try:            
            client = self.createclient(databasename)
            collection = client[databasename][collectionname]
            #
            # do not use index only few entries (< 5)
            # if the collection does not exist or does not have self.index_name
            # index_information = collection.index_information()
            # if index_information.get( self.index_name +'_1' ) is None:
            #    collection.create_index([( self.index_name, pymongo.ASCENDING )], unique=True, background=True, hidden=True)
            #                                      
            obj = collection.find_one( {self.index_name: key })
            datadict[self.index_name] = key
            if isinstance(obj, dict):
                collection.replace_one({'_id': obj['_id']}, datadict)
            else:
                collection.insert_one( datadict )
            client.close()
            return True
        except pymongo.errors.ConnectionFailure  as e :
            self.logger.error( f"set_document_value_in_collection {e}" ) 
        except Exception  as e  :            
            self.logger.error( f"set_document_value_in_collection {e}" ) 
        return False


    def addtocollection(self, databasename, collectionname, datadict):
        try:
            client = self.createclient(databasename)        
            collection = client[databasename][collectionname]                                    
            collection.insert_one(datadict)
            client.close()
            return True
        except pymongo.errors.ConnectionFailure  as e  :
            self.logger.error( f"addtocollection {e}" )     
        except Exception  as e  :
            self.logger.error( f"addtocollection {e}" ) 

        return False

    """
    def config_replicaset( self, replicaset_name ):
        mongoclientcfg = ODMongoDatastoreClient( self.config.hosturl )
        host = mongoclientcfg.gethost()
        config = { '_id': replicaset_name, 'members': [ { '_id':0, 'host': host } ] }
        return config

    def create_replicaset( self, replicaset_name ):
        self.logger.info(f"create replicaset {replicaset_name}")
        c = MongoClient(self.serverfqdn, self.serverport, directConnection=True )
        try:
            # set a default configuration 
            config = self.config_replicaset( replicaset_name )
            repl_status = c.admin.command("replSetInitiate", config, allowable_errors=True)
        except pymongo.errors.OperationFailure as e:
            if e.code == 23: # already initialized
                # another process has done before
                self.logger.info( f"{self.serverfqdn} already use replicatset")
                return True
            else:
                self.logger.error( e )
        except Exception as e:
            self.logger.error( e )
            return False

    def getstatus_replicaset( self, replicaset_name):
        self.logger.info(f"read replicaset {replicaset_name} status")
        c = MongoClient(self.serverfqdn, self.serverport, directConnection=True )
        try:
            repl_status = c.admin.command("replSetGetStatus")
            if isinstance( repl_status, dict ):
                if int(repl_status.get('ok')) == 1:
                    # repl_status.get('set') == replicaset_name
                    self.logger.info( f"{self.serverfqdn} already uses replicatset {repl_status.get('set')}")
                    return True
        except pymongo.errors.OperationFailure as e:
            if e.code == 94: # no replset config has been received
                self.logger.info("no replset config has been received")
        except Exception as e:
            self.logger.error( e )
        return False
    """
