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
from bson.objectid import ObjectId


logger = logging.getLogger(__name__)

class ODDatastoreClient(object):
    def getstoredvalue(self, databasename, key):
        pass

    def removestoredvalue(self, databasename, key):
        raise NotImplementedError("Class %s doesn't implement method %s" %(self.__class__.__name__, 'removestoredvalue'))

    def getcollection(self, databasename, collectionname, myfilter=None, limit=0):
        raise NotImplementedError("Class %s doesn't implement method %s" %(self.__class__.__name__, 'getcollection'))

    def setstoredvalue(self, databasename, key, value):
        raise NotImplementedError("Class %s doesn't implement method %s" %(self.__class__.__name__, 'setstoredvalue'))

    def addtocollection(self, databasename, collectionname, datadict):
        raise NotImplementedError("Class %s doesn't implement method %s" %(self.__class__.__name__, 'addtocollection'))

    def updatestoredvalue(self, databasename, collectionname, myreq, datadict):
        raise NotImplementedError("Class %s doesn't implement method %s" %(self.__class__.__name__, 'updatestoredvalue'))

    def deletestoredvalue(self, databasename, collectionname, id):
        raise NotImplementedError("Class %s doesn't implement method %s" %(self.__class__.__name__, 'deletestoredvalue'))

@oc.logging.with_logger()
class MongoClientConfig(object):
    def __init__(self, serverfqdn, serverport=None):
        self.serverfqdn = serverfqdn    # can be an url connection string mongodb://myDBReader:D1fficultP%40ssw0rd@mongodb0.example.com:27017/?authSource=admin         
        self.serverport = serverport    # server port must be None to use mongodb://server:port format
        self.logger.info( 'mongodb client config server %s', serverfqdn )
       
    def __str__(self):
        data = '%s:%s' % (self.serverfqdn, self.serverport) if self.serverport else self.serverfqdn
        return data


@oc.logging.with_logger()
class ODMongoDatastoreClient(ODDatastoreClient):

    def __init__(self, conf):
        self.serverfqdn = conf.serverfqdn
        self.serverport = conf.serverport
         # Defaults to 20000 (20 seconds). 
        # set to 5000 (5 seconds). 
        self.connectTimeoutMS = 3000  
        # Controls how long (in milliseconds) the driver will wait for a response after sending an ordinary (non-monitoring) database operation 
        # before concluding that a network error has occurred. 
        # Defaults to None (no timeout).
        # set to 5000 (5 seconds). 
        self.socketTimeoutMS  = 2000  
        self.serverSelectionTimeoutMS = 2000

    # Store database call
    # return None is not found or failure
    def getstoredvalue(self, databasename, key):
        obj = None
        self.logger.debug( 'database=%s key=%s', databasename, key )
        try:            
            client = self.createclient()        
            collection = client[databasename][key]            
            if collection is not None:
                obj = collection.find_one()
                if obj is not None:
                    data = obj.get(key, None)                 
                    client.close()
                    return data          
            client.close()  
        except pymongo.errors.ConnectionFailure as e:
            self.logger.error( 'getstoredvalue: ' + str(e) )       
        except Exception as e :            
            self.logger.error( 'getstoredvalue: ' + str(e) )       
        
        return obj

    # Store database call
    def removestoredvalue(self, databasename, key):
        try:            
            client = self.createclient()        
            collection = client[databasename][key]                        
            if collection is not None:
                collection.remove()
            client.close()
            return True
        except pymongo.errors.ConnectionFailure as e :
            self.logger.error( 'removestoredvalue ' + str(e) ) 
        except Exception as e :            
            self.logger.error( 'removestoredvalue ' + str(e) ) 
        
        return False

    def getcollection(self, databasename, collectionname, myfilter=None, limit=0):
        self.logger.debug( 'database=%s collectionname=%s', databasename, collectionname )
        mycollection = []
        try:            
            client = self.createclient()        
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

    def setstoredvalue(self, databasename, key, value):
        self.logger.debug( 'database=%s key=%s value=%s', databasename, key, str(value) )
        datadict = value if isinstance(value, dict) else {key: value}
        try:            
            client = self.createclient()        
            collection = client[databasename][key]                                    
            obj = collection.find_one()
            if obj is not None:
                collection.replace_one({'_id': obj['_id']}, datadict)
            else:
                collection.insert_one(datadict)
            client.close()
            return True
        except pymongo.errors.ConnectionFailure  as e :
            self.logger.error( 'setstoredvalue ' + str(e) ) 
        except Exception  as e  :            
            self.logger.error( 'setstoredvalue ' + str(e) ) 

        return False

    def addtocollection(self, databasename, collectionname, datadict):
        try:
            client = self.createclient()        
            collection = client[databasename][collectionname]                                    
            collection.insert_one(datadict)
            client.close()
            return True
        except pymongo.errors.ConnectionFailure  as e  :
            self.logger.error( 'addtocollection ' + str(e) )     
        except Exception  as e  :
            self.logger.error( 'addtocollection ' + str(e) ) 

        return False

    def updatestoredvalue(self, databasename, collectionname, myreq, datadict):
        try:
            client = self.createclient()        
            collection = client[databasename][collectionname]                                    
            collection.update_one(myreq, {"$set": datadict}, upsert=True)
            client.close()
            return True

        except pymongo.errors.ConnectionFailure  as e  :
            self.logger.error( 'updatestoredvalue ' + str(e) ) 
        
        except Exception  as e :
            self.logger.error( 'updatestoredvalue ' + str(e) ) 

        return False

    def deletestoredvalue(self, databasename, collectionname, id):
        try:
            client = self.createclient()        
            collection = client[databasename][collectionname]                                    
            collection.delete_one({'_id': ObjectId(id)})
            client.close()
            return True
        
        except pymongo.errors.ConnectionFailure  as e  :
            self.logger.error( 'deletestoredvalue ' + str(e) ) 
                
        except Exception as e :
            self.logger.error( 'deletestoredvalue ' + str(e) ) 

        return False

    def createclient(self):
        return MongoClient(self.serverfqdn, self.serverport, connectTimeoutMS=self.connectTimeoutMS, socketTimeoutMS=self.socketTimeoutMS, serverSelectionTimeoutMS=self.serverSelectionTimeoutMS )

    def getcollectionfromdb(self, databasename, collectionname):
        client = self.createclient()        
        return client[databasename][collectionname]