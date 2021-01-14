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

from pymongo import MongoClient
from bson.objectid import ObjectId


class MongoConfig(object):
    def __init__(self, serverfqdn, serverport, login=None, password=None):
        self.serverfqdn = serverfqdn
        self.serverport = serverport
        self.login = login
        self.password = password


class Mongo(object):

    def __init__(self, conf):
        self.serverfqdn = conf.serverfqdn
        self.serverport = conf.serverport

    # Store database call
    def getstoredvalue(self, databasename, key):        
        client = MongoClient(self.serverfqdn, self.serverport)
        db = client[databasename]
        collection = db[key]
        if collection is not None:
            myobj = collection.find_one()
            if myobj is not None:
                _ocdata = myobj.get(key, None)
                if _ocdata is not None:
                    return _ocdata
        return None

    # Store database call
    def removestoredvalue(self, databasename, key):
        client = MongoClient(self.serverfqdn, self.serverport)
        db = client[databasename]
        collection = db[key]
        if collection is not None:
            collection.remove()
            return True
        return False

    def getcollection(self, databasename, collectionname, myfilter=None, limit=0):
        mycollection = []
        client = MongoClient(self.serverfqdn, self.serverport)
        db = client[databasename]
        collection = db[collectionname]
        if collection is not None:
            findcollection = None
            if myfilter is None:
                findcollection = collection.find()
            else:
                findcollection = collection.find(filter=myfilter, limit=limit)
            for obj in findcollection:
                mystrid = None
                myobjid = obj.get('_id', None)           # should never be None
                if myobjid is not None:
                    mystrid = str(myobjid)        # translate type to string
                # set new value type tring None if failed
                obj['_id'] = mystrid
                mycollection.append(obj)
        return mycollection

    def setstoredvalue(self, databasename, key, value):
        bReturn = False
        if isinstance(value, dict):
            dictvalue = value
        else:
            dictvalue = {key: value}

        try:
            client = MongoClient(self.serverfqdn, self.serverport)
            db = client[databasename]
            collection = db[key]
            obj = collection.find_one()
            if obj is not None:
                myfilter = {'_id': obj['_id']}
                collection.replace_one(myfilter, dictvalue)
            else:
                collection.insert_one(dictvalue)
            bReturn = True
        except Exception as e:
            print(e)
            pass
        return bReturn

    def addtocollection(self, databasename, collectionname, mydict):
        bReturn = False
        try:
            client = MongoClient(self.serverfqdn, self.serverport)
            db = client[databasename]
            collection = db[collectionname]
            collection.insert_one(mydict)
            bReturn = True
        except Exception as e:
            print(e)
            pass
        return bReturn

    def updatestoredvalue(self, databasename, collectionname, myreq, mydict):
        bReturn = False
        try:
            client = MongoClient(self.serverfqdn, self.serverport)
            db = client[databasename]
            collection = db[collectionname]
            collection.update_one(myreq, {"$set": mydict}, upsert=True)
            bReturn = True
        except Exception as e:
            print(e)
            pass
        return bReturn

    def deletestoredvalue(self, databasename, collectionname, myid):
        bReturn = False
        try:
            client = MongoClient(self.serverfqdn, self.serverport)
            db = client[databasename]
            collection = db[collectionname]
            collection.delete_one({'_id': ObjectId(myid)})
            bReturn = True
        except Exception as e:
            print(e)
            pass
        return bReturn
