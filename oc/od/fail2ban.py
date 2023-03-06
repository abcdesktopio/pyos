import logging 
import oc.datastore
import pymongo
import datetime
from netaddr import IPNetwork, IPAddress

logger = logging.getLogger(__name__)
@oc.logging.with_logger()
class ODFail2ban:

    def __init__(self, mongodburl, fail2banconfig={}):
        self.databasename = 'fail2ban'
        self.ip_collection_name = 'ipaddr'
        self.login_collection_name = 'login'
        self.enable = fail2banconfig.get('enable') # specify a positive non-zero value 
        self.failmaxvaluebeforeban = fail2banconfig.get('failsbeforeban', 5 ) # specify a positive non-zero value 
        self.banexpireAfterSeconds = fail2banconfig.get('banexpireafterseconds', 30*60 )
        self.protectedNetworks    = fail2banconfig.get('protectednetworks', [] )
        self.datastore = oc.datastore.ODMongoDatastoreClient(mongodburl,  self.databasename)
        self.collections_name = [ self.ip_collection_name, self.login_collection_name ]
        self.sanity_filter = {  
            self.ip_collection_name:"0123456789.", 
            self.login_collection_name:"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_\\/ " 
        }
        # create a new database instance
        self.index_name = 'id'
        self.counter = 'count'
        self.index_date = 'date'

        self.init_collection( self.ip_collection_name )
        self.init_collection( self.login_collection_name )

    def sanity( self, value, filter ):
        """sanity

        Args:
            value (str): value to be check
            filter (str): str of permited char

        Returns:
            bool: True if all chars are permited, False else
        """
        if not isinstance( value, str) or not isinstance( filter, str):
            return False
        for c in value:
            if c not in filter:
                return False
        return True

    def init_collection( self, collection_name ):
        self.logger.debug(f"{self.databasename} {collection_name}")
        mongo_client = oc.datastore.ODMongoDatastoreClient.createclient(self.datastore, self.databasename ) 
        db = mongo_client[self.databasename]
        col = db[collection_name]
        try:
            col.create_index( [( self.index_name, pymongo.ASCENDING )] )
            col.create_index( [( self.index_date, pymongo.DESCENDING )], expireAfterSeconds=self.banexpireAfterSeconds)
        except Exception as e:
            self.logger.info( e )
        mongo_client.close()

    def iscollection( self, collection_name ):
        bReturn = collection_name in self.collections_name
        return bReturn

    def test( self ):
        self.logger.debug('')
        dummy_ipaddr = 'loopback'
        for n in range( self.failmaxvaluebeforeban ):
            self.fail_ip( dummy_ipaddr)
            is_ban = self.isban_ip( dummy_ipaddr )
            if is_ban and (n+1)==self.failmaxvaluebeforeban :
                 self.logger.debug( f"ban self test ok is {dummy_ipaddr} banned {is_ban}")
        list_ban_dummy_ipaddr = self.listban_ip()
        self.logger.debug( f"dump list is {list_ban_dummy_ipaddr}")
        self.logger.debug( f"unban {dummy_ipaddr}")
        self.unban_ip( dummy_ipaddr )
        list_ban_dummy_ipaddr = self.listban_ip()
        self.logger.debug( f"dump list is {list_ban_dummy_ipaddr}")
        
    def get_collection(self, collection_name ):
        mongo_client = oc.datastore.ODMongoDatastoreClient.createclient(self.datastore, self.databasename) 
        db = mongo_client[self.databasename]
        return db[collection_name]

    def fail( self, value, collection_name ):
        myfail = None
        collection = self.get_collection( collection_name )
        bfind = collection.find_one({ self.index_name: value})
        myfail = self.updateorinsert( collection=collection, bUpdate=bfind, value=value, counter=1 ) 
        return myfail

    def fail_ip( self, value ):

        # if ban is not enable nothing to do
        if not self.enable: 
            return

        #
        # do not ban ip address if ip addess is in protectedNetworks
        for network in self.protectedNetworks:
            try:
                if IPAddress(value) in IPNetwork( network ):
                    # skip this ip
                    self.logger.info( f"ip address {value} is not banned, inside protected network {network}" )
                    return
            except Exception as e:
                self.logger.error( e )
        
        return self.fail( value, collection_name = self.ip_collection_name )

    def fail_login( self, value ):
        # if ban is not enable nothing to do
        if not self.enable: 
            return
        return self.fail( value, collection_name = self.login_collection_name )

    def isban( self, value, collection_name ):
        """isban

        Args:
            ipAddr (str): return True if the ipAddr is ban
        """
          # if ban is not enable nothing to do
        if not self.enable: 
            return False

        bReturn = False 

        # sanity check
        if not self.sanity( value, self.sanity_filter.get(collection_name)):
            self.logger.error("bad parameter sanity check")
            return False

        collection = self.get_collection( collection_name )
        bfind = collection.find_one({ self.index_name: value})
        if isinstance(bfind, dict):
            count = bfind.get( self.counter, 0)
            bReturn = count >= self.failmaxvaluebeforeban
        return bReturn

    def updateorinsert( self, collection, bUpdate, value, counter ):
        utc_timestamp = datetime.datetime.utcnow()
        if bUpdate:
            count = bUpdate.get( self.counter, 0)
            if count >= self.failmaxvaluebeforeban:
                self.logger.debug( f" {bUpdate.get(self.index_name)} has reach value {bUpdate.get(self.counter)} ")
            q = collection.update_one({ self.index_name: value, self.index_date: utc_timestamp}, {'$inc' : { self.counter : counter } })
        else: 
            q = collection.insert_one({ self.index_name: value, self.index_date: utc_timestamp,  self.counter : counter })
            q = {"n": 1, "Inserted": 1, "ok": 1.0, "updatedExisting": False }
        return q

    def ban( self, value,  collection_name ):
        myban = None
        if not self.sanity( value, self.sanity_filter.get(collection_name)):
            self.logger.error("bad parameter sanity check")
            return False
        collection = self.get_collection( collection_name )
        bfind = collection.find_one({ self.index_name: value})
        myban = self.updateorinsert( collection=collection, bUpdate=bfind, value=value, counter=self.failmaxvaluebeforeban )
        return myban

    def drop( self, collection_name ):
        collection = self.get_collection( collection_name )
        collection.drop()
        self.init_collection(collection_name=collection_name)

    def unban( self, value,  collection_name ):
        myban = False
        if not self.sanity( value, self.sanity_filter.get(collection_name)):
            self.logger.error("bad parameter sanity check")
            return False
        collection = self.get_collection( collection_name )
        delete_one = collection.delete_one({ self.index_name: value})
        if isinstance( delete_one, pymongo.results.DeleteResult ):
            myban = True
        return myban

    def listban( self, collection_name ):
        ban_list = []
        collection = self.get_collection( collection_name )
        findall = collection.find()
        for data in findall:
            index_name = data.get(self.index_name)
            value = data.get(self.counter)
            date = data.get(self.index_date)
            if all( [ index_name, value, date ] ) :
                ban_list.append( { self.index_name:index_name, self.counter:value, self.index_date:date.isoformat(), 'banexpireAfterSeconds' : self.banexpireAfterSeconds } ) 
        return ban_list