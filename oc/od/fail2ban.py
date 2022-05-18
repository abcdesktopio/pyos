import logging 
import oc.datastore
import pymongo
import datetime

logger = logging.getLogger(__name__)

@oc.logging.with_logger()
class ODFail2ban:

    def __init__(self, mongoconfig, fail2banconfig={}):
        self.failmaxvaluebeforeban = fail2banconfig.get('failsbeforeban', 5 ) # specify a positive non-zero value 
        self.banexpireAfterSeconds = fail2banconfig.get('banexpireafterseconds', 30*60 )
        self.datastore = oc.datastore.ODMongoDatastoreClient(mongoconfig)
        self.databasename = 'fail2ban'
        self.ip_collection_name = 'ipaddr'
        self.login_collection_name = 'login'
        self.collections_name = [ self.ip_collection_name, self.login_collection_name ]
       
        mongo_client = oc.datastore.ODMongoDatastoreClient.createclient(self.datastore)  
        db = mongo_client[self.databasename]
        # create a new database instance
        self.index_name = 'id'
        self.counter = 'count'
        self.index_date = 'date'

        self.init_collection( self.ip_collection_name )
        self.init_collection( self.login_collection_name )
       

    def init_collection( self, collection_name ):
        mongo_client = oc.datastore.ODMongoDatastoreClient.createclient(self.datastore) 
        db = mongo_client[self.databasename]
        col = db[collection_name]
        try:
            col.ensure_index( [( self.index_name, pymongo.ASCENDING )] )
            col.ensure_index( self.index_date, expireAfterSeconds=self.banexpireAfterSeconds)
        except Exception as e:
            self.logger.info( e )
        mongo_client.close()

    def test( self ):
        self.logger.debug('')
        dummy_ipaddr = 'loopback'
        for n in range( self.failmaxvaluebeforeban ):
            self.fail_ip( dummy_ipaddr)
            is_ban = self.isban_ip( dummy_ipaddr )
            if is_ban and (n+1)==self.failmaxvaluebeforeban :
                 self.logger.debug( f"ban self test ok is {dummy_ipaddr} banned {is_ban}")
        self.logger.debug( f"unban {dummy_ipaddr}")
        self.unban_ip( dummy_ipaddr )
        list_ban_dummy_ipaddr = self.listban_ip()
        self.logger.debug( f"dump list is {list_ban_dummy_ipaddr}")
        
    def get_collection(self, collection_name ):
        mongo_client = oc.datastore.ODMongoDatastoreClient.createclient(self.datastore) 
        db = mongo_client[self.databasename]
        return db[collection_name]

    def fail( self, value, collection_name ):
        myfail = None
       
        utc_timestamp = datetime.datetime.utcnow()
        collection = self.get_collection( collection_name )
        bfind = collection.find_one({ self.index_name: value})
        myfail = self.updateorinsert( collection=collection, bUpdate=bfind, value=value, counter=1 ) 
        return myfail

    def fail_ip( self, value ):
        assert isinstance(value, str) , 'bad value ip parameter'
        return self.fail( value, collection_name = self.ip_collection_name )

    def fail_login( self, value ):
        assert isinstance(value, str) , 'bad value login parameter'
        return self.fail( value, collection_name = self.login_collection_name )

    def isban( self, value, collection_name ):
        """isban

        Args:
            ipAddr (str): return True if the ipAddr is ban
        """

        bReturn = False 
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
        assert isinstance(value, str) , 'bad value parameter'
        utc_timestamp = datetime.datetime.utcnow()
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
        assert isinstance(value, str) , 'bad value parameter'
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