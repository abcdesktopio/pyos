import logging 
import oc.datastore
import pymongo

logger = logging.getLogger(__name__)

@oc.logging.with_logger()
class ODFail2ban:

    def __init__(self, mongoconfig, fail2banconfig={}):
        self.failmaxvaluebeforeban = fail2banconfig.get('failsbeforeban', 2 )
        self.banexpireAfterSeconds = fail2banconfig.get('banexpireafterseconds', 3600 )
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

        col = db[self.ip_collection_name]
        col.create_index( [( self.index_name, pymongo.ASCENDING )], expireAfterSeconds=self.banexpireAfterSeconds ) 
        col = db[self.login_collection_name]
        col.create_index( [( self.index_name, pymongo.ASCENDING )], expireAfterSeconds=self.banexpireAfterSeconds )

    def get_collection(self, collection_name ):
        mongo_client = oc.datastore.ODMongoDatastoreClient.createclient(self.datastore) 
        db = mongo_client[self.databasename]
        return db[collection_name]

    def _fail( self, value, collection_name ):
        self.logger.debug('')
        myfail = None
        collection = self.get_collection( collection_name )
        bfind = collection.find_one({ self.index_name: value})
        if bfind:
            myfail = collection.update({ self.index_name: value}, {'$inc' : { 'count' : 1 } })
        else: 
            myfail = collection.insert({ self.index_name: value, 'count' : 1 })
        return myfail

    def fail_ip( self, value ):
        assert isinstance(value, str) , 'bad value ip parameter'
        return self._fail( value, collection_name = self.ip_collection_name )

    def fail_login( self, value ):
        assert isinstance(value, str) , 'bad value login parameter'
        return self._fail( value, collection_name = self.login_collection_name )

    def _isban( self, ipAddr, collection_name ):
        """isban

        Args:
            ipAddr (str): return True if the ipAddr is ban
        """

        self.logger.debug('')
        bReturn = False 
        collection = self.get_collection( collection_name )
        bfind = collection.find_one({ self.index_name: ipAddr})
        if isinstance(bfind, dict):
            count = bfind.get( self.counter, 0)
            bReturn = count >= self.failmaxvaluebeforeban
        return bReturn

    def isban_ip(self, value):
        return self._isban( value, collection_name = self.ip_collection_name )

    def isban_login(self, value):
        assert isinstance(value, str) , 'bad value login parameter'
        return self._isban( value, collection_name = self.login_collection_name )

    def _ban( self, value,  collection_name ):
        myban = None
        self.logger.debug('')
        collection = self.get_collection( collection_name )
        bfind = collection.find_one({ self.index_name: value})
        if bfind:
            myban = collection.update({ self.index_name: value}, {'$inc' : { self.counter : self.failmaxvaluebeforeban } })
        else: 
            myban = collection.insert({ self.index_name: value, self.counter : self.failmaxvaluebeforeban }).__str__()

        return myban

    def ban_ip( self, value ):
        assert isinstance(value, str) , 'bad value ip parameter'
        return self._ban( value, collection_name = self.ip_collection_name )

    def ban_login( self, value ):
        assert isinstance(value, str) , 'bad value login parameter'
        return self._ban( value, collection_name = self.login_collection_name )


    def _listban( self, collection_name ):
        ban_dict = {}
        self.logger.debug('')
        collection = self.get_collection( collection_name )
        findall = collection.find()
        for data in findall:
            key = data.get(self.index_name)
            value = data.get(self.counter)
            if key and value :
                ban_dict[key] = value
        return ban_dict

    def listban_ip( self ):
        mydict = self._listban( collection_name = self.ip_collection_name )
        return mydict

    def listban_login( self ):
        mydict = self._listban( collection_name = self.login_collection_name )
        return mydict