import logging 
import pyasn 
import oc.logging

logger = logging.getLogger(__name__)

@oc.logging.with_logger()
class ODASNumber:

    def __init__(self, database:str='ipasn_db.dat' ):
        self.asndb = None  
        try:
            self.asndb = pyasn.pyasn(database)
        except Exception as e:
            self.logger.error( f"Error while loading ASNumber database {database} : {e}" )

    def isinitialized(self):
        return isinstance( self.asndb, pyasn.pyasn)


    def getasn( self, ipaddr:str ) -> str:
        asn = None
        if not self.isinitialized():
            self.logger.error( "ASNumber database not initialized" )
            return asn
        try:
            asn, prefix = self.asndb.lookup( ipaddr )
        except Exception as e:
            self.logger.error( e )
        return str(asn) if asn is not None else None

    def lookup( self, ipaddr:str, asnumber )->bool:
        bReturn = False
        if not self.isinitialized():
            self.logger.error( "ASNumber database not initialized" )
            return bReturn
        try:
            asn, prefix = self.asndb.lookup( ipaddr )
            if isinstance( asnumber, str):
                if str(asn) == asnumber:
                    bReturn = True
            elif isinstance( asnumber, list):
                if str(asn) in asnumber:
                    bReturn = True
        except Exception as e:
            self.logger.error( e )
        return bReturn