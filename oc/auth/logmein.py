# from
from cryptography.hazmat._oid import ObjectIdentifier
from netaddr import IPNetwork, IPAddress

# import 
import logging
import oc.logging
import cryptography.x509.oid 

logger = logging.getLogger(__name__)

@oc.logging.with_logger()
class ODLogmein:

    def __init__(self, config):
        self.enable = config.get('enable', False)
        self.network_list = config.get('network_list', [])
        self.http_attribut = config.get('http_attribut')
        self.permit_querystring = config.get('permit_querystring', False)
        oid_query_list = config.get('oid_list', [ cryptography.x509.oid.NameOID.USER_ID, cryptography.x509.oid.NameOID.COMMON_NAME ] )
        self.oid_query_list = []
        # convert stroid to oid
        for oid in oid_query_list :
            if isinstance( oid, str ):
                # convert oid dotted_string format to ObjectIdentifier
                oid = ObjectIdentifier( oid )

            if isinstance( oid, ObjectIdentifier ):
                self.oid_query_list.append( oid )

        # check configuration value network_list 
        if self.enable :
            if not isinstance( self.network_list, list):
                self.logger.error( "invalid logmein_network_list value, logmein is disabled")
                self.enable = False
            else:
                try:
                    # check the network_list
                    for network in self.network_list:
                        IPNetwork( network )
                except Exception as e:
                    self.logger.error( f"invalid logmein_network_list value, logmein is disabled {e}")
                    self.enable = False

    def request_match(self, ipsource) :
        """[request_match]
            return True if request need a logmein auth, else False
        Args:
            ipsource ([str]): [source ip addr]

        Returns:
            [bool]: [True if request need a logmein auth, else False]
        """
        if self.enable is False:
            return False

        for network in self.network_list:
            if IPAddress(ipsource) in IPNetwork( network ):
                    return True
                    
        return False
       