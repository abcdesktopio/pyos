import logging
import oc.logging
from netaddr import IPNetwork, IPAddress

logger = logging.getLogger(__name__)

@oc.logging.with_logger()
class ODLogmein:

    def __init__(self, logmein_enable, logmein_network_list, logmein_http_attribut=None, logmein_url_redirect_on_error=None):
        self.enable = logmein_enable
        self.network_list = logmein_network_list
        self.http_attribut = logmein_http_attribut
        self.logmein_url_redirect_on_error = logmein_url_redirect_on_error

        # check configuration value network_list 
        if self.enable :
            if not isinstance( self.network_list, list):
                logger.error( "invalid logmein_network_list value, logmein is disabled")
                self.enable = False
            else:
                try:
                    # check the network_list
                    for network in self.network_list:
                        IPNetwork( network )
                except Exception as e:
                    logger.error( "invalid logmein_network_list value, logmein is disabled")
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
       