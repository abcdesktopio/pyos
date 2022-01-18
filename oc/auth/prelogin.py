import logging
import requests
import chevron
import uuid
from netaddr import IPNetwork, IPAddress

import oc.sharecache

logger = logging.getLogger(__name__)

@oc.logging.with_logger()
class ODPrelogin:

    def __init__(self, prelogin_enable, prelogin_url, prelogin_network_list, base_url, memcache_connection_string, http_attribut=None):
        self.maxlogintimeout = 120
        self.mustache_data = None
        self.prelogin_url = prelogin_url
        self.base_url = base_url
        self.memcache = oc.sharecache.ODMemcachedSharecache( memcache_connection_string )
        self.enable = prelogin_enable
        self.network_list = prelogin_network_list
        self.http_attribut = http_attribut

        # check configuration value prelogin_url 
        if self.enable and not isinstance( self.prelogin_url, str):
            logger.error( "prelogin_url is not set, prelogin is disabled")
            self.enable = False

        # check configuration value network_list 
        if self.enable :
            if not isinstance( self.network_list, list):
                logger.error( "invalid prelogin_network_list value, prelogin is disabled")
                self.enable = False
            else:
                try:
                    # check the network_list
                    for network in self.network_list:
                        IPNetwork( network )
                except Exception as e:
                    logger.error( "invalid prelogin_network_list value, prelogin is disabled")
                    self.enable = False


    def update_prelogin_mustache_data(self):
        logger.debug( 'prelogin_mustache_data update cache read %s',  self.prelogin_url )
        r = requests.get(self.prelogin_url, allow_redirects=False)
        self.mustache_data = r.content.decode('utf-8')
        # logger.debug( self.mustache_data  )


    def prelogin_verify( self, sessionid, userid ):
        if not isinstance(sessionid, str) or not isinstance(userid, str):
            return False
        self.memcacheclient = self.memcache.createclient()
        cacheduserid = self.memcacheclient.get( key=sessionid )
        # do not delete key, to permit reload
        # delete occurs in expired timeout value
        self.memcacheclient.delete( key=sessionid, noreply=True )
        logger.debug( 'prelogin_verify %s %s', str(cacheduserid), str(userid) )
        return userid == cacheduserid

    def prelogin_html( self, userid ):
        sessionid = str( uuid.uuid4() )
        # prelogindict is a dict with values to fill 
        # the prelogin_url mustache template
        prelogindict = { 'base_url': self.base_url,
                         'loginsessionid': sessionid, 
                         'cuid': userid }

        # if the cache mustache_data is empty
        # load the prelogin_url mustache template
        if self.mustache_data is None :
            try: 
                self.update_prelogin_mustache_data()
            except Exception as e:
                logger.error( str(e) )
                return str(e)   # return error as html_data

        # set data to memcached
        self.memcacheclient = self.memcache.createclient()
        self.memcacheclient.set( key=sessionid, val=userid, time=self.maxlogintimeout )
        html_data = chevron.render( self.mustache_data, prelogindict )
        logger.debug( html_data )
        return html_data
             
    def request_match(self, ipsource) :
        """[request_match]
            return True if request need a prelogin auth, else False
        Args:
            ipsource ([str]): [source ip addr]

        Returns:
            [bool]: [True if request need a prelogin auth, else False]
        """
        if self.enable is False:
            return False

        for network in self.network_list:
            if IPAddress(ipsource) in IPNetwork( network ):
                    return True
                    
        return False
       