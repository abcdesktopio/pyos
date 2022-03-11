import logging
import requests
import chevron
import uuid
from netaddr import IPNetwork, IPAddress
import oc.logging
import oc.sharecache

logger = logging.getLogger(__name__)

@oc.logging.with_logger()
class ODPrelogin:

    def __init__(self, config, memcache_connection_string ):
        self.maxlogintimeout = 120
        self.mustache_data = None
        self.prelogin_url = config.get('url')
        self.memcache = oc.sharecache.ODMemcachedSharecache( memcache_connection_string )
        self.enable = config.get('enable')
        self.network_list = config.get('network_list', [] )
        self.http_attribut = config.get('http_attribut')
        self.prelogin_url_redirect_on_error = config.get('url_redirect_on_error')
        self.http_attribut_to_force_auth_prelogin = config.get('http_attribut_to_force_auth_prelogin')

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
        r = requests.get(self.prelogin_url, allow_redirects=False, verify=False )
        self.mustache_data = r.content.decode('utf-8')
        # logger.debug( self.mustache_data  )


    def prelogin_verify( self, sessionid, userid ):
        logger.info( 'prelogin_verify starting' )
        if not isinstance(sessionid, str) or not isinstance(userid, str):
            logger.error( 'prelogin_verify invalid sessionid or userid type' )
            return False
        self.len_sessionid()
        if len( sessionid ) != self.len_sessionid():
            logger.error( 'prelogin_verify bad sessionid params invalid len(sessionid)=%d, expected len %d', len(sessionid), self.len_sessionid() )
            return False
        self.memcacheclient = self.memcache.createclient()
        logger.info( 'prelogin_verify asking cached data key=%s ', sessionid )
        cacheduserid = self.memcacheclient.get( key=sessionid )
        # do not delete key, to permit reload from user's web browser
        # delete occurs in expired timeout value
        # self.memcacheclient.delete( key=sessionid, noreply=True )
        userid = userid.upper()
        logger.info( 'prelogin_verify compare %s == %s', str(cacheduserid), str(userid) )
        # cacheduserid use only upper case
        return userid == cacheduserid

    def len_sessionid( self ):
        return len( str( uuid.uuid4() ) )

    def prelogin_html( self, userid ):
        sessionid = str( uuid.uuid4() )
        # prelogindict is a dict with values to fill 
        # the prelogin_url mustache template
        userid = userid.upper()
        prelogindict = { 'base_url': '../..',
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
        userid = userid.upper() # always cache data in upper case only 
        logger.info( 'prelogin_html setting key=%s value=%s timeout=%d', sessionid, userid, self.maxlogintimeout )
        bset = self.memcacheclient.set( key=sessionid, val=userid, time=self.maxlogintimeout )
        if not isinstance( bset, bool) or bset == False:
            logger.error( 'memcacheclient:set failed to set data key=%s value=%s ', sessionid, userid )
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
       