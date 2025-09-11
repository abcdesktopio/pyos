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

    def __init__(self, config:dict, memcache_connection_string:str ):
        self.maxprelogintimeout = int(config.get('maxprelogintimeout',120))
        self.timetoloadthewebpage = int(config.get('timetoloadthewebpage',5))
        if (self.maxprelogintimeout - self.timetoloadthewebpage) < 5:
            # user don't have enough time to fill the form
            # reset to default value
            self.logger.warning( "maxprelogintimeout - timetoloadthewebpage < 5, reset to default values" )
            self.maxprelogintimeout = 120
            self.timetoloadthewebpage = 5

        # time to refresh the prelogin page in milliseconds
        self.refreshprelogintimeoutinseconds = self.maxprelogintimeout - self.timetoloadthewebpage
        self.mustache_data = None
        self.prelogin_url = config.get('url')
        self.memcache = oc.sharecache.ODMemcachedSharecache( memcache_connection_string )
        self.enable = config.get('enable')
        self.network_list = config.get('network_list', [] )
        self.http_attribut = config.get('http_attribut')
        self.http_attribut_to_force_auth_prelogin = config.get('http_attribut_to_force_auth_prelogin')

        # check configuration value prelogin_url 
        if self.enable :
            if not isinstance( self.prelogin_url, str):
                self.logger.error( "prelogin_url is not set, prelogin is disabled")
                self.enable = False

        # check configuration value network_list 
        if self.enable :
            if not isinstance( self.network_list, list):
                self.logger.error( "invalid prelogin_network_list value, prelogin is disabled")
                self.enable = False
            else:
                try:
                    for network in self.network_list:
                        IPNetwork( network ) # check the network is valid
                except Exception as e:
                    self.logger.error( f"invalid prelogin_network_list value, prelogin is disabled {e}")
                    self.enable = False


    def get_prelogin_mustache_data(self)->None:
        """ update the mustache_data cache from prelogin_url
            load the mustache template from prelogin_url
        Args:
            None    
        Raises:
            Exception: [requests.get failed]
        """
        data = None
        if self.mustache_data is None :
            try: 
                r = requests.get(self.prelogin_url, allow_redirects=False, verify=False )
                data = r.content.decode('utf-8')
                self.mustache_data = data
            except Exception as e:
                self.logger.error(e)
                data = f"<html><body>{e}</body></html>" # return error as html
        else:
            data = self.mustache_data
        return data
        



    def prelogin_verify( self, sessionid:str, userid:str )->bool:
        """ verify if the sessionid is valid for the userid
        Args:
            sessionid (str): [sessionid from user web browser]
            userid (str): [userid from http_attribut header]
        Returns:        
            bool: [True if sessionid is valid for the userid, else False]
        """
        self.logger.debug( 'prelogin_verify starting' )
        if not isinstance(sessionid, str) or not isinstance(userid, str):
            self.logger.error( "prelogin_verify invalid sessionid or userid type" )
            return False
        if len( sessionid ) != self.len_sessionid():
            self.logger.error( f"prelogin_verify bad sessionid params invalid len(sessionid)={len(sessionid)}, expected len={self.len_sessionid()}" )
            return False
        self.memcacheclient = self.memcache.createclient()
        self.logger.debug( f"prelogin_verify asking cached data key={sessionid}" )
        cacheduserid = self.memcacheclient.get( key=sessionid )
        # do not delete key, to permit reload from user's web browser
        # delete occurs in expired timeout value
        # self.memcacheclient.delete( key=sessionid, noreply=True )

        if not isinstance( cacheduserid, str) or len(cacheduserid) == 0:
            self.logger.info( f"prelogin_verify no cached data for key={sessionid}" )
            return False

        self.logger.debug( f"prelogin_verify compare in uppercase {cacheduserid}=={userid}" )
        return userid.upper() == cacheduserid.upper()

    def len_sessionid( self ):
        return len( str( uuid.uuid4() ) )

    def prelogin_html( self, userid:str )->str:
        """ return the prelogin html page with a new sessionid
        Args:
            userid (str): [userid from http_attribut header]
        Returns:        
            str: [html page with a new sessionid]
        """
        if not isinstance(userid, str) or len(userid) == 0:
            return "<html><body>prelogin_html invalid userid</body></html>"
        # generate a new sessionid  
        sessionid = str( uuid.uuid4() )
        # prelogindict is a dict with values to fill 
        # the prelogin_url mustache template
       
        # update the logintimeout value
        # this will reload the web page and create a new sessionid
        # 
        prelogindict = { 'base_url': '../..',
                         'loginsessionid': sessionid,
                         'refresh_timeout': str(self.refreshprelogintimeoutinseconds),
                         'cuid': userid }

        # get the mustache template file content
        mustache_data = self.get_prelogin_mustache_data()

        # set data to memcached
        self.memcacheclient = self.memcache.createclient()
        self.logger.info( f"prelogin_html setting key={sessionid} value={userid} timeout={self.maxprelogintimeout}" )
        bset = self.memcacheclient.set( key=sessionid, value=userid, expire=self.maxprelogintimeout )
        if not isinstance( bset, bool) or bset is False:
            self.logger.error( f"memcacheclient:set failed to set data key={sessionid} value={userid}" )
        html_data = chevron.render( mustache_data, prelogindict )
        # self.logger.debug( html_data )
        return html_data
             
    def request_match(self, ipsource:str)->bool:
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
       