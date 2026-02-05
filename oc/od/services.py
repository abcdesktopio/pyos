import os
import logging
import oc.od.settings as settings
import oc.od.orchestrator
import oc.od.kuberneteswatcher
import oc.auth.authservice

logger = logging.getLogger(__name__)
@oc.logging.with_logger()
class ODServices(object):

    def __init__(self):
        self.datastore = None
        self.sharecache = None
        self.messageinfo = None
        self.auth = None
        self.accounting = None
        self.internaldns = None
        self.jwtdesktop = None
        self.keymanager = None
        self.locatorPublicInternet = None
        self.kuberneteswatcher = None
        self.apps = None
        self.prelogin = None
        self.logmein = None
        self.fail2ban = None
        self.asnumber = None

    def init(self):
        """[init services call all services init() methods]
        """
        self.init_messageinfo()
        self.init_accounting()
        self.init_datastore()
        self.init_datacache()
        self.init_auth()
        self.init_internaldns()
        self.init_jwtdesktop()
        self.init_locator()
        self.init_keymanager()
        self.init_prelogin()
        self.init_logmein()
        self.init_fail2ban()
        self.init_asnumber()
        
    def start(self):
        """start
            start threads 
                * apps mongo change stream watcher
                * kuberneteswatcher
        """
        if isinstance(self.apps, oc.od.apps.ODApps):
            try:
                self.apps.start_mongo_watcher()
                self.logger.info("MongoDB watcher started")
            except Exception as e:
                self.logger.error(f"Error while starting MongoDB watcher: {e}")

        if isinstance( self.kuberneteswatcher, oc.od.kuberneteswatcher.ODKubernetesWatcher):
            self.kuberneteswatcher.start()


    def stop(self):
        '''
            stop services threads
                * apps mongo change stream watcher
                * kuberneteswatcher
        '''
        self.logger.debug('ODServices stopping services threads...')
        if isinstance(self.apps, oc.od.apps.ODApps):
            try:
                self.apps.stop_mongo_watcher()
                self.logger.info("MongoDB watcher stopped")
            except Exception as e:
                self.logger.error(f"Error while stopping MongoDB watcher: {e}")


        # stop thread imagewatcher if instance exists
        if isinstance( self.kuberneteswatcher, oc.od.kuberneteswatcher.ODKubernetesWatcher):
            # always use try/except 
            try:
                self.kuberneteswatcher.stop()
                self.logger.debug( 'kuberneteswatcher stopped')
            except Exception as e:
                self.logger.error(e)
        else:
            self.logger.debug( 'self.kuberneteswatcher is not defined')

        self.logger.debug('done, this is the end') # pom pom pom 


    def init_fail2ban( self ):
        import oc.od.fail2ban
        self.fail2ban = oc.od.fail2ban.ODFail2ban( 
            mongodburl=settings.mongodburl, 
            fail2banconfig=settings.fail2banconfig 
        )
        
    def init_asnumber( self ):
        import oc.od.asnumber
        self.asnumber = oc.od.asnumber.ODASNumber( database='ipasn_db.dat' )


    def init_keymanager(self):
        """[decode arg params query string in metappli mode ]
        """
        import oc.auth.keymanager
        # key manager use the same parameter as jwt_config_desktop
        self.keymanager = oc.auth.keymanager.ODDesktopKeyManager( settings.jwt_config_desktop )

    def init_locator(self):
        """geolocatization from ip address
        """
        import oc.od.locator
        self.locatorPublicInternet = oc.od.locator.ODLocatorPublicInternet()
        self.locatorPrivateActiveDirectory = {}
        self.update_locator()
        
    def update_locator(self):
        """update locator using site entry in ActiveDirecotry LDAP data
        """
        # filter manager to get explicit manager and metaexplicit manager
        for managertype in [  'explicit' , 'metaexplicit']:
            manager_explicit = oc.od.services.services.auth.getmanager( managertype )
            if isinstance( manager_explicit, oc.auth.authservice.ODExplicitAuthManager ) or \
               isinstance( manager_explicit, oc.auth.authservice.ODExplicitMetaAuthManager):
                # for each explicit manager
                for prv in manager_explicit.providers.values():
                    # get all explicit provider                         
                    provider=oc.od.services.services.auth.findprovider( provider_name=prv.name )
                    if isinstance( provider,  oc.auth.authservice.ODAdAuthProvider ):
                        # run ldap query to list site subnet from the ActiveDirectory domain 
                        # look for 'CN=Subnets,CN=Sites,CN=Configuration' + base dn
                        site = provider.listsite()
                        # cache the site data into locatorPrivateActiveDirectory dict 
                        # if locatorPrivateActiveDirectory entry is the domain name
                        self.locatorPrivateActiveDirectory[ provider.domain ] = \
                            oc.od.locator.ODLocatorActiveDirectory( site=site, domain=provider.domain )

    def init_jwtdesktop(self):
        """Load rsa keys jwtdesktopprivatekeyfile jwtdesktoppublickeyfile payloaddesktoppublickeyfile
           to build the jwtdesktop  
        """
        import oc.auth.jwtdesktop
        self.jwtdesktop = oc.auth.jwtdesktop.ODDesktopJWToken( settings.jwt_config_desktop )

    def init_internaldns(self):
        if settings.internaldns.get('enable') is True:
            import oc.od.internaldns
            self.internaldns = oc.od.internaldns.ODInternalDNS( domain=settings.internaldns.get('domain'), server=settings.internaldns.get('server'), secret=settings.internaldns.get('secret') )

    def init_accounting(self):
        import oc.od.accounting
        self.accounting = oc.od.accounting.ODAccounting()

    def init_datastore(self):
        import oc.datastore
        self.datastore = oc.datastore.ODMongoDatastoreClient(settings.mongodburl, settings.mongodbparam)

    def init_datacache(self):
        import oc.sharecache
        self.sharecache = oc.sharecache.ODMemcachedSharecache(settings.memconnectionstring)

    def init_prelogin(self):
        import oc.auth.prelogin
        self.prelogin = oc.auth.prelogin.ODPrelogin( config=settings.prelogin, memcache_connection_string=settings.memconnectionstring )

    def init_logmein(self):
        import oc.auth.logmein
        self.logmein = oc.auth.logmein.ODLogmein( config=settings.logmein )

    def init_messageinfo(self):
        import oc.od.messageinfo
        self.messageinfo = oc.od.messageinfo.ODMessageInfoManager(settings.memconnectionstring)

    def init_auth(self):
        import oc.auth.authservice
        self.auth = oc.auth.authservice.ODAuthTool(settings.default_host_url, settings.jwt_config_user, settings.authmanagers) 

    def init_applist( self ):
        import oc.od.apps 
        # Build applist cache data
        self.apps = oc.od.apps.ODApps(mongodburl=settings.mongodburl, mongodbparam=settings.mongodbparam )
        self.apps.cached_applist(bRefresh=True)

    def init_kuberneteswatcher( self ):
        self.kuberneteswatcher = oc.od.kuberneteswatcher.ODKubernetesWatcher()

# use services to access 
services = ODServices()

def init_infra():
    """init_infra
        Check kubernetes config 
        find configuration for kubernetes
    """
    # Check kubernetes config 
    myOrchestrator = oc.od.orchestrator.ODOrchestratorKubernetes()
    if not myOrchestrator.is_configured():
        logger.fatal('Kubernetes config is not detected')
        exit(-1)

    # read the snap registry secret name values to use snap feature if available
    myOrchestrator.init_snapregistry()

    # reload default menu config because new features amy be available
    settings.init_menuconfig()


def init():
    # init all services 
    services.init()
    
    # init kubernetes 
    # init snapregistry
    init_infra()

    # list images application
    services.init_applist()

    # delete user pods thread
    services.init_kuberneteswatcher()