import logging
import oc.od.settings as settings
import oc.od.orchestrator
import oc.od.kuberneteswatcher
import oc.auth.authservice
import oc.od.apps

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
        self.webrtc = None
        self.kuberneteswatcher = None
        # self.imagewatcher = None
        self.apps = None
        self.prelogin = None
        self.logmein = None
        self.fail2ban = None

    def init(self):
        """[init services call all services init() methods]
        """
        self.init_messageinfo()
        self.init_accounting()

        if not self.init_datastore():
            logger.error( 'Connection refused to database or error')
            exit(-2)

        self.init_datacache()
        self.init_auth()
        self.init_internaldns()
        self.init_jwtdesktop()
        self.init_locator()
        self.init_keymanager()
        self.init_webrtc()
        self.init_prelogin()
        self.init_logmein()
        self.init_fail2ban()

    def start(self):
        """start
            start threads 
                * kuberneteswatcher
        """
        self.logger.debug('')
        if isinstance( self.kuberneteswatcher, oc.od.kuberneteswatcher.ODKubernetesWatcher):
            self.kuberneteswatcher.start()


    def stop( self):
        """stop
            stop threads 
                * kuberneteswatcher
        """
        self.logger.debug('')
        # stop thread imagewatcher if instance exists
        if isinstance( self.kuberneteswatcher, oc.od.kuberneteswatcher.ODKubernetesWatcher):
            try:
                self.logger.debug( 'kuberneteswatcher stop')
                self.kuberneteswatcher.stop()
                self.logger.debug( 'kuberneteswatcher stopped')
            except Exception as e:
                self.logger.error(e)
        else:
            self.logger.debug( 'self.kuberneteswatcher is not defined')

        '''
        # stop thread imagewatcher if instance exists
        if isinstance( self.apps, oc.od.apps.ODApps ):
            try:
                self.logger.debug( 'appswatcher stop')
                self.apps.stop()
                self.logger.debug( 'appswatcher stopped')
            except Exception as e:
                self.logger.error(e)
        else:
            self.logger.debug( 'self.apps is not defined')
        '''
        self.logger.debug('done')


    def init_fail2ban( self ):
        import oc.od.fail2ban
        self.fail2ban = oc.od.fail2ban.ODFail2ban( mongoconfig=settings.mongoconfig, fail2banconfig=settings.fail2banconfig )
        # self.fail2ban.test()

    def init_webrtc(self):
        """init parameters to the janus webrtc gateway
        """
        self.logger.info('')
        import oc.od.janus
        if settings.webrtc_enable :
            self.webrtc = oc.od.janus.ODJanusCluster( settings.webrtc_server )

    def init_keymanager(self):
        """[decode arg params query string in metappli mode ]
        """
        import oc.auth.keymanager
        # key manager use the same parameter as jwt_config_desktop
        self.keymanager = oc.auth.keymanager.ODDesktopKeyManager( settings.jwt_config_desktop )

    def init_locator(self):
        """geolocatization from ip address
        """
        self.logger.info('')
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
        self.logger.info('')
        import oc.auth.jwtdesktop
        self.jwtdesktop = oc.auth.jwtdesktop.ODDesktopJWToken( settings.jwt_config_desktop )


    def init_internaldns(self):
        self.logger.info('')
        if settings.internaldns.get('enable') is True:
            import oc.od.internaldns
            self.internaldns = oc.od.internaldns.ODInternalDNS( domain=settings.internaldns.get('domain'), server=settings.internaldns.get('server'), secret=settings.internaldns.get('secret') )

    def init_accounting(self):
        self.logger.info('')
        import oc.od.accounting
        self.accounting = oc.od.accounting.ODAccounting()

    def init_datastore(self):
        self.logger.info('')
        import oc.datastore
        self.datastore = oc.datastore.ODMongoDatastoreClient(settings.mongoconfig)
        
        '''
        replicaset_name = 'rs0'
        # check if replicaset is configured
        if not self.datastore.getstatus_replicaset(replicaset_name):
           self.logger.info(f"replicaset {replicaset_name} does not exist")
           # create a replicaset
            create_replicaset = self.datastore.create_replicaset(replicaset_name)
            # if create_replicaset is None or False
            # create_replicaset can return None but this is not a failure
            if not create_replicaset :
                # reread if replicaset is configured
                create_replicaset = self.datastore.getstatus_replicaset(replicaset_name)
            return create_replicaset
        self.logger.info(f"replicaset {replicaset_name} exist")
        '''
        return True

    def init_datacache(self):
        self.logger.info('')
        import oc.sharecache
        self.sharecache = oc.sharecache.ODMemcachedSharecache(settings.memconnectionstring)

    def init_prelogin(self):
        self.logger.info('')
        import oc.auth.prelogin
        self.prelogin = oc.auth.prelogin.ODPrelogin(    config=settings.prelogin,
                                                        memcache_connection_string=settings.memconnectionstring )

    def init_logmein(self):
        self.logger.info('')
        import oc.auth.logmein
        self.logmein = oc.auth.logmein.ODLogmein( config=settings.logmein )

    def init_messageinfo(self):
        self.logger.info('')
        import oc.od.messageinfo
        self.messageinfo = oc.od.messageinfo.ODMessageInfoManager(settings.memconnectionstring)

    def init_auth(self):
        self.logger.info('')
        import oc.auth.authservice
        self.auth = oc.auth.authservice.ODAuthTool(settings.default_host_url, settings.jwt_config_user, settings.authmanagers) 

    def init_applist( self ):
        self.logger.info('')
        import oc.od.apps 
        # Build applist cache data
        self.apps = oc.od.apps.ODApps(mongoconfig=settings.mongoconfig)
        self.apps.cached_applist(bRefresh=True)

    def init_kuberneteswatcher( self ):
        self.logger.info('')
        self.kuberneteswatcher = oc.od.kuberneteswatcher.ODKubernetesWatcher()

# use services to access 
services = ODServices()


def init_infra():
    """init_infra

       find configuration docker and kubernetes
    """
    logger.info('')

    # Check kubernetes config 
    myOrchestrator = oc.od.orchestrator.ODOrchestratorKubernetes()
    if not myOrchestrator.is_configured():
       logger.error('Config fkubernetes is not detected')
       exit(-1)

def init():
    # init all services 
    services.init()
    
    # init kubernetes infra
    # check if kubernetes is configured
    init_infra()

    # now list images application
    services.init_applist()

    # watch image pull rm event
    # watch network create destroy event
    services.init_kuberneteswatcher()
