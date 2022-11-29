from errno import ESTALE
import logging
import oc.od.settings as settings
import oc.od.infra
import oc.od.orchestrator
import oc.od.dockerwatcher
import oc.od.kuberneteswatcher
import oc.od.imagewatcher

logger = logging.getLogger(__name__)
@oc.logging.with_logger()
class ODServices(object):

    def __init__(self):
        self.datastore = None
        self.sharecache = None
        self.messageinfo = None
        self.encryption = None
        self.auth = None
        self.accounting = None
        self.internaldns = None
        self.jwtdesktop = None
        self.keymanager = None
        self.locatorPublicInternet = None
        self.webrtc = None
        self.dockerwatcher = None
        self.kuberneteswatcher = None
        self.imagewatcher = None
        self.apps = None
        self.prelogin = None
        self.logmein = None
        self.fail2ban = None

    def init(self):
        """[init services call all services init() methods]
        """
        self.init_messageinfo()
        self.init_accounting()
        self.init_datastore()
        self.init_datacache() # to cache private key
        self.init_auth()
        self.init_internaldns()
        self.init_resolvnetbios()
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
                * dockerwatcher
                * kuberneteswatcher
        """
        self.logger.debug('')
        if isinstance( self.dockerwatcher, oc.od.dockerwatcher.ODDockerWatcher):
            self.dockerwatcher.start()
        if isinstance( self.kuberneteswatcher, oc.od.kuberneteswatcher.ODKubernetesWatcher):
            self.kuberneteswatcher.start()


    def stop( self):
        """stop
            stop threads 
                * dockerwatcher
                * kuberneteswatcher
        """
        self.logger.debug('')
        # stop thread dockerwatcher if instance exists
        if isinstance( self.dockerwatcher, oc.od.dockerwatcher.ODDockerWatcher) :
            try:
                self.logger.debug( 'dockerwatcher stop')
                self.dockerwatcher.stop()
                self.logger.debug( 'dockerwatcher stopped')
            except Exception as e:
                self.logger.error(e)
        else:
            self.logger.debug( 'self.dockerwatcher is not defined')

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


        # stop thread imagewatcher if instance exists
        if hasattr(self, 'imagewatcher') and isinstance( self.imagewatcher, oc.od.imagewatcher.ODImageWatcher):
            try:
                self.logger.debug( 'imagewatcher stop')
                self.imagewatcher.stop()
                self.logger.debug( 'imagewatcher stopped')
            except Exception as e:
                self.logger.error(e)
        else:
            self.logger.debug( 'self.imagewatcher is not defined')

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
        for managertype in [  'explicit' , 'metaexplicit' ]:
            manager_explicit = oc.od.services.services.auth.getmanager( managertype )
            if isinstance( manager_explicit, oc.auth.authservice.ODExplicitAuthManager ) or \
               isinstance( manager_explicit, oc.auth.authservice.ODExplicitMetaAuthManager):
                # for each explicit manager
                for prv in manager_explicit.providers.values():
                    # get all explicit provider                         
                    provider=oc.od.services.services.auth.findprovider( provider_name=prv.name )
                    if isinstance( provider, oc.auth.authservice.ODAdAuthProvider ):
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

    def init_resolvnetbios( self ):
        """resolvnetbios DEPRECATED
        """
        self.logger.info('')
        import oc.od.resolvnetbios
        self.resolvnetbios = oc.od.resolvnetbios.ODResolvNetbios()

    def init_applist( self ):
        self.logger.info('')
        import oc.od.apps 
        # Build applist cache data
        self.apps = oc.od.apps.ODApps()
        self.apps.cached_applist(bRefresh=True)

    def init_dockerwatcher( self ):
        self.logger.info('')
        self.dockerwatcher = oc.od.dockerwatcher.ODDockerWatcher()

    def init_kuberneteswatcher( self ):
        self.logger.info('')
        self.kuberneteswatcher = oc.od.kuberneteswatcher.ODKubernetesWatcher()

    def init_imagewatcher( self ):
        self.logger.info('')
        self.imagewatcher = oc.od.imagewatcher.ODImageWatcher()


# use services to access 
services = ODServices()


def init_infra():
    """init_infra

       find configuration docker and kubernetes
    """
    logger.info('')

    #
    # stack mode in configuration file can be 
    # - 'standalone'     
    # - 'kubernetes'
    detected_stack_mode = 'standalone'  # default value
    
    # get the stack mode from configuration file
    stack_mode = settings.stack_mode
    logger.info( 'Configuration file stack_mode is set to %s' , stack_mode)

    # Now detecting stack mode
    # standalone means a docker just installed        
    # standalone is always supported because only dockerd is need
    myOrchestrator = oc.od.orchestrator.ODOrchestrator()            
    if myOrchestrator.is_configured():
       detected_stack_mode = 'standalone'
    
    # Try to use stack_mode = 'kubernetes':
    # if kubernetes is configured, use kubernetes
    # note swarm is not supported anymore
    myOrchestrator = oc.od.orchestrator.ODOrchestratorKubernetes()
    if myOrchestrator.is_configured():
       detected_stack_mode = 'kubernetes'

    if stack_mode != detected_stack_mode:
        logger.warning('Configuration mismatch : stack mode is %s, detected stack mode is %s', stack_mode, detected_stack_mode)
        if stack_mode == 'standalone':
            # kubernetes is installed and configuration ask to use dockerd only
            # Allow it       
            pass
        elif stack_mode == 'kubernetes':             
            if detected_stack_mode == 'standalone' :
                # can not run a kubernetes config on docker only without kubernetes installed
                logger.error('Config file is set to kubernetes but no kubernetes detected')
                logger.error('docker info is detected as standalone')
                logger.error('this is a mistake report the error and exit')
                logger.error('invalid stack mode parameter : %s', stack_mode)
                exit(-1)
    logger.info('mode is using : %s', stack_mode) 
     
    settings.defaultnetworknetuserid = None

    if stack_mode == 'standalone':
      # get the netuser network id 
      infra = oc.od.infra.ODInfra()
      network = infra.getnetworkbyname(settings.defaultnetworknetuser)
      if network is None:        
        logger.error('%s is not found ', settings.defaultnetworknetuser)
        logger.error('Create network %s before starting od.py', settings.defaultnetworknetuser)
        exit(-1)
      else:
        settings.defaultnetworknetuserid = network.id
      logger.info('default overlay network: %s - id %s', settings.defaultnetworknetuser, settings.defaultnetworknetuserid)




def init():
    # init all services 
    services.init()
    
    # init docker or kubernetes infra
    init_infra()

    # now list images application
    services.init_applist()

    # run docker watcher for images and network object
    # watch image pull rm event
    # watch network create destroy event
    services.init_dockerwatcher()
    services.init_kuberneteswatcher()

    # run image watcher for images ain mongodb
    # watch image pull event
    services.init_imagewatcher()
