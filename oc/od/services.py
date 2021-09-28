import logging
import oc.od.settings as settings
import oc.od.infra
import oc.od.orchestrator
import oc.od.dockerwatcher
import oc.od.imagewatcher


logger = logging.getLogger(__name__)

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
        self.imagewatcher = None
        self.apps = None

    def __del__(self):
        if hasattr(self, 'dockerwatcher') and \
            isinstance( self.dockerwatcher, oc.od.dockerwatcher.ODDockerWatcher) :
            self.dockerwatcher.stop()
        if hasattr(self, 'imagewatcher') and \
            isinstance( self.imagewatcher, oc.od.imagewatcher.ODImageWatcher):
            self.imagewatcher.stop()

    def init(self):
        """init services 
           call all services init() methods
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


    def init_webrtc(self):
        """init parameters to the janus webrtc gateway
        """
        logger.info('')
        import oc.od.janus
        if settings.webrtc_enable :
            self.webrtc = oc.od.janus.ODJanusCluster( settings.webrtc_server )

    def init_keymanager(self):
        """ decode arg params query string in metappli mode 
        """
        import oc.auth.keymanager
        # key manager use the same parameter as jwt_config_desktop
        self.keymanager = oc.auth.keymanager.ODDesktopKeyManager( settings.jwt_config_desktop )

    def init_locator(self):
        """geolocatization from ip address
        """
        logger.info('')
        import oc.od.locator
        self.locatorPublicInternet = oc.od.locator.ODLocatorPublicInternet()
        self.locatorPrivateActiveDirectory = {}
        self.update_locator()
        
    def update_locator(self):
        """update locator using site entry in ActiveDirecotry LDAP data
        """
        # filter manager to get explicit manager
        manager_explicit = oc.od.services.services.auth.getmanager( name='explicit' )
        # for each explicit manager
        for prv in manager_explicit.providers.values():
            # get a explicit provider                         
            provider=oc.od.services.services.auth.findprovider( name=prv.name )
            # if explicit provoder is an activedirectory  
            if provider.type == 'activedirectory' :
                # run ldap query to list site subnet from the ActiveDirectory domain 
                site = provider.listsite()
                # cache the site data into locatorPrivateActiveDirectory dict 
                # if locatorPrivateActiveDirectory entry is the domain name
                self.locatorPrivateActiveDirectory[ provider.domain ] = oc.od.locator.ODLocatorActiveDirectory( site=site, domain=provider.domain )

    def init_jwtdesktop(self):
        """Load rsa keys jwtdesktopprivatekeyfile jwtdesktoppublickeyfile payloaddesktoppublickeyfile
           to build the jwtdesktop  
        """
        logger.info('')
        import oc.auth.jwtdesktop
        self.jwtdesktop = oc.auth.jwtdesktop.ODDesktopJWToken( settings.jwt_config_desktop )


    def init_internaldns(self):
        logger.info('')
        if settings.internaldns.get('enable') is True:
            import oc.od.internaldns
            self.internaldns = oc.od.internaldns.ODInternalDNS( domain=settings.internaldns.get('domain'), server=settings.internaldns.get('server'), secret=settings.internaldns.get('secret') )

    def init_accounting(self):
        logger.info('')
        import oc.od.accounting
        self.accounting = oc.od.accounting.ODAccounting()

    def init_datastore(self):
        logger.info('')
        import oc.datastore
        self.datastore = oc.datastore.ODMongoDatastoreClient(settings.mongoconfig)

    def init_datacache(self):
        logger.info('')
        import oc.sharecache
        self.sharecache = oc.sharecache.ODMemcachedSharecache(settings.memconnectionstring)

    def init_messageinfo(self):
        logger.info('')
        import oc.od.messageinfo
        self.messageinfo = oc.od.messageinfo.ODMessageInfoManager(settings.memconnectionstring)

    def init_auth(self):
        logger.info('')
        import oc.auth.authservice
        self.auth = oc.auth.authservice.ODAuthTool(settings.default_host_url, settings.jwt_config_user, settings.authmanagers) 

    def init_resolvnetbios( self ):
        """resolvnetbios DEPRECATED
        """
        logger.info('')
        import oc.od.resolvnetbios
        self.resolvnetbios = oc.od.resolvnetbios.ODResolvNetbios()

    def init_applist( self ):
        logger.info('')
        import oc.od.apps 
        # Build applist cache data
        self.apps = oc.od.apps.ODApps()
        self.apps.cached_applist(bRefresh=True)

    def init_dockerwatcher( self ):
        logger.info('')
        import oc.od.dockerwatcher
        self.dockerwatcher = oc.od.dockerwatcher.ODDockerWatcher()
        self.dockerwatcher.start()

    def init_imagewatcher( self ):
        logger.info('')
        import oc.od.imagewatcher
        self.imagewatcher = oc.od.imagewatcher.ODImageWatcher()
        self.imagewatcher.start()


# use services to access 
services = ODServices()


def init_infra():
    """init_infra

       find configuration docker and kubernetex
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

    # run image watcher for images ain mongodb
    # watch image pull event
    services.init_imagewatcher()
