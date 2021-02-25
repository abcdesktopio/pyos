import os
import socket
import platform
import sys

import logging
import datetime

from cherrypy.lib.reprconf import Config
from urllib.parse import urlparse

import oc.datastore
import oc.pyutils as pyutils
import oc.logging

logger = logging.getLogger(__name__)

defaultConfigurationFilename = 'od.config'

config  = {}	# use for application config and global config	
gconfig = {}	# use for global config
supportedLocals = []

# Default namespace used by kubernetes 
namespace = 'abcdesktop' 

mongoconfig = None  # Mongodb config Object Class

authprovider = {}  # auth provider dict
authmanagers = {}  # auth manager dict 
controllers  = {}  # controllers dict 
menuconfig   = {}  # default menu config

# User balloon define
# Balloon is the default user used inside container
balloon_defaulthomedirectory = None
balloon_uid = 4096  # default user id
balloon_gid = 4096  # default group id
balloon_name = 'balloon'

defaultdomainname = None  # default local domain name to build fqdn

# use for X509 Certificat
clienttlskey = None     # Client TLS private Key file
clienttlscert = None    # Client TLS certificat file
tlscacert = None        # CA ROOT certificat file
tls_assert_hostname = False

memconnectionstring = None  # memcache connection syting format 'server:port'

jira = None             # Jira tracker configuration 

desktopsharednetworkstack = True
desktophomedirectorytype = None  #
desktopcontainer_autoremove = True
desktopusershareipcnamespace = ''
desktopuserusehostsharememory = False
desktopallowPrivilegeEscalation = False     # Permit sudo command inside a container
desktopusershareprocessnamespace = True     # Share process namespace from the container
desktopdockerprivileged = False             # Run docker container in privilege mode
defaultbackgroundcolors = []
desktopcapabilities     = {}
desktopenvironmentlocal = {}
desktopusedbussession   = None
desktopusedbussystem    = None
desktopimage            = None
desktopnodeselector     = None
desktopimagepullsecret  = None
desktoppolicies         = {}
desktopusepodasapp      = False

# printer container
desktopuseprintercontainer  = False 
desktopprinterimage         = None

# sound container params
desktopusesoundcontainer    = False
desktopsoundimage           = None

# init container params
desktopuseinitcontainer     = False
desktopinitcontainerimage   = None
desktopinitcontainercommand = None

# desktoppostponeapp url 
desktoppostponeapp          = None

desktopsecretsrootdirectory = '/var/secrets/'
kubernetes_default_domain = 'abcdesktop.svc.cluster.local'
desktopuseinternalfqdn = False
desktopusewinsresolver = False
desktopuselocaltime = True
desktopsecurityopt = []
desktopservicestcpport = { 'x11server': 6081, 'spawner': 29786, 'broadcast': 29784, 'pulseaudio': 4714 }

# fake network default interface ip address Only for reverse proxy
# if not set use the default_host_url hostname as defaul ip address
# this is not the binding ip for the server
default_server_ipaddr   = None  # THIS IS NOT THE BINDING IP ADDR 
default_host_url        = None  # default FQDN host name to reach the web site
default_host_url_is_securised = None  # is default_host_url securized https

defaultnetworknetuser   = None  # name of the default netuser network by default netuser
defaultnetworknetuserid = None  # id of the default netuser network

# String to route (container target_ip) or (public host url) default is
# public host 
websocketrouting = None

printercupsdriverLanguageDict = {}  # Dict to map Printer Language to cupsd driver
printercupsembeddedList = []        # List printer embedded inside the user container
user_execute_policy = False
network_control_policy = False

webdaventryname = None  # name of the entry of mount point
webdavurl = None  # url to mount webdav
webdavgroupfilter = False  # boolean use group filter
webdavgroup = []  # list of group startwith
dock = {}  # Web dock JSON config

internaldns = { 'subdomain': None, 'domain': None, 'secret': None }

jwt_config_user = None
jwt_config_desktop = None

# webrtc janus config
webrtc_server = None
webrtc_enable = False

def getuser_execute_policy():
    return user_execute_policy

def getnetwork_control_policy():
    return network_control_policy

def getballoon_name():
    return balloon_name

def getballoon_uid():
    """[summary]

    Returns:
        int: balloon user id
    """
    return balloon_uid

def getballoon_gid():
    """[summary]

    Returns:
        int: balloon group id
    """
    return balloon_gid

def getballoon_defaulthomedirectory():
    return balloon_defaulthomedirectory

def getdesktop_homedirectory_type():
    return desktophomedirectorytype

def getFQDN(hostname):
    ''' concat defaultdomainname to hostname set in configuration file  '''
    ''' return hostname if defaultdomainname is not set                 '''
    ''' or if hostname contains a dot                                   '''
    fqdn = hostname 
    if isinstance(hostname, str):        
        if '.' not in hostname and defaultdomainname is not None :
           fqdn = hostname + '.' + defaultdomainname
    return fqdn


def getbase_url(hostname):
    return 'tcp://' + getFQDN(hostname) + ':' + str(defaultdockertcpport)

def init_webrtc():
    """Read webrtc configuration file
    """
    global webrtc_server
    global webrtc_enable
    webrtc_enable = gconfig.get('webrtc.enable', False )
    webrtc_server = gconfig.get('webrtc.server', None )
   


def init_config_stack():
    """init_config_stack
       read stack mode 'kubernetes' or 'standalone' in configuration file
       read stack.network for docker
       read stack.kubernetesdefaultdomain for kubernetes
    """
    global stack_mode
    global defaultnetworknetuser
    global kubernetes_default_domain
    global namespace

    stack_mode = gconfig.get('stack.mode', None)
    if  stack_mode not in [ 'kubernetes', 'standalone' ] :
        logger.error("invalid stack.mode value")
        logger.error("stack.mode must be set to 'standalone' for docker only daemon")
        logger.error("or set to 'kubernetes' for kubernetes support.")
        exit(-1)

    defaultnetworknetuser = gconfig.get('stack.network', 'abcdesktop_netuser')    
    kubernetes_default_domain = gconfig.get('stack.kubernetesdefaultdomain', 'abcdesktop.svc.cluster.local')
    namespace = gconfig.get('namespace', 'abcdesktop')  

def init_jira():
    global jira 
    jira = gconfig.get('jira', {})

def init_defaulthostfqdn():
    """init_defaulthostfqdn
       read 'default_host_url' in configuration file
       read 'server.default.ipaddr' in configuration file
    """
    global default_host_url                 # default host url
    global default_host_url_is_securised    # default_host_url_is_securised
    global default_server_ipaddr            # default ip addr to fake real ip source in geoip

    # Use for reserve proxy
    default_host_url = gconfig.get('default_host_url')
    if default_host_url is None:
        logger.warning('Invalid default_host_url in config file')
        logger.warning('Use Host HTTP header to redirect url, this is a security Warning')
        logger.warning('Use this config only on private network, not on public Internet')
    else:
        logger.info('default_host_url: %s', default_host_url)

    default_host_url_is_securised = default_host_url.lower().startswith('https')

    default_server_ipaddr = gconfig.get('server.default.ipaddr')
    if default_server_ipaddr is None: 
       # try to get the ip add from the url hostname
       try:
            url = urlparse(default_host_url)
            hostname = url.hostname
            default_server_ipaddr = socket.gethostbyname(hostname)
       except Exception as e:
            logger.warning('default_server_ipaddr set to dummy value %s', str(e) )
            logger.warning('correct default_server_ipaddr to localhost' )
            default_server_ipaddr = '127.0.0.1' # dummy value localhost
    logger.info('default_server_ipaddr: %s', default_server_ipaddr)



def init_printercupsdict():
    global printercupsdriverLanguageDict
    global printercupsembeddedList
    printercupsdriverLanguageDict   = gconfig.get(  'printer.cupsdriverLanguageMap', 
                                                    {'default': 'drv:///sample.drv/generic.ppd'}
                                      )
    printercupsembeddedList         = gconfig.get(  'printer.cupsPrinterEmbeddedList', 
                                                    []
                                      )


def init_websocketrouting():
    """init_websocketrouting
       read 'websocketrouting' in configuration file
       check if websocketrouting value is correct and make sence
    """
    global websocketrouting
    websocketrouting = gconfig.get('websocketrouting', 'http_origin')

    # check permit value 
    if websocketrouting not in ['bridge', 'default_host_url', 'host','http_origin']:
        logger.error("invalid websocketrouting value")
        exit(-1)

    if websocketrouting == 'default_host_url':
        # this value must be set in configuration file
        if default_host_url is None:
            logger.error("webroutingmode is set to 'default_host_url', but 'default_host_url' is not set")
            logger.error("please set the default_host_url parameter in gconfig file")
            exit(-1)

        # try to parse 'default_host_url'
        # for futur usage, need to be shure that the hostname is correct
        try:
            # check if value make sence
            url = urlparse(default_host_url)
            route = url.hostname
            logger.debug('routing mode use hostname %s', route)
        except Exception as e:
            logger.error("webroutingmode is set to 'default_host_url', but 'default_host_url' is in valid format %s ", e)
            logger.error("please check the default_host_url parameter in config file")
            exit(-1)

    logger.info('mode is %s', websocketrouting)
  


def init_tls():
    global clienttlskey
    global clienttlscert
    global tlscacert
    global defaultdockertcpport
    global defaultdomainname

    # How to connect to docker daemon
    # TLS Section
    clienttlskey = gconfig.get('daemondockertlskey', None)
    clienttlscert = gconfig.get('daemondockertlscert', None)
    tlscacert = gconfig.get('daemondockertlscacert', None)

    # default docker daemon listen port tcp
    defaultdockertcpport = gconfig.get('daemondockertcpport', 2376)
    defaultdomainname = gconfig.get('daemondockerdomainname', None)

    if clienttlskey is None:
        logger.warning('SECURITY Warning clienttlskey is not set')
    
    if clienttlscert is None:
        logger.warning('SECURITY Warning clienttlscert is not set')
    
    if tlscacert is None:
        logger.warning('SECURITY Warning tlscacert is not set')

    if clienttlskey is None or clienttlscert is None or tlscacert is None:
        logger.warning('SECURITY Warning connection to docker daemon on host may failed or is insecure')
        logger.warning('Read HOWTO-configure documentation')


def init_desktop():
    global desktophomedirectorytype
    global desktopusex11unixsocket
    global desktopcontainer_autoremove
    global desktopusershareipcnamespace
    global desktopuserusehostsharememory
    global defaultbackgroundcolors
    global desktopsharednetworkstack
    global desktopusershareprocessnamespace
    global desktopimage
    global desktopprinterimage
    global desktopuseprintercontainer
    global desktopusesoundcontainer
    global desktopsoundimage
    global desktopuseinitcontainer
    global desktopinitcontainercommand
    global desktopinitcontainerimage
    global desktoppersistentvolumeclaim
    global desktopallowPrivilegeEscalation
    global desktopnodeselector
    global desktopcapabilities
    global desktopusedbussession
    global desktopusedbussystem
    global desktopenvironmentlocal
    global desktopimagepullsecret
    global desktopuseinternalfqdn
    global desktopdockerprivileged
    global desktopusewinsresolver
    global stack_mode
    global desktopsecurityopt
    global desktopuselocaltime
    global desktoppolicies
    global desktoppostponeapp
    global desktopusepodasapp

    # load docker images name
    desktopimagepullsecret = gconfig.get('desktop.imagePullSecret')
    desktopimage        = gconfig.get('desktop.image')
    desktopprinterimage = gconfig.get('desktop.printerimage')
    desktopsoundimage   = gconfig.get('desktop.soundimage')

    desktoppolicies     = gconfig.get('desktop.policies', {} )
    desktopinitcontainerimage = gconfig.get('desktop.initcontainerimage')
    desktopsharednetworkstack = gconfig.get('desktop.sharednetworkstack', True)
    desktopusex11unixsocket = gconfig.get('desktop.usex11unixsocket', True)
    desktopcontainer_autoremove = gconfig.get('desktop.container_autoremove', True)
    desktopusershareipcnamespace = gconfig.get('desktop.shareipcnamespace', 'shareable')
    desktopuserusehostsharememory = gconfig.get('desktop.userusehostsharememory', False)
    desktopuseprintercontainer = gconfig.get('desktop.useprintercontainer',False)
    desktopusesoundcontainer = gconfig.get('desktop.usesoundcontainer',False)
    desktopuseinitcontainer = gconfig.get('desktop.useinitcontainer',False)
    # desktopinitcontainercommand
    # is an array 
    # example ['sh', '-c',  'chown 4096:4096 /home/balloon' ]  
    desktopinitcontainercommand = gconfig.get('desktop.initcontainercommand')
    desktopusepodasapp = gconfig.get( 'desktop.usepodasapp', False )
    desktopcapabilities = gconfig.get( 'desktop.capabilities', {} )
    defaultbackgroundcolors = gconfig.get('desktop.defaultbackgroundcolors', ['#6EC6F0',  '#CD3C14', '#4BB4E6', '#50BE87', '#A885D8', '#FFB4E6'])
    desktopusershareprocessnamespace = gconfig.get('desktop.usershareprocessnamespace', True)
    desktophomedirectorytype        = gconfig.get('desktop.homedirectorytype', 'volume')
    desktoppersistentvolumeclaim    = gconfig.get('desktop.persistentvolumeclaim', 'abcdesktop-pvc' )
    desktopallowPrivilegeEscalation = gconfig.get('desktop.allowPrivilegeEscalation', False )
    desktopnodeselector     = gconfig.get('desktop.nodeselector', {} )    
    desktopusedbussession   = gconfig.get('desktop.usedbussession', False )
    desktopusedbussystem    = gconfig.get('desktop.usedbussystem', False )
    desktopdockerprivileged = gconfig.get('desktop.dockerprivileged', False) 
    desktopusewinsresolver  = gconfig.get('desktop.usewinsresolver', False )
    desktopuseinternalfqdn  = gconfig.get('desktop.useinternalfqdn', False ) 
    desktopsecurityopt      = gconfig.get('desktop.securityopt', [ 'no-new-privileges', 'seccomp=unconfined' ] )
    desktopuselocaltime     = gconfig.get('desktop.uselocaltime', False ) 
    desktoppostponeapp      = gconfig.get('desktoppostponeapp')
    
    # add default env local vars if not set 
    desktopenvironmentlocal = gconfig.get(  'desktop.envlocal', 
            {   'DISPLAY'               : ':0.0',
                'USER'		        : 'balloon',
                'LIBOVERLAY_SCROLLBAR'  : '0',
                'UBUNTU_MENUPROXY'      : '0',
                'HOME' 		        : '/home/balloon',
                'LOGNAME'	        : 'balloon',
                'PULSE_SERVER'          : '/tmp/.pulse.sock',
                'CUPS_SERVER'           : 'localhost:631'} )
    init_balloon()


def init_menuconfig():
    global menuconfig
    menuconfig = gconfig.get('front.menuconfig', { 'settings': True, 'appstore': True, 'screenshot':True, 'download': True, 'logout': True, 'disconnect': True } )

def init_balloon():
    global balloon_uid
    global balloon_gid
    global balloon_defaulthomedirectory
    global balloon_name

    balloon_name = gconfig.get('desktop.username', 'balloon')
    balloon_uid = gconfig.get('desktop.userid', 4096)
    balloon_gid = gconfig.get('destkop.groupid', 4096)
    balloon_defaulthomedirectory = gconfig.get('desktop.userhomedirectory', '/home/balloon')

def init_config_memcached():
    global stack_mode
    global memconnectionstring
    global kubernetes_default_domain
    # Build memcached memconnectionstring
    memcachedhostname = gconfig.get('memcacheserver')
    memcachedipaddr = None
 
    if memcachedhostname is None:
        memcachedhostname = 'memcached' # this is the default value in docker mode
        logger.info( 'stackmode is %s', stack_mode)
        if stack_mode == 'kubernetes':
            memcachedhostname += '.' + kubernetes_default_domain # this is the default value in docker mode
        logger.info( 'memcachedhostname is %s', memcachedhostname)
    try:
        memcachedipaddr = socket.gethostbyname(memcachedhostname)
        logger.info( 'host %s resolved as %s', memcachedhostname, memcachedipaddr)
    except socket.gaierror as err:
        logger.error('Cannot resolve hostname: %s', memcachedhostname)
        logger.error('Cannot start: %s', err)
        sys.exit(-1)

    memcachedport = gconfig.get('memcachedport', 11211)
    memconnectionstring = str(memcachedipaddr) + ":" + str(memcachedport)
    logger.info('Memcached connection string is set to: %s', memconnectionstring)

def get_mongoconfig():
    # try to use the mongodbserver in config file
    # if not set 
    #   try to read the MONGODB_URL env var
    #       if not set 
    #           use localhost
    global stack_mode
    global kubernetes_default_domain

    # read mongodb_url env var in upper case and lower case
    # 'mongodb://pyos:YWUwNDJhZTI3NjVjZDg4Zjhk@mongodb.abcdesktop.svc.cluster.local:30017'
    env_mongodb_url = os.getenv('MONGODB_URL')
    if env_mongodb_url is None:
        # try lower case
        env_mongodb_url = os.getenv('mongodb_url')

    logger.info('MONGODB_URL: %s' % str(env_mongodb_url) )
    if env_mongodb_url is None:
        mongodburl = gconfig.get('mongodburl')
    else:
        mongodburl = env_mongodb_url

    mongodbhost = None
    if mongodburl is None:
        mongodbhost = 'mongodb' # this is the default value in docker mode
        if stack_mode == 'kubernetes':
            mongodbhost += '.' + kubernetes_default_domain # this is the default value in docker mode
        mongodburl = 'mongodb://' + mongodbhost + ':27017'
        logger.info( 'mongodburl is %s', mongodburl)
    else:
        logger.info( 'mongodburl is set by env %s', mongodburl)
    # make sure gethostbyname works
    try:
        parsedmongourl = urlparse( mongodburl )
        mongodbhost = parsedmongourl.hostname
        mongodbhostipaddr = socket.gethostbyname( mongodbhost )
        logger.info( 'host %s resolved as %s', mongodbhost, mongodbhostipaddr)
    except socket.gaierror as err:
        logger.error('Cannot resolve hostname: %s', str(mongodbhost) )
        logger.error('Cannot start: %s', err)
        sys.exit(-1)

    logger.info('mongodburl is set to: %s', mongodburl)
    return oc.datastore.MongoClientConfig( mongodburl )


def init_controllers():
    """Define controlers access
    """
    global controllers
    # by default manager controller is protected by filtering source ip address as local net 
    # local net is defined as list_local_subnet
    list_local_subnet = [ '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fd00::/8', '169.254.0.0/16', '127.0.0.0/8' ]
    controllers = gconfig.get(  'controllers', { 'manager': { 'permitip': list_local_subnet } } )

def init_config_mongodb():
    """init mongodb config
    """
    global mongoconfig
    # Build mongo database
    mongoconfig = get_mongoconfig()
    logger.info('MongoDB connection string: %s' % mongoconfig)


def init_config_auth():
    global authprovider
    global authmanagers

    authprovider = gconfig.get('authprovider', {})    
    logger.debug(authprovider)

    authmanagers = gconfig.get('authmanagers', {})
    expcfg = pyutils.get_setting(authmanagers, 'explicit.providers')
    if expcfg:
        for name,cfg in expcfg.items(): 
            cfgref = cfg.get('config_ref')
            if cfgref is None: 
                continue
                
            conncfg = gconfig.get(cfgref, {}).get(name, None)

            if conncfg: 
                cfg.update({    **conncfg,
                                'basedn': conncfg.get('ldap_basedn'),
                                'timeout': conncfg.get('ldap_timeout', 15),
                                'secure': conncfg.get('ldap_protocol') == 'ldaps'
                })
                logger.debug(cfg)


def getAuthProvider(name):
    provider = authprovider.get(name, {})
    provider['provider'] = name
    logger.debug('%s => %s', name, provider)
    return provider

#
# init_config_check return True if
# system is Linux and
# kernel release and version are more than min_r, min_v
# return False if failed
def init_config_check(min_r, min_v):
    check = False
    system = platform.system()
    release = platform.release()
    if system == 'Linux':
        release = platform.release()
        if release is not None:
            ar_release = release.split('.')
            if (ar_release and len(ar_release) > 2):
                r = int(ar_release[0])
                v = int(ar_release[1])
                if (r > min_r) or (r == min_r and v > min_v):
                    check = True
    return check


def init_jwt_config():
    """read jwt_token_user and jwt_token_desktop pem key file
    """
    global jwt_config_user
    global jwt_config_desktop
    jwt_config_user     = gconfig.get('jwt_token_user',    { 'exp': 180, 'privatekeyfile': 'userprivatekey.pem',    'publickeyfile': 'userpublickey.pem'    })
    jwt_config_desktop  = gconfig.get('jwt_token_desktop', { 'exp': 180, 'privatekeyfile': 'desktopprivatekey.pem', 'publickeyfile': 'desktoppublickey.pem' })


def init_internaldns_config():
    global internaldns    
    internaldns['subdomain']   = gconfig.get('internaldns.subdomain',  'desktop')
    internaldns['domain']      = gconfig.get('internaldns.domain',     'abcdesktop.local')
    internaldns['secret']      = gconfig.get('internaldns.secret',     'abcdesktopinternaldnssecret')
    internaldns['server']      = gconfig.get('internaldns.server',      None)
    internaldns['enable']      = gconfig.get('internaldns.enable',      False)

def init_policy():
    global user_execute_policy
    global network_control_policy

    user_execute_policy = gconfig.get('user_execute_policy', False)  # by default user_execute_policy is disabled    
    network_control_policy = gconfig.get('network_control_policy', False) # by default network_control_policy is disabled

    logger.info('User Execute Policy is %s', user_execute_policy)
    logger.info('Network Control Policy is %s', network_control_policy)


def init_locales():
    global supportedLocales
    # get supported language
    # all containers application must support this list
    # by default support en_US language
    supportedLocales = gconfig.get('language', ['en_US'])
    logger.info('Supported local language is set to  %s', supportedLocales)

def init_config_logging():
    pass


def init_dock():
    global dock
    dock = gconfig.get('dock', {})

def get_applist_filemanager():
    return dock.get('filemanager', None)

def get_applist_terminal():
    return dock.get('terminal', None)

def get_applist_webshell():
    return dock.get('webshell', None)

def get_applist_lync():
    return dock.get('lync', None)

def get_applist_webshortcut():
    return dock.get('webshortcut', None)

def get_default_applist():
    localdefaultlist = [
        get_applist_filemanager(),
        get_applist_terminal(),
        get_applist_webshell(),
        get_applist_webshortcut() 
    ]
    return [a for a in localdefaultlist if a is not None]

def load():    
    global config
    global gconfig

    configpath = os.environ.get('OD_CONFIG_PATH', defaultConfigurationFilename)
    logger.info("Loading configuration file '%s'" % configpath)
    try:
        if os.path.getsize(configpath) < 64 : # configuration file must always be more than 64 bytes
            raise Exception('Invalid configuration file size')

        config = Config(configpath)
        gconfig = config.get('global', {}) # = cherrypy.gconfig 
    except Exception as e:
        logger.error('Failed to load %s: %s', configpath, e)
        exit(-1)           


def init():
    logger.info('Init configuration --- ')
    load() 

    # load default menu config
    init_menuconfig()

    # init_jwt_config
    init_jwt_config()

    # init_internaldns_config
    init_internaldns_config()

    # load dock web
    init_dock()

    # init TLS
    init_tls()

    # load default hostname for redirect and reverse proxy use
    init_defaulthostfqdn()

    # load auth provider
    init_config_auth()

    # init default overlay netork
    # desktop node list
    init_config_stack()

    # mongodb server 
    # after init_config_stack
    init_config_mongodb()

    # memcached support
    # after init_config_stack
    init_config_memcached()

    # desktop support
    init_desktop()

    # init gconfig how to route web socket
    init_websocketrouting()

    # init policy
    init_policy()

    # init printers dict
    init_printercupsdict()

    init_locales()

    # init janus cluster
    init_webrtc()

    # init jira bugtracker
    init_jira()

    # init_controllers
    init_controllers()

    logger.info('Init configuration done.')
