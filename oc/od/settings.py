import os
import socket
import platform
import sys

import logging
import chevron

from cherrypy.lib.reprconf import Config
from urllib.parse import urlparse

import oc.datastore
import oc.pyutils as pyutils
import oc.logging

import base64

logger = logging.getLogger(__name__)

# for dev use 
# ABCDESKTOP_PYOS_EXEC_MODE = 'dev'
ABCDESKTOP_PYOS_EXEC_MODE = 'dev'
# current pyos release
ABCDESKTOP_PYOS_CURRENT_RELEASE = '3.0'
# supported image format
ABCDESKTOP_IMAGE_FORMAT_RELEASE = '3.0'

defaultConfigurationFilename = 'od.config'

config  = {}	    # use for application config and global config
gconfig = {}	    # use for global config
supportedLocals = []

# Default namespace used by kubernetes is abcdesktop
namespace = 'abcdesktop' 

mongoconfig = None  # Mongodb config Object Class
fail2banconfig = None # Fail2ban config 

authprovider = {}  # auth provider dict
authmanagers = {}  # auth manager dict 
controllers  = {}  # controllers dict 
menuconfig   = {}  # default menu config
geolocation  = None  # default geolocation 
fakedns      = {}

# User balloon define
# Balloon is the default user used inside container
balloon_homedirectory = '/home/balloon'
balloon_uidNumber = 4096  # default user id
balloon_gidNumber = 4096  # default group id
balloon_groupname = 'balloon'
balloon_loginname = 'balloon'
balloon_shell = '/bin/bash'
balloon_passwd = 'lmdpocpetit'

# developer specific params
developer_instance = False


DEFAULT_SHM_SIZE = '64M' # default size of shared memeory

defaultdomainname = None  # default local domain name to build fqdn
memconnectionstring = None  # memcache connection syting format 'server:port'
services_http_request_denied = {} # deny http request 

jira = None             # Jira tracker configuration 

routehostcookiename = 'abcdesktop_host' # cookie with the hostname value for an efficient LoadBalacing
tipsinfoconfig = {}
desktopdescription = {} # define a network interface name mapping 
# like { 'internalip': 'eth1', 'externalip': 'net2'}

ENV_PREFIX_LABEL_NAME = "ABCDESKTOP_LABEL_"
ENV_PREFIX_SERVICE_NAME = "ABCDESKTOP_SERVICE_"

DEFAULT_PASSWD_FILE = ''
DEFAULT_SHADOW_FILE = ''
DEFAULT_GROUP_FILE  = ''
DEFAULT_GSHADOW_FILE = ''

# prelogin
prelogin = {}

# logmein
logmein = {}

# desktop
desktop_pod                = {}
desktop                    = { 'secretsrootdirectory': '/var/secrets/' }

kubernetes_default_domain = 'abcdesktop.svc.cluster.local'

# fake network default interface ip address Only for reverse proxy
# if not set use the default_host_url hostname as defaul ip address
# this is not the binding ip for the server
default_server_ipaddr   = None  # THIS IS NOT THE BINDING IP ADDR 
default_host_url        = None  # default FQDN host name to reach the web site
default_host_url_is_securised = False  # is default_host_url securized https
default_host_accesscontrol_allow_origin = None # host_accesscontrol_allow_origin

desktopwebhookencodeparams = False  # url encode webhook params 
desktopwebhookdict         = {}     # addtional dict data

# String to route (container target_ip) or (public host url) default is
# public host 
websocketrouting = None

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

applicationhostconfig = {}

list_hostconfigkey = [ 
        'auto_remove',
        'cap_add', 
        'cap_drop',
        'cpu_count',
        'cpu_percent',
        'cpu_rt_period',
        'cpu_rt_runtime',
        'cpu_quota',
        'cpu_shares',
        'cpuset_cpus',
        'cpuset_mems',
        'device_cgroup_rules',
        'device_read_bps',
        'device_read_iops',
        'device_write_bps',
        'device_write_iops',
        'devices',
        'device_requests',
        'ipc_mode',
        'mem_limit',
        'mem_reservation',
        'mem_swappiness',
        'memswap_limit',
        'network_mode',
        'nano_cpus',
        'oom_kill_disable',
        'oom_score_adj',
        'pid_mode',
        'pids_limit',
        'privileged',
        'read_only',
        'restart_policy',
        'runtime',
        'security_opt',
        'shm_size', 
        'storage_opt',
        'sysctls',
        'tmpfs',
        'ulimits',
        'uts_mode',
        'secrets_requirement'   # custom for abcdesktop 
        ]

def getballoon_loginname():
    return balloon_loginname

def getballoon_groupname():
    return balloon_groupname

def getballoon_loginShell():
    return balloon_shell

def getballoon_uidNumber():
    """[summary]

    Returns:
        int: balloon user id
    """
    return balloon_uidNumber

def getballoon_gidNumber():
    """[summary]

    Returns:
        int: balloon group id
    """
    return balloon_gidNumber

def getballoon_homedirectory():
    return balloon_homedirectory

def getFQDN(hostname):
    ''' concat defaultdomainname to hostname set in configuration file  '''
    ''' return hostname if defaultdomainname is not set                 '''
    ''' or if hostname contains a dot                                   '''
    fqdn = hostname 
    if isinstance(hostname, str):        
        if '.' not in hostname and defaultdomainname is not None :
           fqdn = hostname + '.' + defaultdomainname
    return fqdn


def init_localaccount():
    global DEFAULT_PASSWD_FILE
    global DEFAULT_GROUP_FILE
    global DEFAULT_SHADOW_FILE
    global DEFAULT_GSHADOW_FILE
    DEFAULT_PASSWD_FILE = loadfile('passwd')
    DEFAULT_GROUP_FILE  = loadfile('group' )
    DEFAULT_SHADOW_FILE = loadfile('shadow')
    DEFAULT_GSHADOW_FILE = loadfile('gshadow')


def init_webrtc():
    """Read webrtc configuration file
    """
    global webrtc_server
    global webrtc_enable
    webrtc_enable = gconfig.get('webrtc.enable', False )
    webrtc_server = gconfig.get('webrtc.server', None )
   
def init_tipsinfo():
    global tipsinfoconfig
    tipsinfoconfig = gconfig.get('tipsinfo', {})

def init_config_stack():
    """init_config_stack
       read namespace should be abcdesktop
       read stack.kubernetesdefaultdomain for kubernetes
    """
    global kubernetes_default_domain
    global namespace
    global desktopdescription
 
    kubernetes_default_domain = gconfig.get('stack.kubernetesdefaultdomain', 'abcdesktop.svc.cluster.local')
    namespace = gconfig.get('namespace', 'abcdesktop')  
    desktopdescription = gconfig.get( 'desktop.description',  { 'internalipaddr': None, 'externalipaddr': None} )   

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
    global routehostcookiename              # name of the cookie with the hostname value for an efficient LoadBalacing
    global services_http_request_denied     # denied http request uri


    # Use for reserve proxy
    default_host_url = gconfig.get('default_host_url')
    if not isinstance( default_host_url, str):
        logger.warning('Invalid default_host_url in config file')
        logger.warning('Use Host HTTP header to redirect url, this is a security Warning')
        
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

    routehostcookiename = gconfig.get('routehostcookiename','abcdesktop_host')
    logger.info('route host cookie name: %s', routehostcookiename)

    # if not set autologin is denied 
    services_http_request_denied = gconfig.get('services_http_request_denied', { 'autologin': True} )
    logger.info('services http request denied: %s', services_http_request_denied)

def init_logmein():
    global logmein
    logmein = gconfig.get(  'auth.logmein', { 'enable': False } )
    if logmein.get('enable') is True:
        logger.info('logmein config %s', str(logmein))

def init_prelogin():
    global prelogin
    prelogin = gconfig.get(  'auth.prelogin', { 'enable': False } )
    if prelogin.get('enable') is True:
        logger.info('prelogin config %s', str(prelogin))

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
  
def init_fakedns():
    global fakedns
    fakedns = gconfig.get('fakedns', { 'interfacename': 'eth0' } )

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


def filter_hostconfig( host_config ):
    """[filter_hostconfig]
        safe function
        return a filtered host_config dict with only entry from the list_hostconfigkey list
    Args:
        host_config ([dict]): [filtered host_config]
    """

    myhostconfig = {}
    for keyconfig in host_config.keys():
        if keyconfig in list_hostconfigkey:
            myhostconfig[keyconfig] =  host_config[keyconfig]
    return myhostconfig

def init_desktop():
    global applicationhostconfig
    global desktop
    global desktop_pod
 
    # read authmanagers configuration 
    # if an explicitproviderapproval is set, then set  desktopauthproviderneverchange to False
    # desktop authprovider can change on the fly 
    desktop['authproviderneverchange'] = gconfig.get('desktop.authproviderneverchange', False )

    authmanagers = gconfig.get('authmanagers', {} )
    for manager in authmanagers.values():
        providers = manager.get('providers',{})
        for provider in providers.values():
            if provider.get('explicitproviderapproval'): # one provider set explicitproviderapproval
                desktop['authproviderneverchange'] = False # this allow a user to change auth provider on the fly
                break


    applicationhostconfig = gconfig.get(    
        'desktop.application_config',
        {   'auto_remove'   : True,
            'network_mode'  : 'container'
        }
    )

    '''
    {   'auto_remove'   : True,
        'pid_mode'      : True,
        'ipc_mode'      : 'shareable',
        'network_mode'  : 'container'
    }
    '''

    # check if applicationhostconfig contains permit value
    applicationhostconfig = filter_hostconfig( applicationhostconfig )

    desktop_pod = gconfig.get( 'desktop.pod' )
    if not isinstance( desktop_pod, dict ):
        logger.error(f"desktop.pod is not defined or is not a dict, read type is {type(desktop.pod)}")
        logger.error('this is a fatal error in configuration file')
        sys.exit(-1)

    desktop['removehomedirectory']      = gconfig.get('desktop.removehomedirectory', False)
    desktop['policies']                 = gconfig.get('desktop.policies', {} )
    desktop['webhookencodeparams']      = gconfig.get('desktop.webhookencodeparams', False )
    desktop['webhookdict']              = gconfig.get('desktop.webhookdict', {} )
    desktop['defaultbackgroundcolors']  = gconfig.get('desktop.defaultbackgroundcolors', 
        ['#6EC6F0',  '#CD3C14', '#4BB4E6', '#50BE87', '#A885D8', '#FFB4E6'])
    desktop['homedirectorytype']        = gconfig.get('desktop.homedirectorytype', 'hostPath')
    desktop['hostPathRoot']             = gconfig.get('desktop.hostPathRoot', '/mnt')
    desktop['persistentvolumeclaim']    = gconfig.get('desktop.persistentvolumeclaim' )
    desktop['nodeselector']             = gconfig.get('desktop.nodeselector')    
    desktop['usedbussession']           = gconfig.get('desktop.usedbussession', False )
    desktop['usedbussystem']            = gconfig.get('desktop.usedbussystem', False )
    desktop['useinternalfqdn']          = gconfig.get('desktop.useinternalfqdn', False ) 
    desktop['uselocaltime']             = gconfig.get('desktop.uselocaltime', False ) 
    desktop['dnspolicy']                = gconfig.get('desktop.dnspolicy', 'ClusterFirst')
    desktop['dnsconfig']                = gconfig.get('desktop.dnsconfig')

    # add default env local vars if not set 
    desktop['environmentlocal'] = gconfig.get(  
        'desktop.envlocal', 
        {   'DISPLAY'               : ':0.0',
            'LIBOVERLAY_SCROLLBAR'  : '0',
            'UBUNTU_MENUPROXY'      : '0',
            'X11LISTEN'             : 'tcp' } 
    )

    init_balloon()

   


def init_menuconfig():
    global menuconfig
    menuconfig = gconfig.get('front.menuconfig', {  'settings': True, 
                                                    'appstore': True, 
                                                    'screenshot':True, 
                                                    'logout':   True, 
                                                    'disconnect': True } )

def init_geolocation():
    global geolocation
    # geolocation config
    # options = { enableHighAccuracy: true, timeout: 5000, maximumAge: 0 };
    geolocation = gconfig.get('geolocation')

def init_balloon():
    global balloon_uidNumber
    global balloon_gidNumber
    global balloon_shell
    global balloon_loginname
    global balloon_groupname
    global balloon_passwd
    global balloon_homedirectory

    balloon_loginname = gconfig.get('desktop.username',  'balloon')
    balloon_groupname = gconfig.get('desktop.groupname', 'balloon')
    balloon_uidNumber = gconfig.get('desktop.userid', 4096)
    balloon_gidNumber = gconfig.get('desktop.groupid', 4096)
    balloon_shell     = gconfig.get('destkop.shell', '/bin/bash')
    balloon_passwd    = gconfig.get('desktop.userpasswd', 'lmdpocpetit')
    balloon_homedirectory = gconfig.get('desktop.userhomedirectory', '/home/balloon')


def init_config_memcached():
    global memconnectionstring
    global kubernetes_default_domain
    # Build memcached memconnectionstring
    memcachedhostname = gconfig.get('memcacheserver')
    memcachedipaddr = None
 
    if memcachedhostname is None:
        memcachedhostname = 'memcached' # this is the default value in docker mode
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
    controllers = gconfig.get(  'controllers', \
                                { 'ManagerController': { 'permitip':    [ '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fd00::/8', '169.254.0.0/16', '127.0.0.0/8' ] },
                                  'StoreController':   { 'wrapped_key': {} } 
                                } )

    #
    # safe check controllers config  
    # StoreController config must be a dict
    if not isinstance( controllers.get('StoreController'), dict ):   
         controllers['StoreController'] = { 'wrapped_key': {} }
    #  ['StoreController']['wrapped_key'] config must be a dict
    if not isinstance( controllers['StoreController'].get('wrapped_key'), dict ):
        controllers['StoreController']['wrapped_key'] = {}
    # ManagerController config must be a dict
    if not isinstance( controllers.get('ManagerController'), dict ):   
         controllers['ManagerController'] = { 'permitip':    [ '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fd00::/8', '169.254.0.0/16', '127.0.0.0/8' ] }
    # end of 

    if desktop['environmentlocal'].get('SET_DEFAULT_COLOR'):
        # wrapper for StoreController key value
        # config use default 'color'  
        controllers['StoreController']['wrapped_key'].update( { 'color': desktop['environmentlocal'].get('SET_DEFAULT_COLOR') } )

    if desktop['environmentlocal'].get('SET_DEFAULT_WALLPAPER') :
        # wrapper for StoreController key value
        # config use default wallpaper 'img' 
        controllers['StoreController']['wrapped_key'].update( { 'backgroundType': 'img' } )


def read_kubernetes_resource_limits( hostconfig ):
    """ [read_resource_limits]
        convert docker cpu_period and cpu_quota as a kubernetes cpu limit ressource
        convert docker mem as a kubernetes cpu limit ressource
    Returns:
        [dict]: [kubernetes resources limit dict]
    """
    limits = {} 
    # you set --cpus="1.5", the container is guaranteed at most one and a half of the CPUs. 
    # This is the equivalent of setting --cpu-period="100000" and --cpu-quota="150000".
    cpu_period = hostconfig.get('cpu_period')
    cpu_quota  = hostconfig.get('cpu_quota')
    if isinstance( cpu_period, int ) and isinstance( cpu_quota,  int ) :
        cpu_period = cpu_period / 100000
        cpu_quota  = cpu_quota  / 100000
        cpu        = float( "{:.1f}".format(cpu_period * cpu_quota) )
        limits.update( { 'cpu': cpu } )
    
    mem_limit = hostconfig.get('mem_limit')
    if isinstance(mem_limit, str ) :
        limits.update( { 'memory': str(mem_limit) } )
    return { 'limits': limits }

def init_config_mongodb():
    """init mongodb config
    """
    global mongoconfig
    # Build mongo database
    mongoconfig = get_mongoconfig()
    logger.info('MongoDB connection string: %s' % mongoconfig)


def init_config_fail2ban():
    global fail2banconfig
    fail2banconfig = gconfig.get('fail2ban', { 'enable' : False } )
    logger.info(f"Fail2ban config: {fail2banconfig}" )



def init_config_auth():
    global authprovider
    global authmanagers

    def parse_provider_configref( authmanagers, provider_type ):
        expcfg = pyutils.get_setting(authmanagers, provider_type )
        if expcfg:
            for name,cfg in expcfg.items(): 
                # if there is a config_ref
                configref_name = cfg.get('config_ref')
                if isinstance( configref_name, str ) :
                    logger.debug( f"config {name} as use configref_name={configref_name}" )
                    config_ref = gconfig.get(configref_name)
                    if not isinstance(config_ref, dict):
                        logger.error( f"config {name} can not read configref_name={configref_name}, skipping" )
                        continue
                        
                    firstkey = next(iter(config_ref)) # Using next() + iter(), getting first key in dictionary
                    logger.debug( f"reading config_ref key {firstkey}" )
                    conncfg = config_ref.get( firstkey )
                    if isinstance(conncfg, dict):
                        logger.debug( f"apply update config to {name}" )
                        cfg.update( conncfg )
                    else:
                        logger.error( f"{configref_name} is not a dict, invalid format type={type(conncfg)}" )

    # load authmanagers from config file
    authmanagers = gconfig.get('authmanagers', {})

    # load configref for all providers
    parse_provider_configref( authmanagers, 'implicit.providers')
    parse_provider_configref( authmanagers, 'explicit.providers')
    parse_provider_configref( authmanagers, 'metaexplicit.providers')


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


def init_locales():
    global supportedLocales
    # get supported language
    # all containers application must support this list
    # by default support en_US language
    supportedLocales = gconfig.get('language', ['en_US'])
    logger.info('Supported local language is set to  %s', supportedLocales)

def init_config_logging():
    pass

def loadfile(filename:str)->str:
    """loadfile

    Args:
        filename (str): name of file

    Returns:
        str: file content
    """
    filepath = os.path.normpath( filename )
    f = open(filepath, 'r')
    data = f.read()
    f.close()
    return data

def make_b64data_from_iconfile(filename):
    """make_b64data_from_iconfile
        load file data and encode in b64
    Args:
        filename (str): filename to encode

    Returns:
        str: encoded content file
    """
    strencode = None
    img_path = 'img/app/'
    filepath = os.path.normpath( img_path + filename )
    try:
        f = open(filepath, 'r')
        file_data = f.read()
        f.close()
        strencode = base64.b64encode( file_data.encode('utf8') ).decode('utf-8') 
    except Exception as e:
        logger.error( e )
    return strencode

      

def init_dock():
    global dock
    dock = gconfig.get('dock', {})
    for key in dock.keys():
        filename = dock[key].get( 'icon' )
        dock[key]['icondata'] = make_b64data_from_iconfile( filename )
        # logger.info("default user dock %s ", str( dock ))


def get_default_appdict():
    return dock

def load_config():    
    global config
    global gconfig

    configpath = os.environ.get('OD_CONFIG_PATH', defaultConfigurationFilename)
    logger.info(f"Loading configuration file {configpath}")
    try:
        config = Config(configpath)
        gconfig = config.get('global', {}) # = cherrypy.gconfig 
    except Exception as e:
        logger.error(f"Failed to load configuration file {configpath} {e}")
        exit(-1)           


def init():
    logger.info('Init configuration start')

    # load config file od.config
    # use global config and gconfig
    load_config() 

    # load passwd, group, shadow file
    init_localaccount()

    # developer specific config
    # only to use for local pyos instance, 
    # if developer_instance is set to True then pyos is not supposed to run inside kubernetes pod 
    global developer_instance
    developer_instance =  gconfig.get('developer_instance', False )

    # load default menu config
    init_menuconfig()

    # init tipsinfo config
    init_tipsinfo()

    # load geolocation config
    init_geolocation()

    # load fakedns config
    init_fakedns()

    # init_jwt_config
    init_jwt_config()

    # init_internaldns_config
    init_internaldns_config()

    # load dock web
    init_dock()

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

    # fail2ban config
    init_config_fail2ban()

    # memcached support
    # after init_config_stack
    init_config_memcached()

    # desktop support
    # init_desktop can change desktop.environmentlocal
    # must be call before init_controllers
    init_desktop()

    # init gconfig how to route web socket
    init_websocketrouting()

    # init locales vars
    init_locales()

    # init janus cluster
    init_webrtc()

    # init jira bugtracker
    init_jira()

    # init prelogin
    init_prelogin()

    # init_logmein
    init_logmein()

    # init_controllers
    # use desktop
    # for SET_DEFAULT_WALLPAPER option
    # for SET_DEFAULT_COLOR option
    init_controllers()

    logger.info('Init configuration done.')
