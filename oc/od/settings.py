import os
import socket
import sys
import logging

from cherrypy.lib.reprconf import Config
from urllib.parse import urlparse
import oc.pyutils as pyutils
import base64

logger = logging.getLogger(__name__)


config  = {}	    # use for application config and global config
gconfig = {}	    # use for global config

# Default namespace used by kubernetes is abcdesktop
namespace = 'abcdesktop' 

mongodburl = None  # Mongodb config url
mongodbparam = None  # Mongodb config parameters
fail2banconfig = None # Fail2ban config 
mongodblist = []

authmanagers = {}  # auth manager dict 
controllers  = {}  # controllers dict 
menuconfig   = {}  # default menu config
imagenotificationconfig = {}  # default notification config
geolocation  = None  # default geolocation 
fakedns      = {}
executeclasses = {}


# User balloon define
# Balloon is the default user used inside container
homerootdirectory = '/root'
balloon_homedirectory = '/home/balloon'
balloon_uidNumber = 4096            # default user id
balloon_gidNumber = 4096            # default group id
balloon_groupname = 'balloon'       # default group name
balloon_loginname = 'balloon'       # default login name
balloon_shell     = '/bin/bash'     # default shell
balloon_password  = 'lmdpocpetit'   # default password

# default registry for snapshoted images dictionary or None 
snapshot_mountpath = None # default mount path for containerd on ubuntu 
snapshot_mounttype = None # should be 'Socket'
snapshot_registry = None  # keep it as None use by init_snapregistry() 
snapshot_registry_protocol = None # default protocol for snapshot registry, like 'https' or 'http'
# read by orchestrator then init_snapregistry is done if snapshot registry secret name is defined
# oc.od.settings.snapshot_registry = {
#                'registry': registry_name,
#                'username': username,
#                'password': password,
#                'auth': auth,
#                'email': email

cgroup_version = None # cgroup version used by the system, can be 'cgroup v1' or 'cgroup v2'
memconnectionstring = None  # memcache connection syting format 'server:port'
services_http_request_denied = {} # deny http request 
tipsinfoconfig = {}
welcomeinfoconfig = {}
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
desktop                    = {}

kubernetes_default_domain = 'abcdesktop.svc.cluster.local'

# fake network default interface ip address Only for reverse proxy
# if not set use the default_host_url hostname as defaul ip address
# this is not the binding ip for the server
default_geolocation_ipaddr  = None  # THIS IS NOT THE BINDING IP ADDR 
default_host_url        = None  # default FQDN host name to reach the web site
default_host_url_is_securised = False  # is default_host_url securized https

# String to route (container target_ip) or (public host url) default is
# public host 
websocketrouting = None
dock = {}  # Web dock JSON config
internaldns = { 'subdomain': None, 'domain': None, 'secret': None }

jwt_config_user = None
jwt_config_desktop = None


def getballoon_loginname()->str:     
    return balloon_loginname
def getballoon_groupname()->str:     
    return balloon_groupname
def getballoon_loginShell()->str:    
    return balloon_shell
def getballoon_homedirectory( uid:str=None )->str:
    """getballoon_homedirectory

    Args:
        uid (str, optional): user id  Defaults to None.

    Returns:
        str: user HOMEDIR str like /home/myuser
    """
    homedirectory = None
    if uid is None:
        homedirectory = balloon_homedirectory
    else:
        homedirectory = os.path.join( homerootdirectory, str(uid) )
    return homedirectory
def getballoon_uidNumber()->int:
    """getballoon_uidNumber

    Returns:
        int: balloon user id
    """
    return balloon_uidNumber

def getballoon_gidNumber()->int:
    """getballoon_gidNumber

    Returns:
        int: balloon group id
    """
    return balloon_gidNumber


def getballoon_password()->str:
    """[getballoon_password]

    Returns:
        str: getballoon_password
    """
    return balloon_password

def init_localaccount():
    global DEFAULT_PASSWD_FILE
    global DEFAULT_GROUP_FILE
    global DEFAULT_SHADOW_FILE
    global DEFAULT_GSHADOW_FILE

    passwd_filename = gconfig.get('template_passwd_filename', 'passwd' )
    group_filename = gconfig.get('template_group_filename', 'group' )
    shadow_filename = gconfig.get('template_shadow_filename', 'shadow' )
    gshadow_filename = gconfig.get('template_gshadow_filename', 'gshadow' )
    DEFAULT_PASSWD_FILE  = loadfile(passwd_filename)
    DEFAULT_GROUP_FILE   = loadfile(group_filename)
    DEFAULT_SHADOW_FILE  = loadfile(shadow_filename)
    DEFAULT_GSHADOW_FILE = loadfile(gshadow_filename)

   
def init_tipsinfo():
    global tipsinfoconfig
    tipsinfoconfig = gconfig.get('tipsinfo', {})

def init_welcomeinfo():
    global welcomeinfoconfig
    welcomeinfoconfig = gconfig.get('welcomeinfo', {})


def init_config_stack():
    """init_config_stack
       read namespace should be abcdesktop
       read stack.kubernetesdefaultdomain for kubernetes
    """
    global kubernetes_default_domain
    global namespace
    global desktopdescription
 
    #
    # read the namespace in config file first, 
    #   else use os.environ.get('POD_NAMESPACE')
    #   else use the default value 'abcdesktop'
    logger.debug( f"reading the current namespace defined" )
    namespace = os.getenv('POD_NAMESPACE') or gconfig.get('namespace', namespace )
    logger.debug( f"use namespace={namespace}" )
    logger.debug( f"reading kubernetesdefaultsvcclusterlocal option in config file" )
    kubernetesdefaultsvcclusterlocal = gconfig.get('kubernetesdefaultsvcclusterlocal', 'svc.cluster.local')
    logger.debug( f"kubernetes default domain svc.cluster.local={kubernetesdefaultsvcclusterlocal}" )
    # kubernetes_default_domain should be by default abcdesktop.svc.cluster.local
    kubernetes_default_domain = gconfig.get('kubernetesdefaultabcdesktopsvcclusterlocal', f"{namespace}.{kubernetesdefaultsvcclusterlocal}" )
    logger.debug( f"abcdesktop domain={kubernetes_default_domain}" )
    # desktopdescription is used to display network page
    # by default desktopdescription is a dict of None values
    desktopdescription = gconfig.get( 'desktop.description',  { 'internalipaddr': None, 'externalipaddr': None} )   

def init_defaulthostfqdn():
    """init_defaulthostfqdn
       read 'default_host_url' in configuration file
       read 'server.default.ipaddr' in configuration file
    """
    global default_host_url                 # default host url
    global default_host_url_is_securised    # default_host_url_is_securised
    global default_geolocation_ipaddr            # default ip addr to fake real ip source in geoip
    global services_http_request_denied     # denied http request uri


    # OAUTHLIB params
    if gconfig.get('OAUTHLIB_INSECURE_TRANSPORT') is True:
        # This allows us to use oauthlib plain HTTP callback
        os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

    if gconfig.get('OAUTHLIB_RELAX_TOKEN_SCOPE') is True:
        os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1' 


    # Use for reserve proxy
    default_host_url = gconfig.get('default_host_url')
    if not isinstance( default_host_url, str):
        logger.warning('Invalid default_host_url in config file')
        logger.warning('Use Host HTTP header to redirect url, this is a security Warning')
        
    else:
        logger.debug( f"default_host_url: {default_host_url}")
        default_host_url_is_securised = default_host_url.lower().startswith('https')


    default_geolocation_ipaddr = gconfig.get('server.geolocation_ipaddr')
    if not isinstance(default_geolocation_ipaddr, str): 
       # try to get the ip add from the url hostname
       try:
            url = urlparse(default_host_url)
            hostname = url.hostname
            default_geolocation_ipaddr = socket.gethostbyname(hostname)
       except Exception as e:
            logger.warning(f"default_geolocation_ipaddr set to dummy value error {e}" )
            logger.warning('fixing default_geolocation_ipaddr to 127.0.0.1' )
            default_geolocation_ipaddr = '127.0.0.1' # dummy value localhost
    logger.debug(f"default_geolocation_ipaddr: {default_geolocation_ipaddr}")


    # if not set autologin is denied 
    services_http_request_denied = gconfig.get('services_http_request_denied', { 'autologin': True } )
    logger.debug( f"services http request denied: {services_http_request_denied}")

def init_logmein():
    global logmein
    logmein = gconfig.get(  'auth.logmein', { 'enable': False } )
    if logmein.get('enable') is True:
        logger.debug( f"logmein config {logmein}")

def init_prelogin():
    global prelogin
    prelogin = gconfig.get(  'auth.prelogin', { 'enable': False } )
    if prelogin.get('enable') is True:
        logger.debug( f"prelogin config {prelogin}" )

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
            logger.debug( f"routing mode use hostname {route}")
        except Exception as e:
            logger.error(f"webroutingmode is set to 'default_host_url', but 'default_host_url' is in valid format {e} ")
            logger.error("please check the default_host_url parameter in config file")
            exit(-1)

    logger.debug( f"mode is {websocketrouting}" )
  
def init_fakedns():
    global fakedns
    fakedns = gconfig.get('fakedns', { 'interfacename': 'eth0' } )


def init_desktop():
    logger.debug('')
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

    desktop_pod = gconfig.get( 'desktop.pod' )
    if not isinstance( desktop_pod, dict ):
        logger.error(f"desktop.pod is not defined or is not a dict, read type is {type(desktop.pod)}")
        logger.error('this is a fatal error in configuration file')
        sys.exit(-1)

    # default secret path
    desktop['secretsrootdirectory']     = gconfig.get('desktop.secretsrootdirectory', '/var/secrets/')
    desktop['secretslocalaccount']      = gconfig.get('desktop.secretslocalaccount',  '/var/secrets/abcdesktop/extrausers')
    desktop['zoom']                     = gconfig.get('desktop.zoom', 1)
    desktop['removehomedirectory']      = gconfig.get('desktop.removehomedirectory', False)
    desktop['policies']                 = gconfig.get('desktop.policies', {} )
    desktop['webhookencodeparams']      = gconfig.get('desktop.webhookencodeparams', False )
    desktop['webhookdict']              = gconfig.get('desktop.webhookdict', {} )
    desktop['defaultbackgroundcolors']  = gconfig.get('desktop.defaultbackgroundcolors', ['#6EC6F0',  '#CD3C14', '#4BB4E6', '#50BE87', '#A885D8', '#FFB4E6'])
    desktop['homedirectorytype']        = gconfig.get('desktop.homedirectorytype', 'hostPath')
    desktop['hostPathRoot']             = gconfig.get('desktop.hostPathRoot', '/mnt')
    desktop['usedbussession']           = gconfig.get('desktop.usedbussession', False )
    desktop['usedbussystem']            = gconfig.get('desktop.usedbussystem', False )
    desktop['useinternalfqdn']          = gconfig.get('desktop.useinternalfqdn', False ) 
    desktop['uselocaltime']             = gconfig.get('desktop.uselocaltime', False ) 
    desktop['dnspolicy']                = gconfig.get('desktop.dnspolicy', 'ClusterFirst')
    desktop['dnsconfig']                = gconfig.get('desktop.dnsconfig')
    desktop['nodeselector']             = gconfig.get('desktop.nodeselector', {} )
    desktop['theme']                    = gconfig.get('desktop.theme') 
    desktop['pulseaudiosocketpath']     = gconfig.get('desktop.pulseaudiosocketpath', '/tmp/runtime/pulse/native' )
    desktop['prestopexeccommand']       = gconfig.get('desktop.prestopexeccommand', [ "/bin/bash", "-c", "rm -rf ~/{*,.*}" ] )
    desktop['persistentvolumeclaim']    = gconfig.get('desktop.persistentvolumeclaim') or gconfig.get('desktop.persistentvolumeclaimspec')
    desktop['persistentvolume']         = gconfig.get('desktop.persistentvolume') or gconfig.get('desktop.persistentvolumespec')
    desktop['homedirdotcachetoemptydir']= gconfig.get('desktop.homedirdotcachetoemptydir', False)
    desktop['directorytomemoryemptydir']= gconfig.get('desktop.directorytomemoryemptydir', [])
    desktop['removepersistentvolume']   = gconfig.get('desktop.removepersistentvolume', False)
    desktop['appendpathtomounthomevolume'] = gconfig.get('desktop.appendpathtomounthomevolume','')
    desktop['removepersistentvolumeclaim'] = gconfig.get('desktop.removepersistentvolumeclaim', False)
    desktop['persistentvolumeclaimforcesubpath'] = gconfig.get('desktop.persistentvolumeclaimforcesubpath',False)
    
    desktop['hostname'] = gconfig.get('desktop.hostname')
    desktop['overwrite_environment_variable_for_application'] = gconfig.get('desktop.overwrite_environment_variable_for_application')
    # features_permissions
    # 'read' features_permissions is exposed to the frontend
    # 'submit' features_permissions can be set to create a desktop
    # full permissions are [ 'read', 'submit' ]
    desktop['features_permissions'] = gconfig.get('desktop.features_permissions', [] )
    # Kubernetes timeout 
    desktop['K8S_BOUND_PVC_TIMEOUT_SECONDS'] = gconfig.get('K8S_BOUND_PVC_TIMEOUT_SECONDS', 60 )
    desktop['K8S_BOUND_PVC_MAX_EVENT'] = gconfig.get('K8S_BOUND_PVC_MAX_EVENT', 5 )
    desktop['K8S_CREATE_POD_TIMEOUT_SECONDS'] = gconfig.get('K8S_CREATE_POD_TIMEOUT_SECONDS', 300 )
    desktop['K8S_CREATE_EPHEMERALCONTAINER_TIMEOUT_SECONDS'] = gconfig.get('K8S_CREATE_EPHEMERALCONTAINER_TIMEOUT_SECONDS', 300 )
    desktop['K8S_NOTIFY_USER_APPLICATION_PULLED_DELAY_SECONDS'] = gconfig.get('K8S_NOTIFY_USER_APPLICATION_PULLED_DELAY_SECONDS', 2 )    
    desktop['K8S_NOTIFY_USER_APPLICATION_STARTED_DELAY_SECONDS'] = gconfig.get('K8S_NOTIFY_USER_APPLICATION_STARTED_DELAY_SECONDS', 5 )    

    if not isinstance(desktop['nodeselector'], dict):
        logger.error( f"nodeselector must be a dict or None, get {type(desktop['nodeselector'])}" )
        sys.exit(-1)

    # add default env local vars if not set 
    desktop['environmentlocal'] = gconfig.get(  
        'desktop.envlocal', 
        {   'DISPLAY'               : ':0.0',
            'LIBOVERLAY_SCROLLBAR'  : '0',
            'UBUNTU_MENUPROXY'      : '0',
            'X11LISTEN'             : 'tcp' 
        } 
    )

    # add default env local rules vars if not set 
    desktop['environmentlocalrules'] = gconfig.get(  'desktop.envlocalrules', {} )
    # environmentlocalrules must be a dict 
    if not isinstance( desktop['environmentlocalrules'], dict ):
        desktop['environmentlocalrules'] = {}  

    # check for desktop['directorytomemoryemptydir']
    if not isinstance(desktop['directorytomemoryemptydir'], list):
        logger.error("desktop.directorytomemoryemptydir must be a list")
        exit(-1)
    
    # for compatibiliy with 3.x
    if gconfig.get('desktop.homedirdotcachetoemptydir', False):
        # homedirdotcachetoemptydir is True
        if '.cache' not in desktop['directorytomemoryemptydir']:
            desktop['directorytomemoryemptydir'].append('.cache')

    if isinstance( gconfig.get('desktop.snapshotregistrysecretname'), str ):
        desktop['snapshotregistrysecretname'] = gconfig.get('desktop.snapshotregistrysecretname')
    
    desktop['snapshotregistryprotocol'] = gconfig.get('desktop.snapshotregistryprotocol', 'https' )


    # fix volume values if missing for compatibility
    if not isinstance ( desktop_pod.get('default_volumes'), dict ):
        desktop_pod['default_volumes'] =  {
            'shm': { 'name': 'shm', 'emptyDir': { 'medium': 'Memory', 'sizeLimit': '512Mi' } },
            'run': { 'name': 'run', 'emptyDir': { 'medium': 'Memory', 'sizeLimit': '1M'    } },
            'tmp': { 'name': 'tmp', 'emptyDir': { 'medium': 'Memory', 'sizeLimit': '8Gi'   } },
            'log': { 'name': 'log', 'emptyDir': { 'medium': 'Memory', 'sizeLimit': '8Gi'   } },
            'rundbus': { 'name': 'rundbus',  'emptyDir': { 'medium': 'Memory', 'sizeLimit': '8M' } },
            'runuser': { 'name': 'runuser',  'emptyDir': { 'medium': 'Memory', 'sizeLimit': '8M' } },
            'x11socket': { 'name': 'x11socket',  'emptyDir': { 'medium': 'Memory' } },
            'pulseaudiosocket' :  { 'name': 'pulseaudiosocket',  'emptyDir': { 'medium': 'Memory' } },
            'cupsdsocket': { 'name': 'cupsdsocket',  'emptyDir': { 'medium': 'Memory' } }
        }
    if not isinstance ( desktop_pod.get('default_volumes_mount'), dict ):
        desktop_pod['default_volumes_mount'] = {
            'shm': { 'name': 'shm', 'mountPath' : '/dev/shm' },
            'run': { 'name': 'run',  'mountPath': '/var/run/desktop' },
            'tmp': { 'name': 'tmp',  'mountPath': '/tmp' },
            'log': { 'name': 'log',  'mountPath': '/var/log/desktop' },
            'rundbus': { 'name': 'rundbus',  'mountPath': '/var/run/dbus' },
            'runuser': { 'name': 'runuser',  'mountPath': '/run/user/' },
            'x11socket': { 'name': 'x11socket',  'mountPath': '/tmp/.X11-unix' },
            'pulseaudiosocket':  { 'name': 'pulseaudiosocket',  'mountPath': '/tmp/.pulseaudio' },
            'cupsdsocket': { 'name': 'cupsdsocket',  'mountPath': '/tmp/.cupsd' }
        }
    if not isinstance ( desktop_pod.get('graphical', {}).get('volumes') , list ):
        desktop_pod['graphical']['volumes'] = [ 'x11socket', 'pulseaudiosocket', 'cupsdsocket', 'tmp', 'run', 'log', 'rundbus', 'runuser' ]
        logger.debug(f"fixing desktop.pod.graphical.volumes config {desktop_pod['graphical']['volumes']}")
    if not isinstance ( desktop_pod.get('ephemeral_container', {}).get('volumes') , list ):
        # ephemeral container use the same volumes as graphical pod
        desktop_pod['ephemeral_container']['volumes'] = [ 'x11socket', 'pulseaudiosocket', 'cupsdsocket', 'tmp', 'run', 'log', 'rundbus', 'runuser' ]
        logger.debug(f"fixing desktop.pod.ephemeral_container.volumes config {desktop_pod['ephemeral_container']['volumes']}")
    if not isinstance ( desktop_pod.get('pod_application', {}).get('volumes') , list ):
        desktop_pod['pod_application']['volumes'] = [ 'tmp', 'run', 'log', 'rundbus', 'runuser' ]
        logger.debug(f"fixing desktop.pod.pod_application.volumes config {desktop_pod['pod_application']['volumes']}")  
    init_balloon()

    # apply cgroup memory and cpu 
    global cgroup_version
    cgroup_version = detect_cgroup_version()
    logger.info( f"cgroup_version is {cgroup_version}" )
    if cgroup_version is None:
        logger.error("cgroup version is not detected, this is a fatal error")
        sys.exit(-1)
    if cgroup_version == 'cgroup v1':
        desktop['resources_usage_cgroup_map'] = gconfig.get(
            'desktop.resources_usage_cgroup_map', 
            {   'memory.usage_in_bytes': '/sys/fs/cgroup/memory/memory.usage_in_bytes',
                'memory.limit_in_bytes': '/sys/fs/cgroup/memory/memory.limit_in_bytes',
                'cpuacct.usage':    '/sys/fs/cgroup/cpu/cpuacct.usage',
                'cpu.cfs_quota_us': '/sys/fs/cgroup/cpuacct/cpu.cfs_quota_us'
            } 
        )
    if cgroup_version == 'cgroup v2':
        desktop['resources_usage_cgroup_map'] = gconfig.get(
            'desktop.resources_usage_cgroup_map', 
            {   'memory.usage_in_bytes': '/sys/fs/cgroup/memory.current',
                'memory.limit_in_bytes': '/sys/fs/cgroup/memory.max',
                'cpuacct.usage':    '/sys/fs/cgroup/cpu.stat',
                'cpu.cfs_quota_us': '/sys/fs/cgroup/cpu.max'
            } 
        )

def init_menuconfig():
    global menuconfig
    menuconfig = gconfig.get('front.menuconfig', {  'settings': True, 
                                                    'appstore': True, 
                                                    'screenshot': True, 
                                                    'logout': True,
                                                    'disconnect': True } )
    # read desktop config 
    menuconfig['snapshot'] = desktop_pod.get('snapshot',{}).get('enable', False)
    logger.debug(f"menuconfig: {menuconfig}")

def init_imagenotificationconfig():
    global imagenotificationconfig
    imagenotificationconfig = gconfig.get(
        'front.imagenotification', { 'ephemeral_container' : False, 'pod_application' : False } )
    logger.debug(f"imagenotificationconfig: {imagenotificationconfig}")

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
    global balloon_password
    global balloon_homedirectory
    global homerootdirectory 

    homerootdirectory = gconfig.get('desktop.homerootdirectory', '/home')
    balloon_loginname = gconfig.get('desktop.username',  'balloon')
    balloon_groupname = gconfig.get('desktop.groupname', 'balloon')
    balloon_uidNumber = gconfig.get('desktop.userid', 4096)
    balloon_gidNumber = gconfig.get('desktop.groupid', 4096)
    balloon_shell     = gconfig.get('destkop.shell', '/bin/bash')
    balloon_password  = gconfig.get('desktop.userpasswd', 'lmdpocpetit')
    balloon_homedirectory = gconfig.get(
        'desktop.userhomedirectory', 
        os.path.join( homerootdirectory, balloon_loginname ) 
    )


def _resolv( fqdh:str )->str:
    """_resolv
        run gethostbyname(fqdh)
        exit(-1) if error

    Args:
        fqdh (str): full qualified host name

    Returns:
        str: ip address
    """    
    assert isinstance(fqdh, str), 'invalid full qualified host name'
    logger.debug( f"trying to gethostbyname {fqdh}" )
    ipaddr = None
    try:
        ipaddr = socket.gethostbyname(fqdh)
    except socket.gaierror as err:
        logger.fatal(f"Cannot resolve hostname:{fqdh} {err}")
        logger.fatal(f"This is a fatal error, check coredns config or netpol")
        sys.exit(-1)
    return ipaddr

def init_config_memcached():
    global memconnectionstring
    # Build memcached memconnectionstring
    memcachedserver = os.getenv('MEMCACHESERVER') or gconfig.get('memcacheserver', 'memcached' )
    logger.debug( f"memcachedserver is read as {memcachedserver}" )
    memcachedipaddr = _resolv(memcachedserver)
    logger.debug(f"a simple check for memcache: host {memcachedserver} resolved as {memcachedipaddr}")
    memcachedport = gconfig.get('memcacheport', gconfig.get('memcachedport', 11211) )
    memconnectionstring = f"{memcachedserver}:{memcachedport}"
    logger.debug(f"memcached connection string is set to {memconnectionstring}")


def get_mongodburl():
    """mongodburl
        get get_mongodburl from env
                - MONGODB_URL
            or from config file
                - config('mongodburl')
        parse mongodburl to resolv hostmane
        exit if resolv hostname error
    Returns:
        MongoClientConfig : MongoClientConfig instance 
    """
    # read MONGODB_URL env var
    # 'mongodb://pyos:YWUwNDJhZTI3NjVjZDg4Zjhk@mongodb.abcdesktop.svc.cluster.local:30017'
    mongodburl = os.getenv('MONGODB_URL') or gconfig.get( 'mongodburl' )
    logger.debug( f"mongodburl is read as {mongodburl}" )
    parsedmongourl = urlparse( mongodburl )
    assert isinstance(parsedmongourl.hostname, str), f"Can not parse mongodburl {mongodburl} result {parsedmongourl}"
    mongodbhostipaddr = _resolv(parsedmongourl.hostname)
    logger.debug(f"a simple check for mongodb: host {parsedmongourl.hostname} resolved as {mongodbhostipaddr}")
    mongodbparam = os.getenv('MONGODB_PARAM') or gconfig.get( 'mongodbparam', 'replicaSet=rs0' )
    return (mongodburl, mongodbparam)

def init_controllers():
    """Define controlers access
    """
    global controllers
    # by default manager controller is protected by filtering source ip address as local net 
    # local net is defined as list_local_subnet
    controllers = gconfig.get(  
        'controllers',  { 
            'ManagerController': { 
                'permitip': [ 
                    '10.0.0.0/8', 
                    '172.16.0.0/12', 
                    '192.168.0.0/16', 
                    'fd00::/8', 
                    '169.254.0.0/16', 
                    '127.0.0.0/8' ] 
            },
            'StoreController': { 'wrapped_key': {} } 
        } 
    )

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
        controllers['ManagerController'] = { 
            'permitip':    [ 
                '10.0.0.0/8', 
                '172.16.0.0/12', 
                '192.168.0.0/16', 
                'fd00::/8', 
                '169.254.0.0/16', 
                '127.0.0.0/8' ] 
        }

    if desktop['environmentlocal'].get('SET_DEFAULT_COLOR'):
        # wrapper for StoreController key value
        # config use default 'color'  
        controllers['StoreController']['wrapped_key'].update( 
            { 'color': desktop['environmentlocal'].get('SET_DEFAULT_COLOR') } 
        )

    if desktop['environmentlocal'].get('SET_DEFAULT_WALLPAPER') :
        # wrapper for StoreController key value
        # config use default wallpaper 'img' 
        controllers['StoreController']['wrapped_key'].update( 
            { 'backgroundType': 'img' } 
        )

def init_config_mongodb():
    """init mongodb config
    """
    global mongodburl
    global mongodblist
    global mongodbparam
    (mongodburl,mongodbparam) = get_mongodburl()
    logger.debug(f"MongoDB url: {mongodburl} param: {mongodbparam}")
    mongodblist = gconfig.get('mongodblist', ['image','fail2ban','loginHistory','applications','profiles','desktop'] )
    logger.debug(f"MongoDB list: {mongodblist}")

def init_config_fail2ban():
    """init fail2ban config
    """
    global fail2banconfig
    fail2banconfig = gconfig.get('fail2ban', { 'enable' : False } )
    logger.debug(f"Fail2ban config: {fail2banconfig}" )


def init_config_auth():

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

def read_b64data_from_iconfile( filename:str )->str:
    """read_b64data_from_iconfile
        load file data and encode in b64
    Args:
        filename (str): filename to encode

    Returns:
        str: encoded content file
    """
    strencode = None
    filepath = os.path.normpath( filename )
    try:
        f = open(filepath, 'r')
        file_data = f.read()
        f.close()
        strencode = base64.b64encode( file_data.encode('utf8') ).decode('utf-8') 
    except Exception as e:
        logger.error( e )
    return strencode

      

def init_dock():
    """init_dock
       load dock config from config file
       load icon file and encode in base64 format for web transmission 
    """
    logger.debug('')
    global dock
    dock = gconfig.get('dock', {})
    # img_path is img/app by default
    img_path = gconfig.get('dock.img_path',  os.path.join('img', 'app') )
    for key in dock.keys():
        logger.debug( f"loading dock entry {key}")
        if not isinstance( dock[key], dict ):
            logger.error(f"bad dock type dock[{key}]={type(dock[key])} is must be a dict")
            exit(-1)           

        filename = dock[key].get('icon')
        if isinstance(filename, str):
            # load the icon file as base64 format
            opened_filename = os.path.join(img_path, filename)
            dock[key]['icondata'] = read_b64data_from_iconfile( opened_filename )
        else:
            logger.error(f"bad dock entry dock[{key}]['icon']={type(filename)} is must be a str (filename)")


def init_executeclass():
    global executeclasses

    executeclasses = gconfig.get('executeclasses', {} )
    if not isinstance( executeclasses.get('default'), dict ):
        default_executeclass =  { 'description': 'default description', 'nodeSelector' : None, 'resources': None } # no limits
        logger.error('something wrong in the config file no default executeclass has been defined ')
        logger.error(f"fixing default execute class {default_executeclass}")
        executeclasses['default'] = default_executeclass


def get_default_appdict():
    """get_default_appdict
       return a default appdict structure
    Returns:
        dict: default appdict
    """    
    return dock


def get_configuration_file_name():
    """get_configuration_file_name

    Returns:
        str: name of the config file 'od.config' by default or read 'OD_CONFIG_PATH' os.getenv
    """
    configuration_file_name = os.getenv('OD_CONFIG_PATH', 'od.config')
    return configuration_file_name

def load_config():
    """load_config
       load configuration file 'od.config'
       set global config and gconfig
    """
    global config
    global gconfig

    configpath = get_configuration_file_name()
    logger.debug(f"Loading configuration file {configpath}")
    try:
        config = Config(configpath)
        if isinstance( config.get('global'), dict ):
            logger.debug(f"config file contains [global] entry (ini file format)")
            gconfig = config.get('global', {}) # = cherrypy.gconfig 
        else:
            logger.debug(f"config file does not set [global] entry")
            logger.debug(f"config file is not a ini file format, use json")
            
    except Exception as e:
        logger.error(f"Failed to load configuration file {configpath} {e}")
        exit(-1)           

def init_snapshot():
    """init_snapshot
       read snapshot config
    """
    global snapshot_mountpath
    global snapshot_mounttype
    global snapshot_registry_protocol 
    snapshot_mountpath = gconfig.get('desktop.snapshotmountpath', '/run/containerd/containerd.sock')
    snapshot_mounttype = gconfig.get('desktop.snapshotmounttype', 'Socket')
    snapshot_registry_protocol = gconfig.get('desktop.snapshotregistryprotocol', 'https' )

def detect_cgroup_version():
    """detect_cgroup_version
       Detect the cgroup version used by the system.
       Returns: string indicating the cgroup version ('cgroup v1' or 'cgroup v2').
    """
    # read source https://faun.pub/migrating-from-cgroup-v1-to-v2-in-kubernetes-what-you-need-to-know-gke-eks-and-beyond-c0784085043b
    # to get more information about cgroup v1 and v2
    cgroup2_path = "/sys/fs/cgroup"

    # In cgroup v2, the file 'cgroup.controllers' exists in /sys/fs/cgroup
    # Its presence indicates a unified cgroup v2 hierarchy
    if os.path.isfile(os.path.join(cgroup2_path, "cgroup.controllers")):
        return "cgroup v2"
    else:
        return "cgroup v1"
   
def init():
    """init
       main init function
       load all configuration
    """
    logger.debug('Init configuration start')

    # load config file od.config
    # use global config and gconfig
    load_config() 

    # load passwd, group, shadow file
    init_localaccount()

    # load execute classes
    init_executeclass()

    # load default menu config
    init_menuconfig()

    # load default imagenotification config
    init_imagenotificationconfig()

    # init tipsinfo config
    init_tipsinfo()

    # init welcomeinfo config
    init_welcomeinfo()

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

    # init internal domain 
    # namespace.svc.cluster.local
    # by default abcdesktop.svc.cluster.local
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

    # init prelogin
    init_prelogin()

    # init_logmein
    init_logmein()

    # init snapshot
    init_snapshot()

    # init_controllers
    # use desktop
    # for SET_DEFAULT_WALLPAPER option
    # for SET_DEFAULT_COLOR option
    init_controllers()

    logger.debug('Init configuration done.')
