import cherrypy
import oc.od.settings
import oc.od.coturn
import base64
import logging
import copy

logger = logging.getLogger(__name__)

def is_coturn_enable()->bool:
    webrtc_coturn = oc.od.settings.webrtc.get('coturn',{})
    coturn_static_auth_secret = webrtc_coturn.get( 'coturn_static_auth_secret' )
    coturn_url = webrtc_coturn.get( 'url' ) 
    coturn_protocol = webrtc_coturn.get( 'protocol' ) 
    is_enable = isinstance(coturn_static_auth_secret, str) and \
                isinstance(coturn_url, str) and \
                isinstance(coturn_protocol, str )
    return is_enable

def coturn_iceserver( format:str='dict' ):

    webrtc_coturn = oc.od.settings.webrtc.get('coturn',{})
    coturn_static_auth_secret = webrtc_coturn.get( 'coturn_static_auth_secret' )
    if not isinstance( coturn_static_auth_secret, str):
        raise cherrypy.HTTPError( 400, message='bad coturn_static_auth_secret for webrtc coturn in configuration file')
    
    coturn_url = webrtc_coturn.get( 'url' ) # take care only one for gstreamer ?
    if not isinstance( coturn_url, str):
        raise cherrypy.HTTPError( 400, message='bad url for webrtc coturn in configuration file')
    
    coturn_protocol = webrtc_coturn.get( 'protocol' ) # take care only one for gstreamer
    if not isinstance( coturn_protocol, str):
        raise cherrypy.HTTPError( 400, message='bad protocol for coturn_protocol in configuration file')
    
    # compute password from coturn_static_auth_secret
    # coturn_username is a timestamp
    # coturn_password is a hash
    (coturn_username, coturn_password) =  oc.od.coturn.create_coturn_credentials( coturn_static_auth_secret )

    iceserver = {   
        'urls': f"{coturn_protocol}:{coturn_url}", # "turn:asia.myturnserver.net",
        'username': coturn_username,
        'credential': coturn_password
    }

    # if format == 'env':
    #    # take care lot of issues with that code 
    #    # do not return a dict but a string for gstreamer
    #    # coturn_username contains : char, use base64 to encode
    #    # coturn_username = base64.b64encode(coturn_username.encode()).decode()
    #    iceserver = f"{coturn_protocol}://{coturn_username}:{coturn_password}@{coturn_url}"
    #    # iceserver = f"{coturn_protocol}://{coturn_url}"

    return iceserver

def coturn_rtcconfiguration()->dict:

    # The configuration below establishes one ICE servers. 
    # stun:stun.services.mozilla.com, requires authentication, so the username and password are provided. 

    # var configuration = { 
    # iceServers: [
    #               'iceTransportPolicy' : 'relay', 
    #               {
    #                  urls: "stun:stun.services.mozilla.com",
    #                  username: "louis@mozilla.com",
    #                  credential: "webrtcdemo"
    #               }]
    # };
    
    default_rtc_configuration = { 'iceServers': [] }
    iceserver = coturn_iceserver()
    webrtc_rtc_configuration = oc.od.settings.webrtc.get('rtc_configuration')
    if not isinstance( webrtc_rtc_configuration, dict) or not isinstance( default_rtc_configuration.get('iceServers'), list):
        logger.error( "bad webrtc_rtc_configuration in config file, fixing it" )
        webrtc_rtc_configuration = default_rtc_configuration
    
    rtc_configuration = copy.deepcopy( webrtc_rtc_configuration )
    rtc_configuration['iceServers'].append(iceserver)
    logger.debug( f"rtc_configuration is {rtc_configuration}" )

    return rtc_configuration
