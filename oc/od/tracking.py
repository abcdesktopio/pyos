

import logging
import datetime
import cherrypy
import oc.cherrypy
from oc.od.desktop import ODDesktop
from oc.auth.authservice  import AuthInfo, AuthUser # to read AuthInfo and AuthUser
from oc.od.services import services

logger = logging.getLogger(__name__)


def filter_user_for_history(auth:AuthInfo, user:AuthUser):
    assert isinstance(auth, AuthInfo), f"auth has invalid type {type(auth)}, AuthInfo is expected"
    assert isinstance(user, AuthUser), f"user has invalid type {type(user)}, AuthUser is expected"  
    filtered_user =  {
        'userid': user.get('userid'),
        'name': user.get('name'),
        'mail': user.get('mail'),
        'geolocation': user.get('geolocation'),
        'objectClass': user.get('objectClass'),
        'labels': auth.data.get('labels'),
        'provider': auth.provider,
        'providertype': auth.providertype }
    return filtered_user

def addstartnewentryindesktophistory(auth:AuthInfo, user:AuthUser, desktop:ODDesktop, isgarbaged:bool=None ):
    """addstartnewentryinloginhistory

    Args:
        auth (AuthInfo): AuthInfo
        user (AuthUser): AuthUser
        desktop (ODDesktop): ODDesktop
        isgarbaged (bool, isgarbaged): _description_. Defaults to None.
    """
    assert isinstance(auth, AuthInfo), f"auth has invalid type {type(auth)}, AuthInfo is expected"
    assert isinstance(user, AuthUser), f"user has invalid type {type(user)}, AuthUser is expected"  
 
    addnewentryindesktophistory( auth, user, desktop, eventtype='start', isgarbaged=isgarbaged)

def addresumenewentryindesktophistory(auth:AuthInfo, user:AuthUser, desktop:ODDesktop, isgarbaged:bool=None ):
    """addresumenewentryinloginhistory

    Args:
        auth (AuthInfo): AuthInfo
        user (AuthUser): AuthUser
        desktop (ODDesktop): ODDesktop
        isgarbaged (bool, isgarbaged): _description_. Defaults to None.
    """
    addnewentryindesktophistory( auth, user, desktop, eventtype='resume', isgarbaged=isgarbaged)

def addstopnewentryindesktophistory(auth:AuthInfo, user:AuthUser, desktop:ODDesktop, isgarbaged:bool=False ):
    """addstopnewentryinloginhistory

    Args:
        auth (AuthInfo): AuthInfo
        user (AuthUser): AuthUser
        desktop (ODDesktop): ODDesktop
        isgarbaged (bool, optional): isgarbaged. Defaults to False.
    """
    assert isinstance(auth, AuthInfo), f"auth has invalid type {type(auth)}, AuthInfo is expected"
    assert isinstance(user, AuthUser), f"user has invalid type {type(user)}, AuthUser is expected"  
    assert isinstance(desktop, ODDesktop), f"desktop has invalid type {type(desktop)}, ODDesktop is expected"

    addnewentryindesktophistory( auth, user, desktop, eventtype='stop', isgarbaged=isgarbaged)

def addnewentryinloginhistory(auth:AuthInfo, user:AuthUser): 

    assert isinstance(auth, AuthInfo), f"auth has invalid type {type(auth)}, AuthInfo is expected"
    assert isinstance(user, AuthUser), f"user has invalid type {type(user)}, AuthUser is expected"  
 
    # read client ip source addr
    webclient_sourceipaddr = oc.cherrypy.getclientipaddr()

    # filter user's entries to accouting
    user_history = filter_user_for_history( auth, user )

    # build an accounting data
    datadict={  **user_history,
                'date': datetime.datetime.utcnow(),
                'useragent': cherrypy.request.headers.get('User-Agent', None),
                'ipaddr': webclient_sourceipaddr,
                'type': 'login'
    }
    # store the accouting data in collectionname 'loginHistory'
    services.datastore.addtocollection( databasename='loginHistory', 
                                        collectionname=user.userid, 
                                        datadict=datadict)
    

def addnewentryindesktophistory(auth:AuthInfo, user:AuthUser, desktop:ODDesktop, eventtype:str=None, isgarbaged:bool=False ): 

    assert isinstance(auth, AuthInfo), f"auth has invalid type {type(auth)}, AuthInfo is expected"
    assert isinstance(user, AuthUser), f"user has invalid type {type(user)}, AuthUser is expected"  
    assert isinstance(desktop, ODDesktop), f"desktop has invalid type {type(desktop)}, ODDesktop is expected"

    # read client ip source addr
    webclient_sourceipaddr = oc.cherrypy.getclientipaddr()

    # filter user's entries to accouting
    user_history = filter_user_for_history( auth, user )

    # build an accounting data
    datadict={  **user_history,
                'isgarbaged': isgarbaged,
                'eventtype': eventtype,
                'desktop_id': desktop.id,
                'date': datetime.datetime.utcnow(),
                'useragent': cherrypy.request.headers.get('User-Agent', None),
                'ipaddr': webclient_sourceipaddr,
                'node': desktop.nodehostname,
                'type': 'desktop'
    }
    # store the accouting data in collectionname 'desktop'
    services.datastore.addtocollection( databasename='desktop', 
                                        collectionname='history', 
                                        datadict=datadict)