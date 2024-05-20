

import logging
from typing_extensions import assert_type
import datetime
import cherrypy

import oc.cherrypy
import oc.logging

from oc.od.desktop import ODDesktop
from oc.auth.authservice  import AuthInfo, AuthUser # to read AuthInfo and AuthUser
from oc.od.services import services

logger = logging.getLogger(__name__)


def filter_user_for_history(auth:AuthInfo, user:AuthUser):
    assert_type( auth, AuthInfo )
    assert_type( user, AuthUser )
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
    addnewentryindesktophistory( auth, user, desktop, eventtype='stop', isgarbaged=isgarbaged)

def addnewentryinloginhistory(auth:AuthInfo, user:AuthUser): 

    assert_type( auth, AuthInfo )
    assert_type( user, AuthUser )

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

    assert_type( auth, AuthInfo )
    assert_type( user, AuthUser )
    assert_type( desktop, ODDesktop )

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