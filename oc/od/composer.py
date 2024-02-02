#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
# Software Name : abcdesktop.io
# Version: 0.2
# SPDX-FileCopyrightText: Copyright (c) 2020-2021 Orange
# SPDX-License-Identifier: GPL-2.0-only
#
# This software is distributed under the GNU General Public License v2.0 only
# see the "license.txt" file for more details.
#
# Author: abcdesktop.io team
# Software description: cloud native desktop service
#

import logging
from typing_extensions import assert_type
import requests
from oc.cherrypy import getclientipaddr
from oc.od.desktop import ODDesktop

import oc.od.settings as settings # Desktop settings lib
import oc.pyutils
import oc.logging
import oc.od.orchestrator

from oc.od.services import services
from oc.auth.authservice  import AuthInfo, AuthUser # to read AuthInfo and AuthUser
from oc.od.error import ODError
import oc.od.appinstancestatus
import oc.od.desktop

import subprocess
import threading
import json

logger = logging.getLogger(__name__)


""" 
    all functions are called by composer_controller
"""

def selectOrchestrator():
    myOrchestrator = oc.od.orchestrator.selectOrchestrator()
    return myOrchestrator


def securitypoliciesmatchlabel( desktop:ODDesktop, authinfo:AuthInfo, labels_filter_list:list ) -> bool:
    assert isinstance(desktop, ODDesktop), f"desktop is not a ODDesktop {type(desktop)}"
    assert isinstance(authinfo, AuthInfo), f"authinfo is not a AuthInfo {type(authinfo)}"
    if not isinstance(labels_filter_list, list):
        return True

    labels_authinfo = authinfo.get_labels().keys()
    labels_desktop  = desktop.labels.keys()
    matches = {}
    for require_label in labels_filter_list:
        if require_label in labels_authinfo.keys():
            matches[require_label] = False
            if require_label in labels_desktop.keys():
                matches[require_label] =True

    logger.debug( f"checking label matching {matches}" )
    result = all( matches.values() )
    return result

def securitypoliciesmatchlabelvalue( desktop:ODDesktop, authinfo:AuthInfo, labels_filter_list:list ) -> bool:
    assert isinstance(desktop, ODDesktop), f"desktop is not a ODDesktop {type(desktop)}"
    assert isinstance(authinfo, AuthInfo), f"authinfo is not a AuthInfo {type(authinfo)}"
    if not isinstance(labels_filter_list, list):
        return True

    labels_authinfo = authinfo.get_labels()
    labels_desktop  = desktop.labels
    # default matches value
    # all( {} ) is True
    matches = {} 
    for require_label in labels_filter_list:
        matches[require_label] = labels_authinfo.get(require_label) == labels_desktop.get(require_label)
        logger.debug( f"match label {require_label} is {matches[require_label] }" )

    result = all( matches.values() )
    return result


def opendesktop(authinfo, userinfo, args ):
    """open a new or return a desktop
    Args:
        authinfo (AuthInfo): authentification data
        userinfo (AuthUser): user data 
        args (dict): additionnal desktop data 
        {   'usersourceipaddr': oc.cherrypy.getclientipaddr(),
            'querystring':  QUERYSTRING env inside the container,
            'metadata' :    METADATA env inside the container,
            'args' :        APPARGS inside the container,
            'timezone' :    TZ env inside the contianer }

    Returns:
        [ODesktop]: Desktop Object if success 
        [str]: if failed      
    """
    logger.debug('')
    desktoptype = 'desktop'

    # start a message info 
    services.messageinfo.start(userinfo.userid, 'b.Looking for your desktop')
    # look for a desktop
    logger.debug('finddesktop')
    desktop = finddesktop( authinfo, userinfo )
   
    if isinstance(desktop, oc.od.desktop.ODDesktop) :
        # ok we find a desktop
        # let's check if security policies match the desktop
        logger.debug('a desktop has been found')
        services.messageinfo.push(userinfo.userid, 'b.Applying labels security policy')
        # the list of uniq_labels_filter must be the same as the user label
        logger.debug('checking if securitypoliciesmatchlabelvalue')
        if securitypoliciesmatchlabelvalue( desktop, authinfo, oc.od.settings.desktop.get('policies').get('user_uniq_labels')) :
            logger.debug('Warm start, reconnecting to running desktop') 
            services.messageinfo.push(userinfo.userid, 'c.Warm start, reconnecting to your running desktop') 
            # if the desktop exists resume the connection
            services.accounting.accountex( desktoptype, 'resumed')
            desktop = resumedesktop( authinfo, userinfo ) # update last connection datetime
            if isinstance( desktop, str):
                # something goes wrong with this pod
                # delete the current desktop
                services.messageinfo.push(userinfo.userid, f"b. {desktop}")  
                # only remove the pod, do not delete secret configmap and everythings else
                removed_desktop = removepodindesktop( authinfo, userinfo )
                if removed_desktop is True:
                    services.messageinfo.push(userinfo.userid, 'b.Your desktop is deleted. creating a new one')
                    services.accounting.accountex( desktoptype, 'deletesuccess')
                else:
                    logger.error(f"Cannot delete desktop") 
                    services.accounting.accountex( desktoptype, 'deletefailed')
                    services.messageinfo.push(userinfo.userid, 'e.Your desktop can not be deleted')
                    return 'Your desktop can not be deleted' 
            else:
                return desktop
        else:
            # security polcies does not match
            # delete the current desktop
            services.messageinfo.push(userinfo.userid, 'b.Deleting your running desktop. It does not match the security policies')  
            # only remove the pod, do not delete secret configmap and everythings else
            removed_desktop = removepodindesktop( authinfo, userinfo )
            if removed_desktop is True:
                services.messageinfo.push(userinfo.userid, 'b.Your desktop is deleted. creating a new one with new security policies')
                services.accounting.accountex( desktoptype, 'deletesuccess')
            else:
                logger.error(f"Cannot delete desktop {desktop}") 
                services.accounting.accountex( desktoptype, 'deletefailed')
                services.messageinfo.push(userinfo.userid, 'e.Your desktop can not be deleted to apply new security policies')
                return 'Your desktop can not be deleted to apply new security policies' 
    else:
        services.messageinfo.push(userinfo.userid, 'b.Cold start, creating your new desktop')
    
    #
    # desktop is not found or has been deleted to match security policies
    # create a new desktop
    #
    logger.debug( 'Cold start, creating your new desktop' )
    desktop = createdesktop( authinfo, userinfo, args) 
    if isinstance( desktop, oc.od.desktop.ODDesktop) :
        services.accounting.accountex( desktoptype, 'createsuccess')
    else:
        services.accounting.accountex( desktoptype, 'createfailed')
        logger.error(f"Cannot create a new desktop return desktop={desktop}")
            
    return desktop

def runwebhook( c, messageinfo=None ):
    bReturn = False
    # check if c contains webhook create or destroy entry
    if hasattr(c, 'webhook') and type(c.webhook) is dict:
        webhook_create  = c.webhook.get('create')

        # convert webhook_create to a list of webhook_create
        if isinstance(webhook_create, str):
            webhook_create = [ webhook_create ]

        if isinstance(webhook_create, list):
            bReturn = True # need to call a command
            for webhook_command in webhook_create:
                logger.debug( f"calling webhook cmd  {webhook_command}" )
                t1=threading.Thread(target=callwebhook, args=[webhook_command, messageinfo])
                t1.start()

        webhook_destroy = c.webhook.get('destroy')
        if webhook_destroy :
            # post pone webhook_destroy call 
            # add url to call in 
            oc.od.services.services.sharecache.set( c.id, webhook_destroy )
    return bReturn 


def remove_desktop_byname( desktop_name:str ):
    myOrchestrator = selectOrchestrator()
    (authinfo, userinfo) = myOrchestrator.find_userinfo_authinfo_by_desktop_name( name=desktop_name )
    return myOrchestrator.removedesktop( authinfo, userinfo )

def stop_container_byname( desktop_name:str, container ):
    myOrchestrator = selectOrchestrator()  
    (authinfo, userinfo) = myOrchestrator.find_userinfo_authinfo_by_desktop_name( name=desktop_name )
    return myOrchestrator.stopContainerApp( authinfo, userinfo, container )

def list_container_byname( desktop_name:str ):
    myOrchestrator = selectOrchestrator()    
    (authinfo, userinfo) = myOrchestrator.find_userinfo_authinfo_by_desktop_name( name=desktop_name )
    return myOrchestrator.listContainerApp(authinfo, userinfo)

def describe_desktop_byname( desktop_name:str ):
    myOrchestrator = selectOrchestrator()    
    pod = myOrchestrator.describe_desktop_byname( desktop_name )
    return pod

def describe_container_byname( desktop_name:str , container_id:str ):
    myOrchestrator = selectOrchestrator()    
    container = myOrchestrator.describe_container( desktop_name, container_id )
    return container

def remove_container_byname(desktop_name: str, container_id:str):
    myOrchestrator = selectOrchestrator()    
    (authinfo, userinfo) = myOrchestrator.find_userinfo_authinfo_by_desktop_name( name=desktop_name )
    return myOrchestrator.removeContainerApp(authinfo,userinfo,container_id=container_id)


def fakednsquery( userid ):
    logger.debug( locals() )
    ipdaddr = None
    
    # read interface name to to get ip addr
    dnsinterface_name = oc.od.settings.fakedns.get('interfacename')
    if not isinstance( dnsinterface_name , str ):
        raise ODError( status=400, message=f"fakednsquery has invalid 'interfacename' value 'str' is expected type={type(dnsinterface_name)} in configuration file")

    # fake an userinfo object
    myDesktop = None
    myOrchestrator = selectOrchestrator()   
    # try to find label value with insensitive case, lower and upper case
    searchuserlist = [ userid, userid.lower(), userid.upper() ]
    logger.debug( f"try to query {searchuserlist}" )
    for nocaseuserid in searchuserlist:
        userinfo = AuthUser( { 'userid': nocaseuserid } )
        myDesktop = myOrchestrator.findDesktopByUser(authinfo=None, userinfo=userinfo )
        if isinstance( myDesktop, oc.od.desktop.ODDesktop ):
            break

    if not isinstance( myDesktop, oc.od.desktop.ODDesktop ):
        logger.debug( f"findDesktopByUser {userid} return not found" )
        return None

    desktop_interfaces = myDesktop.desktop_interfaces
    if not isinstance( desktop_interfaces, dict ):
        logger.debug( f"desktop has no desktop_interfaces desktop_interfaces={desktop_interfaces}" )
        return None
    
    # read the ip value of remappded name of dnsinterface_name
    logger.debug( f"dnsinterface_name={dnsinterface_name}" )
    interface = desktop_interfaces.get( dnsinterface_name )
    logger.debug( f"desktop has desktop_interfaces={interface}" )
    if isinstance( interface, dict ):
        ipdaddr = interface.get('ips')
        if isinstance( ipdaddr, list ):
            ipdaddr = ipdaddr[0]

    return ipdaddr

def getdesktopdescription( authinfo, userinfo ):
    description = {}
    description['clientipaddr'] = getclientipaddr()
    description['user'] = userinfo.get('userid')

    myOrchestrator = selectOrchestrator()    
    myDesktop = myOrchestrator.findDesktopByUser(authinfo, userinfo )
    if not isinstance( myDesktop, oc.od.desktop.ODDesktop ):
        return description
    
    # desktop_interfaces = { 'net1': { 'ips' : '192.168.1.1'}, 'net2': { 'ips' : '192.168.9.1'} }
    desktop_interfaces = myDesktop.desktop_interfaces
    if not isinstance( desktop_interfaces, dict ):
        return description

    # read the ip value of remappded name of 'externalipaddr'
    interface = desktop_interfaces.get( oc.od.settings.desktopdescription.get('externalip') )
    if isinstance( interface, dict ):
        description['externalip'] = interface.get('ips')
    # read the ip value of remappded name of 'internalipaddr'
    interface = desktop_interfaces.get( oc.od.settings.desktopdescription.get('internalip') )
    if isinstance( interface, dict ):
        description['internalip'] = interface.get('ips')
    description['sshconfig'] = oc.od.settings.desktopdescription.get('sshconfig')

    return description

def logdesktop( authinfo, userinfo ):
    """read the log from  the current desktop

    Args:
        authinfo (AuthInfo): authentification data
        userinfo (AuthUser): user data 

    Returns:
        [str]: str log like 'docker logs' command  
    """
    myOrchestrator = selectOrchestrator()    
    return myOrchestrator.logs( authinfo, userinfo )


def removedesktop( authinfo:AuthInfo, userinfo:AuthUser ):
    """removedesktop

    Args:
        authinfo (AuthInfo): authentification data
        userinfo (AuthUser): user data 

    Returns:
        [bool]: True if the desktop is removed 
    """
    myOrchestrator = selectOrchestrator()    
    # remove the desktop
    removed_desktop = myOrchestrator.removedesktop( authinfo, userinfo )
    return removed_desktop


def removepodindesktop( authinfo:AuthInfo, userinfo:AuthUser ):
    """removedesktop

    Args:
        authinfo (AuthInfo): authentification data
        userinfo (AuthUser): user data 

    Returns:
        [bool]: True if the desktop is removed 
    """
    myOrchestrator = selectOrchestrator()    
    # remove the desktop
    removed_desktop = myOrchestrator.removepodindesktop( authinfo, userinfo )
    # remove the desktop
    return removed_desktop


def finddesktop_quiet( authinfo, userinfo ):
    myOrchestrator = selectOrchestrator()
    myDesktop = myOrchestrator.findDesktopByUser(authinfo, userinfo)      
    return myDesktop

def finddesktop( authinfo, userinfo  ):
    """finddesktop for userinfo

    Args:
        authinfo (AuthInfo): authentification data
        userinfo (AuthUser): user data 
        appname ([type], optional): [description]. Defaults to None.

    Returns:
        [ODesktop]: oc.od.desktop.ODDesktop Desktop Object or None if not found
    """
    services.messageinfo.push(userinfo.userid, 'Looking for your desktop.')        
    myOrchestrator = selectOrchestrator() # new Orchestrator Object    
    myDesktop = myOrchestrator.findDesktopByUser(authinfo, userinfo)     
    return myDesktop


def prepareressources( authinfo, userinfo ):
    """prepareressources for user from authinfo
        call Orchestrator.prepareressources

    Args:
        authinfo (AuthInfo): authentification data
        userinfo (AuthUser): user data 
    """
    myOrchestrator = selectOrchestrator()
    myOrchestrator.prepareressources( authinfo=authinfo, userinfo=userinfo )
    

def stopContainerApp(auth, user, podname, containerid):
    """stop container application if the container belongs to the user 
    Args:
        authinfo (AuthInfo): authentification data
        userinfo (AuthUser): user data 
        containerid (str): container id

    Raises:
        ODError: [description]

    Returns:
        [type]: [description]
    """
    logger.info('stopcontainer' )
    # new Orchestrator Object
    myOrchestrator = selectOrchestrator()   
    myDesktop = myOrchestrator.findDesktopByUser( auth, user )
    if not isinstance( myDesktop, oc.od.desktop.ODDesktop):
       raise ODError(status=404,message='stopcontainer::findDesktopByUser not found')

    if not myOrchestrator.isPodBelongToUser( auth, user, podname ):
        services.fail2ban.fail_login( user.userid )
        raise ODError( status=401, message='stopcontainer::invalid user')

    result = myOrchestrator.stopContainerApp( auth, user, podname, containerid )
    return result


def logContainerApp(authinfo, userinfo, podname, containerid):
    logger.info('stopcontainer' )

    # new Orchestrator Object
    myOrchestrator = selectOrchestrator()   
    myDesktop = myOrchestrator.findDesktopByUser( authinfo, userinfo )

    if not isinstance( myDesktop, oc.od.desktop.ODDesktop):
       raise ODError( status=404, message='findDesktopByUser not found')

    if not myOrchestrator.isPodBelongToUser( authinfo, userinfo, podname ):
        services.fail2ban.fail_login( userinfo.userid )
        raise ODError( status=401, message='isPodBelongToUser::invalid user')

    services.accounting.accountex('api', 'log_container_app' )
    result = myOrchestrator.logContainerApp( authinfo, userinfo, podname, containerid )
    return result


def removeContainerApp(authinfo, userinfo, podname, container_id):
    logger.info('removeContainerApp')

    # new Orchestrator Object
    myOrchestrator = selectOrchestrator()   
    myDesktop = myOrchestrator.findDesktopByUser( authinfo, userinfo )
        
    if not isinstance( myDesktop, oc.od.desktop.ODDesktop):
       raise ODError( status=404, message='findDesktopByUser not found')


    if not myOrchestrator.isPodBelongToUser( authinfo, userinfo, podname ):
        services.fail2ban.fail_login( userinfo.userid )
        raise ODError( status=401, message='isPodBelongToUser::invalid user')

    services.accounting.accountex('api', 'remove_container_app' )
    result = myOrchestrator.removeContainerApp( authinfo, userinfo, podname, container_id )
    return result

def getsecretuserinfo( authinfo, userinfo ):
    # new Orchestrator Object
    myOrchestrator = selectOrchestrator()   
    secretuserinfo = myOrchestrator.getsecretuserinfo( authinfo, userinfo )
    return secretuserinfo

def getldifsecretuserinfo( authinfo, userinfo ):
    # new Orchestrator Object
    myOrchestrator = selectOrchestrator()   
    secretuserinfo = myOrchestrator.getldifsecretuserinfo( authinfo, userinfo )
    return secretuserinfo

def listContainerApp(authinfo, userinfo):
    # new Orchestrator Object
    myOrchestrator = selectOrchestrator()   
    myDesktop = myOrchestrator.findDesktopByUser( authinfo, userinfo )     
    if not isinstance( myDesktop, oc.od.desktop.ODDesktop) :
       raise ODError( status=404, message='desktop not found')
    result = myOrchestrator.listContainerApps( authinfo, userinfo, myDesktop, services.apps )
    return result



def envContainerApp(authinfo, userinfo, podname, containerid ):
    # new Orchestrator Object
    myOrchestrator = selectOrchestrator()   
    myDesktop = myOrchestrator.findDesktopByUser( authinfo, userinfo )
        
    if not isinstance( myDesktop, oc.od.desktop.ODDesktop) :
       raise ODError( status=404, message='envContainerApp:findDesktopByUser not found')

    if not myOrchestrator.isPodBelongToUser( authinfo, userinfo, podname ):
        services.fail2ban.fail_login( userinfo.userid )
        raise ODError( status=401, message='isPodBelongToUser::invalid user')

    services.accounting.accountex('api', 'env_container_app')
    result = myOrchestrator.envContainerApp( authinfo, userinfo, podname, containerid )
    return result

def createExecuteEnvironment(authinfo, userinfo, app=None ):
    # build env dict
    # add environment variables        
    # get env from authinfo 
    # copy a env dict from configuration file
    env = oc.od.settings.desktop['environmentlocal'].copy()

    for key in authinfo.data.get('labels').keys():
        if isinstance( oc.od.settings.desktop['environmentlocalrules'].get( key ), dict ):
            env.update( oc.od.settings.desktop['environmentlocalrules'].get( key ) )

    locale = userinfo.get('locale', 'C')
    language = locale
    lang = locale + '.UTF-8'

    # update env with user local values read from the http request
    # LC_ALL is the environment variable that overrides all the other localisation settings 
    # (except $LANGUAGE under some circumstances).
    # no need to set 
    # 'LC_PAPER' : lang,
    # 'LC_ADDRESS' : lang,                
    # 'LC_MONETARY': lang,                
    # 'LC_TIME': lang,                 
    # 'LC_MEASUREMENT': lang,
    # 'LC_IDENTIFICATION': lang,             
    # 'LC_TELEPHONE': lang,               
    # 'LC_NUMERIC': lang,
    # 'LC_COLLATE': lang }
    env.update ( { 'LANGUAGE': language, 'LANG': lang, 'LC_ALL': lang } )

    # # add dbussession is set in config file
    # if oc.od.settings.desktop['usedbussession']  :
    #     env.update( {'OD_DBUS_SESSION_BUS': str(oc.od.settings.desktop['usedbussession']) })
    # # add dbussystem is set in config file
    # if oc.od.settings.desktop.get('usedbussystem') :
    #     env.update( {'OD_DBUS_SYSTEM_BUS': str(oc.od.settings.desktop['usedbussystem']) } )
    
    # add user name and userid 
    env.update( { 'ABCDESKTOP_USERNAME':  userinfo.get('name')} )
    env.update( { 'ABCDESKTOP_USERID':    userinfo.get('userid')} )

    # add provider name and userid 
    env.update( { 'ABCDESKTOP_PROVIDERNAME':  authinfo.get('provider')} )
    env.update( { 'ABCDESKTOP_PROVIDERTYPE':  authinfo.get('providertype')} )

    # 
    # if oc.od.webrtc.is_coturn_enable() is True:
    #    ice_server = oc.od.webrtc.coturn_iceserver( userinfo.userid + '_abcdesktop', format='env' )
    #    env.update( { 'TURN_SERVER': ice_server } )

    return env

def createDesktopArguments( authinfo, userinfo, args ):
    # build env dict
    # add environment variables   
    env = createExecuteEnvironment( authinfo, userinfo  )
    # add source ip addr as WEBCLIENT_SOURCEIPADDR var env
    env.update( { 'WEBCLIENT_SOURCEIPADDR':  args.get('WEBCLIENT_SOURCEIPADDR') } )                   
    myCreateDesktopArguments = { 'env' : env }
    return myCreateDesktopArguments
 
def resumedesktop( authinfo:AuthInfo, userinfo:AuthUser ) -> ODDesktop:
    myOrchestrator = selectOrchestrator()
    myDesktop = myOrchestrator.resumedesktop(authinfo, userinfo)
    return myDesktop
        

def createdesktop( authinfo:AuthInfo, userinfo:AuthUser, args  ):
    """create a new desktop 

    Args:
        authinfo (AuthInfo): authentification data
        userinfo (AuthUser): user data 
        args ([type]): [description]

    Returns:
        [type]: [description]
    """
    logger.info('Starting desktop creation') 
    logger.debug('createdesktop:createDesktopArguments')
    myCreateDesktopArguments = createDesktopArguments( authinfo, userinfo, args )
    
    messageinfo = services.messageinfo.getqueue(userinfo.userid)

    # new Orchestrator Object
    myOrchestrator = selectOrchestrator()
    myOrchestrator.desktoplaunchprogress += on_desktoplaunchprogress_info

    # Create the desktop                
    logger.debug('createdesktop:Orchestrator.createdesktop')
    myDesktop = myOrchestrator.createdesktop(   userinfo=userinfo, 
                                                authinfo=authinfo,  
                                                **myCreateDesktopArguments )

    if isinstance( myDesktop, oc.od.desktop.ODDesktop ):
        # logger.debug( 'desktop dump : %s', myDesktop.to_json() )
        if runwebhook( myDesktop, messageinfo ): # run web hook as soon as possible 
            messageinfo.push('c.Webhooking network services')
       
        messageinfo.push('c.Starting up core services')
        processready = myOrchestrator.waitForDesktopProcessReady( myDesktop, messageinfo.push )
        messageinfo.push('c.Core services started')
        logger.info(f"mydesktop on node {myDesktop.nodehostname} is processready={processready}")
        services.accounting.accountex('desktop', 'new') # increment new destkop creation accounting counter
    else:
        if isinstance( myDesktop, str ):
            # this is an error message
            messageinfo.push("e. " + myDesktop)
        else:
            messageinfo.push(f"e.CreateDesktop error - myOrchestrator.createDesktop return {type(myDesktop)}")
    return myDesktop


def sampledesktop(authinfo:AuthInfo, userinfo:AuthUser):

    kwargs   = {}
    myCreateDesktopArguments = createDesktopArguments( authinfo, userinfo, kwargs  )

    # new Orchestrator Object
    myOrchestrator = selectOrchestrator()
    myOrchestrator.desktoplaunchprogress = None
    # dry_run
    myCreateDesktopArguments['dry_run'] = 'All'
    # Create the desktop                
    jsonDesktop = myOrchestrator.createdesktop( authinfo, userinfo, **myCreateDesktopArguments )
    return jsonDesktop
    

def list_desktop():
    # new Orchestrator Object
    myOrchestrator = selectOrchestrator()
    listdesktop = myOrchestrator.list_desktop()
    return listdesktop

    
def openapp( auth, user={}, kwargs={} ):
    logger.debug('')
    
    appname  = kwargs.get('image')        # name of the image
    userargs = kwargs.get('args')         # get arguments for apps for example a file name

    # new Orchestrator Object
    myOrchestrator = selectOrchestrator()  

    # find the desktop for the current user 
    myDesktop = myOrchestrator.findDesktopByUser( auth, user )
    if not isinstance( myDesktop, ODDesktop):
        raise ODError( status=404, message='openapp:findDesktopByUser not found')

    # get application object from application name
    app = getapp(auth, appname)
    if not isinstance( app, dict ):
        raise ODError( status=404, message=f"app {appname} not found")

    # verify if app is allowed 
    # this can occur only if the applist has been (hacked) modified 
    # or applist has been updated in background 
    if not services.apps.is_app_allowed( auth, app ) :
        logger.error( 'SECURITY Warning applist has been modified or updated')
        raise ODError( status=401, message='Application access is denied by security policy')

    # Check limit apps counter
    max_app_counter = oc.od.settings.desktop['policies'].get('max_app_counter')
    if isinstance( max_app_counter, int ):
        # count running applications
        running_user_applications_counter = myOrchestrator.countRunningAppforUser( auth, user, myDesktop )
        if running_user_applications_counter > max_app_counter:
            raise ODError( status=400, message=f"policies {running_user_applications_counter}/{max_app_counter} too much applications are running, stop one of them" )

    """
    Deprecated
    # Check if the image is has the uniquerunkey Label set
    if app.get('uniquerunkey'):
        logger.debug(f"app {appname} has an uniqu key property set" )
        appinstance = myOrchestrator.getappinstance(auth, user, app )            
        if myOrchestrator.is_instance_app( appinstance ):
            logger.debug('Another container with the same uniquerunkey %s is running for userid %s', app.get('uniquerunkey'), user.userid)
            cmd,result = launch_app_in_process(myOrchestrator, app, appinstance, userargs)
            services.accounting.accountex('container', 'reused')
            services.accounting.accountex('image', app['name'] )
            return {    'container_id': appinstance.id,
                        'cmd': cmd,
                        'stdout': result['stdout']
            }
    
    logger.debug( 'no application instance %s is running, create a new one', str(appname) )                  
    services.accounting.accountex('api', 'openapp')
    """

    appinstancestatus = myOrchestrator.createappinstance( myDesktop, app, auth, user, userargs, **kwargs )
    if not isinstance( appinstancestatus, oc.od.appinstancestatus.ODAppInstanceStatus ):
        raise ODError( status=500, message=f"Failed to run application createappinstance return {type(appinstancestatus)}")
    logger.info(f"app {appinstancestatus.id} is {appinstancestatus.message}")
    
    runwebhook( appinstancestatus )
    # default return value appinstancestatus dict format to json format
    return appinstancestatus.to_dict()

def callwebhook(webhookcmd, messageinfo=None, timeout=60):
    logger.debug( f"callwebhook exec {webhookcmd}" )
    exitCode = -1
    try :
        proc = subprocess.run(webhookcmd, shell=True, timeout=timeout, stdout=subprocess.PIPE )
        if isinstance( proc, subprocess.CompletedProcess) :
            proc.check_returncode()
            if messageinfo:
                messageinfo.push('c.Webhooking updated service successfully')
            logger.info( f"command {webhookcmd} exit_code={proc.returncode} stdtout={proc.stdout.decode()}" )
            exitCode = proc.returncode
        else:
            logger.error( f"command {webhookcmd} subprocess.run return {str(type(proc))}" )
            if messageinfo:
                messageinfo.push("e.Webhooking updated service error, please read the log file ")
    except subprocess.CalledProcessError as e:
        if messageinfo:
            messageinfo.push(f"e.Webhooking updated service error {e}" )
        logger.error( f"command failed CalledProcessError {webhookcmd} error={e}")
    except subprocess.TimeoutExpired as e :
        logger.error( f"command TimeoutExpired {webhookcmd} error={e}" )
    except Exception as e:
        logger.error( f"command exception {webhookcmd} error={e}" )
        if messageinfo:
            messageinfo.push(f"e.Webhooking command exception error={e}" )
        logger.error( e )
    return exitCode

def notify_user_from_pod_application( pod_application, message:str )->None:
    # new Orchestrator Object
    myOrchestrator = selectOrchestrator() 
    (authinfo,userinfo) = myOrchestrator.extract_userinfo_authinfo_from_pod( pod_application )
    myDesktop = myOrchestrator.findDesktopByUser(authinfo=authinfo, userinfo=userinfo )
    if isinstance( myDesktop, oc.od.desktop.ODDesktop ):
        # default message data 
        data = {    'message': pod_application.metadata.name, 
                    'name': message
        }
        # get image from the pod image
        image = pod_application.status.container_statuses[0].image
        # read the icon from 
        app = services.apps.find_app_by_id(image)
        if isinstance(app, dict):
            # add more info the data
            data['icon'] = app.get('icon')
            data['icondata'] = app.get('icondata')
        else:
            logger.error( f"image {image} is not found by find_app_by_id")
        myOrchestrator.notify_user( myDesktop, 'container', data )

def notify_user(  authinfo:AuthInfo, userinfo:AuthUser, method:str, data:json )->None:
    """[notify_user]
        Send a notify message to a userid
    Args:
        userid ([str]): [userid]
        status ([str]): [one of 'oom']
        message ([str]): [message]
    """

    # new Orchestrator Object
    myOrchestrator = selectOrchestrator()  
    myDesktop = myOrchestrator.findDesktopByUser( authinfo, userinfo )
    if isinstance( myDesktop, ODDesktop) :
        myOrchestrator.notify_user( myDesktop, method, json.dumps(data) )
    

def getapp(authinfo:AuthInfo, name:str)->dict:
    app = services.apps.find_app_by_authinfo_and_name(authinfo, name)
    # if not isinstance(app, dict):
    #    raise ODError(message=f"Fatal error - Cannot find image associated to application {name}")
    return app

""" 
Deprecated
def launch_app_in_process(orchestrator, app, appinstance, userargs):
    cmd = [ app['path'],  app['args'], userargs ]
    result = orchestrator.execininstance(appinstance, cmd)
    if type(result) is not dict:
        raise ODError(status=500, message= 'execininstance error result is not a dict')
    return (cmd, result)
"""

def garbagecollector( expirein:int, force:bool=False ):
    logger.debug('')
    # new Orchestrator Object
    myOrchestrator = selectOrchestrator()   
    return myOrchestrator.garbagecollector( expirein=expirein, force=force )

# call info messages service
def on_desktoplaunchprogress_info(source, key, *args):
    logger.debug('')
    if key=='lookup_desktop':
        message = key
    elif key=='create_networks':
        message = key
    elif key=='create_desktop':
        message = key
    elif key=='start_desktop':
        message = key
    elif key=='wait_desktop_ready':
        message = key
    elif key=='desktop_ready':
        message = key
    else:
        try:
            message = key.format(*args)
        except Exception:
            message = key    
    services.messageinfo.push( services.auth.user.userid, message)


def detach_container_from_network( id:str ):
    """detach_container_from_network
        execute a postpone command when container or desktop stop

    Usage:
        call a url_webhook_destroy formated by orchestrator to notify stop on firewall for example 

    Args:
        id (str): container id or pod name

    Returns:
        bool: True if command exit command is 0 and id removed
    """
    bReturn = False
    logger.debug( f"detach_container_from_network:key={id}" )
    # read the postponed command
    cmd_webhook_destroy = oc.od.services.services.sharecache.get( id )
    if isinstance( cmd_webhook_destroy, str) :
        # execute the postponed command
        exitCode = callwebhook( cmd_webhook_destroy )
        if exitCode == 0 :
            # delete the postponed command
            bReturn = oc.od.services.services.sharecache.delete( id )
    return bReturn




def listAllSecretsByUser(authinfo:AuthInfo, userinfo:AuthUser )->list:
    """[listAllSecretsByUser]
        list all kubernetes secrets type for a user

    Args:
        authinfo ([AuthInfo]): [AuthInfo]
        userinfo ([AuthUser]): [AuthUser]

    Returns:
        [list]: [list of secret type]
    """

    # new Orchestrator Object
    myOrchestrator = selectOrchestrator()
    # find all screcrets for a user
    # do not show empty secret
    # empty secrets always exists to be updated with full data in case of double auth provider
    secrets_dict = myOrchestrator.list_dict_secret_data( authinfo, userinfo, hidden_empty=True )
    # for secret in secrets_dict.values():
    # map to filter secret type
    secrets_type_list = list( map(lambda x: x.get('type'), secrets_dict.values() ) )
    # return list
    return secrets_type_list


def notify_endpoint( url:str )->bool:
    """notify_endpoint
        call url endpoint 
        if apikey is set add as http header

    Args:
        url (str): url

    Returns:
        bool: http response.ok
    """
    try:
        headers = None
        apikey = oc.od.settings.controllers.get('ManagerController').get('apikey', [ None ])[0]
        if isinstance( apikey, str ) :
            headers={'X-API-Key': apikey }
        response = requests.get(url, headers=headers )
        if isinstance( response, requests.models.Response ):
            return response.ok
    except Exception as e:
        logger.error( e )
    return False


def notify_endpoints(pyos_endpoint_uri:str, pyos_endpoint_port:int, pyos_endpoint_addresses:str)->None:
    """notify_endpoints
        query endpoint '/API/manager/buildapplist' on a pyos instance
        url = f"http://{pyos_endpoint_address}:{pyos_endpoint_port}{pyos_endpoint_uri}"
        if pyos is running in developer mode, only call localhost as pyos_endpoint_addresses
        all call run as thread
    Args:
        pyos_endpoint_uri (str): uri endpoint
        pyos_endpoint_port (int): tcp port 
        pyos_endpoint_addresses (str): endpoint address
        
    """
    # if pyos is not running inside kubernetes pod  
    if oc.od.settings.developer_instance is True:
        # overwrite pyos_endpoint_addresses value  
        pyos_endpoint_addresses = [ 'localhost' ]
    for pyos_endpoint_address in pyos_endpoint_addresses:
        url = f"http://{pyos_endpoint_address}:{pyos_endpoint_port}{pyos_endpoint_uri}"
        notify_thread = threading.Thread(target=notify_endpoint, kwargs={'url': url } )
        notify_thread.start()


def notity_pyos_buildapplist()->None:
    """notity_pyos_buildapplist
        query endpoint '/API/manager/buildapplist'
        for all pyos pods instance 

    """
    ## new Orchestrator Object
    myOrchestrator = selectOrchestrator()
    # list all pyos endpoints (port and address)
    # listEndpointAddresses can return (None,None)
    (pyos_endpoint_port, pyos_endpoint_addresses) = myOrchestrator.listEndpointAddresses( 'pyos' )
    if isinstance(pyos_endpoint_port, int) and isinstance( pyos_endpoint_addresses, list ):
        # create a thread for each pyos_endpoint_addresses and call buildapplist
        notify_endpoints('/API/manager/buildapplist', pyos_endpoint_port, pyos_endpoint_addresses)
    else:
        # pyos account can't list listEndpointAddresses
        # call buildapplist only for this pyos pod's instance
        services.apps.cached_applist( bRefresh=True)

    return myOrchestrator



def pull_application_image( json_images:dict, node:str=None ):
    """pull_application_image

    Args:
        json_images (str): list of json image

    Returns:
        json: _description_
    """
    logger.debug('')

    # add entry from mongodb
    logger.debug('add json_image to collection start')
    json_put = oc.od.services.services.apps.add_json_image_to_collection( json_images )
    logger.debug(f"json_put type is {type(json_put)}")
    pulling = False
    if isinstance( json_put, dict ) or isinstance( json_put, list ):
        logger.debug('add json_image to collection done')
        # new Orchestrator Object
        myOrchestrator = selectOrchestrator()

        if isinstance(node,str):
            # if there is only one image
            if isinstance( json_put, dict ):
                json_put['pulling'] = myOrchestrator.pullimage( json_put, node )
            elif isinstance( json_put, list ) and len(json_put)>0:
                for app in json_put:
                    app['pulling'] = myOrchestrator.pullimage( app, node )
        else:
            # if there is only one image
            if isinstance( json_put, dict ):
                json_put['pulling'] = myOrchestrator.pullimage_on_all_nodes( json_put )
            elif isinstance( json_put, list ) and len(json_put)>0:
                for app in json_put:
                    app['pulling'] = myOrchestrator.pullimage_on_all_nodes( app )

        # broadcast event to all pyos instance to sync applist object
        notity_pyos_buildapplist()
    else:
        raise ODError( status=400, message="failed to add json image format to collection")
    # updated with app['pulling'] = status
    return json_put


def add_application_image( json_images ):
    """add_application_image

    Args:
        json_images (str): list of json image

    Returns:
        json: _description_
    """
    # add entry from mongodb
    json_put =  oc.od.services.services.apps.add_json_image_to_collection( json_images )
    notity_pyos_buildapplist()
    return json_put


def del_application_image( image:str )->list:
    """del_application_image

    Args:
        image (str): image id or image name

    Returns:
        list: delete image
    """
    images = []
    deleted_image = oc.od.services.services.apps.del_image( image )
    if deleted_image is True:
        notity_pyos_buildapplist()
        images.append( image )
    return images

def del_application_all_images():
    # remove entry from mongodb
    images = oc.od.services.services.apps.del_all_images()
    notity_pyos_buildapplist()
    return images
