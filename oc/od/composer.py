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
import ua_parser

from oc.cherrypy import getclientipaddr
from oc.od.desktop import ODDesktop

import oc.od.orchestrator

from oc.od.services import services
from oc.auth.authuser import AuthUser
from oc.auth.authinfo import AuthInfo
from oc.auth.authroles import AuthRoles
from oc.od.error import ODError
import oc.od.appinstancestatus
import oc.od.desktop
import oc.od.services
import oc.od.tracking
import oc.od.settings

# type need for garbage collector
from kubernetes.client.models.v1_pod_list import V1PodList
from kubernetes.client.rest import ApiException

import subprocess
import json

from concurrent.futures import ThreadPoolExecutor

# Create a pool ONCE at module load
_WEBHOOK_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix='webhook')


logger = logging.getLogger(__name__)


""" 
    all functions are called by composer_controller
"""

def selectOrchestrator():
    myOrchestrator = oc.od.orchestrator.selectOrchestrator()
    return myOrchestrator

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


def get_webclient_os_family():
    desktop_theme = oc.od.settings.desktop.get('theme')
    if isinstance(desktop_theme, str):
        if desktop_theme == 'autodetect':
            desktop_theme = parse_user_agent_os_family()
    return desktop_theme

def parse_user_agent_os_family()->str:
    os_family = None # default value as fallback
    try:
        user_agent = oc.cherrypy.getuseragent()
        if isinstance(user_agent, str):
            user_agent = user_agent[:512]  # guard against pathological UA strings
        ua_parsed = ua_parser.parse(user_agent)
        if isinstance( ua_parsed, ua_parser.core.Result):
            os_family = ua_parsed.os.family.replace(' ', '').lower()
        # Mac OS/X -> macosx
        # Linux -> linux
        # Windows -> windows
    except Exception as e:
        logger.error(e)
    return os_family


def opendesktop(authinfo:AuthInfo, userinfo:AuthUser, rolesinfo:AuthRoles, args:dict ):
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
   
    if isinstance(desktop, ODDesktop) :
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
                if isinstance( desktop, ODDesktop):
                    oc.od.tracking.addresumenewentryindesktophistory(authinfo, userinfo, desktop )
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

    # read http headers for accounting and log history data
    args[ 'ABCDESKTOP_WEBCLIENT_SOURCEIPADDR' ] = oc.cherrypy.getclientipaddr()
    args[ 'ABCDESKTOP_WEBCLIENT_USERAGENT_OS_FAMILY' ] = get_webclient_os_family() # parse_user_agent_os_family()
    # open a new desktop
    desktop = createdesktop( authinfo, userinfo, rolesinfo, args)
    if isinstance( desktop, ODDesktop) :
        oc.od.tracking.addstartnewentryindesktophistory(authinfo, userinfo, desktop )
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
            bReturn = True
            for webhook_command in webhook_create[:16]:  # limit the list length
                logger.debug( f"calling webhook cmd  {webhook_command}" )
                # Submit to the pool instead of creating a new thread
                _WEBHOOK_EXECUTOR.submit(callwebhook, webhook_command, messageinfo)

        # if isinstance(webhook_create, list):
        #    bReturn = True # need to call a command
        #    for webhook_command in webhook_create:
        #        logger.debug( f"calling webhook cmd  {webhook_command}" )
        #        t1=threading.Thread(target=callwebhook, args=[webhook_command, messageinfo])
        #        t1.start()

        webhook_destroy = c.webhook.get('destroy')
        if webhook_destroy :
            # post pone webhook_destroy call 
            # add url to call in 
            oc.od.services.services.sharecache.set( c.id, webhook_destroy )
    return bReturn 


def remove_desktop_byname( desktop_name:str ):
    myOrchestrator = selectOrchestrator()
    (authinfo, userinfo) = myOrchestrator.find_userinfo_authinfo_by_desktop_name( name=desktop_name )
    if not isinstance( authinfo, AuthInfo) or not isinstance( userinfo, AuthUser) :
        raise ODError( status=404, message='desktop not found')
    return removedesktop( authinfo, userinfo )

def stop_container_byname( desktop_name:str, container:str )->bool:
    myOrchestrator = selectOrchestrator()  
    (authinfo, userinfo) = myOrchestrator.find_userinfo_authinfo_by_desktop_name( name=desktop_name )
    if not isinstance( authinfo, AuthInfo) or not isinstance( userinfo, AuthUser) :
        raise ODError( status=404, message='desktop not found')
    return myOrchestrator.stopContainerApp( authinfo, userinfo, desktop_name, container )

def list_container_byname( desktop_name:str ):
    myOrchestrator = selectOrchestrator()    
    (authinfo, userinfo, myDesktop) = myOrchestrator.find_userinfo_authinfo_desktop_by_desktop_name( name=desktop_name )
    if not isinstance( myDesktop, oc.od.desktop.ODDesktop) :
        raise ODError( status=404, message='desktop not found')
    if not isinstance( authinfo, AuthInfo) or not isinstance( userinfo, AuthUser) :
        raise ODError( status=404, message='desktop not found')
    return myOrchestrator.listContainerApps(authinfo, userinfo, myDesktop, services.apps )

def list_applications_by_name_and_type( desktop_name:str, type_of_application:str ):
    myOrchestrator = selectOrchestrator()    
    (authinfo, userinfo, myDesktop) = myOrchestrator.find_userinfo_authinfo_desktop_by_desktop_name( name=desktop_name )
    if not isinstance( myDesktop, oc.od.desktop.ODDesktop) :
        raise ODError( status=404, message='desktop not found')
    if not isinstance( authinfo, AuthInfo) or not isinstance( userinfo, AuthUser) :
        raise ODError( status=404, message='desktop not found')
    return myOrchestrator.list_application_by_type_of_application(authinfo, userinfo, myDesktop, [ type_of_application ] , services.apps )

def describe_desktop_byname( desktop_name:str ):
    myOrchestrator = selectOrchestrator()    
    myPod = myOrchestrator.describe_desktop_byname( desktop_name )
    if not isinstance( myPod, dict ):
        raise ODError( status=404, message='desktop not found')
    return myPod

def describe_application_byname( desktop_name:str, app_name:str ):
    myOrchestrator = selectOrchestrator()
    (authinfo, userinfo) = myOrchestrator.find_userinfo_authinfo_by_desktop_name( name=desktop_name )
    description = myOrchestrator.describe_application( authinfo, userinfo, desktop_name, app_name, services.apps )
    return description

def remove_container_byname(desktop_name:str, container:str):
    myOrchestrator = selectOrchestrator()    
    (authinfo, userinfo) = myOrchestrator.find_userinfo_authinfo_by_desktop_name( name=desktop_name )
    if not isinstance( authinfo, AuthInfo) or not isinstance( userinfo, AuthUser) :
        raise ODError( status=404, message='desktop not found')
    return myOrchestrator.removeContainerApp(authinfo,userinfo,desktop_name,container)

def get_pod_resources_usage(desktop_name:str, pod_name:str):
    myOrchestrator = selectOrchestrator()    
    (authinfo, userinfo) = myOrchestrator.find_userinfo_authinfo_by_desktop_name( name=desktop_name )
    if not isinstance( authinfo, AuthInfo) or not isinstance( userinfo, AuthUser) :
        raise ODError( status=404, message='desktop not found')
    return myOrchestrator.get_pod_resources_usage(authinfo,userinfo,pod_name=pod_name)

def get_container_resources_usage(desktop_name:str, container_name:str):
    myOrchestrator = selectOrchestrator()
    (authinfo, userinfo) = myOrchestrator.find_userinfo_authinfo_by_desktop_name( name=desktop_name )
    if not isinstance( authinfo, AuthInfo) or not isinstance( userinfo, AuthUser) :
        raise ODError( status=404, message='desktop not found')
    return myOrchestrator.get_container_resources_usage( authinfo, userinfo, container_name=container_name)

def get_desktop_resources_usage(desktop_name:str):
    myOrchestrator = selectOrchestrator()    
    (authinfo, userinfo) = myOrchestrator.find_userinfo_authinfo_by_desktop_name( name=desktop_name )
    if not isinstance( authinfo, AuthInfo) or not isinstance( userinfo, AuthUser) :
        raise ODError( status=404, message='desktop not found')
    return myOrchestrator.getdesktop_resources_usage(authinfo,userinfo)

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
    myDesktop = myOrchestrator.removedesktop( authinfo, userinfo )
    removed_desktop = isinstance( myDesktop, ODDesktop)
    if removed_desktop is True:
        oc.od.tracking.addstopnewentryindesktophistory(authinfo, userinfo, myDesktop )
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


def list_applications_by_phase( authinfo:AuthInfo, userinfo:AuthUser, phase:str )->list:
    # phase can be [ 'Running', 'Terminated', 'Waiting', 'Completed', 'Succeeded']
    myOrchestrator = selectOrchestrator() # new Orchestrator Object    
    myDesktop = myOrchestrator.findDesktopByUser(authinfo, userinfo)
    if not isinstance( myDesktop, oc.od.desktop.ODDesktop) :
        raise ODError( status=404, message='desktop not found')
    # list all type of application
    list_of_type_of_application = [ myOrchestrator.pod_application, myOrchestrator.ephemeral_container ]
    return myOrchestrator.list_application_by_type_of_application(authinfo, userinfo, myDesktop, list_of_type_of_application, services.apps, [ phase ] )


def prepareressources( authinfo: AuthInfo, userinfo: AuthUser ):
    """prepareressources for user from authinfo
        call Orchestrator.prepareressources

    Args:
        authinfo (AuthInfo): authentification data
        userinfo (AuthUser): user data 
    """
    myOrchestrator = selectOrchestrator()
    myOrchestrator.prepareressources( authinfo=authinfo, userinfo=userinfo )
    

def stopContainerApp(authinfo: AuthInfo, userinfo: AuthUser, podname:str, app_name:str):
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
    myDesktop = myOrchestrator.findDesktopByUser( authinfo, userinfo )
    if not isinstance( myDesktop, oc.od.desktop.ODDesktop):
       raise ODError(status=404,message='stopcontainer::findDesktopByUser not found')

    if not myOrchestrator.isPodBelongToUser( authinfo, userinfo, podname ):
        services.fail2ban.fail_login( userinfo.userid )
        raise ODError( status=401, message='stopcontainer::invalid user')

    result = myOrchestrator.stopContainerApp( authinfo, userinfo, podname, app_name )
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


def removeContainerApp(authinfo:AuthInfo, userinfo:AuthUser, podname, container_id):
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

def getsecretuserinfo( authinfo:AuthInfo, userinfo:AuthUser ):
    # new Orchestrator Object
    myOrchestrator = selectOrchestrator()   
    secretuserinfo = myOrchestrator.getsecretuserinfo( authinfo, userinfo )
    return secretuserinfo

def getldifsecretuserinfo( authinfo:AuthInfo, userinfo:AuthUser ):
    # new Orchestrator Object
    myOrchestrator = selectOrchestrator()   
    secretuserinfo = myOrchestrator.getldifsecretuserinfo( authinfo, userinfo )
    return secretuserinfo

def listContainerApps(authinfo:AuthInfo, userinfo:AuthUser):
    # new Orchestrator Object
    myOrchestrator = selectOrchestrator()   
    myDesktop = myOrchestrator.findDesktopByUser( authinfo, userinfo )     
    if not isinstance( myDesktop, oc.od.desktop.ODDesktop) :
       raise ODError( status=404, message='desktop not found')
    result = myOrchestrator.listContainerApps( authinfo, userinfo, myDesktop, services.apps )
    return result



def envContainerApp(authinfo:AuthInfo, userinfo:AuthUser, podname:str, containerid ):
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

def createExecuteEnvironment(authinfo:AuthInfo, userinfo:AuthUser, app=None ):
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

    return env

def createDesktopArguments( authinfo:AuthInfo, userinfo:AuthUser, args:dict )-> dict:
    # build env dict
    # add environment variables   
    env = createExecuteEnvironment( authinfo, userinfo  )
    # add source ip addr as WEBCLIENT_SOURCEIPADDR var env
    env.update( { 'ABCDESKTOP_WEBCLIENT_SOURCEIPADDR':  args.get('ABCDESKTOP_WEBCLIENT_SOURCEIPADDR') } )   
    env.update( { 'ABCDESKTOP_WEBCLIENT_USERAGENT_OS_FAMILY':  args.get('ABCDESKTOP_WEBCLIENT_USERAGENT_OS_FAMILY') } )
    authorizedkey = services.authorized_keys.get_key( userinfo.userid )      
    if isinstance( authorizedkey, str ): 
        env.update( { 'ABCDESKTOP_AUTHORIZEDKEY': authorizedkey } )
    myCreateDesktopArguments = { 'env' : env }
    return myCreateDesktopArguments
 
def resumedesktop( authinfo:AuthInfo, userinfo:AuthUser ) -> ODDesktop:
    myOrchestrator = selectOrchestrator()
    myDesktop = myOrchestrator.resumedesktop(authinfo, userinfo)
    return myDesktop
        

def createdesktop( authinfo:AuthInfo, userinfo:AuthUser, rolesinfo:AuthRoles, args  ):
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
    myDesktop = myOrchestrator.createdesktop(   userinfo=userinfo, 
                                                authinfo=authinfo,  
                                                rolesinfo=rolesinfo,
                                                **myCreateDesktopArguments )

    if isinstance( myDesktop, oc.od.desktop.ODDesktop ):
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


def dry_run_desktop(authinfo:AuthInfo, userinfo:AuthUser, rolesinfo:AuthRoles):
    """dry_run_desktop
        create a desktop with dry_run mode, this is used to test the desktop creation
        without creating a pod or a container   
    Args:
        authinfo (AuthInfo): authentification data
        userinfo (AuthUser): user data  
    Returns:
        [dict]: json dict with desktop information
    """
    myCreateDesktopArguments = createDesktopArguments( authinfo, userinfo, kwargs={}  )
    myCreateDesktopArguments['dry_run'] = 'All'
    
    # new Orchestrator Object
    myOrchestrator = selectOrchestrator()
    myOrchestrator.desktoplaunchprogress = dry_run_on_desktoplaunchprogress_info

    # Create the desktop dry_run             
    jsonDesktop = myOrchestrator.createdesktop( authinfo, userinfo, rolesinfo, **myCreateDesktopArguments )
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

    appinstancestatus = myOrchestrator.createappinstance( myDesktop, app, auth, user, userargs, **kwargs )
    if not isinstance( appinstancestatus, oc.od.appinstancestatus.ODAppInstanceStatus ):
        raise ODError( status=500, message=f"Failed to run application createappinstance return {type(appinstancestatus)}")
    logger.info(f"app {appinstancestatus.id} is {appinstancestatus.message}")
    
    # runwebhook( appinstancestatus )
    # default return value appinstancestatus dict format to json format
    return appinstancestatus.to_dict()

def callwebhook(webhookcmd:str, messageinfo=None, timeout:int=60):
    logger.debug( f"callwebhook exec {webhookcmd}" )
    exitCode = -1
    try :
        proc = subprocess.run(webhookcmd, timeout=timeout, stdout=subprocess.PIPE, shell=True)
        if isinstance( proc, subprocess.CompletedProcess) :
            proc.check_returncode()
            if messageinfo:
                messageinfo.push('c.Webhooking updated service successfully')
            # logger.info( f"command {webhookcmd} exit_code={proc.returncode} stdtout={proc.stdout.decode()}" )
            exitCode = proc.returncode
        else:
            logger.error( f"command {webhookcmd} subprocess.run return {str(type(proc))}" )
            if messageinfo:
                messageinfo.push("e.Webhooking updated service error, please read the log file ")
    except subprocess.CalledProcessError as e:
        if messageinfo:
            messageinfo.push(f"e.Webhooking updated service error" )
        logger.error( f"command failed CalledProcessError {webhookcmd} error={e}")
    except subprocess.TimeoutExpired as e :
        logger.error( f"command TimeoutExpired {webhookcmd} error={e}" )
    except Exception as e:
        logger.error( f"command exception {webhookcmd} error={e}" )
        if messageinfo:
            messageinfo.push(f"e.Webhooking command exception" )
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

def notify_user( authinfo:AuthInfo, userinfo:AuthUser, method:str, data:json )->None:
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


def garbagecollector( expirein:int, nodename:str=None, force:bool=False, snapshot:bool=False )->dict:

    """garbagecollector

    Args:
        expirein (int): garbage expired in millisecond 
        force (bool, optional): force event if user is connected. Defaults to False.

    Returns:
        list: list of str, list of pod name garbaged
    """
    assert isinstance(expirein, int), f"expirein has invalid type {type(expirein)}"
    # new Orchestrator Object
    myOrchestrator = selectOrchestrator() 
    # list of garbaged pod 
    garbaged = [] 
    list_label_selector = [ 'type=' + myOrchestrator.x11servertype ]

    # field_selector to select pod from a dedicated node 
    # implement gracefull shutdown of a node
    field_selector = None
    if isinstance( nodename, str ):
        field_selector = f"spec.nodeName={nodename}"

    for label_selector in list_label_selector:
        # list all graphical pods 
        myPodList = myOrchestrator.kubeapi.list_namespaced_pod(myOrchestrator.namespace, label_selector=label_selector, field_selector=field_selector, timeout_seconds=180)
        if isinstance( myPodList, V1PodList):
            for pod in myPodList.items:
                try:
                    isgarbagable = myOrchestrator.isgarbagable( pod, expirein, force )
                    myOrchestrator.logger.info( f"{pod.metadata.name} isgarbagable return {isgarbagable}" )
                    if isgarbagable is True:
                        # pod is garbageable, remove it
                        # fake an authinfo object
                        (authinfo,userinfo) = myOrchestrator.extract_userinfo_authinfo_from_pod(pod)
                        # remove desktop
                        myDesktop = myOrchestrator.removedesktop( authinfo, userinfo, pod, snapshot=snapshot )
                        removed_desktop = isinstance( myDesktop, ODDesktop)
                        if removed_desktop is True:
                            oc.od.tracking.addstopnewentryindesktophistory(authinfo, userinfo, myDesktop, isgarbaged=True )
                            # log remove desktop
                            myOrchestrator.logger.info( f"{pod.metadata.name} is removed" )
                            # add the name of the pod to the list of garbaged pod
                            garbaged.append( pod.metadata.name )
                except ApiException as e:
                    myOrchestrator.logger.error(e)
    return garbaged





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


def dry_run_on_desktoplaunchprogress_info(source, key, *args):
    # nothing to do here
    # this is a dry run call
    pass

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


def notity_pyos_buildapplist()->None:
    """notity_pyos_buildapplist
        query endpoint '/API/manager/buildapplist'
        for all pyos pods instance 

    """

    # update local applist first 
    # charity begins at home.
    services.apps.cached_applist(bRefresh=True)

    # notify ohers pyos instances to update their applist
    # this section code is removed 


def add_application_image( json_images ):
    """add_application_image

    Args:
        json_images (str): list of json image

    Returns:
        json: _description_
    """
    # add entry from mongodb
    json_put =  oc.od.services.services.apps.add_json_image_to_collection( json_images )

    if not oc.od.services.services.apps.is_mongo_watcher_alive():
        logger.error( "Mongo watcher is not alive, the application list may not be updated on other pyos instances" )
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
        if not oc.od.services.services.apps.is_mongo_watcher_alive():
            logger.error( "Mongo watcher is not alive, the application list may not be updated on other pyos instances" )
            notity_pyos_buildapplist() 
        images.append( image )
    return images

def del_application_all_images():
    # remove entry from mongodb
    images = oc.od.services.services.apps.del_all_images()
    if not oc.od.services.services.apps.is_mongo_watcher_alive():
        logger.error( "Mongo watcher is not alive, the application list may not be updated on other pyos instances" )
        notity_pyos_buildapplist() 
    return images
