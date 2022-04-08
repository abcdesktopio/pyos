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
from oc.od.desktop import ODDesktop

import oc.od.settings as settings # Desktop settings lib
import oc.pyutils
import oc.od.infra
import oc.logging
import oc.od.orchestrator

from oc.od.services import services
from oc.od.infra import ODError  # Desktop Infrastructure Class lib
from oc.auth.authservice  import AuthInfo, AuthUser # to read AuthInfo and AuthUser


import json

import subprocess
import threading

from docker.models.images               import Image
from docker.models.containers           import Container    # only for type
from kubernetes.client.models.v1_pod    import V1Pod        # only for type


logger = logging.getLogger(__name__)

""" 
    all functions are called by composer_controller
"""

def selectOrchestrator(arguments=None):
    """select Orchestrator 
       return a docker Orchestrator if oc.od.settings.stack_mode == 'standalone'
       return a kubernetes ODOrchestratorKubernetes if oc.od.settings.stack_mode == 'kubernetes'       

    Args:
        arguments ([type], optional): arguments to init Orchestrator. Defaults to None.

    Raises:
        NotImplementedError: if oc.od.settings.stack_mode not in [ 'standalone', 'kubernetes' ]
        NotImplementedError: if init orchestrator.__init__ config failed

    Returns:
        [ODOrchestrator]: [description]
    """
    myOrchestrator = None
    myOrchestratorClass = None
    if oc.od.settings.stack_mode == 'standalone' :     
        # standalone means a docker just installed        
        myOrchestratorClass = oc.od.orchestrator.ODOrchestrator
    
    elif oc.od.settings.stack_mode == 'kubernetes' :
        # kubernetes means a docker and kubernetes installed        
        myOrchestratorClass = oc.od.orchestrator.ODOrchestratorKubernetes

    if myOrchestratorClass is None:
        raise NotImplementedError('Orchestrator stack=%s is not implemented', oc.od.settings.stack_mode )  
    
    myOrchestrator = myOrchestratorClass( arguments )
    if myOrchestrator is None:
        raise NotImplementedError('Orchestrator stack=%s class=%s can not be instantiated', oc.od.settings.stack_mode, str(myOrchestratorClass) )  
    
    return myOrchestrator


def opendesktop(authinfo, userinfo, args ):
    """open a new or return a desktop
    Args:
        authinfo (AuthInfo): authentification data
        userinfo (AuthUser): user data 
        args (dict): additionnal desktop data 
                    {   'app':          application name,
                        'usersourceipaddr': oc.cherrypy.getclientipaddr(),
                        'querystring':  QUERYSTRING env inside the container,
                        'metadata' :    METADATA env inside the container,
                        'args' :        APPARGS inside the container,
                        'timezone' :    TZ env inside the contianer }

    Returns:
        [ODesktop]: Desktop Object
    """
    logger.info('')
    app = args.get('app')
    
    services.messageinfo.start(userinfo.userid, 'Looking for your desktop')
    # look for a desktop
    desktop = finddesktop( authinfo, userinfo, app )
    desktoptype = 'desktopmetappli' if app else 'desktop' 
    if isinstance(desktop, oc.od.desktop.ODDesktop) :
        services.messageinfo.push(userinfo.userid, 'Warm start, reconnecting to your running desktop') 
        logger.info('Warm start, reconnecting to running desktop') 
        # if the desktop exists resume the connection
        services.accounting.accountex( desktoptype, 'resumed')
        resumedesktop( authinfo, userinfo ) # update last connection datetime
    else:
        # create a new desktop
        services.messageinfo.push(userinfo.userid, 'Cold start, creating your new desktop')
        desktop = createdesktop( authinfo, userinfo, args) 
        if isinstance( desktop, oc.od.desktop.ODDesktop) :
            services.accounting.accountex( desktoptype, 'createsucess')
        else:
            services.accounting.accountex( desktoptype, 'createfailed')
            logger.error('Cannot create a new desktop') 
            if isinstance( desktop, str) :
                return desktop
            return None
            
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
                logger.debug( 'calling webhook cmd %s', webhook_command )
                t1=threading.Thread(target=callwebhook, args=[webhook_command, messageinfo])
                t1.start()

        webhook_destroy = c.webhook.get('destroy')
        if webhook_destroy :
            # post pone webhook_destroy call 
            # add url to call in 
            oc.od.services.services.sharecache.set( c.id, webhook_destroy )
    return bReturn 




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

def removedesktop( authinfo, userinfo ):
    """removedesktop

    Args:
        authinfo (AuthInfo): authentification data
        userinfo (AuthUser): user data 
        args ([type]): [description]

    Returns:
        [str]: status 
    """
    myOrchestrator = selectOrchestrator()    

    # webrtc look for the desktop
    myDesktop = myOrchestrator.findDesktopByUser(authinfo, userinfo )
    removed_desktop = myOrchestrator.removedesktop( authinfo, userinfo )
    
    if myDesktop and isinstance( services.webrtc, oc.od.janus.ODJanusCluster ):
        # if myDesktop has been found AND webrtc is a ODJanusCluster then 
        # remove the entry stream and to free the listening port on the janus gateway
        services.webrtc.destroy_stream( myDesktop.name )
    
    # remove the desktop
    return removed_desktop

def finddesktop_quiet( authinfo, userinfo, appname=None ):

    if userinfo.userid is None:
        logger.debug('finddesktop return None for userid None')
        return None
   
    myOrchestrator = selectOrchestrator()
    kwargs = { 'defaultnetworknetuserid': oc.od.settings.defaultnetworknetuserid, 'appname': appname }
    myDesktop = myOrchestrator.findDesktopByUser(authinfo, userinfo, **kwargs)      
    return myDesktop

def finddesktop( authinfo, userinfo, appname=None ):
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
    kwargs = { 'defaultnetworknetuserid': oc.od.settings.defaultnetworknetuserid, 'appname': appname }
    myDesktop = myOrchestrator.findDesktopByUser(authinfo, userinfo, **kwargs)     
    return myDesktop


def prepareressources( authinfo, userinfo):
    """prepareressources for user from authinfo
        call Orchestrator.prepareressources

    Args:
        authinfo (AuthInfo): authentification data
        userinfo (AuthUser): user data 
    """
    myOrchestrator = selectOrchestrator()
    myOrchestrator.prepareressources(authinfo, userinfo)
    

def stopContainerApp(auth, user, containerid):
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
        
    if myDesktop is None:
       raise ODError( 'stopcontainer::findDesktopByUser not found')

    services.accounting.accountex('api', 'container_app')
    myOrchestrator.nodehostname = myDesktop.nodehostname
    result = myOrchestrator.stopContainerApp( auth, user, containerid )
    return result


def logContainerApp(auth, user, containerid):
    logger.info('stopcontainer' )

    # new Orchestrator Object
    myOrchestrator = selectOrchestrator()   
    myDesktop = myOrchestrator.findDesktopByUser( auth, user )
        
    if myDesktop is None:
       raise ODError( 'stopcontainer::findDesktopByUser not found')

    services.accounting.accountex('api', 'log_container_app' )
    myOrchestrator.nodehostname = myDesktop.nodehostname
    result = myOrchestrator.logContainerApp( auth, user, containerid )
    return result


def removeContainerApp(auth, user, containerid):
    logger.info('removeContainerApp')

    # new Orchestrator Object
    myOrchestrator = selectOrchestrator()   
    myDesktop = myOrchestrator.findDesktopByUser( auth, user )
        
    if myDesktop is None:
       raise ODError( 'removeContainerApp:findDesktopByUser not found')

    services.accounting.accountex('api', 'remove_container_app' )
    myOrchestrator.nodehostname = myDesktop.nodehostname
    result = myOrchestrator.removeContainerApp( auth, user, containerid )
    return result

def getsecretuserinfo( auth, user ):
    logger.info('completeuserinfo')

    # new Orchestrator Object
    myOrchestrator = selectOrchestrator()   
    secretuserinfo = myOrchestrator.getsecretuserinfo( auth, user )
   
    return secretuserinfo



def listContainerApp(auth, user ):
    logger.info('listContainerApp')

    # new Orchestrator Object
    myOrchestrator = selectOrchestrator()   
    myDesktop = myOrchestrator.findDesktopByUser( auth, user )
        
    if myDesktop is None:
       raise ODError( 'listContainerApp:findDesktopByUser not found')

    services.accounting.accountex('api', 'list_container_app')
    myOrchestrator.nodehostname = myDesktop.nodehostname
    result = myOrchestrator.listContainerApps( auth, user )
    return result



def envContainerApp(auth, user, containerid ):
    logger.info('listcontainer')

    # new Orchestrator Object
    myOrchestrator = selectOrchestrator()   
    myDesktop = myOrchestrator.findDesktopByUser( auth, user )
        
    if myDesktop is None:
       raise ODError( 'stopcontainer::findDesktopByUser not found')

    services.accounting.accountex('api', 'env_container_app')
    myOrchestrator.nodehostname = myDesktop.nodehostname
    result = myOrchestrator.envContainerApp( auth, user, containerid )
    return result


def createExecuteEnvironment(authinfo, userinfo, app=None ):
    # build env dict
    # add environment variables        
    # get env from authinfo 
    # copy a env dict from configuration file
    env = oc.od.settings.desktop['environmentlocal'].copy()

    locale = userinfo['locale']
    language = locale
    lang = locale + '.UTF-8'

    # update env with user local values read from the http request
    env.update (    {   'LANGUAGE' : language,                
                        'LANG'	   : lang,                
                        'LC_ALL'   : lang,                  
                        'LC_PAPER' : lang,
                        'LC_ADDRESS' : lang,                
                        'LC_MONETARY': lang,                
                        'LC_TIME': lang,                 
                        'LC_MEASUREMENT': lang,
                        'LC_IDENTIFICATION': lang,             
                        'LC_TELEPHONE': lang,               
                        'LC_NUMERIC': lang }
    )
                    
    # add dbussession is set in config file
    if oc.od.settings.desktop['usedbussession']  :
        env.update( {'OD_DBUS_SESSION_BUS': str(oc.od.settings.desktop['usedbussession']) })

    # add dbussystem is set in config file
    if oc.od.settings.desktop.get('usedbussystem') :
        env.update( {'OD_DBUS_SYSTEM_BUS': str(oc.od.settings.desktop['usedbussystem']) } )
    
    # add user name and userid 
    env.update( { 'ABCDESKTOP_USERNAME':  userinfo.get('name')} )
    env.update( { 'ABCDESKTOP_USERID':    userinfo.get('userid')} )

    # add provider name and userid 
    env.update( { 'ABCDESKTOP_PROVIDERNAME':  authinfo.get('provider')} )
    env.update( { 'ABCDESKTOP_PROVIDERTYPE':  authinfo.get('providertype')} )

    return env

def createDesktopArguments( authinfo, userinfo, args ):

    # build env dict
    # add environment variables   
    env = createExecuteEnvironment( authinfo, userinfo  )
    
    # add source ip addr 
    env.update( { 'WEBCLIENT_SOURCEIPADDR':  args.get('WEBCLIENT_SOURCEIPADDR') } )


    #
    # get value from configuration files to build dict
    #                        
    myCreateDesktopArguments = { 
    
            # set the default network id to bind network interface
            # use only in docker and swarn mode 
            # not used by kubernetes mode 
        'defaultnetworknetuserid': settings.defaultnetworknetuserid,
            # set the default command to start the container
        'command': [ '/composer/docker-entrypoint.sh' ],
            # set command args
        'args'  : [],
            # set the getdesktop_homedirectory_type
            # can be volume or nfs 
        'homedirectory_type': settings.desktop['homedirectorytype'],
            # set the homedir for balloon running inside the docker container 
            # by default /home/balloon
        'balloon_homedirectory': settings.getballoon_homedirectory(),
            # set the uid for balloon running inside the docker container
            # by default 4096
        'balloon_uid': settings.getballoon_uid(),  
            # set the gid for balloon running inside the docker container
            # by default 4096
        'balloon_gid': settings.getballoon_gid(),   
            # set the username for balloon running inside the docker container 
            # by default balloon            
        'balloon_name': settings.getballoon_name(),       
            # environment vars
        'env' : env
    }
    return myCreateDesktopArguments
 
def resumedesktop( authinfo, userinfo, appname='' ):
    myOrchestrator = selectOrchestrator()
    kwargs = { 'defaultnetworknetuserid': oc.od.settings.defaultnetworknetuserid, 'appname': appname }
    myDesktop = myOrchestrator.resumedesktop(authinfo, userinfo, **kwargs)  
    return myDesktop
        

def createdesktop( authinfo, userinfo, args  ):
    """create a new desktop 

    Args:
        authinfo (AuthInfo): authentification data
        userinfo (AuthUser): user data 
        args ([type]): [description]

    Returns:
        [type]: [description]
    """
    logger.info('Starting desktop creation')
    app = None
    
    myCreateDesktopArguments = createDesktopArguments( authinfo, userinfo, args )
   
    appname = args.get('app')
    
    if type(appname) is str:
        app = getapp(authinfo, appname)
        myCreateDesktopArguments['desktopmetappli'] = True
        myCreateDesktopArguments['appname'] = appname
        myCreateDesktopArguments['image'] = app.name

        # environment variables for application 
        querystring = args.get('querystring')      
        if querystring :
            myCreateDesktopArguments['env'].update({'QUERYSTRING': querystring})
        
        argumentsmetadata = args.get('metadata')
        if argumentsmetadata :
            myCreateDesktopArguments['env'].update({'METADATA': argumentsmetadata })

        arguments = args.get('args')
        if arguments :
            myCreateDesktopArguments['env'].update({'APPARGS': arguments })

        timezone = args.get('timezone')
        if type(timezone) is str and len(timezone) > 1:
            myCreateDesktopArguments['env'].update({'TZ': timezone })

        logger.info("App image name : %s %s", app.name, arguments)

    
    messageinfo = services.messageinfo.getqueue(userinfo.userid)

    # new Orchestrator Object
    myOrchestrator = selectOrchestrator()
    myOrchestrator.desktoplaunchprogress += on_desktoplaunchprogress_info

    # Create the desktop                
    myDesktop = myOrchestrator.createdesktop(   userinfo=userinfo, 
                                                authinfo=authinfo,  
                                                **myCreateDesktopArguments )

    if isinstance( myDesktop, oc.od.desktop.ODDesktop ):
        logger.debug( 'desktop dump : %s', myDesktop.to_json() )
        if runwebhook( myDesktop, messageinfo ): # run web hook as soon as possible 
            messageinfo.push('Webhooking network services')
       
        messageinfo.push('Starting up internal services')
        processready = myOrchestrator.waitForDesktopProcessReady( myDesktop, messageinfo.push )
        messageinfo.push('Internal services started')
        logger.info('mydesktop on node %s is %s', myDesktop.nodehostname, str(processready))
        services.accounting.accountex('desktop', 'new') # increment new destkop creation accounting counter
    else:
        if isinstance( myDesktop, str ):
            messageinfo.push(myDesktop)
        else:
            messageinfo.push('createDesktop error - myOrchestrator.createDesktop return None')
    return myDesktop



    
def openapp( auth, user={}, kwargs={} ):
    logger.debug('')
    
    appname  = kwargs.get('image')        # name of the image
    userargs = kwargs.get('args')         # get arguments for apps for example a file name

    # new Orchestrator Object
    myOrchestrator = selectOrchestrator()  
    # find the desktop for the current user 
    myDesktop = myOrchestrator.findDesktopByUser( auth, user, **kwargs )
    if myDesktop is None:
        raise ODError( 'openapp:findDesktopByUser not found')

    myOrchestrator.nodehostname = myDesktop.nodehostname

    kwargs[ 'homedirectory_type' ] = settings.desktop['homedirectorytype']

    # Check limit apps counter
    max_app_counter = oc.od.settings.desktop['policies'].get('max_app_counter', -1)
    # check if 
    if max_app_counter > 0 :
        # count running applications
        running_user_applications_counter = myOrchestrator.countRunningContainerforUser( auth, user )
        if running_user_applications_counter > max_app_counter:
            raise ODError( 'policies %d too much applications are running, stop one of them' % running_user_applications_counter )

    # get application object from application name
    app = getapp(auth, appname)
    if app is None:
        raise ODError( 'app %s not found' % appname)

    # check if app is allowed 
    # this can occur only if the applist has been (hacked) modified 
    if not services.apps.is_app_allowed( auth, app ) :
        logger.error( 'SECURITY Warning applist has been (hacked) modified')
        # Block this IP source addr + user ?
        raise ODError('Application access is denied by security policy')

    # Check if the image is has the uniquerunkey Label set
    if app.get('uniquerunkey'):
        logger.debug('the app %s has an uniqu key property set', appname )
        appinstance = myOrchestrator.getappinstance(auth, user, app )            
        if appinstance is not None:
            logger.debug('Another container with the same uniquerunkey %s is running for userid %s', app.get('uniquerunkey'), user.userid)
            cmd,result = launchappprocess(myOrchestrator, app, appinstance, userargs)
            services.accounting.accountex('container', 'reused')
            services.accounting.accountex('image', app['name'] )
            return {
                'container_id': appinstance.id,
                'cmd': cmd,
                'stdout': result['stdout']
            }
    
    logger.debug( 'no application instance %s is running, create a new one', str(appname) )                  
    services.accounting.accountex('api', 'openapp')

    appinstance = myOrchestrator.createappinstance( myDesktop, app, auth, user, userargs, **kwargs )
    if not isinstance(appinstance, Container) and not isinstance(appinstance, V1Pod ):
        raise ODError('Failed to run application return %s', type(appinstance) )

    logger.info('app %s is started', appinstance.id)

    runwebhook( appinstance )
   
    # default return value
    openapp_dict =  { 'container_id': appinstance.id, 'state': appinstance.message }
    return openapp_dict

def callwebhook(webhookcmd, messageinfo=None, timeout=60):
    logger.debug( 'callwebhook exec ' + webhookcmd )
    try :
        proc = subprocess.run(webhookcmd, shell=True, timeout=timeout )
        if isinstance( proc, subprocess.CompletedProcess) :
            proc.check_returncode()
            if messageinfo:
                messageinfo.push('Webhooking updated service successfully')
            logger.info( 'command %s exit_code=%d stdtout=%s', webhookcmd, proc.returncode, proc.stdout )
        else:
            if messageinfo:
                messageinfo.push('Webhooking updated service error ' + str(proc.stdout) )
            logger.error( 'command %s failed ',webhookcmd )
    except subprocess.CalledProcessError as e:
        if messageinfo:
            messageinfo.push('Webhooking updated service error ' + str(e) )
        logger.error( 'command %s failed error=%s', webhookcmd, str(e) )
    except Exception as e:
        if messageinfo:
            messageinfo.push('Webhooking updated service error ' + str(e) )
        logger.error( e )

def notify_user( access_userid, access_type, method, data ):
    """[notify_user]
        Send a notify message to a userid
    Args:
        userid ([str]): [userid]
        status ([str]): [one of 'oom']
        message ([str]): [message]
    """
    # fake an authinfo object
    authinfo = AuthInfo( provider=access_type )
    # fake an userinfo object
    userinfo = AuthUser( {  'userid': access_userid } )

    # new Orchestrator Object
    myOrchestrator = selectOrchestrator()  
    myDesktop = myOrchestrator.findDesktopByUser( authinfo, userinfo )
    cmd = [ 'node',  '/composer/node/occall/occall.js', method, json.dumps(data) ]
    if isinstance( myDesktop, ODDesktop) :
        myOrchestrator.execininstance(myDesktop, cmd)
    

def getapp(authinfo, name):
    app = services.apps.findappbyname(authinfo, name)
    if app is None:
        raise ODError('Fatal error - Cannot find image associated to application %s: ' % name)
    return app


def launchappprocess(orchestrator, app, appinstance, userargs):
    cmd = [ app['path'],  app['args'], userargs ]
    result = orchestrator.execininstance(appinstance, cmd)
    if type(result) is not dict:
        raise ODError('execininstance error')
    return (cmd, result)

def garbagecollector( expirein, force=False ):
    logger.debug('')
    garbaged = []
    try:
        # new Orchestrator Object
        myOrchestrator = selectOrchestrator()   
        garbaged = myOrchestrator.garbagecollector( expirein=expirein, force=force )
    except Exception as e:
        logger.exception(e)
    return garbaged

        

# call info messages service
def on_desktoplaunchprogress_info(source, key, *args):
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

# call accounting service
# def on_desktoplaunchprogress_count(source, key, *args):
#     if key=='resume_desktop':
#        message = key
#    elif key=='create_desktop':
#        message = key
#    elif key=='create_desktop_error':
#        pass
#    else:
#        return



def detach_container_from_network( container_id ):
    """ detach a container from a network
        call a url_webhook_destroy formated by orchestrator
        to notify stop on firewall for example 
    Args:
        container_id ([str]): [container id]
    """
    logger.debug( 'detach_container_from_network:key=%s', container_id )
    cmd_webhook_destroy = oc.od.services.services.sharecache.get( container_id )
    if isinstance( cmd_webhook_destroy, str) :
        callwebhook( cmd_webhook_destroy )



def listAllSecretsByUser(authinfo, userinfo ):
    """[listAllSecretsByUser]

    Args:
        authinfo ([type]): [description]
        userinfo ([type]): [description]

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