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

import oc.od.settings as settings # Desktop settings lib
import oc.pyutils
import oc.od.infra
import oc.logging
import oc.od.orchestrator

from oc.od.services import services
from oc.od.infra import ODError  # Desktop Infrastructure Class lib
import distutils.util
import docker # only for type
from cherrypy import _json as json
import requests

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


def opendesktop(nodehostname, authinfo, userinfo, args ):
    """open a new or resule a desktop
    Args:
        nodehostname (str): prefered node host name
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
    
    # look for a desktop
    desktop = finddesktop( authinfo, userinfo, app )
    desktoptype = 'desktopmetappli' if app else 'desktop' 
    if type(desktop) is oc.od.desktop.ODDesktop :
        # if the desktop exists resume the connection
        services.accounting.accountex( desktoptype, 'resumed')
        logger.info("Container %s available, resuming", userinfo.userid)
        resumedesktop( nodehostname, authinfo, userinfo ) # update last connection datetime
    else:
        # create a new desktop
        desktop = createdesktop(nodehostname, authinfo, userinfo, args) 
        if desktop is None:
            services.accounting.accountex( desktoptype, 'createfailed')
            logger.error('Cannot create a new desktop') 
            return None
        else:
            services.accounting.accountex( desktoptype, 'createsucess')

    return desktop


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

def removedesktop( authinfo, userinfo, args ):
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
    myDesktop = myOrchestrator.findDesktopByUser(authinfo, userinfo, **args)
    removed_destop = myOrchestrator.removedesktop( authinfo, userinfo, args )
    
    if myDesktop :
        # if webrtc is enabled then 
        # remove the entry stream and listening port on the janus gateway
        if services.webrtc :
            # remove the stream
            services.webrtc.destroy_stream( myDesktop.name )
    
    # remove the desktop
    return removed_destop

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
    services.messageinfo.push(userinfo.userid, 'Looking for your desktop...')        
    myOrchestrator = selectOrchestrator() # new Orchestrator Object    
    kwargs = { 'defaultnetworknetuserid': oc.od.settings.defaultnetworknetuserid, 'appname': appname }
    myDesktop = myOrchestrator.findDesktopByUser(authinfo, userinfo, **kwargs)  
    services.messageinfo.push(userinfo.userid, 'Looking for your desktop done')     
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
    env = oc.od.settings.desktopenvironmentlocal.copy()

    locale = userinfo['locale']
    language = locale
    lang = locale + '.UTF-8'

    # update env with local values
    env.update ( {
        'LANGUAGE'	: language,                'LANG'		: lang,                'LC_ALL': lang,                  'LC_PAPER'	: lang,
        'LC_ADDRESS' 	: lang,                'LC_MONETARY': lang,                'LC_TIME': lang,                 'LC_MEASUREMENT': lang,
        'LC_IDENTIFICATION': lang,             'LC_TELEPHONE': lang,               'LC_NUMERIC': lang               }
    )
                    
    # add dbussession is set in config file
    if oc.od.settings.desktopusedbussession :
        env.update( {'OD_DBUS_SESSION_BUS': str(oc.od.settings.desktopusedbussession) })

    # add dbussystem is set in config file
    if oc.od.settings.desktopusedbussystem :
        env.update( {'OD_DBUS_SYSTEM_BUS': str(oc.od.settings.desktopusedbussystem) } )
    
    if type(app) is docker.models.images.Image:
        pass

    return env

def createDesktopArguments( authinfo, userinfo ):

    # build env dict
    # add environment variables   
    env = createExecuteEnvironment( authinfo, userinfo  )

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
        'desktophomedirectorytype': settings.getdesktop_homedirectory_type(),
            # set the homedir for balloon running inside the docker container 
            # by default /home/balloon
        'balloon_defaulthomedirectory': settings.getballoon_defaulthomedirectory(),
            # set the uid for balloon running inside the docker container
            # by default 4096
        'balloon_uid': settings.getballoon_uid(),  
            # set the gid for balloon running inside the docker container
            # by default 4096
        'balloon_gid': settings.getballoon_gid(),   
            # set the username for balloon running inside the docker container 
            # by default balloon            
        'balloon_name': settings.getballoon_name(), 
            # set desktopuserusehostsharememory
            # use the host share memory 
        'desktopuserusehostsharememory': settings.desktopuserusehostsharememory,            
            # ipc_mode for share ipc between container 
            # by default ipc_mode is 'shareable' 
        'ipc_mode' : settings.desktopusershareipcnamespace,
            # environment vars
        'env' : env
    }
    return myCreateDesktopArguments
 
def resumedesktop( preferednodehostname, authinfo, userinfo, appname='' ):
    myOrchestrator = selectOrchestrator()
    kwargs = { 'defaultnetworknetuserid': oc.od.settings.defaultnetworknetuserid, 'appname': appname }
    myDesktop = myOrchestrator.resumedesktop(authinfo, userinfo, **kwargs)  
    return myDesktop
        

def createdesktop( preferednodehostname, authinfo, userinfo, args  ):
    """create a new desktop 

    Args:
        preferednodehostname (str): [description]
        authinfo (AuthInfo): authentification data
        userinfo (AuthUser): user data 
        args ([type]): [description]

    Returns:
        [type]: [description]
    """
    logger.info('Starting desktop creation')
    app = None

    try:
        myCreateDesktopArguments = createDesktopArguments( authinfo, userinfo )
        myCreateDesktopArguments['preferednodehostname'] = preferednodehostname
        myCreateDesktopArguments['usersourceipaddr']     = args[ 'usersourceipaddr' ] 
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
        else:
            # use the desktop image
            myCreateDesktopArguments['image'] = settings.desktopimage

        if oc.od.settings.websocketrouting == 'bridge' :
            # no filter if cointainer ip addr use a bridged network interface
            myCreateDesktopArguments['env'].update({'DISABLE_REMOTEIP_FILTERING': 'enabled' })
        
        messageinfo = services.messageinfo.getqueue(userinfo.userid)
        messageinfo.push('Building desktop')

        # new Orchestrator Object
        myOrchestrator = selectOrchestrator()
        myOrchestrator.desktoplaunchprogress += on_desktoplaunchprogress_info

        # Create the desktop                
        myDesktop = myOrchestrator.createdesktop( userinfo=userinfo, authinfo=authinfo,  **myCreateDesktopArguments )

        if myDesktop is not None:
            messageinfo.push('Starting network services, it will take a while...')
            processready = myOrchestrator.waitForDesktopProcessReady( myDesktop, messageinfo.push )
            messageinfo.push('Network services started.')
            logger.info('mydesktop on node %s is %s', myDesktop.nodehostname, str(processready))
            services.accounting.accountex('desktop', 'new') # increment new destkop creation accounting counter
        else:
            messageinfo.push('createDesktop error - myOrchestrator.createDesktop return None')

        return myDesktop


    except Exception as e:
        logger.exception('failed: %s', e)
        return None




def openapp( auth, user={}, kwargs={} ):
    logger.debug('')
    
    appname  = kwargs.get('image')        # name of the image
    pod_name = kwargs.get('pod_name')     # pod_name can be none or example docker native mode
    userargs = kwargs.get('args')         # get arguments for apps for example a file name

    # new Orchestrator Object
    myOrchestrator = selectOrchestrator()  
    # find the desktop for the current user 
    myDesktop = myOrchestrator.findDesktopByUser( auth, user, **kwargs )
    if myDesktop is None:
        raise ODError( 'openapp:findDesktopByUser not found')

    myOrchestrator.nodehostname = myDesktop.nodehostname

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
        appinstance = myOrchestrator.getappinstance(app, user.userid)            
        if appinstance is not None:
            logger.debug('Another container %s with the same uniquerunkey %s is running for userid %s', appinstance.id, app.get('uniquerunkey'), user.userid)
            cmd,result = launchappprocess(myOrchestrator, appinstance, userargs)
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
    if type(appinstance) is not docker.models.containers.Container :
        raise ODError('Failed to run application')
        
    logger.info('Container %s is started', appinstance.id)
    
    # default return value
    openapp_dict =  {   'container_id': appinstance.id,  'state':        appinstance.status }

    # check if appinstances contains hook create or destroy
    if type(appinstance.webhook) is dict:
        webhook_create  = appinstance.webhook.get('create')
        if type(webhook_create) is str:
            webhook_result = callwebhook(webhook_create)
            openapp_dict.update( { 'webhook': { 'create' : webhook_result } } )

        webhook_destroy = appinstance.webhook.get('destroy')
        if type(webhook_destroy) is str:
            # post pone webhook_destroy call 
            # add url to call in 
            oc.od.services.services.sharecache.set( appinstance.id, webhook_destroy )

    return openapp_dict

def callwebhook(webhookurl):
    # webhook should work 
    logger.info(webhookurl)   
    hookdict = None
    if type(webhookurl) is str:
        hookdict = {}
        try :
            r = requests.get(webhookurl) 
            hookdict['status'] = r.status_code
            hookdict['text'] = r.text
            if r.status_code != 200:
                self.logger.error( 'failed to call %s resutl %s', webhookurl, str(r) )
        except Exception as e:
            hookdict['status'] = 500
            hookdict['text'] = str(e)
            self.logger.error( e )
    return hookdict


def getapp(authinfo, name):
    app = services.apps.findappbyname(authinfo, name)
    if app is None:
        raise ODError('Fatal error - Cannot find image associated to application %s: ' % name)
    return app


def launchappprocess(orchestrator, appinstance, userargs):
    app = appinstance.app
    cmd = [ app['path'],  app['args'], userargs ]
    result = orchestrator.execincontainer(appinstance.id, cmd)
    if type(result) is not dict:
        raise ODError('execincontainer error')
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
    url_webhook_destroy = oc.od.services.services.sharecache.get( container_id )
    if url_webhook_destroy :
        response_url_detach = callwebhook( url_webhook_destroy )
        logger.info( response_url_detach )
        