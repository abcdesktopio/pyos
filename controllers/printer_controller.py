#!/usr/bin/env python3
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
import cherrypy
import oc.od.composer
import ldap.filter

import oc.od.settings as settings
from oc.cherrypy import WebAppError, Results, getclientipaddr
from oc.od.printer import ODPrinterControl
from oc.od.services import services
import oc.od.locator
from oc.od.base_controller import BaseController


logger = logging.getLogger(__name__)

@cherrypy.config(**{ 'tools.auth.on': True })
class PrinterController(BaseController):

    def __init__(self, config_controller=None):
        super().__init__(config_controller)

    def getclientlocation(self, auth):
        logger.info('')
        location = None
        try:
            domain = auth.data.get('domain')
        except Exception:
            return location

        logger.debug( 'domain is %s', str(domain) )    
        locatorPrivateActiveDirectory = services.locatorPrivateActiveDirectory.get(domain)
        try:        
            ipAddr = getclientipaddr()
            location = oc.od.locator.resolvlocation_activeDirectory( ipAddr, locatorPrivateActiveDirectory )
        except Exception as e:
            logger.error( e )
        return location

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def list(self):
        logger.info('')

        try:
            (auth, user ) = self.validate_env()
        except Exception as e:
            logger.error( e )
            return Results.error( message=str(e) )

        printers = []        
        logger.debug('self.getclientlocation')
        location = self.getclientlocation( auth )                

        if type(location) is oc.od.locator.ODLocation and \
           location.resolved and location.site :
            logger.debug('location is resolved')
            # find the auth provider 
            logger.debug('looking for the auth provider')
            provider=services.auth.findprovider( name=auth.data.get('domain') )            
            # build the ldap filter
            logger.debug('build the ldap filter')
            sitefilter = '(location=' + location.site + '*)'
            logger.debug('ldap filter %s', sitefilter)
            # run query to ldap server
            printers=provider.listprinter( sitefilter )
        else:
            # return empty data, location is not found
            # we do know where the user is and 
            # we can not query the activedirectory to find printers
            pass        
        return Results.success(result=printers)


    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def listenable(self):
        logger.debug('')
        
        try:
            (auth, user ) = self.validate_env()
        except Exception as e:
            logger.error( e )
            return Results.error( message=str(e) )

        try:
            name=auth.data.get('domain')
        except Exception:
            message='only activedirectory printer are supported'
            logger.error( message )
            return Results.error(message=message)


        printerenabledlist = []
        provider=services.auth.findprovider( name )
        printerctl = self.createprinterctl( auth, user )
        for printername in printerctl.list():
            if printername not in settings.printercupsembeddedList:
                printercn = printerctl.describe(printername).get('Description')
                if printercn:                   
                    printerfilter = '(cn=' + printercn + ')'
                    logger.debug('filter %s', printerfilter)
                    # run query to ldap server
                    printerentry=provider.listprinter( printerfilter )
                    if len(printerentry) == 1: # Only one printer should be found
                        printerenabledlist.append(printerentry[0])

        return Results.success(result=printerenabledlist)


    def list_ldap_printer( self, attribut, value, domain):
        """
            return a list of one printer from the ldap directory services
            use to make ure that the printer exist
        """
        # protect against ldap injection
        escape_value = ldap.filter.escape_filter_chars(value)
        if len(escape_value) != len( value ):
            logger.error( 'SECURITY WARNING Printer name contains escaped value' )
            logger.error( 'value=%s escape_value=%s', value, escape_value )

        printerfilter = '(' + attribut + '=' + escape_value + ')'
        # Get printer properties from cn by query ldap
        provider=services.auth.findprovider(domain)
        # run query to ldap server
        printers=provider.listprinter( printerfilter )
        return printers

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def add(self):
        logger.debug('')        
        
        #
        # get the cn json paramater
        try:
            cn = cherrypy.request.json.get('cn')
            if not cn:
                return Results.error( message='Argument not set: cn')
        except Exception as e:
            logger.error( e )
            return Results.error( message=str(e) )

        # valide env user and auth
        try:
            (auth, user ) = self.validate_env()
        except Exception as e:
            logger.error( e )
            return Results.error( message=str(e) )

        try:
            domain=auth.data.get('domain')
        except Exception:
            return Results.error(message='only activedirectory printers are supported')
        
        # value is escaped in list_ldap_printer
        printers = self.list_ldap_printer( attribut='cn', value=cn, domain=domain)
        
        if type(printers) is not list:  # Only one printer should be found
            return Results.error(message='Printer not found')    
        
        if len(printers) != 1:  # Only one printer should be found
            return Results.error(message='Printer not found or too much data found, expected only one')    

        printer = printers[0]
        
        myOrchestrator = oc.od.orchestrator.ODOrchestratorBase.selectOrchestrator()
        try:
            # network printers use Samba share by default  
            credentials = myOrchestrator.findSecretByUser(auth, user, 'cifs')  
        except Exception as e:
            self.logger.error( e )
            return Results.error( message=str(e) )

        try:
            # use only LDAP attribut
            # NEVER use user input data 
            self.createprinterctl( auth, user ).add( 
                name = printer.get('printerName'),
                cn = printer.get('cn'),
                uncname = printer.get('uNCName'),
                location = printer.get('location'),
                language = printer.get('printerLanguage'),
                options = printer.get('options', {}),
                printMediaReady = printer.get('printMediaReady'),
                username = credentials.get('username'), 
                password = credentials.get('password'), 
                domain = credentials.get('domain') 
            )
            return Results.success()

        except Exception as e:
            self.logger.error( e )
            return Results.error( message=str(e) )


    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def remove(self):

        #
        # get the printername json paramater
        printername = cherrypy.request.json.get('printerName')
        if type(printername) is not str or len(printername)<1:
            raise WebAppError('Invalid argument: printerName')
       
        try:
            (auth, user ) = self.validate_env()
        except Exception as e:
            logger.error( e )
            return Results.error( message=str(e) )

        try:
            domain=auth.data.get('domain')
        except Exception:
            return Results.error(message='only activedirectory printers are supported')


        # Do not trust user inpout
        # Only trust LDAP data 
        # Run a secure query to ldap to check that printer exists 
        # value is escaped in list_ldap_printer
        printers = self.list_ldap_printer( attribut='printerName', value=printername, domain=domain)
        
        if type(printers) is not list:  # Only one printer should be found
            return Results.error(message='Printer not found')    
        
        if len(printers) != 1:  # Only one printer should be found
            return Results.error(message='Printer not found or too much data found')    

        printer = printers[0]
        try:
            trustedprintername = printer.get('printerName')
            # logger.debug( 'removing printer name found in directory %s', trustedprintername )
            self.createprinterctl( auth, user ).remove( trustedprintername )
        except Exception as e:
            logger.error( e )
            return Results.error( message=str(e) )   
        
        return Results.success()

            

    def createprinterctl(self, auth, user ):
        #
        # new Orchestrator Object
        myOrchestrator = oc.od.composer.selectOrchestrator()
        # get desktop 
        desktop = myOrchestrator.findDesktopByUser(auth, user )
        # return the printerControl        
        return ODPrinterControl(desktop, myOrchestrator )
